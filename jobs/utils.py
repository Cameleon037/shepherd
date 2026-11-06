import gc
import os
import queue
import signal
import subprocess
import threading
import time

from django.utils.timezone import now

from jobs.models import Job
from project.models import Project

# How often (seconds) the captured output is persisted to the database.
FLUSH_INTERVAL = 5.0
# Also flush once this many lines have accumulated (protects against huge buffers).
MAX_LINES_PER_FLUSH = 100
# How long to wait for the next line before re-checking the flush timer (seconds).
READ_TIMEOUT = 0.5
# Retry parameters for transient DB errors (e.g. SQLite "database is locked").
DB_MAX_RETRIES = 5
DB_RETRY_DELAY = 1.0

# Sentinel pushed by the reader thread when the subprocess stdout reaches EOF.
_EOF = object()


def _persist_fields(job, fields, max_retries=DB_MAX_RETRIES, delay=DB_RETRY_DELAY):
    """Best-effort save of the given job fields.

    The child management command writes to the same database, so under SQLite the
    parent can hit transient "database is locked" errors. Retry instead of letting
    a transient lock kill the job. If the save ultimately fails the output stays in
    the in-memory ``job.output`` and is retried on the next flush cycle, so no
    output is lost.
    """
    for attempt in range(max_retries):
        try:
            job.save(update_fields=fields)
            return True
        except Exception:
            if attempt == max_retries - 1:
                return False
            time.sleep(delay)
    return False


def _persist_job(job, max_retries=DB_MAX_RETRIES, delay=DB_RETRY_DELAY):
    """Best-effort full save (terminal status/timestamps + any pending output)."""
    for attempt in range(max_retries):
        try:
            job.save()
            return True
        except Exception:
            if attempt == max_retries - 1:
                return False
            time.sleep(delay)
    return False


def run_job(command, args, projectid, user=None):
    """Run a scan command as a subprocess and record its Job row.

    No wall-clock cap: legitimate scans run for days. A scan always terminates
    itself (see run_scan, which writes the Job row), and a dead process is turned
    around by reap_stale_jobs().
    """
    job = Job()
    job.related_project = Project.objects.get(id=projectid)
    job.user = user
    job.status = 'running'
    job.started_at = now()
    job.command = command
    job.args = args
    job.output = ''
    job.save()

    process = None
    reader_thread = None
    line_queue = queue.Queue()
    try:
        # Launched through the run_scan wrapper, which writes the job's terminal
        # status itself — so the outcome survives even if this (web/celery) supervisor
        # dies, e.g. on a dev-server reload while the scan keeps running.
        process = subprocess.Popen(
            ['python3', '-u', 'manage.py', 'run_scan',
             '--jobid', str(job.pk), '--command', job.command, '--args', job.args or ''],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        # Record the OS pid so a delete can kill the process tree (same process
        # group as the child, so one killpg reaches its tools too).
        job.pid = process.pid
        _persist_fields(job, ['pid'])

        def _read_stdout():
            try:
                for line in process.stdout:
                    line_queue.put(line)
            finally:
                line_queue.put(_EOF)
                try:
                    process.stdout.close()
                except Exception:
                    pass

        # Read the subprocess output in a separate thread so the flush loop below
        # can run on a strict timer even when the subprocess is silent. Otherwise
        # (line-driven flush) output produced in bursts would sit in memory until
        # the next line arrives or the process exits.
        reader_thread = threading.Thread(target=_read_stdout, daemon=True)
        reader_thread.start()

        pending = []
        last_flush = time.monotonic()
        eof = False

        while not eof:
            try:
                item = line_queue.get(timeout=READ_TIMEOUT)
            except queue.Empty:
                item = None  # timeout: no new line yet

            if item is _EOF:
                eof = True
            elif item is not None:
                pending.append(item)

            now_t = time.monotonic()
            if pending and (
                eof
                or len(pending) >= MAX_LINES_PER_FLUSH
                or now_t - last_flush >= FLUSH_INTERVAL
            ):
                job.output = (job.output or '') + ''.join(pending)
                pending = []
                last_flush = now_t
                _persist_fields(job, ['output'])

        # Flush any output still buffered when the subprocess closed its stdout.
        if pending:
            job.output = (job.output or '') + ''.join(pending)
            pending = []
            _persist_fields(job, ['output'])

        if reader_thread:
            reader_thread.join(timeout=5)
        process.wait()
        # The run_scan wrapper records the scan's own outcome (surviving the
        # death of this supervisor). Adopt it when present; otherwise fall back
        # to the exit code.
        recorded = Job.objects.filter(pk=job.pk).values_list('status', flat=True).first()
        if recorded and recorded != 'running':
            job.status = recorded
        elif process.returncode == 0:
            job.status = 'finished'
        else:
            job.status = 'failed'
    except Exception as e:
        job.output = (job.output or '') + f"\nError: {e}"
        job.status = 'failed'
    finally:
        job.finished_at = now()
        _persist_job(job)

        # Defensive cleanup: never leave a stray subprocess or reader thread behind.
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            except Exception:
                pass
        if reader_thread is not None:
            reader_thread.join(timeout=2)
        gc.collect()


# Grace period (seconds) after SIGTERM before escalating to SIGKILL.
KILL_GRACE = 5.0


# Chromium process names Playwright spawns (its driver's children). Verified on
# prod (comm 'headless_shell', /var/www/.cache/ms-playwright) and dev.
BROWSER_PROCESS_NAMES = ('headless_shell', 'chrome', 'chromium', 'chromium-browser',
                         'chrome_crashpad_handler')

# Playwright always launches its bundled browsers from its cache directory, so the
# marker also appears in their command lines (prod: /var/www/.cache/ms-playwright/...).
# Reclaiming orphans requires it, so a developer's own Chrome is never matched.
PLAYWRIGHT_PATH_MARKER = 'ms-playwright'


def _looks_like_browser(name):
    lowered = (name or '').lower()
    return any(marker in lowered for marker in BROWSER_PROCESS_NAMES)


def _proc_cmdline(pid):
    """Command line of a pid, or '' when it cannot be read."""
    if os.path.isdir('/proc'):
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                return f.read().decode('utf-8', 'replace')
        except Exception:
            return ''
    try:
        return subprocess.run(['ps', '-o', 'command=', '-p', str(pid)],
                              capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ''


def _process_edges():
    """All processes as (pid, ppid, comm) tuples.

    Uses ``/proc`` on Linux and ``ps`` elsewhere — macOS dev has no ``/proc``, and
    the descendant walk is what lets us reach Playwright's Chromium, which runs in
    its own session and therefore survives ``killpg`` of the scan's group."""
    edges = []
    if os.path.isdir('/proc'):
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                with open(f'/proc/{entry}/comm') as f:
                    name = f.read().strip()
                with open(f'/proc/{entry}/stat') as f:
                    # ppid is the 4th field; comm (field 2) may contain spaces or
                    # parens, so parse after the last ')'.
                    ppid = int(f.read().rsplit(')', 1)[1].split()[1])
                edges.append((int(entry), ppid, name))
            except Exception:
                continue
        return edges
    try:
        out = subprocess.run(['ps', '-axo', 'pid=,ppid=,comm='],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            edges.append((int(parts[0]), int(parts[1]), parts[2].strip().split('/')[-1]))
    return edges


def _descendant_pids(root):
    """Direct + transitive descendant pids of *root*. Catches processes living in
    other process groups/sessions — Playwright's Chromium runs in its own session,
    so ``killpg`` of the scan's group would miss it."""
    kids = {}
    for pid, ppid, _name in _process_edges():
        kids.setdefault(ppid, []).append(pid)
    out, stack = [], [root]
    while stack:
        p = stack.pop()
        for c in kids.get(p, []):
            out.append(c)
            stack.append(c)
    return out


def _descendant_browser_pids(root, extra_names=()):
    """Descendants of *root* that are browser processes (plus *extra_names*).
    Name matching is enough here: these are our own children."""
    names = tuple(extra_names)
    kids = {}
    info = {}
    for pid, ppid, name in _process_edges():
        kids.setdefault(ppid, []).append(pid)
        info[pid] = name
    found, stack = [], [root]
    while stack:
        p = stack.pop()
        for c in kids.get(p, []):
            stack.append(c)
            if _looks_like_browser(info.get(c)) or info.get(c) in names:
                found.append(c)
    return found


def kill_job_process_tree(pid, grace=KILL_GRACE):
    """Terminate a running job's process group AND its descendants. Descendants are
    SIGKILLed first because Playwright's Chromium lives in its own session, which
    killpg of the scan's group would miss. Returns True if the process is gone / not
    reachable; False on PermissionError (owned by another user — nothing to do)."""
    for p in _descendant_pids(pid):
        try:
            os.kill(p, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.2)
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def _proc_name_and_parent(pid):
    """(comm_name, ppid) for a pid, or (None, None)."""
    for proc_pid, ppid, name in _process_edges():
        if proc_pid == pid:
            return name, ppid
    return None, None


def _proc_age_seconds(pid):
    """Process lifetime in seconds, or None when it cannot be determined."""
    if os.path.isdir('/proc'):
        try:
            with open(f'/proc/{pid}/stat') as f:
                starttime = int(f.read().rsplit(')', 1)[1].split()[19])  # field 22
            with open('/proc/uptime') as f:
                uptime = float(f.read().split()[0])
            return uptime - starttime / os.sysconf('SC_CLK_TCK')
        except Exception:
            return None
    try:
        out = subprocess.run(['ps', '-o', 'etime=', '-p', str(pid)],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return None
    # etime is [[DD-]hh:]mm:ss
    if not out:
        return None
    days = 0
    if '-' in out:
        days, out = out.split('-', 1)
        days = int(days)
    parts = [int(p) for p in out.split(':')]
    seconds = 0
    for p in parts:
        seconds = seconds * 60 + p
    return days * 86400 + seconds


def _orphan_browser_pids(min_age=60):
    """Pids of Playwright-launched Chromium processes reparented to init (ppid == 1),
    i.e. leaked by a scan whose parent died. An actively-used browser's Chromium has
    the live node driver as its parent (never 1), so this never touches it. The
    command-line marker is what keeps a developer's own Chrome out of the match."""
    found = []
    for pid, ppid, name in _process_edges():
        if ppid != 1 or not _looks_like_browser(name):
            continue
        if PLAYWRIGHT_PATH_MARKER not in _proc_cmdline(pid):
            continue
        age = _proc_age_seconds(pid)
        if age is None or age > min_age:
            found.append(pid)
    return found


def reap_stale_jobs():
    """Flip 'running' Job rows whose recorded process is gone to 'failed', and
    reclaim orphaned Chromium left by dead scans. Returns the rows reaped.

    Deliberately age-blind: legitimate scans run for days, so only process liveness
    proves a row is stranded. A live pid (or a row with no pid recorded) is left alone.
    """
    reaped = 0
    for job in Job.objects.filter(status='running'):
        pid = job.pid
        if not pid:
            continue
        try:
            os.kill(pid, 0)              # PermissionError => foreign, treat as alive
            continue
        except ProcessLookupError:
            reason = f"process {pid} is no longer running (orphaned job row)"
        except PermissionError:
            continue
        job.status = 'failed'
        job.finished_at = now()
        job.output = (job.output or '') + f"\nError: reaped - {reason}."
        try:
            job.save(update_fields=['status', 'finished_at', 'output'])
            reaped += 1
        except Exception:
            pass
    # Reclaim wedged/orphaned Chromium (reparented to init) so their 100% CPU burn
    # stops even after the Job row was handled above.
    for opid in _orphan_browser_pids():
        for p in [opid] + _descendant_pids(opid):
            try:
                os.kill(p, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    return reaped