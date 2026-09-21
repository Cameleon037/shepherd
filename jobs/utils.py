import gc
import queue
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


def _persist_output(job, max_retries=DB_MAX_RETRIES, delay=DB_RETRY_DELAY):
    """Best-effort save of the job's output field.

    The child management command writes to the same database, so under SQLite the
    parent can hit transient "database is locked" errors. Retry instead of letting
    a transient lock kill the job. If the save ultimately fails the output stays in
    the in-memory ``job.output`` and is retried on the next flush cycle, so no
    output is lost.
    """
    for attempt in range(max_retries):
        try:
            job.save(update_fields=['output'])
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
        process = subprocess.Popen(
            ['python3', '-u', 'manage.py', job.command] + job.args.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

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
                _persist_output(job)

        if reader_thread:
            reader_thread.join(timeout=5)

        process.wait()
        # Defensive: ensure all output is captured
        if process.returncode == 0:
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