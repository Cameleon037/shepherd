import shlex
import signal
import sys
import time

from django.core.management import call_command
from django.core.management.base import BaseCommand

from jobs.models import Job


class _PipeSafeStdout:
    """Output that survives the death of the supervisor.

    run_job reads this process through a pipe. When that reader disappears (a
    dev-server reload while the scan keeps running), the next write would raise
    BrokenPipeError and abort an otherwise healthy scan mid-run. Swallow it instead:
    the output simply stops being captured, and the scan still finishes and records
    its own outcome."""

    def __init__(self, stream):
        self._stream = stream
        self.broken = False

    def write(self, msg):
        if self.broken:
            return len(msg)
        try:
            self._stream.write(msg)
        except (BrokenPipeError, ValueError, OSError):
            self.broken = True
        return len(msg)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        if self.broken:
            return
        try:
            self._stream.flush()
        except (BrokenPipeError, ValueError, OSError):
            self.broken = True

    def isatty(self):
        return False


class Command(BaseCommand):
    help = (
        'Supervise a scan command and self-finalize its Job row. run_job launches '
        'scans through this wrapper so the outcome is recorded by the scan process '
        'itself: it still lands when the launching web/celery supervisor died (dev '
        'server reload), and even when the scan itself is terminated.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--jobid', type=int, required=True)
        parser.add_argument('--command', required=True, help='inner management command name')
        # dest must NOT be 'args': BaseCommand.run_from_argv pops the parse result's
        # 'args' key as the positional-args list, which would silently drop this value.
        parser.add_argument('--args', dest='scan_args', default='',
                            help='args string for the inner command')

    def _finalize(self, status):
        """Record the scan's own outcome, retrying the transient sqlite failures this
        dev database shows ('attempt to write a readonly database'). If every attempt
        fails, reap_stale_jobs() still turns the row around once the pid is gone."""
        from django.utils.timezone import now
        for attempt in range(3):
            try:
                Job.objects.filter(pk=self.jobid).update(status=status, finished_at=now())
                return True
            except Exception:
                if attempt < 2:
                    time.sleep(1.0)
        return False

    def _on_term(self, signum, frame):
        self._finalize('failed')
        raise SystemExit(128 + signum)

    def handle(self, *args, **options):
        self.jobid = options['jobid']
        inner = options['command']
        inner_args = options.get('scan_args') or ''

        signal.signal(signal.SIGTERM, self._on_term)

        status = 'failed'
        # The scan's output goes to run_job's pipe. If that reader is gone (dev-server
        # reload, worker restart), a write would raise BrokenPipeError and kill a scan
        # that is otherwise running fine, so make the stream tolerant first.
        original_stdout = sys.stdout
        sys.stdout = _PipeSafeStdout(original_stdout)
        try:
            call_command(inner, *shlex.split(inner_args))
            status = 'finished'
        except SystemExit as e:
            status = 'finished' if (e.code in (0, None)) else 'failed'
        except Exception as e:
            status = 'failed'
            # Keeps the reason visible in the job output instead of dying silently.
            self.stdout.write(f'run_scan: {inner} raised {type(e).__name__}: {e}')
        finally:
            sys.stdout = original_stdout
        self._finalize(status)
