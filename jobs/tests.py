import io
import os
import subprocess
import sys
import time
from contextlib import redirect_stdout
from datetime import timedelta
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from jobs.models import Job
from jobs.utils import (_descendant_pids, _persist_fields, kill_job_process_tree,
                        run_job, reap_stale_jobs)
from project.models import Project


class JobOutputTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(projectname='Job tests')

    @patch('jobs.utils.subprocess.Popen')
    def test_output_and_exit_status_are_persisted(self, popen):
        for returncode, status in [(0, 'finished'), (1, 'failed')]:
            with self.subTest(returncode=returncode):
                process = Mock(pid=123, returncode=returncode)
                process.stdout = io.StringIO('first line\n  indented <output>\nlast line')
                process.poll.return_value = returncode
                popen.return_value = process
                run_job('test_job', '', self.project.pk)
                job = Job.objects.latest('id')
                self.assertEqual(job.status, status)
                self.assertEqual(job.output, 'first line\n  indented <output>\nlast line')
                self.assertIsNotNone(job.finished_at)
                self.assertEqual(job.pid, 123)

    @patch('jobs.utils.subprocess.Popen', side_effect=OSError('launch failed'))
    def test_launch_failure_is_recorded(self, popen):
        run_job('test_job', '', self.project.pk)
        job = Job.objects.get()
        self.assertEqual(job.status, 'failed')
        self.assertIn('launch failed', job.output)
        self.assertIsNotNone(job.finished_at)

    def test_field_persistence_retries_transient_failures(self):
        job = Mock()
        job.save.side_effect = [RuntimeError('database locked'), None]
        self.assertTrue(_persist_fields(job, ['output'], delay=0))
        self.assertEqual(job.save.call_count, 2)

    def test_field_persistence_does_not_recreate_a_deleted_job(self):
        job = Job.objects.create(related_project=self.project, command='test_job', started_at=timezone.now())
        Job.objects.filter(pk=job.pk).delete()
        with transaction.atomic():
            self.assertFalse(_persist_fields(job, ['output'], max_retries=1))
        self.assertFalse(Job.objects.filter(pk=job.pk).exists())


class RunScanWrapperTests(TestCase):
    """The scan process writes its own terminal status, so the outcome survives the
    death of the web/celery supervisor (dev-server reload, worker restart)."""

    def setUp(self):
        self.project = Project.objects.create(projectname='Wrapper tests')

    def _running_job(self):
        return Job.objects.create(related_project=self.project, command='scan_nmap',
                                  status='running', started_at=timezone.now())

    def test_wrapper_records_success(self):
        job = self._running_job()
        out = io.StringIO()
        with patch('time.sleep'), redirect_stdout(out):
            call_command('run_scan', jobid=job.pk, command='test_job',
                         scan_args=f'--projectid {self.project.pk}')
        job.refresh_from_db()
        self.assertEqual(job.status, 'finished')
        self.assertIsNotNone(job.finished_at)
        # The inner command must actually receive the args (regression: --args dest
        # collided with Django's positional-args pop and was silently dropped).
        self.assertIn(f'Project id: {self.project.pk} has waited', out.getvalue())

    def test_wrapper_records_failure(self):
        job = self._running_job()
        call_command('run_scan', jobid=job.pk, command='this_command_does_not_exist')
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertIsNotNone(job.finished_at)

    def test_wrapper_survives_a_dead_supervisor_pipe(self):
        """run_job reads the scan through a pipe. If that reader disappears (dev-server
        reload), the scan's next print must not abort the run — the wrapper keeps going
        and records the outcome itself."""
        class BrokenPipe:
            def write(self, msg):
                raise BrokenPipeError('reader is gone')

            def flush(self):
                raise BrokenPipeError('reader is gone')

        job = self._running_job()
        with patch('time.sleep'), redirect_stdout(BrokenPipe()):
            call_command('run_scan', jobid=job.pk, command='test_job',
                         scan_args=f'--projectid {self.project.pk}')
        job.refresh_from_db()
        self.assertEqual(job.status, 'finished')

    def test_run_job_adopts_wrapper_status(self):
        # Supervisor-side fallback must not clobber the wrapper's verdict: a child
        # exiting 0 while the wrapper recorded 'failed' keeps 'failed'.
        job = self._running_job()
        process = Mock(pid=4323)
        process.poll.return_value = None
        process.stdout = io.StringIO('work\n')
        process.returncode = 0
        with patch('jobs.utils.subprocess.Popen', return_value=process):
            Job.objects.filter(pk=job.pk).update(status='failed')  # as the wrapper would
            run_job('test_job', '', self.project.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')


class JobReaperTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(projectname='Reaper tests')

    def test_descendant_walk_reaches_a_process_outside_our_group(self):
        """The reclaim path must find descendants that live in their own session —
        Playwright's Chromium does, and killpg of the scan's group misses it. Covers
        the /proc (Linux) and ps (macOS) walks with a real process."""
        child = subprocess.Popen(
            [sys.executable, '-c', 'import os, time; os.setsid(); time.sleep(60)'],
            start_new_session=True)
        try:
            self.assertIn(child.pid, _descendant_pids(os.getpid()))
            self.assertTrue(kill_job_process_tree(child.pid))
            child.wait(timeout=10)
            self.assertNotEqual(child.returncode, 0)   # terminated by a signal
        finally:
            if child.poll() is None:
                child.kill()

    @patch('jobs.utils._orphan_browser_pids', return_value=[])
    @patch('jobs.utils.os.kill', side_effect=ProcessLookupError)
    def test_reaper_fails_dead_pid(self, kill, orphans):
        job = Job.objects.create(related_project=self.project, command='scan_playwright',
                                 status='running', pid=999999, started_at=timezone.now())
        self.assertEqual(reap_stale_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, 'failed')
        self.assertIn('reaped', job.output)
        self.assertIsNotNone(job.finished_at)

    @patch('jobs.utils.kill_job_process_tree')
    @patch('jobs.utils._orphan_browser_pids', return_value=[])
    @patch('jobs.utils.os.kill', return_value=None)
    def test_reaper_leaves_old_but_live_job_alone(self, kill, orphans, kill_tree):
        """Age is never a reap reason: a days-long scan with a live pid stays running."""
        old = timezone.now() - timedelta(days=3)
        job = Job.objects.create(related_project=self.project, command='scan_nmap',
                                 status='running', pid=999998, started_at=old)
        self.assertEqual(reap_stale_jobs(), 0)
        job.refresh_from_db()
        self.assertEqual(job.status, 'running')
        kill_tree.assert_not_called()
