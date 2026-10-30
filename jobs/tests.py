import io
from unittest.mock import Mock, patch

from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from jobs.models import Job
from jobs.utils import _persist_fields, run_job
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
