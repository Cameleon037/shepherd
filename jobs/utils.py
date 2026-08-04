import subprocess
import threading
import time
import gc
from django.utils.timezone import now
from jobs.models import Job
from project.models import Project

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
    try:
        process = subprocess.Popen(
            ['python3', '-u', 'manage.py', job.command] + job.args.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        
        # Collect output in chunks to reduce memory usage and database writes
        output_buffer = []
        buffer_size = 100  # Save to DB every 100 lines
        flush_interval = 5.0  # Also flush every 4 seconds for small outputs
        line_count = 0
        last_flush_time = time.time()
        
        for line in process.stdout:
            output_buffer.append(line)
            line_count += 1
            current_time = time.time()
            
            # Save to database in chunks to reduce memory pressure
            # Flush if we have enough lines OR enough time has passed
            if (line_count % buffer_size == 0 or 
                (output_buffer and current_time - last_flush_time >= flush_interval)):
                # Append new output to existing output
                new_output = ''.join(output_buffer)
                job.output = (job.output or '') + new_output
                job.save(update_fields=['output'])
                # Clear buffer to free memory
                output_buffer = []
                last_flush_time = current_time
        
        # Save any remaining output
        if output_buffer:
            new_output = ''.join(output_buffer)
            job.output = (job.output or '') + new_output
            job.save(update_fields=['output'])
            
        process.stdout.close()
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
        job.save()
        
        # Explicit memory cleanup
        try:
            # Clear local variables to free memory
            if 'output_buffer' in locals():
                output_buffer.clear()
            if 'process' in locals():
                del process
            # Force garbage collection
            gc.collect()
        except:
            pass  # Don't let cleanup errors affect the job status
