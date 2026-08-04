from django.core.management.base import BaseCommand
from assets.models import Asset

class Command(BaseCommand):
    help = 'Delete all Asset objects from the database.'

    def handle(self, *args, **options):
        count = Asset.objects.count()
        Asset.objects.all().delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {count} Asset objects."))

        # Clean up external assets from file uploads
        file_upload_count = Asset.objects.filter(source='file_upload', scope='external').count()
        Asset.objects.filter(source='file_upload', scope='external').delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {file_upload_count} external Asset objects with source 'file_upload'."))
