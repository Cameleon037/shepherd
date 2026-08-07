from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
import secrets
import string


class Command(BaseCommand):
    help = 'Set up user groups with read and write access'

    # Models moved out of `project` during the app split: (old_app, model, new_app)
    MOVED_MODELS = [
        ('project', 'asset', 'assets'),
        ('project', 'keyword', 'keywords'),
        ('project', 'job', 'jobs'),
        ('project', 'finding', 'findings'),
        ('project', 'port', 'findings'),
        ('project', 'endpoint', 'findings'),
        ('project', 'screenshot', 'findings'),
        ('project', 'dnsrecord', 'findings'),
    ]

    def handle(self, *args, **kwargs):
        self.fix_stale_permissions()

        # Drop DRF TokenProxy perms (duplicate of Token in admin)
        proxy_ct = ContentType.objects.filter(app_label='authtoken', model='tokenproxy')
        deleted, _ = Permission.objects.filter(content_type__in=proxy_ct).delete()
        if deleted:
            self.stdout.write(self.style.SUCCESS(f'Removed {deleted} TokenProxy permission(s).'))

        app_labels = ['findings', 'project', 'keywords', 'assets', 'jobs']

        write_permissions = Permission.objects.none()
        read_permissions = Permission.objects.none()
        for app_label in app_labels:
            for content_type in ContentType.objects.filter(app_label=app_label):
                write_permissions |= Permission.objects.filter(content_type=content_type)
                read_permissions |= Permission.objects.filter(
                    content_type=content_type, codename__startswith='view_'
                )

        # API tokens: both groups get full Token perms (Preferences scopes to own key)
        token_perms = Permission.objects.filter(
            content_type__app_label='authtoken', content_type__model='token'
        )
        write_permissions |= token_perms
        read_permissions |= token_perms

        write_group, _ = Group.objects.get_or_create(name='Read/Write')
        write_group.permissions.set(write_permissions)
        self.stdout.write(self.style.SUCCESS(
            f'Read/Write group updated ({write_permissions.count()} permissions).'
        ))

        read_only_group, _ = Group.objects.get_or_create(name='Read Only')
        read_only_group.permissions.set(read_permissions)
        self.stdout.write(self.style.SUCCESS(
            f'Read Only group updated ({read_permissions.count()} permissions).'
        ))

        # Create scheduler superuser if missing
        User = get_user_model()
        if not User.objects.filter(username='scheduler').exists():
            alphabet = string.ascii_letters + string.digits + string.punctuation
            random_password = ''.join(secrets.choice(alphabet) for _ in range(20))
            User.objects.create_superuser(
                username='scheduler', email='', password=random_password
            )
            self.stdout.write(self.style.SUCCESS(
                f'Admin user "scheduler" created with password: {random_password}'
            ))
        else:
            self.stdout.write(self.style.WARNING('Admin user "scheduler" already exists.'))

        self.stdout.write(
            'Have users log in again after group changes. '
            'Check: user.has_perm("assets.view_asset")'
        )

    def fix_stale_permissions(self):
        """Move group/user perms from old project.* ContentTypes to the new apps."""
        User = get_user_model()
        for old_app, model, new_app in self.MOVED_MODELS:
            old_ct = ContentType.objects.filter(app_label=old_app, model=model).first()
            if not old_ct:
                continue

            new_ct = ContentType.objects.filter(app_label=new_app, model=model).first()
            if new_ct is None:
                old_ct.app_label = new_app
                old_ct.save(update_fields=['app_label'])
                self.stdout.write(f'Renamed ContentType {old_app}.{model} → {new_app}.{model}')
                continue

            if old_ct.pk == new_ct.pk:
                continue

            for old_perm in Permission.objects.filter(content_type=old_ct):
                new_perm = Permission.objects.filter(
                    content_type=new_ct, codename=old_perm.codename
                ).first()
                if not new_perm:
                    continue
                for group in Group.objects.filter(permissions=old_perm):
                    group.permissions.add(new_perm)
                    group.permissions.remove(old_perm)
                for user in User.objects.filter(user_permissions=old_perm):
                    user.user_permissions.add(new_perm)
                    user.user_permissions.remove(old_perm)

            Permission.objects.filter(content_type=old_ct).delete()
            old_ct.delete()
            self.stdout.write(f'Removed stale ContentType {old_app}.{model}')
