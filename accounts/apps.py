from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        # Distinguish DRF TokenProxy from Token in admin (same default verbose_name).
        # Permission rows are cleaned in setup_user_groups; avoid DB access here.
        try:
            from rest_framework.authtoken.models import TokenProxy
        except ImportError:
            return

        TokenProxy._meta.verbose_name = 'Token (admin proxy)'
        TokenProxy._meta.verbose_name_plural = 'Tokens (admin proxy)'
