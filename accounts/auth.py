import logging
from urllib.parse import urlencode

from azure.identity import CredentialUnavailableError, ManagedIdentityCredential
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import absolutify, import_from_settings
from requests.exceptions import HTTPError

# Audience Entra's federated identity credential requires on the MI token.
MI_ASSERTION_SCOPE = 'api://AzureADTokenExchange/.default'
CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

LOGGER = logging.getLogger(__name__)


class CustomOIDCBackend(OIDCAuthenticationBackend):
    """OIDC backend whose client credential is the VM's managed identity.

    Entra ID trusts the managed identity through a federated identity credential
    on the app registration, so no OIDC client secret exists anywhere.
    """

    @staticmethod
    def get_settings(attr, *args):
        # mozilla-django-oidc requires OIDC_RP_CLIENT_SECRET to exist; we never
        # configure one, so default it instead of raising ImproperlyConfigured.
        if attr == 'OIDC_RP_CLIENT_SECRET':
            args = args or ('',)
        return import_from_settings(attr, *args)

    def create_user(self, claims):
        user = super().create_user(claims)
        user.username = claims.get('email')
        user.save()
        read_only_group, _ = Group.objects.get_or_create(name='Read Only')
        user.groups.add(read_only_group)
        return user

    def filter_users_by_claims(self, claims):
        email = claims.get('email')
        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username=email)

    def get_token(self, payload):
        """Exchange the authorization code, authenticating with the MI token."""
        payload.pop('client_secret', None)
        payload['client_assertion_type'] = CLIENT_ASSERTION_TYPE
        payload['client_assertion'] = self._managed_identity_assertion()
        try:
            return super().get_token(payload)
        except HTTPError as exc:
            # e.g. AADSTS700211 when the FIC subject/audience is wrong.
            LOGGER.error('Entra token exchange failed: %s', exc.response.text)
            raise PermissionDenied('SSO token exchange failed') from exc

    @staticmethod
    def _managed_identity_assertion():
        try:
            credential = ManagedIdentityCredential(
                client_id=getattr(settings, 'AZURE_MI_CLIENT_ID', None) or None)
            return credential.get_token(MI_ASSERTION_SCOPE).token
        except CredentialUnavailableError as exc:
            LOGGER.error('Managed identity unavailable for SSO: %s', exc)
            raise PermissionDenied('Managed identity unavailable for SSO') from exc


def entra_logout_url(request):
    """Microsoft Entra end-session URL for the configured tenant."""
    params = urlencode(
        {'post_logout_redirect_uri': absolutify(request, settings.LOGIN_REDIRECT_URL)})
    return ('https://login.microsoftonline.com/%s/oauth2/v2.0/logout?%s'
            % (settings.OIDC_TENANT_ID, params))
