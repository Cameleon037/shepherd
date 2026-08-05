from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ShepherdTokenAuthentication(TokenAuthentication):
    """DRF token auth that also accepts a bare key in Authorization (Swagger-friendly).

    Accepted forms:
      Authorization: Token <key>
      Authorization: <key>
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth:
            return None

        # Bare key only — what Swagger Authorize typically sends for apiKey schemes
        if len(auth) == 1:
            try:
                token = auth[0].decode()
            except UnicodeError:
                raise AuthenticationFailed(
                    'Invalid token header. Token string should not contain invalid characters.'
                )
            return self.authenticate_credentials(token)

        if auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) > 2:
            raise AuthenticationFailed(
                'Invalid token header. Token string should not contain spaces.'
            )

        try:
            token = auth[1].decode()
        except UnicodeError:
            raise AuthenticationFailed(
                'Invalid token header. Token string should not contain invalid characters.'
            )

        return self.authenticate_credentials(token)


class ShepherdTokenScheme(OpenApiAuthenticationExtension):
    target_class = 'api.authentication.ShepherdTokenAuthentication'
    name = 'ApiKeyAuth'
    match_subclasses = True
    priority = -1

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': (
                'Paste your API key only (Preferences → API Key). '
                'Alternatively use: Authorization: Token <key>'
            ),
        }
