from drf_spectacular.extensions import OpenApiAuthenticationExtension


class IdentityJWKSAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = 'apps.authapi.authentication.IdentityJWKSAuthentication'
    name = 'bearerAuth'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
            'description': (
                'JWT access token issued by identity-service. '
                'Paste `Bearer <token>` or the raw JWT.'
            ),
        }
