from rest_framework.permissions import BasePermission

from apps.authapi.agent_tokens import is_agent_principal


class IsAuthenticatedPrincipal(BasePermission):
    """Require a StoragePrincipal from IdentityJWKSAuthentication.

    Views with ``global_refused = True`` reject MCP agent callers.
    """

    def has_permission(self, request, view):
        user = request.user
        if not (user and getattr(user, 'is_authenticated', False)):
            return False
        if getattr(view, 'global_refused', False) and is_agent_principal(user):
            return False
        return True


class IsStaffOrCompanyOwner(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not getattr(user, 'is_authenticated', False):
            return False
        return bool(getattr(user, 'is_staff', False) or getattr(user, 'is_company_owner', False))
