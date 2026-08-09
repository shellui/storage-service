from rest_framework.permissions import BasePermission


class IsAuthenticatedPrincipal(BasePermission):
    """Require a StoragePrincipal from IdentityJWKSAuthentication."""

    def has_permission(self, request, view):
        user = request.user
        return bool(user and getattr(user, 'is_authenticated', False))


class IsStaffOrCompanyOwner(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not getattr(user, 'is_authenticated', False):
            return False
        return bool(getattr(user, 'is_staff', False) or getattr(user, 'is_company_owner', False))
