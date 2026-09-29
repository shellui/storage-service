"""Staff / company-owner gate for Shellui Actions admin REST API."""

from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response


def _company_id_from_request(request) -> int | None:
    raw = request.GET.get('company_id')
    if raw is None and hasattr(request, 'data'):
        raw = request.data.get('company_id')
    if raw not in (None, ''):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    user = getattr(request, 'user', None)
    if user and getattr(user, 'company_id', None) is not None:
        try:
            return int(user.company_id)
        except (TypeError, ValueError):
            return None
    return None


def require_staff_or_company_owner(request):
    """
    Authenticated staff or company owner scoped to a company_id.

    Non-staff owners use JWT ``company_id``. Staff may pass ``company_id`` as a query param.
    """
    user = request.user
    if not user or not getattr(user, 'is_authenticated', False):
        return None, None, Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    company_id = _company_id_from_request(request)
    if company_id is None:
        return None, None, Response({'error': 'Missing company_id parameter.'}, status=status.HTTP_400_BAD_REQUEST)

    token_company = getattr(user, 'company_id', None)
    if token_company is not None and int(token_company) != int(company_id):
        if not getattr(user, 'is_staff', False):
            return None, None, Response(
                {'error': 'Requested company_id does not match token company_id.'},
                status=status.HTTP_403_FORBIDDEN,
            )

    if getattr(user, 'is_staff', False) or getattr(user, 'is_company_owner', False):
        return user, company_id, None
    return None, None, Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
