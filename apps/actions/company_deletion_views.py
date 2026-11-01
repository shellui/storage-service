"""``POST /api/v1/internal/company-deletions``: identity-service flags a company for deletion."""

from __future__ import annotations

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.actions.company_deletion import (
    DeletionAssertionError,
    flag_company_deletion,
    verify_deletion_assertion,
)


class CompanyDeletionView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        header = request.headers.get('Authorization', '')
        if not header.lower().startswith('bearer '):
            return Response({'detail': 'A signed assertion is required.'}, status=401)
        try:
            company_id = verify_deletion_assertion(header.split(' ', 1)[1].strip())
        except DeletionAssertionError as exc:
            return Response({'detail': str(exc)}, status=401)
        flag_company_deletion(company_id)
        return Response({'company_id': company_id, 'status': 'deleting'}, status=202)
