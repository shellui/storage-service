from django.contrib.auth.models import AnonymousUser
from django.urls import path
from rest_framework.response import Response
from rest_framework.views import APIView


class CompanyItemView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request, company_id):
        auth = getattr(request, 'auth', None)
        if auth is None:
            underlying = getattr(request, '_request', request)
            auth = getattr(underlying, 'auth', None) or getattr(underlying, '_force_auth_token', None)
        agent_id = auth.get('agent_id') if isinstance(auth, dict) else None
        user_ok = bool(getattr(request.user, 'is_authenticated', False))
        return Response({'company_id': company_id, 'agent_id': agent_id, 'user_ok': user_ok})


class RenderPreviewView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response({'ok': True})


urlpatterns = [
    path('api/v1/companies/<int:company_id>/items/', CompanyItemView.as_view()),
    path('api/v1/templates/render-preview/', RenderPreviewView.as_view()),
]
