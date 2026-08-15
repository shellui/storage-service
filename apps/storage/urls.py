from django.urls import path, re_path

from . import views

urlpatterns = [
    path('health', views.HealthView.as_view(), name='storage-health'),
    path('bucket', views.BucketListCreateView.as_view(), name='bucket-list'),
    path('bucket/<slug:bucket_id>', views.BucketDetailView.as_view(), name='bucket-detail'),
    path('bucket/<slug:bucket_id>/empty', views.BucketEmptyView.as_view(), name='bucket-empty'),
    path('access/grant', views.AccessGrantListCreateView.as_view(), name='access-grant-list'),
    path(
        'access/grant/<uuid:grant_id>',
        views.AccessGrantDetailView.as_view(),
        name='access-grant-detail',
    ),
    path('share/link/<str:token>', views.ShareLinkView.as_view(), name='share-link'),
    re_path(
        r'^share/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectShareView.as_view(),
        name='object-share',
    ),
    path('object/list/<slug:bucket_id>', views.ObjectListView.as_view(), name='object-list'),
    path('object/id/<uuid:object_id>', views.ObjectByIdView.as_view(), name='object-by-id'),
    path('object/prefix/<slug:bucket_id>', views.ObjectPrefixView.as_view(), name='object-prefix'),
    path('object/move', views.ObjectMoveView.as_view(), name='object-move'),
    path('object/copy', views.ObjectCopyView.as_view(), name='object-copy'),
    path('object/<slug:bucket_id>', views.ObjectDeleteManyView.as_view(), name='object-delete-many'),
    re_path(
        r'^object/sign/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectSignView.as_view(),
        name='object-sign',
    ),
    path('object/sign/<slug:bucket_id>', views.ObjectSignView.as_view(), name='object-sign-body'),
    re_path(
        r'^object/info/authenticated/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectInfoView.as_view(),
        name='object-info-auth',
    ),
    re_path(
        r'^object/info/public/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectInfoView.as_view(),
        name='object-info-public',
    ),
    re_path(
        r'^object/public/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectPublicDownloadView.as_view(),
        name='object-public',
    ),
    re_path(
        r'^object/authenticated/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectDownloadView.as_view(),
        name='object-authenticated',
    ),
    re_path(
        r'^object/(?P<bucket_id>[^/]+)/(?P<object_path>.+)$',
        views.ObjectResourceView.as_view(),
        name='object-resource',
    ),
    path('quota', views.QuotaView.as_view(), name='quota'),
    path('stats', views.StatsView.as_view(), name='storage-stats'),
    path('metrics', views.StorageMetricsView.as_view(), name='storage-metrics'),
    path('metrics/all', views.StorageGlobalMetricsView.as_view(), name='storage-metrics-all'),
    path('quota/company/<int:company_id>', views.CompanyQuotaAdminView.as_view(), name='quota-company'),
    path(
        'quota/company/<int:company_id>/user/<int:user_id>',
        views.UserQuotaAdminView.as_view(),
        name='quota-user',
    ),
]
