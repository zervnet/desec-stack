from django.urls import include, path, re_path
from rest_framework.routers import SimpleRouter

from desecapi import views

tokens_router = SimpleRouter()
tokens_router.register(r'', views.TokenViewSet, base_name='token')

auth_urls = [
    # User management
    path('', views.UserCreateView.as_view(), name='register'),
    path('account/', views.AccountView.as_view(), name='account'),
    path('account/delete/', views.AccountDeleteView.as_view(), name='account-delete'),
    path('account/change-email/', views.AccountChangeEmailView.as_view(), name='account-change-email'),
    path('account/reset-password/', views.AccountResetPasswordView.as_view(), name='account-reset-password'),
    path('login/', views.AccountLoginView.as_view(), name='login'),
    path('verify/', views.VerifyView.as_view(), name='verify'),  # TODO or account/verify/?

    # Token management
    path('tokens/', include(tokens_router.urls)),
]

api_urls = [
    # API home
    path('', views.Root.as_view(), name='root'),

    # Domain and RRSet endpoints
    path('domains/', views.DomainList.as_view(), name='domain-list'),
    path('domains/<name>/', views.DomainDetail.as_view(), name='domain-detail'),
    path('domains/<name>/rrsets/', views.RRsetList.as_view(), name='rrsets'),
    path('domains/<name>/rrsets/.../<type>/', views.RRsetDetail.as_view(), kwargs={'subname': ''}),
    re_path(r'domains/(?P<name>[^/]+)/rrsets/(?P<subname>[^/]*)\.\.\./(?P<type>[^/]+)/',
            views.RRsetDetail.as_view(), name='rrset'),
    path('domains/<name>/rrsets/@/<type>/', views.RRsetDetail.as_view(), kwargs={'subname': ''}),
    re_path(r'domains/(?P<name>[^/]+)/rrsets/(?P<subname>[^/]*)@/(?P<type>[^/]+)/',
            views.RRsetDetail.as_view(), name='rrset@'),
    path('domains/<name>/rrsets/<subname>/<type>/', views.RRsetDetail.as_view()),

    # DynDNS update endpoint
    path('dyndns/update', views.DynDNS12Update.as_view(), name='dyndns12update'),

    # Donation endpoints
    path('donation/', views.DonationList.as_view(), name='donation'),
]

app_name = 'desecapi'
urlpatterns = [
    path('auth/', include(auth_urls)),
    path('', include(api_urls)),
]
