"""omi_security URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
import oauth2_provider.views as oauth2_views
from django.conf import settings
from django.contrib import admin
from django.urls import include, re_path, path
#from security_node.views import ApiEndpoint
 

urlpatterns = [
    path('', include('security_node.urls')),
    path('oauth/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
     #path(r'o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
     #re_path(r'^o/', include(oauth2_endpoint_views, namespace="oauth2_provider")),
    re_path(r'^o/', include(('oauth2_provider.urls', 'oauth2_provider_app', ), namespace='oauth2_provider'), ),
#    re_path(r'^omi_authquery', ApiEndpoint.as_view()),
]

oauth2_endpoint_views = [
    re_path(r'^authorize/$', oauth2_views.AuthorizationView.as_view(), name="authorize"),
    re_path(r'^token/$', oauth2_views.TokenView.as_view(), name="token"),
    re_path(r'^revoke-token/$', oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
]

if settings.DEBUG:
    # OAuth2 Application Management endpoints0
    oauth2_endpoint_views += [
        re_path(r'^applications/$', oauth2_views.ApplicationList.as_view(), name="list"),
        re_path(r'^applications/register/$', oauth2_views.ApplicationRegistration.as_view(), name="register"),
        re_path(r'^applications/(?P<pk>\d+)/$', oauth2_views.ApplicationDetail.as_view(), name="detail"),
        re_path(r'^applications/(?P<pk>\d+)/delete/$', oauth2_views.ApplicationDelete.as_view(), name="delete"),
        re_path(r'^applications/(?P<pk>\d+)/update/$', oauth2_views.ApplicationUpdate.as_view(), name="update"),
    ]

    # OAuth2 Token Management endpoints
    oauth2_endpoint_views += [
        re_path(r'^authorized-tokens/$', oauth2_views.AuthorizedTokensListView.as_view(), name="authorized-token-list"),
        re_path(r'^authorized-tokens/(?P<pk>\d+)/delete/$', oauth2_views.AuthorizedTokenDeleteView.as_view(),
            name="authorized-token-delete"),
    ]

