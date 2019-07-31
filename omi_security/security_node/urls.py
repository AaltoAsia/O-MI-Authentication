from django.urls import path, re_path
from django.conf.urls import url, include
from . import views

urlpatterns = [
    path(r'', views.home, name='home'),
    path(r'login', views.login, name='login'),
    path(r'signup', views.signup, name='signup'),
    path(r'logout', views.logout, name='logout'),
    path(r'authmodule', views.authmodule, name='authmodule'),
    path(r'omi_authquery', views.omi_authquery, name='omi_authquery'),
    path(r'about', views.about, name='about'),
    path(r'create_oauth_token', views.create_oauth_token, name='create_oauth_token'),
    path(r'superusers_panel', views.superusers_panel, name='superusers_panel'),
    re_path(r'^userRole/(?P<user_id>[0-9]+)/$', views.userRole, name='userRole'),
    path(r'secret',views.secret_page, name='secret'),
]

