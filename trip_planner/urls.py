from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url
from home import views
from django.contrib.auth import views as auth_views
from django.conf.urls import url

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing, name="landing"),
    path('timeline/', views.timeline, name="timeline"),
    path('about/', views.about, name="about"),
    path('auth/', views.auth, name="auth"),
    path('registration/', include(('home.urls','home'))),
    url(r'^$', views.home, name='home'),
    url(r'^login/$', auth_views.LoginView, name='login'),
    url(r'^logout/$', views.logout_view, name='logout'),
    url(r'^oauth/', include('social_django.urls', namespace='social')),
    url(r'activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',
    views.activate, name='activate'),
]
