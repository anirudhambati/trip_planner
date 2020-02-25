from django.contrib import admin
from django.urls import path, include
from home import views
from django.conf.urls import url

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing, name="landing"),
    path('timeline/', views.timeline, name="timeline"),
    path('about/', views.about, name="about"),   
    path('auth/', views.auth, name="auth"),
    path('registration/', include(('home.urls','home'))),
    url(r'activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',
    views.activate, name='activate'),
]
