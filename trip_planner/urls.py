from django.contrib import admin
from django.urls import path, include
from django.conf.urls import url
from home import views
from django.contrib.auth import views as auth_views
from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing, name="landing"),
    path('timeline/', views.timeline, name="timeline"),
    path('review/', views.review, name="review"),
    path('blog/', views.blog, name='blog'),
    path('blogabout/', views.blogabout, name='blogabout'),
    path('addpost/', views.addpost, name='addpost'),
    path('about/', views.about, name="about"),
    path('auth/', views.auth, name="auth"),
    path('registration/', include(('home.urls','home'))),
    url('home/', views.home, name='home'),
    url(r'^login/$', auth_views.LoginView, name='login'),
    url(r'^logout/$', views.logout_view, name='logout'),
    url(r'^oauth/', include('social_django.urls', namespace='social')),
    url(r'activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',
    views.activate, name='activate'),
    path('plan/', views.plan, name="plan"),
    path('verify/', views.verify, name="verify"),
    url(r'verify_reset_password/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.verify_reset_password, name='verify_reset_password'),
    path('reset_display/',views.reset_display,name='reset_display'),
    path('reset_password/',views.reset_password,name='reset_password'),
    path('save_password/',views.save_password,name='save_password'),
    path('questions/', views.questions, name='questions'),
    path('overview/', views.overview, name='overview'),
    path('maps/', views.maps, name='maps'),
    path('userapi/', views.loginapi.as_view(), name='userapi'),
    path('planapi/', views.planapi.as_view(), name='planapi'),
    path('accounts/', include('allauth.urls')),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
