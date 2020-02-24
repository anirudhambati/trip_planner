from django.contrib import admin
from django.urls import path, include
from home import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing, name="landing"),
    path('timeline/', views.timeline, name="timeline"),
    path('about/', views.about, name="about"),
    path('auth/', views.auth, name="auth")
]
