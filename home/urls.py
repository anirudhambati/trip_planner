from django.conf.urls import url
from django.urls import path, include
from . import views

app_name = 'home'

urlpatterns = [

    path('login/', views.login, name="login"),
    path('signup/', views.signup, name="signup"),
    path('questions/', views.questions, name="questions"),
    path('plan/', views.plan, name="plan"),
    path('timeline/', views.timeline, name="timeline"),
    path('maps/', views.maps, name="maps"),
    path('upload/', views.post_add, name='upload'),
    path('create/', views.addpost, name='create')

    ]
