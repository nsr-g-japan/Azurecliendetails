from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('signin', sign_in, name='signin'),
    path('landingpage', landingpage),
    path('signout', sign_out, name='signout'),
    path('calendar', calendar, name='calendar'),
    path('calendar/new', newevent, name='newevent'),
    ]