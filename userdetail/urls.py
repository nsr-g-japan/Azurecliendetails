from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('signin', sign_in, name='signin'),
    path('landingpage', landingpage),
    path('signout', sign_out, name='signout'),
    path('calendar', calendar, name='calendar'),
    path('calendar/new', newevent, name='newevent'),
    path('subscriptions', subscriptions, name='subscriptions'),
    path('subscriptions/resource', subscriptionsresource, name='subscriptionsresource'),
    path('subscriptions/resource/file_management', subscriptionsresource_file_management, name='file_management'),
    path('subscriptions/resource/file_management/bloblist', bloblist, name='bloblist'),
    path('subscriptions/resource/file_management/blobdetails', blobdetails, name='blobdetails'),
    path('configdetails', configdetails, name='configdetails'),
    path('addconfigdetails', addconfigdetails, name='addconfigdetails'),
    path('updatedata', updatedata, name='updatedata'),
path('deletedata', deletedata, name='deletedata'),




    ]