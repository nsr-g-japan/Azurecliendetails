import re
from datetime import timedelta, datetime

import pyodbc as pyodbc
from dateutil import tz, parser
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect

from django.urls import reverse

from .auth_helper import *
from .graph_helper import *
import logging

db = pyodbc.connect('Driver={SQL server};' 'server=Nisarbasha;' 'Database=dwproject;' 'Trusted_connection=yes;')
cursor = db.cursor()

# Creating and Configuring Logger

Log_Format = "%(levelname)s %(asctime)s - %(message)s"

logging.basicConfig(filename="log_file.log",
                    filemode="w",
                    format=Log_Format,
                    level=logging.ERROR)

logger = logging.getLogger()

# Create your views here.
global user
user = {}


def home(request):
    context = initialize_context(request)

    return render(request, 'homepage.html', context)


def initialize_context(request):
    context = {}

    # Check for any errors in the session
    error = request.session.pop('flash_error', None)

    if error != None:
        context['errors'] = []
        context['errors'].append(error)

    # Check for user in the session
    context['user'] = request.session.get('user', {'is_authenticated': False})
    return context


def sign_in(request):
    # Get the sign-in flow
    flow = get_sign_in_flow()
    # Save the expected flow so we can use it in the callback
    try:
        request.session['auth_flow'] = flow
    except Exception as e:
        print(e)
    # Redirect to the Azure sign-in page
    return HttpResponseRedirect(flow['auth_uri'])


def landingpage(request):
    # Make the token request
    result = get_token_from_code(request)

    request.session['refresh_token_cache'] = result['refresh_token']

    # Get the user's profile
    user = get_user(result['access_token'])

    dbuserinsert(user)
    print(type(user))
    print(user['displayName'])
    # Store user
    store_user(request, user)
    return HttpResponseRedirect(reverse('home'))


def user_profile(request):
    context = initialize_context(request)
    context['subscriptionId'] = request.session.get('subscriptionId')
    return render(request, 'user_profile.html', context)


def subscriptions(request):
    context = initialize_context(request)

    azure_token = get_azure_management_token(request)

    events = get_subscription_list(azure_token)

    if events:
        context['subscriptionList'] = events['value']

    return render(request, 'subscriptions.html', context)


def subscriptionsresource(request):
    context = initialize_context(request)
    request.session['subscriptionId'] = request.GET.get('subId', '')
    context['subscriptionId'] = request.session.get('subscriptionId')

    return render(request, 'subscriptions_resource.html', context)


def subscriptionsresource_file_management(request):
    context = initialize_context(request)
    context['subscriptionId'] = request.session.get('subscriptionId')
    azure_token = get_azure_management_token(request)

    storageaccountlist = get_storageaccount_list(azure_token, context['subscriptionId'])

    if storageaccountlist:
        context['storageAccountList'] = storageaccountlist['value']
    return render(request, 'file_management.html', context)


def bloblist(request):
    context = initialize_context(request)
    azure_token = get_azure_management_token(request)

    request.session['storageAccountName'] = request.GET.get('qid', '')
    request.session['acc_name'] = request.GET.get('acc_name', '')
    context['storageAccountName'] = request.session.get('storageAccountName')
    context['acc_name'] = request.session.get('acc_name')

    blob_list = get_blob_list(azure_token, context['storageAccountName'])
    print(blob_list)

    if blob_list:
        context['blob_list'] = blob_list['value']

    return render(request, 'bloblist.html', context)


def blobdetails(request):
    context = initialize_context(request)
    token = get_token(request)

    request.session['blobid'] = request.GET.get('blobid', '')
    request.session['container_name'] = request.GET.get('container_name', '')
    context['storageAccountName'] = request.session.get('storageAccountName')
    context['blobid'] = request.session.get('blobid')
    context['acc_name'] = request.session.get('acc_name')
    context['container_name'] = request.session.get('container_name')

    azure_token = 'tSVdeBiewtJ3K1F7qMzc1FBAdqDkcj+tcCdtYsbjGlnM0qQA/fDP758U5cevGvKolBFAl6TxC4CapVwCVcACnA=='

    blob_details = get_blob_details(azure_token, context['acc_name'], context['container_name'])

    if blob_details:
        context['blob_details'] = blob_details
    try:
        if request.method == 'POST' and request.FILES['myfile']:
            myfile = request.FILES['myfile']
            block_blob_service = BlockBlobService('setuptest1906',
                                                  'ttSVdeBiewtJ3K1F7qMzc1FBAdqDkcj+tcCdtYsbjGlnM0qQA/fDP758U5cevGvKolBFAl6TxC4CapVwCVcACnA==')
            block_blob_service.create_blob_from_bytes(context['container_name'], myfile.name, myfile.read())
            context['msg'] = ' Uloaded success'
            return render(request, 'blobdetails.html', context)
    except Exception as e:
        errormsg = str(e).split('.')
        context['msg'] = errormsg[0]
        return render(request, 'blobdetails.html', context)

    return render(request, 'blobdetails.html', context)


def configdetails(request):
    context = initialize_context(request)
    record = cursor.execute("select * from config_details where config_is_deleted='0' ORDER BY config_id")
    records = record.fetchall()
    data = []
    for record in records:
        da = {}
        da.update({'config_id': record[0], 'c_userid': record[1], 'hostaddress': record[2], 'portnumber': record[3],
                   'serverName': record[4], 'databaseName': record[5], 'config_username': record[6],
                   'congif_password': record[7], 'database_type': record[8]})
        data.append(da)
    context['rows'] = data
    status = request.GET.get('status')
    context['msg'] = status
    return render(request, 'configdetails.html', context)


def addconfigdetails(request):
    context = initialize_context(request)
    user = context['user']['name']
    record = cursor.execute("select user_id from users where user_fullname ='{}' ".format(user))
    records = record.fetchone()
    context['uid'] = records[0]
    hostid = request.POST.get('hostname')

    if request.method == 'POST':
        myform = request.POST.get('myForm')
        userid = records[0]
        hostid = request.POST.get('hostadd')
        servername = request.POST.get('servername')
        dbname = request.POST.get('dbname')
        uname = request.POST.get('username')
        pwd = request.POST.get('pwd')
        dbtype = request.POST.get('dbtype')
        portname = request.POST.get('port')
        # usenameregex = "^(?=(?:.*[a-z]){4})(?=.*[$@_])(?=.*[A-Z])[a-zA-Z$@_]{6}$"
        # pwdregex="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,18}$"

        sql = ("""insert into config_details(config_user_id, config_hostaddress, config_serverName,config_databaseName, config_username,
                    config_password, config_database_type, config_PortName) values('{}','{}','{}','{}','{}','{}','{}','{}')"""
               .format(userid, hostid, servername, dbname, uname, pwd, dbtype, portname))
        cursor.execute(sql)
        cursor.commit()
        return HttpResponseRedirect('configdetails?status=Created Successfully')

    return render(request, 'addconfigdetails.html', context)


def updatedata(request):
    context = initialize_context(request)
    uhostid = request.GET.get('uid')
    sql = ("""select * from config_details where config_id='{}' """.format(uhostid))
    record = cursor.execute(sql).fetchone()
    da = {}
    da.update({'c_userid': record[1], 'hostaddress': record[2], 'portnumber': record[3],
               'serverName': record[4], 'databaseName': record[5], 'config_username': record[6],
               'congif_password': record[7], 'database_type': record[8]})
    context['rows'] = da
    if request.method == 'POST':
        hostid = request.POST.get('hostadd')
        servername = request.POST.get('servername')
        dbname = request.POST.get('dbname')
        uname = request.POST.get('username')
        pwd = request.POST.get('pwd')
        dbtype = request.POST.get('dbtype')
        portno = request.POST.get('port')
        sql = ("""update config_details set  config_hostaddress='{}', config_serverName='{}',config_databaseName='{}',
        config_username='{}',config_password='{}',config_database_type='{}',config_updated_at=getdate(), config_PortName='{}'
         where config_id='{}' """.format(hostid, servername, dbname, uname, pwd, dbtype, portno, uhostid))
        cursor.execute(sql)
        cursor.commit()
        return HttpResponseRedirect('configdetails?status=Updated Successfully')
    return render(request, 'update.html', context)


def deletedata(request):
    uhostid = request.GET.get('uid')
    print(uhostid)
    sql = ("""update  config_details set config_is_deleted='1' where config_id='{}' """
           .format(uhostid))
    cursor.execute(sql)
    cursor.commit()
    # return redirect('configdetails', args=(video_id,))
    return HttpResponseRedirect('configdetails?status=Deleted Successfully')


def server_is_exists(request):
    if request.method == 'POST':
        sname = request.POST.get('server_name')

        rec = ("""select config_serverName from config_details where config_serverName='{}' """.format(sname))
        record = cursor.execute(rec).fetchone()
        print(record)
        if record is None:
            print("If working now")
            return HttpResponse('OK')
        else:
            print('else working now')
            return HttpResponse("user already Exists")
    else:
        print("ajax Not calling")


def dbuserinsert(user):
    usname = user['displayName']
    uemail = user['mail']
    mobileno = user['mobilePhone']
    rec = ("""select user_fullname from users where user_fullname = '{}' """.format(usname))
    record = cursor.execute(rec).fetchone()
    print(record)
    if record is None:
        sql = (
            """insert into users(user_fullname, user_mail, user_mobile,user_is_session_active) values('{}','{}','{}','1')"""
                .format(usname, uemail, mobileno))
        cursor.execute(sql)
        cursor.commit()
    else:
        sql = (
            """update users set user_updated_at=getdate(),user_is_session_active='1' where user_fullname = '{}' """.format(
                usname))
        cursor.execute(sql)
        cursor.commit()


def dbdataupdate(user):
    session_active = '0'
    uname = user['name']
    print(uname)
    sql = (
        """update users set user_updated_at=getdate(),user_is_session_active='0' where user_fullname = '{}' """.format(
            uname))

    cursor.execute(sql)
    cursor.commit()


def sign_out(request):
    context = initialize_context(request)
    user = context['user']
    dbdataupdate(user)
    # Clear out the user and token
    remove_user_and_token(request)

    return HttpResponseRedirect(reverse('home'))


def calendar(request):
    context = initialize_context(request)
    user = context['user']

    # Load the user's time zone
    # Microsoft Graph can return the user's time zone as either
    # a Windows time zone name or an IANA time zone identifier
    # Python datetime requires IANA, so convert Windows to IANA
    time_zone = get_iana_from_windows(user['timeZone'])
    tz_info = tz.gettz(time_zone)

    # Get midnight today in user's time zone
    today = datetime.now(tz_info).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0)

    # Based on today, get the start of the week (Sunday)
    if (today.weekday() != 6):
        start = today - timedelta(days=today.isoweekday())
    else:
        start = today

    end = start + timedelta(days=7)

    token = get_token(request)

    events = get_calendar_events(
        token,
        start.isoformat(timespec='seconds'),
        end.isoformat(timespec='seconds'),
        user['timeZone'])

    if events:
        # Convert the ISO 8601 date times to a datetime object
        # This allows the Django template to format the value nicely
        for event in events['value']:
            event['start']['dateTime'] = parser.parse(event['start']['dateTime'])
            event['end']['dateTime'] = parser.parse(event['end']['dateTime'])

        context['events'] = events['value']

    return render(request, 'calendar.html', context)


def newevent(request):
    context = initialize_context(request)
    user = context['user']

    if request.method == 'POST':
        # Validate the form values
        # Required values
        if (not request.POST['ev-subject']) or \
                (not request.POST['ev-start']) or \
                (not request.POST['ev-end']):
            context['errors'] = [
                {'message': 'Invalid values', 'debug': 'The subject, start, and end fields are required.'}
            ]
            return render(request, 'newevent.html', context)

        attendees = None
        if request.POST['ev-attendees']:
            attendees = request.POST['ev-attendees'].split(';')
        body = request.POST['ev-body']

        # Create the event
        token = get_token(request)

        create_event(
            token,
            request.POST['ev-subject'],
            request.POST['ev-start'],
            request.POST['ev-end'],
            attendees,
            request.POST['ev-body'],
            user['timeZone'])

        # Redirect back to calendar view
        return HttpResponseRedirect(reverse('calendar'))
    else:
        # Render the form
        return render(request, 'newevent.html', context)
