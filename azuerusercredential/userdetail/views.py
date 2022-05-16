from datetime import timedelta, datetime

import pyodbc as pyodbc
from dateutil import tz, parser
from django.http import HttpResponseRedirect
from django.shortcuts import render

from django.urls import reverse

from .auth_helper import *
from .graph_helper import *
import logging
db = pyodbc.connect('Driver={SQL server};' 'server=Nisarbasha;' 'Database=dwproject;' 'Trusted_connection=yes;')
cursor = db.cursor()


#Creating and Configuring Logger

Log_Format = "%(levelname)s %(asctime)s - %(message)s"

logging.basicConfig(filename = "log_file.log",
                    filemode = "w",
                    format = Log_Format,
                    level = logging.ERROR)

logger = logging.getLogger()

# Create your views here.
global user
user={}
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
    userdata(user)
    dbdatainsert()
    print(type(user))
    print(user['displayName'])
    # Store user
    store_user(request, user)
    return HttpResponseRedirect(reverse('home'))


def user_profile(request):
    context = initialize_context(request)
    context['subscriptionId'] = request.session.get('subscriptionId')
    return render(request, 'user_profile.html', context)




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
            block_blob_service = BlockBlobService('setuptest1906', 'ttSVdeBiewtJ3K1F7qMzc1FBAdqDkcj+tcCdtYsbjGlnM0qQA/fDP758U5cevGvKolBFAl6TxC4CapVwCVcACnA==')
            block_blob_service.create_blob_from_bytes(context['container_name'], myfile.name, myfile.read())
            context['msg'] = ' Uloaded success'
            return render(request, 'blobdetails.html', context )
    except Exception as e:
        errormsg = str(e).split('.')
        context['msg'] = errormsg[0]
        return render(request, 'blobdetails.html', context)

    return render(request, 'blobdetails.html', context)

def configdetails(request):
    context = initialize_context(request)
    record =cursor.execute("select * from config_details ORDER BY id")
    records = record.fetchall()
    data = []
    for record in records:
        da = {}
        da.update({'userid': record[1], 'hostid': record[2], 'servername': record[3], 'database': record[4]})
        print(type(da))
        data.append(da)
    context['rows']=data
    return render(request, 'configdetails.html', context)

def updatedata(request):
    context = initialize_context(request)
    uhostid = request.GET.get('uid')

    sql = ("""select * from config_details where userid='{}' """.format(uhostid))
    record= cursor.execute(sql).fetchone()
    print(record)
    da = {}
    da.update({'userid': record[1], 'hostid': record[2], 'servername': record[3], 'database': record[4]})
    context['rows'] = da
    if request.method == 'POST':
        print('hi')
        userid = request.POST.get('userid')
        print(userid)
        hostid = request.POST.get('hostid')
        servername = request.POST.get('servername')
        database = request.POST.get('database')
        sql = ("""update config_details set userid ='{}', hostId='{}', serverName='{}',data_base='{}' where userid='{}' """
               .format(userid, hostid, servername, database, userid))
        cursor.execute(sql)
        cursor.commit()
        return HttpResponseRedirect('configdetails')
    return render(request, 'update.html', context)

def deletedata(request):
    uhostid = request.GET.get('uid')

    sql = ("""delete from config_details where userid='{}' """.format(uhostid))
    cursor.execute(sql)
    cursor.commit()

    return HttpResponseRedirect('configdetails')
def addconfigdetails(request):
    context = initialize_context(request)
    if request.method == 'POST':
        userid= request.POST.get('userid')
        hostid = request.POST.get('hostid')
        servername = request.POST.get('servername')
        database = request.POST.get('database')
        sql = ("""insert into config_details(userid, hostId, serverName,data_base) values('{}','{}','{}','{}')"""
               .format(userid, hostid, servername, database))
        cursor.execute(sql)
        cursor.commit()
    return render(request, 'addconfigdetails.html', context)


def userdata(user):
    global usname, uemail, mobileno, cdate
    usname = user['displayName']
    uemail = user['mail']
    mobileno = user['mobilePhone']
    cdate = user['mailboxSettings']['automaticRepliesSetting']['scheduledStartDateTime']['dateTime']
    cdate = cdate[:10]

def dbdatainsert():
    rec = ("""select username from users where username = '{}' """.format(usname))
    record = cursor.execute(rec).fetchone()
    print(record)
    if record is None:
        print("hi")
        sql = ("""insert into users(username, useremail, mbno,created_date) values('{}','{}','{}','{}')"""
               .format(usname, uemail, mobileno, cdate))
        cursor.execute(sql)
        cursor.commit()
    else:
        session_active='1'
        sql = ("""update users set created_date='{}',is_session_active='{}' where username = '{}' """.format(cdate,  session_active, usname)
               .format(usname, uemail, mobileno, cdate))
        cursor.execute(sql)
        cursor.commit()

def dbdataupdate(user):
    session_active='0'
    uname=user['name']
    print(uname)
    sql = ("""update users set is_session_active='{}' where username = '{}' """.format(session_active, uname))

    cursor.execute(sql)
    cursor.commit()

def sign_out(request):
    context = initialize_context(request)
    user = context['user']
    dbdataupdate(user)
    # Clear out the user and token
    remove_user_and_token(request)


    return HttpResponseRedirect(reverse('home'))
