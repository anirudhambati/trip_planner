from django.shortcuts import render
from django.http import HttpResponse
from django.core.mail import send_mail
import hashlib
import datetime
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render,redirect
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib import sessions
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
import json
import urllib
from django.conf import settings
from django.utils.dateparse import parse_date
from .models import post
import datetime
import pyrebase
import numpy as np
import matplotlib.pyplot as plt
from scipy import *
from pylab import *
import seaborn as sns; sns.set()
from math import sin, cos, sqrt, atan2, radians, ceil
from datetime import date, time
from datetime import timedelta
from django.utils.dateparse import parse_date
rcParams['figure.figsize'] = 7,7
from IPython.display import display
import requests, json
from collections import defaultdict
import random
from .tourplan import *

config = {
    'apiKey': "AIzaSyDvn6TnR5SB4ZHVo90XsKvnChd0ve5C5ps",
    'authDomain': "traveland-3a34c.firebaseapp.com",
    'databaseURL': "https://traveland-3a34c.firebaseio.com",
    'projectId': "traveland-3a34c",
    'storageBucket': "traveland-3a34c.appspot.com",
    'messagingSenderId': "832786504613",
    'appId': "1:832786504613:web:5b3afab39839600e73664c"
}

firebase = pyrebase.initialize_app(config)
storage= firebase.storage()
authe = firebase.auth()
database = firebase.database()
countries = [
    "Afghanistan",
    "Åland Islands",
    "Albania",
    "Algeria",
    "American Samoa",
    "Andorra",
    "Angola",
    "Anguilla",
    "Antarctica",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Aruba",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Belize",
    "Benin",
    "Bermuda",
    "Bhutan",
    "Bolivia",
    "Bonaire, Sint Eustatius and Saba",
    "Bosnia and Herzegovina",
    "Botswana",
    "Bouvet Island",
    "Brazil",
    "British Indian Ocean Territory",
    "United States Minor Outlying Islands",
    "Virgin Islands",
    "Brunei Darussalam",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Cambodia",
    "Cameroon",
    "Canada",
    "Cabo Verde",
    "Cayman Islands",
    "Central African Republic",
    "Chad",
    "Chile",
    "China",
    "Christmas Island",
    "Cocos Islands",
    "Colombia",
    "Comoros",
    "Congo",
    "Congo",
    "Cook Islands",
    "Costa Rica",
    "Croatia",
    "Cuba",
    "Curaçao",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Djibouti",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "El Salvador",
    "Equatorial Guinea",
    "Eritrea",
    "Estonia",
    "Ethiopia",
    "Falkland Islands",
    "Faroe Islands",
    "Fiji",
    "Finland",
    "France",
    "French Guiana",
    "French Polynesia",
    "French Southern Territories",
    "Gabon",
    "Gambia",
    "Georgia",
    "Germany",
    "Ghana",
    "Gibraltar",
    "Greece",
    "Greenland",
    "Grenada",
    "Guadeloupe",
    "Guam",
    "Guatemala",
    "Guernsey",
    "Guinea",
    "Guinea-Bissau",
    "Guyana",
    "Haiti",
    "Heard Island and McDonald Islands",
    "Holy See",
    "Honduras",
    "Hong Kong",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Côte d'Ivoire",
    "Iran",
    "Iraq",
    "Ireland",
    "Isle of Man",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jersey",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "Kuwait",
    "Kyrgyzstan",
    "Laos",
    "Latvia",
    "Lebanon",
    "Lesotho",
    "Liberia",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Macao",
    "Macedonia",
    "Madagascar",
    "Malawi",
    "Malaysia",
    "Maldives",
    "Mali",
    "Malta",
    "Marshall Islands",
    "Martinique",
    "Mauritania",
    "Mauritius",
    "Mayotte",
    "Mexico",
    "Micronesia",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Montserrat",
    "Morocco",
    "Mozambique",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Netherlands",
    "New Caledonia",
    "New Zealand",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "Niue",
    "Norfolk Island",
    "North Korea",
    "Northern Mariana Islands",
    "Norway",
    "Oman",
    "Pakistan",
    "Palau",
    "Palestine, State of",
    "Panama",
    "Papua New Guinea",
    "Paraguay",
    "Peru",
    "Philippines",
    "Pitcairn",
    "Poland",
    "Portugal",
    "Puerto Rico",
    "Qatar",
    "Republic of Kosovo",
    "Réunion",
    "Romania",
    "Russian Federation",
    "Rwanda",
    "Saint Barthélemy",
    "Saint Helena, Ascension and Tristan da Cunha",
    "Saint Kitts and Nevis",
    "Saint Lucia",
    "Saint Martin",
    "Saint Pierre and Miquelon",
    "Saint Vincent and the Grenadines",
    "Samoa",
    "San Marino",
    "Sao Tome and Principe",
    "Saudi Arabia",
    "Senegal",
    "Serbia",
    "Seychelles",
    "Sierra Leone",
    "Singapore",
    "Sint Maarten (Dutch part)",
    "Slovakia",
    "Slovenia",
    "Solomon Islands",
    "Somalia",
    "South Africa",
    "South Georgia and the South Sandwich Islands",
    "South Korea",
    "South Sudan",
    "Spain",
    "Sri Lanka",
    "Sudan",
    "Suriname",
    "Svalbard and Jan Mayen",
    "Swaziland",
    "Sweden",
    "Switzerland",
    "Syrian Arab Republic",
    "Taiwan",
    "Tajikistan",
    "Tanzania, United Republic of",
    "Thailand",
    "Timor-Leste",
    "Togo",
    "Tokelau",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Turkey",
    "Turkmenistan",
    "Turks and Caicos Islands",
    "Tuvalu",
    "Uganda",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States of America",
    "Uruguay",
    "Uzbekistan",
    "Vanuatu",
    "Venezuela",
    "Viet Nam",
    "Wallis and Futuna",
    "Western Sahara",
    "Yemen",
    "Zambia",
    "Zimbabwe"
]
continents = ["Asia", "Europe", "Africa","North America", "South America"]

def reset_display(request):
    return render(request,'registration/reset_form.html',{})

def reset_password(request):
    email = request.POST.get('email')
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('user')
    users = table.scan(FilterExpression=Attr('email').eq(email))
    if(len(users['Items'])!=0):
        user = users['Items'][0]
        current_site = get_current_site(request)
        mail_subject = 'Password Reset Link.'
        message = render_to_string('registration/reset_confirm_email.html', {
            'user': user['username'],
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user['email'])),
            'token': account_activation_token.make_token(user['email']),
        })
        send_mail(mail_subject, message, 'tripplanneread@gmail.com', [email])
        return render(request, 'registration/email_confirmation.html',{})
    else:
        messages.success(request, 'The email ID is not registerd')
        return redirect('reset_display')

def verify_reset_password(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        print(uid)
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('user')
        users = table.scan(FilterExpression=Attr('email').eq(uid))
        if(len(users['Items'])!=0):
            user = users['Items'][0]
    except(TypeError, ValueError, OverflowError):
        user = None
    if user is not None and account_activation_token.check_token(user['email'], token):
        # login(request, user)
        request.session['email'] = user['email']
        return render(request,'registration/save_password.html',{})
    else:
        return HttpResponse('Activation link is invalid!')

def save_password(request):
    email = request.session['email']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('user')
    users = table.scan(FilterExpression=Attr('email').eq(email))
    user = users['Items'][0]
    new_password  = request.POST.get('password')
    password = hashlib.sha256(new_password.encode())
    password = password.hexdigest()
    response = table.update_item(
        Key={
            'email': user['email'],
        },
        UpdateExpression="set password = :r",
        ExpressionAttributeValues={
            ':r': password
        },
        ReturnValues="UPDATED_NEW"
    )

    return redirect('landing')

def home(request):
    if request.method == 'POST':
        if (request.POST['place'].lower() in continents) or (request.POST['place'].lower() in countries):
            details = {}
            details['place'] = request.POST['place']
            details['checkin'] = request.POST['checkin']
            details['checkout'] = request.POST['checkout']
            details['price'] = request.POST['price']
            details['type'] = 'continent' if (request.POST['place'].lower() in continent) else 'country'
            return render(request, 'questions.html', details)
        else:
            pass

    idtoken = request.session['uid']
    a = authe.get_account_info(idtoken)
    a = a['users'][0]['localId']

    plans = database.child('users').child(a).child('plans').shallow().get().val()
    trips = []
    for key in list(plans):
        obj = database.child('users').child(a).child('plans').child(key).get().val()
        new_obj = {'checkin':obj['checkin'], 'checkout':obj['checkout'], 'days':obj['days'], 'pid':obj['pid'], 'name':obj['plan_name']}
        trips.append(new_obj)
    return render(request, 'home.html', {'plans':trips})

def questions(request):

    details = {}
    details['place'] = request.POST['place']
    details['checkin'] = request.POST['checkin']
    details['checkout'] = request.POST['checkout']

    request.session['place'] = details['place']
    request.session['checkin'] = details['checkin']
    request.session['checkout'] = details['checkout']

    return render(request, 'questions.html', details)

def plan(request):
    id = request.GET.get('id', '')
    print(id)
    if id == '':
        import random
        import string

        place = request.session['place']
        checkin = request.session['checkin']
        checkout = request.session['checkout']

        checkin = checkin.split('/')
        checkout = checkout.split('/')
        checkin = date(int(checkin[2]), int(checkin[0]), int(checkin[1]))
        checkout = date(int(checkout[2]), int(checkout[0]), int(checkout[1]))
        days = str(checkout - checkin)
        days = days.split()[0]
        cities = get_data(place)

        plan = fplan(cities, checkin, checkout)
        print(plan)

        pid = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(5)])
        idtoken = request.session['uid']
        a = authe.get_account_info(idtoken)
        a = a['users'][0]['localId']

        data = {
            'plan_name': place,
            'pid': pid,
            'plan': plan,
            'checkin': str(checkin),
            'checkout': str(checkout),
            'days': int(str(days))
        }

        request.session['pdata'] = data

        database.child('users').child(a).child('plans').child(pid).set(data)
    else:
        idtoken = request.session['uid']
        a = authe.get_account_info(idtoken)
        a = a['users'][0]['localId']
        plan = database.child('users').child(a).child('plans').child(id).child('plan').get().val()
        plan['id'] = id

    return render(request, 'trip_overview.html', plan)

def review(request):
    if request.method == 'POST':
        if (request.POST['email'] != '' and request.POST['title'] != '' and request.POST['content'] != ''):
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table('reviews')

            table.put_item(
                Item={
                    'email': request.POST['email'],
                    'review': request.POST['content'],
                    'title': request.POST['title']
                }
            )

    return redirect('/')

def landing(request):
    if request.method == 'POST':
        if (request.POST['place'].lower() in continents) or (request.POST['place'].lower() in countries):
            details = {}
            details['place'] = request.POST['place']
            details['checkin'] = request.POST['checkin']
            details['checkout'] = request.POST['checkout']
            details['price'] = request.POST['price']
            details['type'] = 'continent' if (request.POST['place'].lower() in continent) else 'country'
            return render(request, 'questions.html', details)
        else:
            pass
    return render(request, 'index.html')

def blog(request):

    blogs = database.child('blog').get().val()
    for x in blogs:
        print(x)
    blogs = list(blogs)
    blog_list = []
    for blog in blogs:
        blog_obj = database.child('blog').child(blog).get().val()
        user = database.child('users').child(blog_obj['idToken']).child('details').child('name').get().val()
        print(user)
        obj = {'category':blog_obj['category'], 'bid':blog, 'description':blog_obj['description'], 'image':blog_obj['image'], 'user':user, 'title':blog_obj['title']}
        blog_list.append(obj)
    print(blog_list[0])

    return render(request, 'blog2.html', {'blogs':blog_list})

def blogabout(request):
    bid = request.GET.get('bid', '')
    if bid == '':
        return redirect('/blog')
    blog = database.child('blog').child(bid).get().val()
    user = database.child('users').child(blog['idToken']).child('details').child('name').get().val()
    return render(request, 'blogabout.html', {'blog':blog, 'user':user})

def addpost(request):
    return render(request, 'addpost2.html')

def post_add(request):

    import random
    import string

    c1 = request.POST['check1']
    c2 = request.POST['check2']
    c3 = request.POST['check3']
    c4 = request.POST['check4']
    c5 = request.POST['check5']
    c6 = request.POST['check6']

    title = request.POST['title']
    image = request.POST['image']
    description = request.POST['description']
    cat=[c1,c2,c3,c4,c5,c6]

    while("" in cat) :
        cat.remove("")

    pid = 'b'.join([random.choice(string.ascii_letters + string.digits) for n in range(5)])
    idtoken = request.session['uid']
    a = authe.get_account_info(idtoken)
    a = a['users'][0]['localId']

    data = {
        'pid': pid,
        'idToken':a,
        'title': title,
        'description': description,
        'image': image,
        'category': cat,}

    database.child('blog').child(pid).set(data)
    return redirect('blog')

def about(request):
    return render(request, 'addpost2.html')

def timeline(request):
    id = request.GET.get('id', '')
    if id == "":
        data = request.session['pdata']
        print(data)
    else:
        idtoken = request.session['uid']
        a = authe.get_account_info(idtoken)
        a = a['users'][0]['localId']
        data = database.child('users').child(a).child('plans').child(id).get().val()
        print(data)
        data['id'] = id
    return render(request, 'timeline.html', data)

def auth(request):
    return render(request, 'auth.html')

def login(request):

    email = request.POST.get('email')
    password = request.POST.get('password')

    recaptcha_response = request.POST.get('g-recaptcha-response')

    url = 'https://www.google.com/recaptcha/api/siteverify'
    values = {
        'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    data = urllib.parse.urlencode(values).encode()
    req =  urllib.request.Request(url, data=data)
    response = urllib.request.urlopen(req)
    result = json.loads(response.read().decode())

    if not result['success']:
        messages.error(request, 'Invalid reCAPTCHA. Please try again.')
        return redirect('auth')

    try:
        user = authe.sign_in_with_email_and_password(email, password)
    except:
        if(email != '' and password!=''):
            messages.success(request, 'Failed to login as the email or password does not match.')
            return redirect('auth')
        else:
            messages.success(request, 'Failed to login as the email or password is provided empty')
            return redirect('auth')

    session_id = user['idToken']
    request.session['uid'] = str(session_id)

    return redirect('home')

def signup(request):

    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    re_password = request.POST.get('repassword')

    try:
        user = authe.create_user_with_email_and_password(email, password)
        uid = user['localId']
        data = {'name':username}
        database.child('users').child(uid).child('details').set(data, user['idToken'])
    except:
         messages.success(request, 'Failed to sign up')
         return redirect('auth')

    return redirect('home')

def logout_view(request):
    logout(request)
    return redirect('/')

def verify(request):
    return render(request, 'verify.html')

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        print(uid)
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('user')

        response = table.scan(
            FilterExpression=Attr('email').eq(uid)
        )
        if (len(response['Items']) != 0):
            user = response['Items'][0]
    except(TypeError, ValueError, OverflowError):
        user = None
    if user is not None and account_activation_token.check_token(user['email'], token):

        response = table.update_item(
            Key={
                'email': user['email'],
            },
            UpdateExpression="set is_active = :r",
                ExpressionAttributeValues={
                    ':r':True
                },
            ReturnValues="UPDATED_NEW"
        )
        request.session['username'] = user['username']
        request.session['email']=user['email']
        return redirect('home')

    else:
        return HttpResponse('Activation link is invalid!')

finalplan = {"start": 'New Delhi, India',
        'finalplan':[
                    {
                        "place":"Hyderabad, India",
                        "lat":17.3850,
                        "lng":78.4867,
                        'journey':[
                                    {
                                        "mode": 'Fly',
                                        "distance": 900,
                                        "time": 2
                                    },
                                    {
                                        "mode": 'Train',
                                        "distance": 1900,
                                        "time": 48
                                    },
                                    {
                                        "mode": 'Car',
                                        "distance": 1100,
                                        "time": 24
                                    }
                                  ],
                        "start": parse_date('2020-03-20'),
                        "end": parse_date('2020-03-22'),
                        "places":[{'day': datetime.date(2020, 7, 17),
  'places': [{'starttime': '10:30',
    'endtime': '12:00',
    'name': 'Shilparamam',
    'lat': 17.452573,
    'lng': 78.3783065,
    'next': '30min'},
   {'starttime': '12:30',
    'endtime': '15:00',
    'name': 'Qutb Shahi Tombs',
    'lat': 17.3950064,
    'lng': 78.39675419999999,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '17:15',
    'name': 'Golconda Fort',
    'lat': 17.383309,
    'lng': 78.4010528,
    'next': '30min'},
   {'starttime': '17:45',
    'endtime': '20:15',
    'name': 'Chowmahalla Palace',
    'lat': 17.3578233,
    'lng': 78.4716897}]},
 {'day': datetime.date(2020, 7, 18),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Charminar',
    'lat': 17.3615636,
    'lng': 78.4746645,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '15:45',
    'name': 'Salar Jung Museum',
    'lat': 17.3713224,
    'lng': 78.4803589,
    'next': '15min'},
   {'starttime': '16:00',
    'endtime': '18:00',
    'name': 'Lumbini Park',
    'lat': 17.4098755,
    'lng': 78.47315180000001,
    'next': '15min'},
   {'starttime': '18:15',
    'endtime': '20:15',
    'name': 'NTR Gardens',
    'lat': 17.4124512,
    'lng': 78.4688386}]},
 {'day': datetime.date(2020, 7, 19),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Buddha Statue',
    'lat': 17.4155657,
    'lng': 78.474973,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '13:45',
    'name': 'Jalavihar Water Park',
    'lat': 17.4325926,
    'lng': 78.4647823,
    'next': '15min'},
   {'starttime': '14:00',
    'endtime': '15:00',
    'name': 'Shri Jagannath Temple, Hyderabad',
    'lat': 17.4151421,
    'lng': 78.4261934,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '16:45',
    'name': 'Kasu Brahmanandha Reddy National Park',
    'lat': 17.4237592,
    'lng': 78.41595199999999,
    'next': '30min'},
   {'starttime': '17:15',
    'endtime': '18:45',
    'name': 'Snow World',
    'lat': 17.4145708,
    'lng': 78.48092249999999}]}]
                    },
                    {
                        "place":"Chennai, India",
                        "lat":13.0827,
                        "lng":80.2707,
                        'journey':[
                                    {
                                        "mode": 'Train',
                                        "distance": 900,
                                        "time": 12
                                    },
                                    {
                                        "mode": 'Fly',
                                        "distance": 900,
                                        "time": 2
                                    },
                                    {
                                        "mode": 'Car',
                                        "distance": 1100,
                                        "time": 14
                                    }
                                  ],
                        "start": parse_date('2020-03-24'),
                        "end": parse_date('2020-03-26'),
                        "places":[{'day': datetime.date(2020, 7, 17),
  'places': [{'starttime': '10:30',
    'endtime': '12:00',
    'name': 'Shilparamam',
    'lat': 17.452573,
    'lng': 78.3783065,
    'next': '30min'},
   {'starttime': '12:30',
    'endtime': '15:00',
    'name': 'Qutb Shahi Tombs',
    'lat': 17.3950064,
    'lng': 78.39675419999999,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '17:15',
    'name': 'Golconda Fort',
    'lat': 17.383309,
    'lng': 78.4010528,
    'next': '30min'},
   {'starttime': '17:45',
    'endtime': '20:15',
    'name': 'Chowmahalla Palace',
    'lat': 17.3578233,
    'lng': 78.4716897}]},
 {'day': datetime.date(2020, 7, 18),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Charminar',
    'lat': 17.3615636,
    'lng': 78.4746645,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '15:45',
    'name': 'Salar Jung Museum',
    'lat': 17.3713224,
    'lng': 78.4803589,
    'next': '15min'},
   {'starttime': '16:00',
    'endtime': '18:00',
    'name': 'Lumbini Park',
    'lat': 17.4098755,
    'lng': 78.47315180000001,
    'next': '15min'},
   {'starttime': '18:15',
    'endtime': '20:15',
    'name': 'NTR Gardens',
    'lat': 17.4124512,
    'lng': 78.4688386}]},
 {'day': datetime.date(2020, 7, 19),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Buddha Statue',
    'lat': 17.4155657,
    'lng': 78.474973,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '13:45',
    'name': 'Jalavihar Water Park',
    'lat': 17.4325926,
    'lng': 78.4647823,
    'next': '15min'},
   {'starttime': '14:00',
    'endtime': '15:00',
    'name': 'Shri Jagannath Temple, Hyderabad',
    'lat': 17.4151421,
    'lng': 78.4261934,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '16:45',
    'name': 'Kasu Brahmanandha Reddy National Park',
    'lat': 17.4237592,
    'lng': 78.41595199999999,
    'next': '30min'},
   {'starttime': '17:15',
    'endtime': '18:45',
    'name': 'Snow World',
    'lat': 17.4145708,
    'lng': 78.48092249999999}]}]
                    },
                    {
                        "place":"Kodaikanal, India",
                        "lat":10.2381,
                        "lng":77.4892,
                        'journey':[
                                    {
                                        "mode": 'Bus',
                                        "distance": 500,
                                        "time": 6
                                    },
                                    {
                                        "mode": 'Car',
                                        "distance": 500,
                                        "time": 5
                                    }
                                  ],
                        "start": parse_date('2020-03-27'),
                        "end": parse_date('2020-03-29'),
                        "places":[{'day': datetime.date(2020, 7, 17),
  'places': [{'starttime': '10:30',
    'endtime': '12:00',
    'name': 'Shilparamam',
    'lat': 17.452573,
    'lng': 78.3783065,
    'next': '30min'},
   {'starttime': '12:30',
    'endtime': '15:00',
    'name': 'Qutb Shahi Tombs',
    'lat': 17.3950064,
    'lng': 78.39675419999999,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '17:15',
    'name': 'Golconda Fort',
    'lat': 17.383309,
    'lng': 78.4010528,
    'next': '30min'},
   {'starttime': '17:45',
    'endtime': '20:15',
    'name': 'Chowmahalla Palace',
    'lat': 17.3578233,
    'lng': 78.4716897}]},
 {'day': datetime.date(2020, 7, 18),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Charminar',
    'lat': 17.3615636,
    'lng': 78.4746645,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '15:45',
    'name': 'Salar Jung Museum',
    'lat': 17.3713224,
    'lng': 78.4803589,
    'next': '15min'},
   {'starttime': '16:00',
    'endtime': '18:00',
    'name': 'Lumbini Park',
    'lat': 17.4098755,
    'lng': 78.47315180000001,
    'next': '15min'},
   {'starttime': '18:15',
    'endtime': '20:15',
    'name': 'NTR Gardens',
    'lat': 17.4124512,
    'lng': 78.4688386}]},
 {'day': datetime.date(2020, 7, 19),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Buddha Statue',
    'lat': 17.4155657,
    'lng': 78.474973,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '13:45',
    'name': 'Jalavihar Water Park',
    'lat': 17.4325926,
    'lng': 78.4647823,
    'next': '15min'},
   {'starttime': '14:00',
    'endtime': '15:00',
    'name': 'Shri Jagannath Temple, Hyderabad',
    'lat': 17.4151421,
    'lng': 78.4261934,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '16:45',
    'name': 'Kasu Brahmanandha Reddy National Park',
    'lat': 17.4237592,
    'lng': 78.41595199999999,
    'next': '30min'},
   {'starttime': '17:15',
    'endtime': '18:45',
    'name': 'Snow World',
    'lat': 17.4145708,
    'lng': 78.48092249999999}]}]
                    },
                    {
                        "place":"Mysuru, India",
                        "lat":12.2958,
                        "lng":76.6394,
                        'journey':[
                                    {
                                        "mode": 'Bus',
                                        "distance": 900,
                                        "time": 6
                                    },
                                    {
                                        "mode": 'Car',
                                        "distance": 900,
                                        "time": 7
                                    }
                                  ],
                        "start": parse_date('2020-03-31'),
                        "end": parse_date('2020-04-2'),
                        "places":[{'day': datetime.date(2020, 7, 17),
  'places': [{'starttime': '10:30',
    'endtime': '12:00',
    'name': 'Shilparamam',
    'lat': 17.452573,
    'lng': 78.3783065,
    'next': '30min'},
   {'starttime': '12:30',
    'endtime': '15:00',
    'name': 'Qutb Shahi Tombs',
    'lat': 17.3950064,
    'lng': 78.39675419999999,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '17:15',
    'name': 'Golconda Fort',
    'lat': 17.383309,
    'lng': 78.4010528,
    'next': '30min'},
   {'starttime': '17:45',
    'endtime': '20:15',
    'name': 'Chowmahalla Palace',
    'lat': 17.3578233,
    'lng': 78.4716897}]},
 {'day': datetime.date(2020, 7, 18),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Charminar',
    'lat': 17.3615636,
    'lng': 78.4746645,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '15:45',
    'name': 'Salar Jung Museum',
    'lat': 17.3713224,
    'lng': 78.4803589,
    'next': '15min'},
   {'starttime': '16:00',
    'endtime': '18:00',
    'name': 'Lumbini Park',
    'lat': 17.4098755,
    'lng': 78.47315180000001,
    'next': '15min'},
   {'starttime': '18:15',
    'endtime': '20:15',
    'name': 'NTR Gardens',
    'lat': 17.4124512,
    'lng': 78.4688386}]},
 {'day': datetime.date(2020, 7, 19),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Buddha Statue',
    'lat': 17.4155657,
    'lng': 78.474973,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '13:45',
    'name': 'Jalavihar Water Park',
    'lat': 17.4325926,
    'lng': 78.4647823,
    'next': '15min'},
   {'starttime': '14:00',
    'endtime': '15:00',
    'name': 'Shri Jagannath Temple, Hyderabad',
    'lat': 17.4151421,
    'lng': 78.4261934,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '16:45',
    'name': 'Kasu Brahmanandha Reddy National Park',
    'lat': 17.4237592,
    'lng': 78.41595199999999,
    'next': '30min'},
   {'starttime': '17:15',
    'endtime': '18:45',
    'name': 'Snow World',
    'lat': 17.4145708,
    'lng': 78.48092249999999}]}]
                    },
                    {
                        "place":"Bengaluru, India",
                        "lat":12.9716,
                        "lng":77.5946,
                        'journey':[
                                    {
                                        "mode": 'Car',
                                        "distance": 100,
                                        "time": 2
                                    },
                                    {
                                        "mode": 'Bus',
                                        "distance": 100,
                                        "time": 3
                                    },
                                    {
                                        "mode": 'Train',
                                        "distance": 150,
                                        "time": 5
                                    }
                                  ],
                        "start": parse_date('2020-04-3'),
                        "end": parse_date('2020-04-5'),
                        "places":[{'day': datetime.date(2020, 7, 17),
  'places': [{'starttime': '10:30',
    'endtime': '12:00',
    'name': 'Shilparamam',
    'lat': 17.452573,
    'lng': 78.3783065,
    'next': '30min'},
   {'starttime': '12:30',
    'endtime': '15:00',
    'name': 'Qutb Shahi Tombs',
    'lat': 17.3950064,
    'lng': 78.39675419999999,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '17:15',
    'name': 'Golconda Fort',
    'lat': 17.383309,
    'lng': 78.4010528,
    'next': '30min'},
   {'starttime': '17:45',
    'endtime': '20:15',
    'name': 'Chowmahalla Palace',
    'lat': 17.3578233,
    'lng': 78.4716897}]},
 {'day': datetime.date(2020, 7, 18),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Charminar',
    'lat': 17.3615636,
    'lng': 78.4746645,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '15:45',
    'name': 'Salar Jung Museum',
    'lat': 17.3713224,
    'lng': 78.4803589,
    'next': '15min'},
   {'starttime': '16:00',
    'endtime': '18:00',
    'name': 'Lumbini Park',
    'lat': 17.4098755,
    'lng': 78.47315180000001,
    'next': '15min'},
   {'starttime': '18:15',
    'endtime': '20:15',
    'name': 'NTR Gardens',
    'lat': 17.4124512,
    'lng': 78.4688386}]},
 {'day': datetime.date(2020, 7, 19),
  'places': [{'starttime': '10:30',
    'endtime': '11:30',
    'name': 'Buddha Statue',
    'lat': 17.4155657,
    'lng': 78.474973,
    'next': '15min'},
   {'starttime': '11:45',
    'endtime': '13:45',
    'name': 'Jalavihar Water Park',
    'lat': 17.4325926,
    'lng': 78.4647823,
    'next': '15min'},
   {'starttime': '14:00',
    'endtime': '15:00',
    'name': 'Shri Jagannath Temple, Hyderabad',
    'lat': 17.4151421,
    'lng': 78.4261934,
    'next': '15min'},
   {'starttime': '15:15',
    'endtime': '16:45',
    'name': 'Kasu Brahmanandha Reddy National Park',
    'lat': 17.4237592,
    'lng': 78.41595199999999,
    'next': '30min'},
   {'starttime': '17:15',
    'endtime': '18:45',
    'name': 'Snow World',
    'lat': 17.4145708,
    'lng': 78.48092249999999}]}]
                    }
                ],
         "end":{
                    "place": "New Delhi, India",
                    "journey":[
                        {
                            "mode": 'Fly',
                            "distance": 1000,
                            "time": 2
                        },
                        {
                            "mode": 'Train',
                            "distance": 1900,
                            "time": 24
                        },
                        {
                            "mode": 'Car',
                            "distance": 2000,
                            "time": 27
                        }
                    ]
               }
        }

def maps(request):
    id = request.GET.get('id', '')
    if id == '':
        finalplan1 = request.session['pdata']
        finalplan = finalplan1['plan']
    else:
        idtoken = request.session['uid']
        a = authe.get_account_info(idtoken)
        a = a['users'][0]['localId']
        finalplan = database.child('users').child(a).child('plans').child(id).child('plan').get().val()
        finalplan['id'] = id
    return render(request, 'maps.html', finalplan)

def overview(request):
    return render(request, 'trip_overview.html')

class loginapi(APIView):

    def get(self,request):
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('user')
        response_api = table.scan(FilterExpression=Attr('is_active').eq(True))

        return Response(response_api['Items'])

class planapi(APIView):

    def get(self,request):
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Plans')
        response_planapi = table.scan()

        return Response(response_planapi['Items'])
