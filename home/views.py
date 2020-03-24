from django.shortcuts import render
import boto3
from boto3.dynamodb.conditions import Key, Attr
from django.http import HttpResponse
from django.core.mail import send_mail
import hashlib
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
    return render(request, 'home.html')

def questions(request):
    if request.method == 'POST':
        print(request.POST)
        return redirect('/')
    return render(request, 'questions.html')

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
    # try:
    #     request.user.social_auth.filter(provider="google-oauth2")
    # except NameError:
    #     print("error")
    # print("-------------------------------")
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')

def timeline(request):
    return render(request, 'timeline.html')

def auth(request):
    return render(request, 'auth.html')

def plan(request):
    return render(request, 'plan.html')

def login(request):
    # if request.method == 'POST':
    email = request.POST.get('email')
    password = request.POST.get('password')
    password=hashlib.sha256(password.encode())
    password=password.hexdigest()

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

    dynamodb = boto3.resource('dynamodb')
    if(email != '' and password!=''):
        table = dynamodb.Table('user')
        response = table.scan(FilterExpression=Attr('email').eq(email))
        print(response)
        # response = table.scan(
        # ProjectionExpression="email,password,organizations_created,organizations_joined,username",
        # FilterExpression=Attr('email').eq(email)
        # )
        print('\n\n\n')
        print(response['Items'])
        # print(response['Items'][0])

        print('\n\n\n')
        if(len(response['Items'])>0):
            if(response['Items'][0]['password']==password):
                if(response['Items'][0]['is_active']):

                    request.session['username'] = response['Items'][0]['username']
                    request.session['email']=response['Items'][0]['email']
                    print(request.session['username'],request.session['email'])

                    return redirect('home')
                else:
                    return redirect('verify')
            else:
                messages.success(request, 'Failed to login as the password does not match.')
                return redirect('auth')
        else:
            messages.success(request, 'Failed to login as the email ID is not registered.')
            return redirect('auth')
    else:
        messages.success(request, 'Failed to login as the email or password is provided empty')
        return redirect('auth')


def signup(request):
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    re_password = request.POST.get('repassword')

    if (username != '' and email != '' and password != '' and re_password != ''):
        if (password == re_password):

            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table('user')

            response = table.scan(
                ProjectionExpression="email",
                FilterExpression=Attr('email').eq(email)
            )
            password = hashlib.sha256(password.encode())
            password = password.hexdigest()

            if (len(response['Items']) == 0):
                response = table.put_item(
                    Item={
                        'username': username,
                        'email': email,
                        'password': password,
                        'is_active': False,
                    }
                )


                # request.session['username'] = username
                # request.session['email'] = email
                #
                # return redirect('landing')
                current_site = get_current_site(request)
                mail_subject = 'Activate your account.'
                message = render_to_string('acc_active_email.html', {
                    'user': username,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(email)),
                    'token': account_activation_token.make_token(email),
                })

                send_mail(mail_subject, message, 'tripplanneread@gmail.com', [email])
                return redirect('verify')


            else:
                messages.success(request, 'The email ID is already registerd')
                return redirect('auth')
        else:
            messages.success(request, 'Failed to register as the password and confirm password do not match')
            return redirect('auth')
    else:
        messages.success(request, 'Fill all the fields')
        return redirect('auth')

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

def overview(request):
    return render(request, 'trip_overview.html')
