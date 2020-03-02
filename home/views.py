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

def landing(request):
    if request.method == 'POST':
        print(request.POST)
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
