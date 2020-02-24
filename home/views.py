from django.shortcuts import render
import boto3
from boto3.dynamodb.conditions import Key, Attr
from django.http import HttpResponse
import hashlib
from django.shortcuts import render,redirect
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.contrib import sessions
from django.contrib import messages


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


def login(request):
    # if request.method == 'POST':
    email = request.POST.get('email')
    password = request.POST.get('password')
    password=hashlib.sha256(password.encode())
    password=password.hexdigest()


    dynamodb = boto3.resource('dynamodb')
    if(email != '' or password!=''):
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

                request.session['username'] = response['Items'][0]['username']
                request.session['email']=response['Items'][0]['email']
                print(request.session['username'],request.session['email'])
          
                return redirect('landing')
            else:
                messages.success(request, 'Failed to login as the password does not match.')
                return redirect('auth')
        else:
            messages.success(request, 'Failed to login as the email ID is not registered.')
            return redirect('auth')
    else:
        messages.success(request, 'Failed to login as the email or password is provided empty')
        return redirect('auth')
