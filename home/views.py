from django.shortcuts import render
from django.http import HttpResponse

def landing(request):
    return render(request, 'index.html')

def timeline(request):
    return render(request, 'timeline.html')
