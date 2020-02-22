from django.shortcuts import render
from django.http import HttpResponse

def landing(request):
    if request.method == 'POST':
        print(request.POST)
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')

def timeline(request):
    return render(request, 'timeline.html')
