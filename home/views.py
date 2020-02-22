from django.shortcuts import render

def landing(request):
    if request.method == 'POST':
        print(request.POST)
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')
