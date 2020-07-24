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

def get_data(place):
    api_key = 'AIzaSyCe2otGPKiUf4Qq35MmOfDWHaQm-Cjtopw'
    url = "https://maps.googleapis.com/maps/api/place/textsearch/json?"
    place = 'tourist places in ' + str(place)
    r = requests.get(url + 'query=' + place + '&key=' + api_key)

    x = r.json()
    y = x['results']
    places=[]  #our places list
    picurl="https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference="   #for getting google images url using photo reference

    for i in range(len(y)):
        photourl= picurl + y[i]['photos'][0]['photo_reference'] + '&key=' +api_key
        try:
            places.append({
            "name": y[i]['name'],
            "url":photourl,
            "location":y[i]['geometry']['location'],
            "type":y[i]['types'],
            "rating":y[i]['rating'],
            "no_of_ratings":y[i]['user_ratings_total'],
            "status":y[i]['business_status'],
            "opening_hours":y[i]['opening_hours']
            })
        except:
            places.append({
            "name": y[i]['name'],
            "url":photourl,
            "location":y[i]['geometry']['location'],
            "type":y[i]['types'],
            "rating":y[i]['rating'],
            "no_of_ratings":y[i]['user_ratings_total'],
            "status":y[i]['business_status']
            })

    return places

def Distance(s, e, mode=0):
    R = 6373.0

    lat1 = radians(s[0])
    lon1 = radians(s[1])
    lat2 = radians(e[0])
    lon2 = radians(e[1])

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c

    if mode == 1:
        return ceil((distance/25)*60)
    return distance

def TotalDistance(city, R):
    dist=0
    for i in range(len(city)-1):
        dist += Distance(R[city[i]],R[city[i+1]])
    dist += Distance(R[city[-1]],R[city[0]])
    return dist

def reverse(city, n):
    nct = len(city)
    nn = (1+ ((n[1]-n[0]) % nct))//2
    for j in range(nn):
        k = (n[0]+j) % nct
        l = (n[1]-j) % nct
        (city[k],city[l]) = (city[l],city[k])

def Plot(city, R, dist, title):
    # Plot
    Pt = [R[city[i]] for i in range(len(city))]
    Pt += [R[city[0]]]
    Pt = array(Pt)
    # plt.title(title+' Total distance='+str(dist))
    # plt.plot(Pt[:,0], Pt[:,1], '-o')
    # plt.show()

def simulation(R, ncity, maxSteps, maxAccepted, city, dist, n, nct, maxTsteps=100, T=0.2, fCool=0.9):
    for t in range(maxTsteps):

        accepted = 0
        for i in range(maxSteps):

            while True:
                n[0] = int((nct)*rand())
                n[1] = int((nct-1)*rand())
                if (n[1] >= n[0]): n[1] += 1
                if (n[1] < n[0]): (n[0],n[1]) = (n[1],n[0])
                nn = (n[0]+nct -n[1]-1) % nct
                if nn>=3: break

            n[2] = (n[0]-1) % nct
            n[3] = (n[1]+1) % nct

            de = Distance(R[city[n[2]]],R[city[n[1]]]) + Distance(R[city[n[3]]],R[city[n[0]]]) - Distance(R[city[n[2]]],R[city[n[0]]]) - Distance(R[city[n[3]]],R[city[n[1]]])

            if de<0 or exp(-de/T)>rand():
                accepted += 1
                dist += de
                reverse(city, n)

            if accepted > maxAccepted: break

        T *= fCool
        if accepted == 0: break

    return dist, city

def check(city, cities, num_days):
    print(city)
    max_time = 480*num_days
    c = 0
    time = 60
    for idx in city[1:]:
        time += random.randrange(30, 180, 15) #+ Distance([cities[idx-1]['location']['lat'], cities[idx-1]['location']['lng']], [cities[idx]['location']['lat'], cities[idx]['location']['lng']], mode=1)
        if(time > max_time):
            return True
    return False

def round_time(time, round_to=15):
    rounded = datetime.datetime(100, 1, 1, time.hour, time.minute, time.second) + datetime.timedelta(minutes=round_to/1.55)
    rounded -= datetime.timedelta(minutes=rounded.minute % round_to,
                                  seconds=rounded.second,
                                  microseconds=rounded.microsecond)
    return rounded.time()

def check_time(t1, t2):
    time = datetime.datetime(100, 1, 1, t1.hour, t1.minute, t1.second) - datetime.datetime(100, 1, 1, t2.hour, t2.minute, t2.second)
    return time.total_seconds()/60

def journey(origin, dest):
    dist_url = 'https://maps.googleapis.com/maps/api/distancematrix/json?origins={}&destinations={}&mode={}&key={}'
    api_key = 'AIzaSyCn12sRqYwxSTVWD8debtCCpBBNwFU-6js'
    arr = []
    r = requests.get(dist_url.format(origin, dest, 'DRIVING', api_key)).json()
    dist, time = r['rows'][0]['elements'][0]['distance']['text'], r['rows'][0]['elements'][0]['duration']['text']
    arr.append({'mode': "Car", 'distance':dist, 'time': time})
    r = requests.get(dist_url.format(origin, dest, 'TRANSIT', api_key)+'&transit_mode=BUS').json()
    dist, time = r['rows'][0]['elements'][0]['distance']['text'], r['rows'][0]['elements'][0]['duration']['text']
    arr.append({'mode': "Bus", 'distance':dist, 'time': time})
    r = requests.get(dist_url.format(origin, dest, 'TRANSIT', api_key)+'&transit_mode=TRAIN').json()
    dist, time = r['rows'][0]['elements'][0]['distance']['text'], r['rows'][0]['elements'][0]['duration']['text']
    arr.append({'mode': "Train", 'distance':dist, 'time': time})

    return arr

def fplan(cities, start_date, end_date):
    num_days = end_date - start_date
    num_days = num_days.days+1
    print(num_days)
    print(len(cities))
    if num_days*6 < len(cities):
        R = [[place['location']['lat'], place['location']['lng']] for place in cities[:num_days*6]]
        ncity = len(R)
        maxSteps = 100*ncity
        maxAccepted = 10*ncity
        city = list(range(ncity))
        dist = TotalDistance(city, R)
        n = zeros(6, dtype=int)
        nct = len(R)

        #Plot(city, R, dist, 'Initial')

        dist, city = simulation(R, ncity, maxSteps, maxAccepted, city, dist, n, nct)

        #Plot(city, R, dist, 'Final')
    else:
        R = [[place['location']['lat'], place['location']['lng']] for place in cities]
        city = list(range(len(cities)))

    print(city)

    while(check(city, cities, num_days)):
        R = R[:-1]
        ncity = len(R)
        maxSteps = 100*ncity
        maxAccepted = 10*ncity
        city = list(range(ncity))
        dist = TotalDistance(city, R)
        n = zeros(6, dtype=int)
        nct = len(R)

        #Plot(city, R, dist, 'Initial')

        dist, city = simulation(R, ncity, maxSteps, maxAccepted, city, dist, n, nct)
    #Plot(city, R, dist, 'Final')

    plan = []
    date = start_date
    max_time = time(20, 30)
    max_l = max(city)
    for dayid in range(num_days):
        day = {"day":str(parse_date(date.strftime("%Y-%m-%d"))), "places": []}
        t = time(10, 30)
        for _ in range(5):
            if(len(city) == 0):
                break
            if(check_time(max_time, t) < 60):
                break
            name = cities[city[0]]['name']
            lat = cities[city[0]]['location']['lat']
            lng = cities[city[0]]['location']['lng']
            type = cities[city[0]]['type']
            rating = cities[city[0]]['rating']
            url = cities[city[0]]['url']
            t = round_time(t)
            strt = t.strftime("%H:%M")
            end = (datetime.datetime(100, 1, 1, t.hour, t.minute, t.second) + timedelta(minutes=60)).time()
            end = round_time(end)

            n=[]
            for k in type:
                n.append(k.replace('_', ' '))

            place = {"starttime":strt, "endtime":end.strftime("%H:%M"), "name":name, "lat":lat, "lng":lng, "type":n, "rating":rating,'url':url}
            if(len(city) != 1):
                next_time = Distance(R[city[0]], R[city[1]], mode=1)
                next_time = ceil(next_time*1.0/15)*15
                place['next'] = str(next_time)+"min"
                t = (datetime.datetime(100, 1, 1, end.hour, end.minute, end.second) + timedelta(minutes=next_time)).time()
            day["places"].append(place)
            city = city[1:]
        plan.append(day)
        date = date + timedelta(days=1)

    idx = max_l
    for day in plan:
        try:
            day['places'][-1].pop('next')
        except:
            pass
        last_place = day['places'][-1]
        last_time = day['places'][-1]['endtime'].split(":")
        last_time = time(int(last_time[0]), int(last_time[1]))
        rt = random.randrange(30, 120, 15)
        if check_time(max_time, last_time) > rt:
            next_time = Distance([last_place['lat'], last_place['lng']], [cities[idx]['location']['lat'], cities[idx]['location']['lng']], mode=1)
            next_time = ceil(next_time*1.0/15)*15
            last_place['next'] = str(next_time)+"min"
            name = cities[idx]['name']
            lat = cities[idx]['location']['lat']
            lng = cities[idx]['location']['lng']
            type = cities[idx]['type']
            url = cities[idx]['url']

            n=[]
            for k in type:
                n.append(k.replace('_', ' '))
            rating = cities[idx]['rating']

            t = (datetime.datetime(100, 1, 1, last_time.hour, last_time.minute, last_time.second) + timedelta(minutes=next_time)).time()
            strt = t.strftime("%H:%M")
            end = (datetime.datetime(100, 1, 1, t.hour, t.minute, t.second) + timedelta(minutes=rt)).time()
            end = round_time(end)
            place = {"starttime":str(strt), "endtime":str(end.strftime("%H:%M")), "name":name, "lat":lat, "lng":lng, "type":n, "rating":rating, 'url':url}
            day['places'].append(place)
        idx += 1

# ------------------------- city extracts here ---------------------------

    data = plan
    coords = []
    for day in data:
        place_lat = day['places'][-1]['lat']
        place_lng = day['places'][-1]['lng']
        coords.append((place_lat, place_lng))

    url = "https://maps.googleapis.com/maps/api/geocode/json?latlng={},{}&key={}"
    key = 'AIzaSyCe2otGPKiUf4Qq35MmOfDWHaQm-Cjtopw'
    cities = []
    for coord in coords:
        r = requests.get(url.format(coord[0], coord[1], key))
        result_city = r.json()['results'][0]['address_components'][-4]['long_name']
        result_country = r.json()['results'][0]['address_components'][-2]['long_name']
        cities.append(result_city+", "+result_country)

    final_obj = []
    visited = []
    city_dict = {}
    for i, city in enumerate(cities, 0):
        #print(city)
        if city not in visited:
            final_obj.append(city_dict)
            visited.append(city)
            city_dict = {'place':city, 'lat':coords[i][0], 'lng':coords[i][1], 'start_date':str(data[i]['day']), 'end_date':str(data[i]['day']), 'places':[data[i]]}
        else:
            city_dict['end_date'] = str(data[i]['day'])
            city_dict['places'].append(data[i])
    final_obj.append(city_dict)
    final_obj = final_obj[1:]

    start_city = 'New Delhi, India'
    end_city = 'New Delhi, India'
    final_obj = {"start":start_city, 'finalplan':final_obj, 'end':{"place": end_city, "journey":[]}}

    final_obj['finalplan'][0]['journey'] = journey(start_city, final_obj['finalplan'][0]['place'])
    for i, city in enumerate(final_obj['finalplan'][:-1], 0):
        final_obj['finalplan'][i+1]['journey'] = journey(final_obj['finalplan'][i]['place'], final_obj['finalplan'][i+1]['place'])
    final_obj['end']['journey'] = journey(final_obj['finalplan'][-1]['place'], end_city)

    return final_obj
