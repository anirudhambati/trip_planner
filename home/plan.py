# from itertools import combinations
# import math
# import networkx as nx
# from graph import *
#
# def plan(place, days, questions):
#
#     if place == country:
#         plan = plan_country(place, days, questions)
#     elif place == continent:
#         plan = plan_continent(place, days, questions)
#     else:
#         plan_city(place, days, questions)
#
#     return plan
#
# def plan_city(city, days, questions):
#     places, times = get_places(city, days, questions)
#     time_counter = 0
#     total_time = days * 7
#     coords = []
#     final_places, final_times = [], []
#     for place, time in zip(places, times):
#         time_counter = time_counter + time
#         if time_counter >= total_time:
#             break
#         else:
#             final_places.append(place)
#             final_times.append(time)
#             coords.append(get_coords(place))
#             continue
#
#     G = get_graph(coords)
#     plan = dijkstra(G)
#
#     return plan
#
# '''
# functions to implement
# -----------------------
# get_countries
# get_cities
# get_places
# -----------------------
# plan_city
# -----------------------
# get_coords
# '''
