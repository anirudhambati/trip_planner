def plan(place, start_date, end_date, questions):
    days = end_date - start_date

    if place == country or place == continent:
        tourist_spots = tourist_spots(place)
    else:
        tourist_spots = tourist_spots(place)

    return plan
