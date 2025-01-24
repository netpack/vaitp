
from django.http import HttpResponse
from rest_framework import status
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate as django_authenticate


def authenticate(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    body = request.json

    username = body.get("username")
    password = body.get("password")


    if not username or not password:
        return JsonResponse({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

    user = django_authenticate(username=username, password=password)

    if not user:
        return JsonResponse({"error": "Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
         return JsonResponse({"error": "User account is inactive"}, status=status.HTTP_403_FORBIDDEN)

    # Authentication successful
    return JsonResponse({"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IkpvaG5Eb2UiLCJleHAiOjE2MzE0NjI5Mjd9.k0Kp6lArw3p2cfdYPf5X8Y0V_dP8ucgrhI8BT_x-f10"}, status=status.HTTP_200_OK)