from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class BlockUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'status') and request.user.status == 'blocked':
            logout(request)
            messages.error(request, 'Your account has been blocked.')
            return redirect(reverse('userside:login'))
        response = self.get_response(request)
        return response