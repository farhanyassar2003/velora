# userside/decorators.py

from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def non_admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_staff or request.user.is_superuser:
            messages.warning(request, "Admins cannot access the user site.")
            return redirect('/admin/')  # Or any custom error page
        return view_func(request, *args, **kwargs)
    return wrapper
