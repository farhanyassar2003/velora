# ===========================# Django and Third-Party Imports# ===========================
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, get_user_model, update_session_auth_hash
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Q, Avg, F
from django.contrib import messages
from django.views.decorators.cache import never_cache, patch_cache_control
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.http import require_POST
import random
from decimal import Decimal
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.views.decorators.cache import never_cache
from django.contrib.auth import login
from django.core.mail import send_mail
from .forms import CustomUserCreationForm
from adminside.models import UserProfile, Coupon
from django.contrib.auth.models import User
import uuid
from datetime import datetime, timedelta
import json
from django.views.decorators.csrf import csrf_exempt

# ===========================# App Imports# ===========================
from .forms import CustomUserCreationForm, EditProfileForm, ChangePasswordForm
from .models import EmailOTP, CustomUser
from adminside.models import Product, Category, Order, Address, CartItem, Wishlist, OrderItem
from .models import FeaturedSection
from .utils import send_otp_email # Moved from inside edit_profile function

# ===========================# Utility Functions# ===========================
import json
import random
import logging
import uuid
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.db import IntegrityError, transaction
from adminside.models import UserProfile,ReferralCoupon
from .models import  EmailOTP
from .forms import CustomUserCreationForm
from datetime import date, timedelta

logger = logging.getLogger(__name__)

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_referral_code():
    return str(uuid.uuid4())[:8].upper()

@never_cache
@csrf_exempt
def register(request):
    # Clear all cached messages at the start
    storage = messages.get_messages(request)
    storage.used = True

    if request.user.is_authenticated:
        return redirect('userside:home')

    if request.method == 'POST':
        if 'application/json' in request.headers.get('Content-Type', ''):
            try:
                data = json.loads(request.body)
                form_data = {
                    'first_name': data.get('first_name'),
                    'last_name': data.get('last_name', ''),
                    'email': data.get('email'),
                    'phone_number': data.get('phone_number'),
                    'password1': data.get('password'),
                    'password2': data.get('password'),
                    'referral_code': data.get('referral_code', '')
                }
                form = CustomUserCreationForm(form_data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON data received")
                return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
        else:
            form_data = request.POST.copy()
            form_data['referral_code'] = form_data.get('referral_code', '')
            form = CustomUserCreationForm(form_data)

        if form.is_valid():
            otp = generate_otp()
            request.session['registration_data'] = {
                'email': form.cleaned_data['email'],
                'password1': form.cleaned_data['password1'],
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'phone_number': form.cleaned_data['phone_number'],
                'referral_code': form.cleaned_data.get('referral_code', '')
            }
            request.session['registration_otp'] = otp
            request.session['otp_last_sent'] = timezone.now().timestamp()
            request.session['otp_created_at'] = timezone.now().timestamp()

            try:
                send_mail(
                    'Your OTP Code',
                    f'Your OTP is {otp}',
                    'from@example.com',
                    [form.cleaned_data['email']],
                    fail_silently=False,
                )
                logger.info(f"OTP sent to {form.cleaned_data['email']}: {otp}")
                if 'application/json' in request.headers.get('Content-Type', ''):
                    response = {
                        'success': True,
                        'message': 'An OTP has been sent to your email. Please verify to complete registration.',
                        'redirect_url': '/verify_otp/'
                    }
                    logger.debug(f"Sending JsonResponse: {response}")
                    return JsonResponse(response)
                messages.success(request, 'An OTP has been sent to your email. Please verify to complete registration.')
                return redirect('userside:verify_otp')
            except Exception as e:
                logger.error(f"Failed to send OTP: {str(e)}")
                if 'application/json' in request.headers.get('Content-Type', ''):
                    return JsonResponse({'success': False, 'message': f'Failed to send OTP: {str(e)}'}, status=500)
                messages.error(request, f'Failed to send OTP: {str(e)}')
                request.session.pop('registration_data', None)
                request.session.pop('registration_otp', None)
                request.session.pop('otp_last_sent', None)
                request.session.pop('otp_created_at', None)
        else:
            if 'application/json' in request.headers.get('Content-Type', ''):
                response = {
                    'success': False,
                    'message': 'Please correct the errors.',
                    'errors': form.errors.as_json()
                }
                logger.debug(f"Sending JsonResponse with errors: {response}")
                return JsonResponse(response, status=400)
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm(initial={'referral_code': request.GET.get('referral_code', '') or request.GET.get('token', '')})

    response = render(request, 'userside/register.html', {'form': form})
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.db import transaction, IntegrityError
from django.utils import timezone
from .forms import OTPForm, ForgotPasswordForm, ResetPasswordForm
from .utils import create_otp_for_user
from .models import EmailOTP
from adminside.models import ReferralCoupon
from datetime import date, timedelta
import json
import logging

logger = logging.getLogger(__name__)
User = get_user_model()



@never_cache
@csrf_exempt
def otp_verify(request):
    purpose = request.session.get('otp_purpose', 'registration')
    is_json = 'application/json' in request.headers.get('Content-Type', '')
    now = timezone.now().timestamp()

    if request.method == 'POST':
        try:
            if is_json:
                data = json.loads(request.body)
                input_otp = data.get('otp')
                resend_otp = data.get('resend_otp') == '1'
            else:
                form = OTPVerificationForm(request.POST)
                if not form.is_valid():
                    error_message = 'Invalid OTP format: ' + '; '.join([f"{field}: {', '.join(errors)}" for field, errors in form.errors.items()])
                    logger.warning(f"Form validation failed: {error_message}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': error_message}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:verify_otp')
                input_otp = form.cleaned_data['otp']
                resend_otp = 'resend_otp' in request.POST
        except json.JSONDecodeError:
            logger.error("Invalid JSON data received")
            if is_json:
                return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
            messages.error(request, 'Invalid JSON data')
            return redirect('userside:verify_otp')

        # Handle OTP resend
        if resend_otp:
            last_sent = request.session.get('otp_last_sent')
            if last_sent and now - last_sent < 60:
                wait = int(60 - (now - last_sent))
                logger.info(f"Resend OTP blocked: Wait {wait} seconds")
                if is_json:
                    return JsonResponse({'success': False, 'message': f'Please wait {wait} seconds before resending OTP.'}, status=400)
                messages.error(request, f'Please wait {wait} seconds before resending OTP.')
                return redirect('userside:verify_otp')

            if purpose == 'registration':
                registration_data = request.session.get('registration_data')
                if not registration_data:
                    logger.warning("Session expired: No registration data found")
                    if is_json:
                        return JsonResponse({'success': False, 'message': 'Session expired. Please register again.'}, status=400)
                    messages.error(request, 'Session expired. Please register again.')
                    return redirect('userside:register')

                new_otp = generate_otp()
                request.session['registration_otp'] = new_otp
                request.session['otp_last_sent'] = now
                request.session['otp_created_at'] = now

                try:
                    send_mail(
                        'Your OTP Code',
                        f'Your new OTP is {new_otp}. It is valid for 5 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [registration_data['email']],
                        fail_silently=False,
                    )
                    logger.info(f"OTP sent to {registration_data['email']}: {new_otp}")
                    if is_json:
                        return JsonResponse({'success': True, 'message': 'A new OTP has been sent to your email.'})
                    messages.success(request, 'A new OTP has been sent to your email.')
                    return redirect('userside:verify_otp')
                except Exception as e:
                    logger.error(f"Failed to send OTP to {registration_data['email']}: {str(e)}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': f'Failed to send OTP: {str(e)}'}, status=500)
                    messages.error(request, f'Failed to send OTP: {str(e)}')
                    return redirect('userside:verify_otp')

            else:  # password_reset
                email = request.session.get('reset_email')
                if not email:
                    logger.warning("Session expired: No reset email found")
                    if is_json:
                        return JsonResponse({'success': False, 'message': 'Session expired. Please start over.'}, status=400)
                    messages.error(request, 'Session expired. Please start over.')
                    return redirect('userside:forgot_password')

                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    logger.warning(f"No user found for email: {email}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': 'No account found with this email.'}, status=400)
                    messages.error(request, 'No account found with this email.')
                    return redirect('userside:forgot_password')

                create_otp_for_user(user, purpose='password_reset')
                request.session['otp_last_sent'] = now
                logger.info(f"OTP sent to {user.email} for password reset")
                if is_json:
                    return JsonResponse({'success': True, 'message': 'A new OTP has been sent to your email.'})
                messages.success(request, 'A new OTP has been sent to your email.')
                return redirect('userside:verify_otp')

        # Handle OTP verification
        if purpose == 'registration':
            registration_data = request.session.get('registration_data')
            if not registration_data:
                logger.warning("Session expired: No registration data found")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'Session expired. Please register again.'}, status=400)
                messages.error(request, 'Session expired. Please register again.')
                return redirect('userside:register')

            session_otp = request.session.get('registration_otp')
            otp_created_at = request.session.get('otp_created_at')

            if not session_otp:
                logger.warning("Session expired: Missing registration OTP")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'Session expired. Please register again.'}, status=400)
                messages.error(request, 'Session expired. Please register again.')
                return redirect('userside:register')

            if otp_created_at and (now - otp_created_at) > 300:  # 5 minutes
                logger.warning("OTP expired for registration")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'OTP has expired. Please resend.'}, status=400)
                messages.error(request, 'OTP has expired. Please resend.')
                return redirect('userside:verify_otp')

            if input_otp and input_otp.strip() == session_otp.strip():
                try:
                    with transaction.atomic():
                        user = User.objects.create_user(
                            email=registration_data['email'],
                            password=registration_data['password1'],
                            first_name=registration_data['first_name'],
                            last_name=registration_data['last_name'],
                            phone_number=registration_data['phone_number'],
                            referral_code=generate_referral_code()
                        )
                        if registration_data.get('referral_code'):
                            referral_code = registration_data['referral_code'].upper()
                            try:
                                referrer = User.objects.get(referral_code__iexact=referral_code)
                                if ReferralCoupon.objects.filter(owner=referrer).count() < 10:
                                    user.referred_by = referrer
                                    coupon = ReferralCoupon.objects.create(
                                        owner=referrer,
                                        discount_percentage=5.00,
                                        valid_from=date.today(),
                                        valid_until=date.today() + timedelta(days=30)
                                    )
                                    try:
                                        send_mail(
                                            'You Earned a Referral Coupon!',
                                            f'Your referral code was used by {user.email}. You’ve received a 5% discount coupon (Code: {coupon.code}) valid until {coupon.valid_until}.',
                                            settings.DEFAULT_FROM_EMAIL,
                                            [referrer.email],
                                            fail_silently=True,
                                        )
                                        logger.info(f"Referral coupon notification sent to {referrer.email}")
                                    except Exception as e:
                                        logger.error(f"Failed to send referral notification to {referrer.email}: {str(e)}")
                            except User.DoesNotExist:
                                logger.warning(f"Invalid referral code {referral_code}")
                                pass

                        UserProfile.objects.get_or_create(
                            user=user,
                            defaults={'mobile': registration_data['phone_number'], 'status': 'active'}
                        )
                        logger.info(f"User created: {user.email}")

                        request.session.pop('registration_data', None)
                        request.session.pop('registration_otp', None)
                        request.session.pop('otp_last_sent', None)
                        request.session.pop('otp_purpose', None)
                        request.session.pop('otp_created_at', None)

                        if is_json:
                            return JsonResponse({
                                'success': True,
                                'message': 'Registration complete! Please log in.',
                                'redirect_url': reverse('userside:login')
                            })
                        messages.success(request, 'Registration complete! Please log in.')
                        return redirect('userside:login')
                except Exception as e:
                    logger.error(f"Error creating user for {registration_data['email']}: {str(e)}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': f'Error creating user: {str(e)}'}, status=500)
                    messages.error(request, f'Error creating user: {str(e)}')
                    return redirect('userside:verify_otp')
            else:
                logger.warning(f"Invalid OTP entered for registration: {input_otp}")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'Invalid OTP. Please try again.'}, status=400)
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('userside:verify_otp')
        else:  # password_reset
            email = request.session.get('reset_email')
            if not email:
                logger.warning("Session expired: No reset email found")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'Session expired. Please start over.'}, status=400)
                messages.error(request, 'Session expired. Please start over.')
                return redirect('userside:forgot_password')

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                logger.warning(f"No user found for email: {email}")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'No account found with this email.'}, status=400)
                messages.error(request, 'No account found with this email.')
                return redirect('userside:forgot_password')

            try:
                email_otp = EmailOTP.objects.get(user=user, otp=input_otp, purpose=purpose)
                if not email_otp.is_valid():
                    logger.warning(f"OTP expired for {user.email}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': 'OTP has expired. Please resend.'}, status=400)
                    messages.error(request, 'OTP has expired. Please resend.')
                    return redirect('userside:verify_otp')

                request.session['otp_verified'] = True
                EmailOTP.objects.filter(user=user, purpose='password_reset').delete()
                if is_json:
                    return JsonResponse({
                        'success': True,
                        'message': 'OTP verified successfully.',
                        'redirect_url': reverse('userside:reset_password')
                    })
                messages.success(request, 'OTP verified successfully.')
                return redirect('userside:reset_password')
            except EmailOTP.DoesNotExist:
                logger.warning(f"Invalid OTP entered for {user.email}: {input_otp}")
                if is_json:
                    return JsonResponse({'success': False, 'message': 'Invalid OTP. Please try again.'}, status=400)
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('userside:verify_otp')
            except Exception as e:
                logger.error(f"Unexpected error in OTP verification for {user.email}: {str(e)}")
                if is_json:
                    return JsonResponse({'success': False, 'message': f'An unexpected error occurred: {str(e)}'}, status=500)
                messages.error(request, f'An unexpected error occurred: {str(e)}')
                return redirect('userside:verify_otp')

    context = {'purpose': purpose}
    last_sent = request.session.get('otp_last_sent')
    if last_sent:
        context['remaining_time'] = max(0, int(60 - (timezone.now().timestamp() - last_sent)))
    return render(request, 'userside/otp_verify.html', context)

@never_cache
@csrf_exempt
def forgot_password(request):
    is_json = 'application/json' in request.headers.get('Content-Type', '')
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST or json.loads(request.body) if is_json else None)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                if not user.is_active:
                    error_message = 'This account is blocked or inactive.'
                    logger.warning(f"Inactive user attempted password reset: {email}")
                    if is_json:
                        return JsonResponse({'success': False, 'message': error_message}, status=400)
                    messages.error(request, error_message)
                    return render(request, 'userside/forgot_password.html', {'form': form})
                logger.info(f"Creating OTP for user: {email}")
                create_otp_for_user(user, purpose='password_reset')
                request.session['reset_email'] = email
                request.session['otp_purpose'] = 'password_reset'
                request.session['otp_last_sent'] = timezone.now().timestamp()
                success_message = 'An OTP has been sent to your email.'
                logger.info(f"OTP sent to {email} for password reset")
                if is_json:
                    return JsonResponse({
                        'success': True,
                        'message': success_message,
                        'redirect_url': reverse('userside:verify_otp')
                    })
                messages.success(request, success_message)
                return redirect('userside:verify_otp')
            except User.DoesNotExist:
                error_message = 'No account found with this email.'
                logger.warning(f"No user found for email: {email}")
                if is_json:
                    return JsonResponse({'success': False, 'message': error_message}, status=400)
                messages.error(request, error_message)
            except Exception as e:
                logger.error(f"Error in forgot_password: {str(e)}")
                error_message = 'An error occurred. Please try again.'
                if is_json:
                    return JsonResponse({'success': False, 'message': error_message}, status=500)
                messages.error(request, error_message)
        else:
            error_message = 'Invalid email format.'
            logger.warning(f"Invalid form submission: {form.errors}")
            if is_json:
                return JsonResponse({'success': False, 'message': error_message}, status=400)
            messages.error(request, error_message)
    else:
        form = ForgotPasswordForm()
    return render(request, 'userside/forgot_password.html', {'form': form})

from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.contrib.auth import get_user_model
from django.urls import reverse
from .forms import ResetPasswordForm
import json
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

@never_cache
@csrf_exempt
def reset_password(request):
    if 'reset_email' not in request.session or 'otp_verified' not in request.session:
        error_message = 'Invalid or expired session. Please start over.'
        logger.warning('Reset password attempted without valid session.')
        if 'application/json' in request.headers.get('Content-Type', ''):
            return JsonResponse({'success': False, 'message': error_message}, status=400)
        messages.error(request, error_message)
        return redirect('userside:forgot_password')

    email = request.session['reset_email']
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        error_message = 'No account found with this email.'
        logger.warning(f"No user found for email: {email}")
        if 'application/json' in request.headers.get('Content-Type', ''):
            return JsonResponse({'success': False, 'message': error_message}, status=400)
        messages.error(request, error_message)
        return redirect('userside:forgot_password')

    is_json = 'application/json' in request.headers.get('Content-Type', '')
    if request.method == 'POST':
        form = ResetPasswordForm(user, request.POST or json.loads(request.body) if is_json else None)
        if form.is_valid():
            try:
                form.save()
                request.session.pop('reset_email', None)
                request.session.pop('otp_verified', None)
                request.session.pop('otp_purpose', None)
                request.session.pop('otp_last_sent', None)
                success_message = 'Your password has been reset successfully.'
                logger.info(f"Password reset successful for user: {email}")
                if is_json:
                    return JsonResponse({
                        'success': True,
                        'message': success_message,
                        'redirect_url': reverse('userside:login')
                    })
                messages.success(request, success_message)
                return redirect('userside:login')
            except Exception as e:
                logger.error(f"Error saving new password for {email}: {str(e)}")
                error_message = 'An error occurred while saving the password. Please try again.'
                if is_json:
                    return JsonResponse({'success': False, 'message': error_message}, status=500)
                messages.error(request, error_message)
        else:
            error_message = 'Invalid password format: ' + '; '.join([f"{field}: {', '.join(errors)}" for field, errors in form.errors.items()])
            logger.warning(f"Form validation failed for {email}: {form.errors}")
            if is_json:
                return JsonResponse({'success': False, 'message': error_message}, status=400)
            messages.error(request, error_message)
    else:
        form = ResetPasswordForm(user)
    return render(request, 'userside/reset_password.html', {'form': form})
@never_cache
@csrf_exempt
def validate_referral_code(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            referral_code = data.get('referral_code', '').strip().upper()
            valid = CustomUser.objects.filter(referral_code__iexact=referral_code).exists()
            return JsonResponse({'valid': valid})
        except json.JSONDecodeError:
            return JsonResponse({'valid': False, 'message': 'Invalid data'}, status=400)
    return JsonResponse({'valid': False, 'message': 'Invalid request'}, status=400)

# ===========================# Authentication Views# ===========================
@never_cache
def user_login(request):
    if request.user.is_authenticated:
        return redirect('userside:home')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                if hasattr(user, 'status') and user.status == 'blocked':
                    messages.error(request, 'Your account has been blocked.')
                    return redirect('userside:login')
                login(request, user)
                messages.success(request, 'Login successful!')
                return redirect('userside:home')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid login credentials.')
    else:
        form = AuthenticationForm()
    response = render(request, 'userside/login.html', {'form': form})
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

from django.contrib.auth import logout
from django.views.decorators.cache import never_cache
from django.shortcuts import redirect
from django.http import HttpResponse

@never_cache
def logout_view(request):
    request.session.flush()
    logout(request)
    response = redirect('userside:landing_page')
    # Set cache-control headers to prevent caching
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

def login_redirect(request):
    if request.user.is_authenticated:
        return redirect('userside:landing_page')
    else:
        return redirect('userside:login')

# ===========================# Landing Page and Category Views# ===========================
from django.views.decorators.cache import cache_control
@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def landing_page(request):
    # Redirect admin users away from user landing page
    if request.user.is_superuser:
        return redirect('adminside:sales_report')
    categories = Category.objects.filter(is_listed=True).order_by('name')
    hero_sections = FeaturedSection.objects.filter(
        is_active=True,
        section_type__in=['hero', 'featured']
    ).order_by('display_order')
    context = {
        'categories': categories,
        'hero_sections': hero_sections,
        'user': request.user,
    }
    response = render(request, 'userside/landing_page.html', context)
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True, max_age=0)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

def category_redirect(request, category_name):
    try:
        category = Category.objects.get(name__iexact=category_name, is_listed=True)
        return redirect(f"/products/?category={category.name.lower()}")
    except Category.DoesNotExist:
        messages.error(request, f"Category '{category_name}' not found.")
        return redirect('userside:landing_page')

def category_products(request, category_id):
    category = get_object_or_404(Category, id=category_id, is_listed=True)
    products = Product.objects.filter(
        category=category,
        is_active=True,
        is_listed=True,
        category__is_listed=True
    )
    context = {
        'category': category,
        'products': products,
    }
    return render(request, 'userside/category_products.html', context)

# ===========================# Product Views# ===========================
from adminside.models import Product, Category, ProductOffer, CategoryOffer
@never_cache
def product_list(request):
    products = Product.objects.filter(
        is_listed=True,
        is_deleted=False,
        is_active=True,
        category__is_listed=True,
        category__is_deleted=False,
    ).prefetch_related('product_images')

    categories = Category.objects.filter(is_listed=True, is_deleted=False)
    search_query = request.GET.get('search', '').strip()
    
    if search_query:
        products = products.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(category__name__icontains=search_query)
        )

    category_filter = request.GET.get('category', '').strip()
    if category_filter and category_filter != 'all':
        products = products.filter(category__name__iexact=category_filter)

    sort_by = request.GET.get('sort', 'name_asc')
    sort_mapping = {
        'name_asc': 'name',
        'name_desc': '-name',
        'price_asc': 'price',
        'price_desc': '-price',
    }
    products = products.order_by(sort_mapping.get(sort_by, 'name'))

    # Calculate offer percentage for each product
    product_list_with_offers = []
    for product in products:
        offer_percentage = None
        # Check for ProductOffer
        product_offer = ProductOffer.objects.filter(
            product=product,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        # Check for CategoryOffer
        category_offer = CategoryOffer.objects.filter(
            category=product.category,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        # Determine the highest discount
        product_discount = Decimal('0')
        category_discount = Decimal('0')

        if product_offer:
            product_discount = Decimal(product_offer.discount_percentage)
        
        if category_offer:
            category_discount = Decimal(category_offer.discount_percentage)

        # Use the higher discount
        if product_discount or category_discount:
            offer_percentage = max(product_discount, category_discount)

        product_list_with_offers.append({
            'product': product,
            'offer_percentage': offer_percentage
        })

    # Pagination
    page_number = request.GET.get('page', 1)
    paginator = Paginator(product_list_with_offers, 8)
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'products': [item['product'] for item in page_obj.object_list],
        'categories': categories,
        'search_query': search_query,
        'selected_category': category_filter,
        'selected_sort': sort_by,
        'total_products': paginator.count,
        'has_filters': bool(search_query or (category_filter and category_filter != 'all')),
        'products_with_offers': page_obj.object_list,  # Pass the list with offer percentages
    }

    response = render(request, 'userside/product_list.html', context)
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.db.models import Avg, Sum
from collections import defaultdict
from adminside.models import Product, ColorVariant, Size, ProductVariant, Wishlist, ProductOffer, CategoryOffer
import logging
from datetime import date
from decimal import Decimal
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
import traceback
from django.views.decorators.cache import cache_control

logger = logging.getLogger(__name__)

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def product_detail_view(request, id):
    product = get_object_or_404(Product, id=id, is_deleted=False)
    
    logger.info("Product: %s, is_listed=%s, is_active=%s, category.is_listed=%s",
                product.name, product.is_listed, product.is_active, product.category.is_listed)

    color_variants = product.color_variants.filter(
        is_listed=True,
        variants__is_listed=True
    ).distinct()
    sizes = product.variants.filter(is_listed=True).values_list('size__name', flat=True).distinct()
    variants = product.variants.filter(is_listed=True)

    original_price = product.price
    discounted_price = original_price
    discount = None
    offer = None
    offer_type = None

    product_offer = ProductOffer.objects.filter(
        product=product,
        is_active=True,
        is_deleted=False,
        start_date__lte=date.today(),
        end_date__gte=date.today()
    ).first()

    category_offer = CategoryOffer.objects.filter(
        category=product.category,
        is_active=True,
        is_deleted=False,
        start_date__lte=date.today(),
        end_date__gte=date.today()
    ).first()

    product_discount = Decimal(product_offer.discount_percentage) if product_offer else Decimal('0')
    category_discount = Decimal(category_offer.discount_percentage) if category_offer else Decimal('0')

    if product_discount > 0 or category_discount > 0:
        if product_discount >= category_discount:
            discount = original_price * (product_discount / Decimal('100'))
            offer = product_offer
            offer_type = 'Product Offer'
        else:
            discount = original_price * (category_discount / Decimal('100'))
            offer = category_offer
            offer_type = 'Category Offer'
        discounted_price = original_price - discount

    # Fetch related products (same category only)
    related_products = Product.objects.filter(
        category=product.category,
        is_listed=True,
        is_active=True,
        is_deleted=False
    ).exclude(id=product.id).select_related('category').prefetch_related('product_images')[:4]

    # Calculate discounts for related products
    for related_product in related_products:
        related_product.original_price = related_product.price
        related_product.discounted_price = related_product.price
        related_product.discount = Decimal('0')
        related_product.offer_discount_percentage = Decimal('0')

        product_offer = ProductOffer.objects.filter(
            product=related_product,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        category_offer = CategoryOffer.objects.filter(
            category=related_product.category,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        product_discount = Decimal(product_offer.discount_percentage) if product_offer else Decimal('0')
        category_discount = Decimal(category_offer.discount_percentage) if category_offer else Decimal('0')

        if product_discount > 0 or category_discount > 0:
            if product_discount >= category_discount:
                related_product.discount = related_product.price * (product_discount / Decimal('100'))
                related_product.offer_discount_percentage = product_discount
            else:
                related_product.discount = related_product.price * (category_discount / Decimal('100'))
                related_product.offer_discount_percentage = category_discount
            related_product.discounted_price = related_product.price - related_product.discount

    is_in_wishlist = False
    if request.user.is_authenticated:
        is_in_wishlist = Wishlist.objects.filter(user=request.user, product=product).exists()

    context = {
        'product': product,
        'color_variants': color_variants,
        'sizes': sizes,
        'variants': variants,
        'related_products': related_products,
        'reviews': product.reviews.all(),
        'avg_rating': product.reviews.aggregate(avg=Avg('rating'))['avg'] or 0.0,
        'discount': discount,
        'original_price': original_price,
        'discounted_price': discounted_price,
        'offer': offer,
        'offer_type': offer_type,
        'is_in_wishlist': is_in_wishlist,
        'product_unlisted': not product.is_listed,
        'category_unlisted': not product.category.is_listed,
    }
    return render(request, 'userside/product_detail.html', context)
def clear_filters(request):
    return redirect('userside:product_list')

# ===========================# User Profile and Address Management# ===========================
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.messages import get_messages
from adminside.models import Order, Address
from django.contrib.auth import get_user_model
import random

@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def user_profile(request):
    user = request.user
    orders = Order.objects.filter(user=user).order_by('-created_at')
    user_addresses = Address.objects.filter(user=user)
    
    # Count users where this user is the referrer
    User = get_user_model()
    referred_count = User.objects.filter(referred_by=user).count()

    # Clear existing messages to prevent stacking
    storage = get_messages(request)
    for message in storage:
        pass  # Iterate to mark messages as used
    storage.used = True

    context = {
        'user': user,
        'orders': orders,
        'addresses': user_addresses,
        'referred_count': referred_count,
    }
    return render(request, 'userside/profile.html', context)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from adminside.models import Address
import logging

logger = logging.getLogger(__name__)
@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def my_addresses(request):
    try:
        addresses = Address.objects.filter(user=request.user)
        return render(request, 'userside/my_addresses.html', {'addresses': addresses})
    except Exception as e:
        logger.error(f"Error in my_addresses: {str(e)}")
        messages.error(request, "An error occurred while fetching addresses.", extra_tags='error')
        return render(request, 'userside/my_addresses.html', {'addresses': []})

@login_required(login_url='login')
def save_address(request):
    if request.method == 'POST':
        try:
            address_id = request.POST.get('address_id')
            full_name = request.POST.get('full_name')
            phone = request.POST.get('phone')
            address_line1 = request.POST.get('address_line1')
            address_line2 = request.POST.get('address_line2', '')
            city = request.POST.get('city')
            state = request.POST.get('state')
            postal_code = request.POST.get('postal_code')
            country = request.POST.get('country')

            # Validate required fields to prevent empty submissions
            if not all([full_name, phone, address_line1, city, state, postal_code, country]):
                messages.error(request, 'All required fields must be filled.', extra_tags='error')
                context = {
                    'addresses': Address.objects.filter(user=request.user),
                    'form_data': {
                        'address_id': address_id,
                        'full_name': full_name,
                        'phone': phone,
                        'address_line1': address_line1,
                        'address_line2': address_line2,
                        'city': city,
                        'state': state,
                        'postal_code': postal_code,
                        'country': country,
                    },
                    'modal_title': 'Edit Address' if address_id else 'Add New Address'
                }
                return render(request, 'userside/my_addresses.html', context)

            # Check for duplicate address (excluding the current address if editing)
            query = Address.objects.filter(
                user=request.user,
                address_line1=address_line1,
                city=city,
                state=state,
                postal_code=postal_code
            )
            if address_id and address_id.isdigit():  # Only exclude if address_id is a valid integer
                query = query.exclude(id=int(address_id))

            if query.exists():
                messages.error(request, 'An address with these details already exists.', extra_tags='duplicate')
                context = {
                    'addresses': Address.objects.filter(user=request.user),
                    'form_data': {
                        'address_id': address_id,
                        'full_name': full_name,
                        'phone': phone,
                        'address_line1': address_line1,
                        'address_line2': address_line2,
                        'city': city,
                        'state': state,
                        'postal_code': postal_code,
                        'country': country,
                    },
                    'modal_title': 'Edit Address' if address_id else 'Add New Address'
                }
                return render(request, 'userside/my_addresses.html', context)

            if address_id and address_id.isdigit():
                address = get_object_or_404(Address, id=int(address_id), user=request.user)
                messages.success(request, 'Address updated successfully.', extra_tags='updated')
            else:
                address = Address(user=request.user)
                messages.success(request, 'Address added successfully.', extra_tags='added')

            address.full_name = full_name
            address.phone = phone
            address.address_line1 = address_line1
            address.address_line2 = address_line2
            address.city = city
            address.state = state
            address.postal_code = postal_code
            address.country = country
            address.save()
            return redirect('userside:my_addresses')
        except Exception as e:
            logger.error(f"Error in save_address: {str(e)}")
            messages.error(request, 'An error occurred while saving the address.', extra_tags='error')
            return redirect('userside:my_addresses')
    return redirect('userside:my_addresses')

@login_required(login_url='login')
def delete_address(request, address_id):
    try:
        address = get_object_or_404(Address, id=address_id, user=request.user)
        address.delete()
        messages.success(request, 'Address deleted successfully.', extra_tags='deleted')
        return redirect('userside:my_addresses')
    except Exception as e:
        logger.error(f"Error in delete_address: {str(e)}")
        messages.error(request, 'An error occurred while deleting the address.', extra_tags='error')
        return redirect('userside:my_addresses')

@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_profile(request):
    User = get_user_model()
    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            new_email = form.cleaned_data.get('email')
            old_email = User.objects.get(pk=request.user.pk).email
            updated_user = form.save(commit=False)
            
            # Handle profile image removal
            if request.POST.get('remove_image') == 'true':
                updated_user.profile_image = None
            
            # Handle email change and OTP verification
            if new_email != old_email:
                otp = str(random.randint(100000, 999999))
                updated_user.otp = otp
                updated_user.temp_email = new_email
                updated_user.email_verified = False
                send_otp_email(new_email, otp)
                updated_user.save()
                messages.info(request, "Please verify your new email via OTP.")
                return redirect('userside:verify_email')
            
            updated_user.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('userside:user_profile')
    else:
        form = EditProfileForm(instance=request.user)
    return render(request, 'userside/edit_profile.html', {'form': form})


@login_required(login_url='login')
def verify_email_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        if otp and request.user.otp == otp:
            request.user.email = request.user.temp_email # Apply new email
            request.user.temp_email = ''
            request.user.otp = ''
            request.user.email_verified = True
            request.user.save()
            messages.success(request, 'Email verified and updated successfully.')
            return redirect('userside:user_profile')
        else:
            messages.error(request, 'Invalid OTP.')
    return render(request, 'userside/verify_email.html')


@login_required(login_url='/login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def change_password(request):
    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Password changed successfully.')
            return redirect('userside:user_profile')
    else:
        form = ChangePasswordForm(request.user)
    return render(request, 'userside/change_password.html', {'form': form})

# ===========================# Order Views# ===========================
@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def order_list(request):
    query = request.GET.get('search', '')
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    if query:
        orders = orders.filter(order_id__icontains=query)
    
    # Pagination: 5 orders per page
    paginator = Paginator(orders, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'userside/order_list.html', {'orders': page_obj})

import logging
from django.shortcuts import render, get_object_or_404, redirect, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse
from django.db import transaction
from django.urls import reverse
from datetime import date
from decimal import Decimal
import json
from adminside.models import Coupon, Address, CartItem, ProductOffer, CategoryOffer, Order, OrderItem, ReferralCoupon, Wallet, Transaction, ProductVariant

logger = logging.getLogger(__name__)

@login_required(login_url='userside:login')
@require_POST

def cancel_order_item(request, item_id):
    try:
        item = get_object_or_404(
            OrderItem,
            id=item_id,
            order__user=request.user,
            is_cancelled=False,
            is_refunded_to_wallet=False
        )
    except Exception as e:
        logger.error(f"Error fetching OrderItem {item_id}: {str(e)}", exc_info=True)
        messages.error(request, "Item not found or already cancelled/refunded.")
        return redirect('userside:order_list')

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, "Please provide a reason for cancellation.")
        return redirect('userside:order_detail', order_id=item.order.order_id)

    try:
        with transaction.atomic():
            item.is_cancelled = True
            item.cancel_reason = reason
            item.save()

            # Restore stock if variant exists
            if item.variant:
                item.variant.stock += item.quantity
                item.variant.save()
                logger.info(f"Stock restored: {item.quantity} for variant {item.variant.id} of product {item.product.name}")
            else:
                logger.warning(f"OrderItem {item.id} has no associated ProductVariant.")

            # Calculate base refund amount (before discount adjustment)
            base_refund_amount = (item.discounted_price or item.price or Decimal('0')) * item.quantity
            if base_refund_amount <= 0:
                logger.error(f"Invalid refund amount ₹{base_refund_amount} for OrderItem {item.id}: discounted_price={item.discounted_price}, price={item.price}")
                messages.error(request, "Error processing refund: Invalid amount.")
                return redirect('userside:order_detail', order_id=item.order.order_id)

            # Handle coupon and referral discounts
            refund_amount = base_refund_amount
            order = item.order
            unique_products_count = order.items.values('product__id').distinct().count()

            if unique_products_count == 0:
                logger.error(f"No unique products found in order {order.order_id} for refund calculation.")
                messages.error(request, "Error: No items in the order.")
                return redirect('userside:order_detail', order_id=order.order_id)

            coupon_discount = order.coupon_discount or Decimal('0.00')
            referral_discount = order.referral_coupon_discount or Decimal('0.00')
            coupon_discount_per_product = (coupon_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')
            referral_discount_per_product = (referral_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')
            total_discount_per_product = coupon_discount_per_product + referral_discount_per_product
            refund_amount = max(refund_amount - total_discount_per_product, Decimal('0.00')).quantize(Decimal('0.01'))

            logger.info(f"Order {order.order_id}: Unique products={unique_products_count}, Coupon discount=₹{coupon_discount:.2f}, Referral discount=₹{referral_discount:.2f}")
            logger.info(f"Item {item.id}: Coupon discount per product=₹{coupon_discount_per_product:.2f}, Referral discount per product=₹{referral_discount_per_product:.2f}, Total discount per product=₹{total_discount_per_product:.2f}")
            logger.info(f"Item {item.id}: Base refund amount=₹{base_refund_amount:.2f}, Adjusted refund amount=₹{refund_amount:.2f}")

            # Process refund if applicable
            if refund_amount > 0 and (order.is_paid or order.payment_method != 'COD'):
                wallet = get_object_or_404(Wallet, user=request.user)
                try:
                    wallet.credit(refund_amount)
                    Transaction.objects.create(
                        wallet=wallet,
                        transaction_type='REFUND',
                        amount=refund_amount,
                        description=f"Refund for cancelled item '{item.product.name}' in order {order.order_id}",
                        source_order=order
                    )
                    item.is_refunded_to_wallet = True
                    item.refund_amount = refund_amount  # Store refund amount for consistency
                    item.save()
                    logger.info(f"Refunded ₹{refund_amount:.2f} to wallet for item {item.id}.")
                    messages.success(request, f"₹{refund_amount:.2f} refunded to your wallet.")
                except Exception as e:
                    logger.error(f"Failed to process refund for item {item.id}: {str(e)}", exc_info=True)
                    raise  # Re-raise to trigger rollback
            else:
                messages.info(request, "No refund issued (COD, zero amount, or fully discounted).")

            # Check if all items in the order are cancelled
            if all(i.is_cancelled for i in order.items.all()):
                order.status = 'cancelled'
                order.reason = reason
                order.save()
                logger.info(f"Order {order.order_id} fully cancelled.")
                messages.success(request, f"Order {order.order_id} fully cancelled.")

            messages.success(request, f"Item '{item.product.name}' cancelled successfully.")

    except Exception as e:
        logger.error(f"Error cancelling item {item.id}: {str(e)}", exc_info=True)
        messages.error(request, f"Failed to cancel item: {str(e)}")
        return redirect('userside:order_detail', order_id=item.order.order_id)

    return redirect('userside:order_detail', order_id=item.order.order_id)

@login_required(login_url='userside:login')
@require_POST
def cancel_entire_order(request, order_id):
    try:
        order = get_object_or_404(Order, order_id=order_id, user=request.user)
    except Exception as e:
        logger.error(f"Error fetching Order {order_id}: {str(e)}", exc_info=True)
        messages.error(request, "Order not found.")
        return redirect('userside:order_list')

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, "Please provide a reason for cancellation.")
        return redirect('userside:order_detail', order_id=order.order_id)

    if order.status == 'cancelled':
        messages.warning(request, "Order already cancelled.")
        return redirect('userside:order_list')

    try:
        with transaction.atomic():
            # Calculate previously refunded amount
            previously_refunded = sum(item.total for item in order.items.filter(is_refunded_to_wallet=True))

            # Calculate total discount (coupon + referral coupon)
            total_discount = (order.coupon_discount or Decimal('0.00')) + (order.referral_coupon_discount or Decimal('0.00'))

            # Identify unique products (group by product, variant, color_name, size)
            unique_products = {}
            for item in order.items.all():
                # Define a key for uniqueness (product, variant, color_name, size)
                product_key = (item.product_id, item.variant_id, item.color_name, item.size)
                if product_key not in unique_products:
                    unique_products[product_key] = {
                        'items': [item],
                        'total_price': item.total,
                        'quantity': item.quantity
                    }
                else:
                    unique_products[product_key]['items'].append(item)
                    unique_products[product_key]['total_price'] += item.total
                    unique_products[product_key]['quantity'] += item.quantity

            # Number of scant products
            num_unique_products = len(unique_products)
            if num_unique_products > 0:
                discount_per_product = total_discount / num_unique_products
            else:
                discount_per_product = Decimal('0.00')

            # Calculate refund amount for non-cancelled items
            refund_amount = Decimal('0.00')
            for product_key, product_data in unique_products.items():
                # Only process if at least one item is not cancelled
                if any(not item.is_cancelled for item in product_data['items']):
                    # Calculate refund for the product (total price minus its discount share)
                    product_refund = max(product_data['total_price'] - discount_per_product, Decimal('0.00'))
                    # Distribute refund proportionally among non-cancelled items of this product
                    non_cancelled_items = [item for item in product_data['items'] if not item.is_cancelled]
                    if non_cancelled_items:
                        total_quantity = sum(item.quantity for item in non_cancelled_items)
                        if total_quantity > 0:
                            for item in non_cancelled_items:
                                # Proportion of refund based on item quantity
                                item_refund = (product_refund * item.quantity) / product_data['quantity']
                                refund_amount += item_refund
                                item.refund_amount = item_refund
                                item.save()

            # Ensure refund doesn't exceed order total minus previously refunded
            refund_amount = max(refund_amount, Decimal('0.00'))

            # Update order status
            order.status = 'cancelled'
            order.reason = reason
            order.save()

            # Update items
            for item in order.items.filter(is_cancelled=False):
                item.is_cancelled = True
                item.cancel_reason = reason
                item.save()

                if item.variant:
                    item.variant.stock += item.quantity
                    item.variant.save()
                    logger.info(f"Stock restored for item {item.id}.")
                else:
                    logger.warning(f"OrderItem {item.id} has no associated ProductVariant.")

            # Process refund if applicable
            if refund_amount > 0 and (order.is_paid or order.payment_method != 'COD'):
                wallet = get_object_or_404(Wallet, user=request.user)
                try:
                    wallet.credit(refund_amount)
                    Transaction.objects.create(
                        wallet=wallet,
                        transaction_type='REFUND',
                        amount=refund_amount,
                        description=f"Refund for cancelled order {order.order_id}",
                        source_order=order
                    )
                    order.items.filter(is_refunded_to_wallet=False).update(is_refunded_to_wallet=True)
                    logger.info(f"Refunded ₹{refund_amount} for order {order.order_id}.")
                    messages.success(request, f"₹{refund_amount:.2f} refunded to your wallet.")
                except Exception as e:
                    logger.error(f"Failed to process refund for order {order.order_id}: {str(e)}", exc_info=True)
                    raise  # Re-raise to trigger rollback
            else:
                messages.info(request, "No refund issued (COD or zero amount).")

            messages.success(request, f"Order {order.order_id} cancelled successfully.")

    except Exception as e:
        logger.error(f"Error cancelling order {order.order_id}: {str(e)}", exc_info=True)
        messages.error(request, f"Failed to cancel order: {str(e)}")
        return redirect('userside:order_list')

    return redirect('userside:order_list')
# ===========================# Cart Views# ==========================

from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, render
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Avg, Sum
from collections import defaultdict
from adminside.models import Product, ColorVariant, Size, ProductVariant, Wishlist, ProductOffer, CategoryOffer
import logging
import traceback
from datetime import date
from decimal import Decimal

logger = logging.getLogger(__name__)

@csrf_protect
def add_to_cart(request, product_id):
    if request.method == 'POST':
        try:
            logger.debug("POST data received: %s", request.POST)
            user = request.user
            color_id = request.POST.get('color_id')
            size_name = request.POST.get('size')  # Removed 'sizes[]' as frontend sends 'size'
            quantity = int(request.POST.get('quantity', 1))

            if not color_id or not size_name:
                logger.error("Missing color_id or size_name: color_id=%s, size_name=%s", color_id, size_name)
                return JsonResponse({'success': False, 'message': 'Please select both color and size.'}, status=400)

            color_variant = ColorVariant.objects.get(id=color_id)
            size = Size.objects.get(name=size_name)
            variant = ProductVariant.objects.get(product_id=product_id, color_variant=color_variant, size=size)

            # Check if product, variant, or category is unlisted
            if not variant.product.is_listed or not variant.is_listed or not variant.product.category.is_listed:
                logger.warning("Unlisted item: product=%s, variant=%s, category=%s", 
                             variant.product.is_listed, variant.is_listed, variant.product.category.is_listed)
                return JsonResponse({
                    'success': False,
                    'message': 'This product or category is currently unavailable.',
                    'redirect': True,
                    'redirect_url': '/userside/product_list/'  # Fixed URL
                }, status=400)

            if quantity <= 0:
                logger.error("Invalid quantity: %s", quantity)
                return JsonResponse({'success': False, 'message': 'Quantity must be greater than 0.'}, status=400)

            if quantity > variant.stock:
                logger.error("Quantity exceeds stock: requested=%s, available=%s", quantity, variant.stock)
                return JsonResponse({
                    'success': False,
                    'message': f'Requested quantity ({quantity}) exceeds available stock ({variant.stock}).'
                }, status=400)

            cart_item, created = CartItem.objects.get_or_create(
                user=user,
                product_id=product_id,
                size=size_name,
                color_name=color_variant.color_name,
                defaults={'quantity': quantity}
            )
            if not created:
                new_quantity = cart_item.quantity + quantity
                if new_quantity > variant.stock:
                    logger.error("Cart quantity exceeds stock: requested=%s, available=%s", new_quantity, variant.stock)
                    return JsonResponse({
                        'success': False,
                        'message': f'Exceeds stock limit. Maximum available is {variant.stock}.'
                    }, status=400)
                cart_item.quantity = new_quantity
                cart_item.save()

            cart_count = CartItem.objects.filter(user=user).count()
            logger.info("Cart updated: user=%s, product_id=%s, cart_count=%s", 
                        user.email, product_id, cart_count)  # Fixed to use email
            return JsonResponse({
                'success': True,
                'message': 'Added to cart successfully.',
                'cart_count': cart_count,
                'product_name': cart_item.product.name
            })

        except ObjectDoesNotExist as e:
            logger.error("ObjectDoesNotExist error: %s", str(e))
            return JsonResponse({'success': False, 'message': f'Invalid data: {str(e)}'}, status=400)
        except ValueError as e:
            logger.error("ValueError: %s", str(e))
            return JsonResponse({'success': False, 'message': 'Invalid quantity value.'}, status=400)
        except Exception as e:
            logger.error("Unexpected error in add_to_cart: %s", str(e), exc_info=True)
            return JsonResponse({
                'success': False,
                'message': 'please login to continue.'
            }, status=500)

from django.views.decorators.cache import cache_control
@login_required(login_url='/login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def view_cart(request):
    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
    cart_items = cart_items.prefetch_related('product__variants', 'product__category')
    
    cart_items_with_stock = []
    total = Decimal('0.00')
    for item in cart_items:
        try:
            variant = item.product.variants.filter(
                color_variant__color_name=item.color_name,
                size__name=item.size
            ).first()
            # Check if product, variant, and category are listed
            is_product_listed = item.product.is_listed
            is_variant_listed = variant.is_listed if variant else False
            is_category_listed = item.product.category.is_listed
            item.stock = variant.stock if variant and is_variant_listed else 0
            item.is_product_listed = is_product_listed
            item.is_variant_listed = is_variant_listed
            item.is_category_listed = is_category_listed
            
            # Calculate original and discounted prices
            item.original_price = item.product.price
            item.discounted_price = item.original_price
            item.discount = None
            item.offer = None
            item.offer_type = None

            # Only apply offers if product, variant, and category are listed
            if is_product_listed and is_variant_listed and is_category_listed:
                # Check for ProductOffer
                product_offer = ProductOffer.objects.filter(
                    product=item.product,
                    is_active=True,
                    is_deleted=False,
                    start_date__lte=date.today(),
                    end_date__gte=date.today()
                ).first()

                # Check for CategoryOffer
                category_offer = CategoryOffer.objects.filter(
                    category=item.product.category,
                    is_active=True,
                    is_deleted=False,
                    start_date__lte=date.today(),
                    end_date__gte=date.today()
                ).first()

                # Determine the highest discount
                product_discount = None
                category_discount = None

                if product_offer:
                    product_discount = Decimal(product_offer.discount_percentage)
                    item.discount = item.original_price * (product_discount / Decimal('100'))
                    item.discounted_price = item.original_price - item.discount
                    item.offer = product_offer
                    item.offer_type = 'Product Offer'
                    logger.debug("ProductOffer found for cart item %s (product %s): %s%% discount, original_price=%s, discounted_price=%s, discount=%s",
                                 item.id, item.product.name, product_discount, item.original_price, item.discounted_price, item.discount)

                if category_offer:
                    category_discount = Decimal(category_offer.discount_percentage)
                    category_discount_amount = item.original_price * (category_discount / Decimal('100'))
                    if not product_offer or category_discount > product_discount:
                        item.discount = category_discount_amount
                        item.discounted_price = item.original_price - item.discount
                        item.offer = category_offer
                        item.offer_type = 'Category Offer'
                        logger.debug("CategoryOffer found for cart item %s (product %s, category %s): %s%% discount, original_price=%s, discounted_price=%s, discount=%s",
                                     item.id, item.product.name, item.product.category.name, category_discount, item.original_price, item.discounted_price, item.discount)
                    elif product_offer:
                        logger.debug("CategoryOffer found but ProductOffer has higher/equal discount for cart item %s: %s%% vs %s%%",
                                     item.id, category_discount, product_discount)

                if not product_offer and not category_offer:
                    logger.debug("No active offers found for cart item %s (product %s)", item.id, item.product.name)

            # Update subtotal using discounted price
            item.subtotal_value = item.discounted_price * item.quantity
            total += item.subtotal_value
            cart_items_with_stock.append(item)
        except Exception as e:
            logger.error("Error fetching stock or price for cart item %s: %s", item.id, str(e))
            item.stock = 0
            item.is_product_listed = False
            item.is_variant_listed = False
            item.is_category_listed = False
            item.original_price = item.product.price
            item.discounted_price = item.original_price
            item.discount = None
            item.offer = None
            item.offer_type = None
            item.subtotal_value = item.product.price * item.quantity
            total += item.subtotal_value
            cart_items_with_stock.append(item)
    
    return render(request, 'userside/cart.html', {
        'cart_items': cart_items_with_stock,
        'total': total,
    })
    
def clear_filters(request):
    return redirect('userside:product_list')

@login_required(login_url='login')
@require_POST
def update_cart_quantity(request, cart_item_id, action):
    cart_item = get_object_or_404(CartItem, id=cart_item_id, user=request.user, is_listed=True)
    try:
        # Use color_name and size from CartItem to find the matching ProductVariant
        variant_stock = ProductVariant.objects.filter(
            product=cart_item.product,
            color_variant__color_name=cart_item.color_name,
            size__name=cart_item.size,
            is_listed=True
        ).values_list('stock', flat=True).first() or 0
    except Exception as e:
        return JsonResponse({'success': False, 'message': 'Variant not found. Please remove this item and add it again.'}, status=400)

    response_data = {'success': True, 'message': ''}

    if action == 'update':
        new_quantity = int(request.POST.get('quantity', 1))
        if new_quantity <= 0:
            response_data['success'] = False
            response_data['message'] = 'Quantity must be at least 1.'
        elif new_quantity > 5:
            response_data['success'] = False
            response_data['message'] = 'Maximum limit is 5 items per product.'
        elif new_quantity > variant_stock:
            response_data['success'] = False
            response_data['message'] = f'Maximum quantity is {variant_stock}.'
        else:
            cart_item.quantity = new_quantity
            cart_item.save()
            response_data['message'] = 'Quantity updated successfully.'
            response_data['new_quantity'] = new_quantity
    elif action == 'increment':
        if cart_item.quantity < 5 and cart_item.quantity < variant_stock:
            cart_item.quantity += 1
            cart_item.save()
            response_data['message'] = 'Quantity increased successfully.'
            response_data['new_quantity'] = cart_item.quantity
        else:
            response_data['success'] = False
            response_data['message'] = f'Maximum quantity is {min(5, variant_stock)}.'
    elif action == 'decrement':
        if cart_item.quantity > 1:
            cart_item.quantity -= 1
            cart_item.save()
            response_data['message'] = 'Quantity decreased successfully.'
            response_data['new_quantity'] = cart_item.quantity
        else:
            response_data['success'] = False
            response_data['message'] = 'Minimum quantity is 1.'

    return JsonResponse(response_data)

@login_required(login_url='login')
def remove_from_cart(request, cart_item_id):
    item = get_object_or_404(CartItem, id=cart_item_id, user=request.user)
    item.delete()
    messages.success(request, "Item removed from cart.")
    return redirect('userside:view_cart')

# ===========================# Checkout and Order Placement Views# ===========================
import logging
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.conf import settings
from datetime import date
from decimal import Decimal
import json
from django.views.decorators.cache import cache_control
from django.db import transaction
from adminside.models import Coupon, Address, CartItem, ProductOffer, CategoryOffer, Order, OrderItem, ReferralCoupon, Wallet, Transaction

logger = logging.getLogger(__name__)

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@login_required(login_url='userside:login')
@never_cache
def checkout_view(request):
    # Check if an order was just placed
    if request.session.get('order_placed', False):
        del request.session['order_placed']
        request.session.modified = True
        messages.info(request, 'Your order has been placed. Browse more products!')
        return redirect('userside:product_list')

    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
    
    # Check if cart is empty
    if not cart_items.exists():
        messages.info(request, 'Your cart is empty. Please add items to proceed.')
        return redirect('userside:product_list')

    addresses = Address.objects.filter(user=request.user)
    default_address = addresses.filter(is_default=True).first()

    # Get or create the user's wallet
    wallet, created = Wallet.objects.get_or_create(user=request.user)

    # Fetch all valid regular coupons (not expired) and determine validity for the current user
    regular_coupons = Coupon.objects.filter(
        valid_from__lte=date.today(),
        valid_until__gte=date.today(),
    ).exclude(used_by=request.user)

    # Fetch all valid referral coupons for the user
    referral_coupons = ReferralCoupon.objects.filter(
        owner=request.user,
        used=False,
        valid_from__lte=date.today(),
        valid_until__gte=date.today()
    )

    # Combine coupons with their validity status
    coupons_with_validity = [
        {
            'type': 'regular',
            'coupon': coupon,
            'is_valid_for_user': coupon.is_valid(request.user),
            'used_by_user': request.user in coupon.used_by.all(),
            'code': coupon.code,
            'discount': f"{coupon.discount_percentage}%"
        }
        for coupon in regular_coupons
    ] + [
        {
            'type': 'referral',
            'coupon': coupon,
            'is_valid_for_user': coupon.is_valid(),
            'used_by_user': coupon.used,
            'code': coupon.code,
            'discount': f"{coupon.discount_percentage}%"
        }
        for coupon in referral_coupons
    ]

    # Calculate discounts for each cart item
    cart_items_with_discounts = []
    subtotal = Decimal('0.00')
    total_discount = Decimal('0.00')

    for item in cart_items:
        original_price = item.product.price
        discounted_price = original_price
        discount = Decimal('0.00')
        applied_offer = None

        # Check for ProductOffer
        product_offer = ProductOffer.objects.filter(
            product=item.product,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        # Check for CategoryOffer
        category_offer = CategoryOffer.objects.filter(
            category=item.product.category,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()

        # Determine the highest discount
        product_discount = Decimal('0.00')
        category_discount = Decimal('0.00')

        if product_offer:
            product_discount = Decimal(product_offer.discount_percentage)
            discount = original_price * (product_discount / Decimal('100'))
            discounted_price = original_price - discount
            applied_offer = f"Product Offer: {product_offer.name} ({product_offer.discount_percentage}%)"

        if category_offer:
            category_discount = Decimal(category_offer.discount_percentage)
            category_discount_amount = original_price * (category_discount / Decimal('100'))
            if not product_offer or category_discount > product_discount:
                discount = category_discount_amount
                discounted_price = original_price - discount
                applied_offer = f"Category Offer: {category_offer.name} ({category_offer.discount_percentage}%)"

        item_subtotal = original_price * item.quantity
        item_discounted_subtotal = discounted_price * item.quantity
        item_discount = item_subtotal - item_discounted_subtotal

        cart_items_with_discounts.append({
            'item': item,
            'subtotal': item_subtotal,
            'discount': item_discount,
            'discounted_price': item_discounted_subtotal,
            'applied_offer': applied_offer
        })

        subtotal += item_subtotal
        total_discount += item_discount

    # Check for applied regular coupons
    applied_regular_coupons = []
    regular_coupon_discount = Decimal('0.00')
    if 'coupon_codes' in request.session and request.session['coupon_codes']:
        if not isinstance(request.session['coupon_codes'], list):
            request.session['coupon_codes'] = []
            request.session.modified = True

        for coupon_code in request.session['coupon_codes'][:]:
            try:
                coupon = Coupon.objects.get(code=coupon_code)
                if coupon.is_valid(request.user):
                    applied_regular_coupons.append(coupon)
                    regular_coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                else:
                    request.session['coupon_codes'].remove(coupon_code)
                    request.session.modified = True
                    messages.error(request, f"Coupon {coupon_code} is no longer valid.")
            except Coupon.DoesNotExist:
                request.session['coupon_codes'].remove(coupon_code)
                request.session.modified = True
                messages.error(request, f"Coupon {coupon_code} is invalid.")

    # Check for applied referral coupons
    applied_referral_coupons = []
    referral_coupon_discount = Decimal('0.00')
    if 'referral_coupon_codes' in request.session and request.session['referral_coupon_codes']:
        if not isinstance(request.session['referral_coupon_codes'], list):
            request.session['referral_coupon_codes'] = []
            request.session.modified = True

        for coupon_code in request.session['referral_coupon_codes'][:]:
            try:
                coupon = ReferralCoupon.objects.get(code=coupon_code, owner=request.user)
                if coupon.is_valid():
                    applied_referral_coupons.append(coupon)
                    referral_coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                else:
                    request.session['referral_coupon_codes'].remove(coupon_code)
                    request.session.modified = True
                    messages.error(request, f"Referral coupon {coupon_code} is no longer valid.")
            except ReferralCoupon.DoesNotExist:
                request.session['referral_coupon_codes'].remove(coupon_code)
                request.session.modified = True
                messages.error(request, f"Referral coupon {coupon_code} is invalid.")

    # Create dictionaries for applied coupons
    applied_regular_coupons_dict = {coupon.code: {
        'code': coupon.code,
        'discount': f"{coupon.discount_percentage}%",
        'type': 'regular'
    } for coupon in applied_regular_coupons}
    applied_referral_coupons_dict = {coupon.code: {
        'code': coupon.code,
        'discount': f"{coupon.discount_percentage}%",
        'type': 'referral'
    } for coupon in applied_referral_coupons}
    applied_coupons_dict = {**applied_regular_coupons_dict, **applied_referral_coupons_dict}

    # Calculate final totals
    tax = Decimal('0.00')  # Update with your tax logic
    shipping = Decimal('0.00')  # Update with your shipping logic
    total = subtotal - total_discount - regular_coupon_discount - referral_coupon_discount + tax + shipping
    wallet_balance_deficit = total - wallet.balance if wallet.balance < total else Decimal('0.00')

    context = {
        'cart_items_with_discounts': cart_items_with_discounts,
        'addresses': addresses,
        'default_address': default_address,
        'coupons': coupons_with_validity,
        'subtotal': subtotal,
        'total_discount': total_discount,
        'regular_coupon_discount': regular_coupon_discount,
        'referral_coupon_discount': referral_coupon_discount,
        'applied_coupons': applied_coupons_dict,
        'tax': tax,
        'shipping': shipping,
        'total': total,
        'wallet_balance': wallet.balance,
        'wallet_balance_deficit': wallet_balance_deficit,
        'payment_method': request.session.get('payment_method', None) 
    }
    response = render(request, 'userside/checkout.html', context)
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.conf import settings
from datetime import date
from decimal import Decimal
import json
from adminside.models import Coupon,ReferralCoupon

@login_required(login_url='userside:login')
def apply_coupon(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            coupon_code = data.get('coupon_code', '').strip()
            
            if not coupon_code:
                return JsonResponse({'success': False, 'message': 'Please enter a coupon code.'})
            
            try:
                coupon = Coupon.objects.get(code=coupon_code)
                if not coupon.is_valid(request.user):
                    return JsonResponse({'success': False, 'message': 'Coupon is invalid, expired, or already used.'})
                
                if 'coupon_codes' not in request.session:
                    request.session['coupon_codes'] = []
                
                if coupon_code in request.session['coupon_codes']:
                    return JsonResponse({'success': False, 'message': 'Coupon already applied.'})
                
                request.session['coupon_codes'].append(coupon_code)
                request.session.modified = True
                return JsonResponse({
                    'success': True,
                    'message': 'Coupon applied successfully!',
                    'coupon_discount': str(coupon.discount_percentage),
                    'coupon_code': coupon_code,
                    'coupon_type': 'regular'
                })
            except Coupon.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid coupon code.'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid request.'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

import json
from datetime import date
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import logging

logger = logging.getLogger(__name__)

@login_required
def apply_referral_coupon(request):
    if request.method != 'POST':
        logger.warning(f"Invalid request method: {request.method}")
        return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=400)

    try:
        data = json.loads(request.body)
        coupon_code = data.get('coupon_code', '').strip()
        coupon_type = data.get('coupon_type', '').strip()  # Handle coupon_type from frontend
        
        if not coupon_code:
            logger.warning("No coupon code provided in request")
            return JsonResponse({'success': False, 'message': 'Please enter a referral coupon code.'}, status=400)
        
        if coupon_type != 'referral':
            logger.warning(f"Invalid coupon type: {coupon_type}")
            return JsonResponse({'success': False, 'message': 'Invalid coupon type for referral coupon.'}, status=400)
        
        try:
            coupon = ReferralCoupon.objects.get(code__iexact=coupon_code)
            if not coupon.is_valid():
                reason = ('expired' if date.today() > coupon.valid_until else
                         'not yet valid' if date.today() < coupon.valid_from else
                         'already used')
                logger.info(f"Coupon {coupon_code} invalid: {reason}")
                return JsonResponse({
                    'success': False,
                    'message': f'Referral coupon is invalid: {reason}.',
                    'details': {
                        'valid_from': str(coupon.valid_from),
                        'valid_until': str(coupon.valid_until),
                        'used': coupon.used,
                        'owner': coupon.owner.email
                    }
                }, status=400)
            
            # Initialize session list if not present
            if 'referral_coupon_codes' not in request.session:
                request.session['referral_coupon_codes'] = []
            
            # Check if coupon is already applied (case-insensitive)
            if coupon_code.lower() in [code.lower() for code in request.session['referral_coupon_codes']]:
                logger.info(f"Coupon {coupon_code} already applied for user {request.user.id}")
                return JsonResponse({
                    'success': False,
                    'message': 'Referral coupon already applied.'
                }, status=400)
            
            # Get the latest pending order
            order = Order.objects.filter(user=request.user, status='pending').last()
            if not order:
                logger.warning(f"No pending order found for user {request.user.id}")
                return JsonResponse({
                    'success': False,
                    'message': 'No pending order found to apply the coupon.'
                }, status=400)
            
            # Apply the coupon
            request.session['referral_coupon_codes'].append(coupon_code)
            request.session.modified = True
            
            order.referral_coupons.add(coupon)
            order.referral_coupon_discount = coupon.discount_percentage * order.subtotal / 100
            order.coupon_code = coupon_code
            order.coupon_type = 'referral'
            order.coupon_discount_percentage = coupon.discount_percentage
            order.total = (order.subtotal - order.referral_coupon_discount - 
                          order.discount - order.coupon_discount + order.tax + 
                          order.shipping_price)
            order.save()
            logger.info(f"Coupon {coupon_code} applied to order {order.id} for user {request.user.id}")
            
            return JsonResponse({
                'success': True,
                'message': 'Referral coupon applied successfully!',
                'coupon_discount': float(coupon.discount_percentage),  # Ensure JSON-serializable
                'coupon_code': coupon_code,
                'coupon_type': 'referral'
            }, status=200)
        
        except ReferralCoupon.DoesNotExist:
            logger.info(f"No coupon found for code: {coupon_code}")
            return JsonResponse({
                'success': False,
                'message': f'No referral coupon found for code "{coupon_code}".'
            }, status=404)
        
        except Exception as e:
            logger.error(f"Unexpected error applying coupon {coupon_code}: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False,
                'message': f'An unexpected error occurred: {str(e)}'
            }, status=500)
    
    except json.JSONDecodeError:
        logger.error("Invalid JSON format in request body")
        return JsonResponse({
            'success': False,
            'message': 'Invalid request format.'
        }, status=400)

@login_required(login_url='userside:login')
def remove_coupon(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            coupon_code = data.get('coupon_code', '').strip()
            coupon_type = data.get('coupon_type', '').strip()
            
            if coupon_type == 'regular' and 'coupon_codes' in request.session and coupon_code in request.session['coupon_codes']:
                request.session['coupon_codes'].remove(coupon_code)
                request.session.modified = True
                return JsonResponse({'success': True, 'message': 'Coupon removed successfully!'})
            elif coupon_type == 'referral' and 'referral_coupon_codes' in request.session and coupon_code in request.session['referral_coupon_codes']:
                request.session['referral_coupon_codes'].remove(coupon_code)
                request.session.modified = True
                return JsonResponse({'success': True, 'message': 'Referral coupon removed successfully!'})
            return JsonResponse({'success': False, 'message': 'Coupon not applied.'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid request.'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})
from django.shortcuts import render, get_object_or_404, redirect
from django.conf import settings
import razorpay
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
import json
import logging
from decimal import Decimal
from datetime import date
from adminside.models import Order, OrderItem, CartItem, Address, Coupon, ReferralCoupon, ProductOffer, CategoryOffer, ProductVariant

# Set up logging
logger = logging.getLogger(__name__)

def log_payment_event(event, order_id, data=None, error=None):
    """Enhanced logging for payment events"""
    log_entry = f"PAYMENT_{event} - Order: {order_id}"
    if data:
        log_entry += f" - Data: {json.dumps(data, default=str)}"
    if error:
        log_entry += f" - Error: {str(error)}"
    
    if error:
        logger.error(log_entry)
    else:
        logger.info(log_entry)

import logging
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.conf import settings
from datetime import date
from decimal import Decimal
import json
from django.db import transaction
from adminside.models import Coupon, Address, CartItem, ProductOffer, CategoryOffer, Order, OrderItem, ReferralCoupon, Wallet, Transaction, ProductVariant

logger = logging.getLogger(__name__)

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from decimal import Decimal
from datetime import date
from adminside.models import Address, Order, OrderItem, Coupon, ReferralCoupon, ProductOffer, CategoryOffer, CartItem, Wallet, Transaction, ProductVariant
from django.http import JsonResponse
import json
import logging

logger = logging.getLogger(__name__)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@login_required(login_url='userside:login')
@transaction.atomic
def place_order(request):
    # Check if the request is AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method != 'POST':
        error_message = 'Invalid request method.'
        logger.warning(error_message)
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_method'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    address_id = request.POST.get('address_id')
    payment_method = request.POST.get('payment_method')
    payment_gateway = request.POST.get('payment_gateway')

    # Validate inputs
    if not address_id:
        error_message = 'Please select a shipping address.'
        logger.warning(error_message)
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'missing_address'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    if not payment_method:
        error_message = 'Please select a payment method.'
        logger.warning(error_message)
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'missing_payment'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    if payment_method == 'Online' and not payment_gateway:
        error_message = 'Please select a payment gateway.'
        logger.warning(error_message)
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'missing_gateway'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    try:
        address = Address.objects.get(id=address_id, user=request.user)
    except Address.DoesNotExist:
        error_message = 'Invalid address selected.'
        logger.error(f"Invalid address ID {address_id} for user {request.user.id}")
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_address'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product__category')
    if not cart_items:
        error_message = 'Your cart is empty.'
        logger.warning(f"No cart items for user {request.user.id}")
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'empty_cart'}, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    # Validate product and category listing status
    unlisted_items = []
    for item in cart_items:
        if not item.product.is_listed:
            unlisted_items.append({
                'type': 'product',
                'name': item.product.name,
                'message': f'The product "{item.product.name}" is no longer available.'
            })
        if not item.product.category.is_listed:
            unlisted_items.append({
                'type': 'category',
                'name': item.product.category.name,
                'message': f'The category "{item.product.category.name}" for product "{item.product.name}" is no longer available.'
            })

    if unlisted_items:
        error_message = unlisted_items[0]['message']
        logger.warning(f"Unlisted items detected for user {request.user.id}: {json.dumps(unlisted_items, default=str)}")
        if is_ajax:
            return JsonResponse({
                'success': False,
                'message': error_message,
                'error_code': 'unlisted_item',
                'unlisted_items': unlisted_items
            }, status=400)
        messages.error(request, error_message)
        return redirect('userside:checkout')

    # Calculate totals and prepare order items
    subtotal = Decimal('0.00')
    total_discount = Decimal('0.00')
    cart_items_with_discounts = []

    try:
        with transaction.atomic():
            # Get or create wallet
            wallet, created = Wallet.objects.get_or_create(user=request.user)

            for item in cart_items:
                original_price = item.product.price
                discounted_price = original_price
                item_discount = Decimal('0.00')
                applied_offer = None

                # Find the ProductVariant
                try:
                    variant = ProductVariant.objects.get(
                        product=item.product,
                        color_variant__color_name=item.color_name,
                        size__name=item.size,
                        is_listed=True
                    )
                except ProductVariant.DoesNotExist:
                    error_message = f'Invalid variant for {item.product.name} (Color: {item.color_name}, Size: {item.size})'
                    logger.error(error_message)
                    if is_ajax:
                        return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_variant'}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:checkout')

                # Check stock availability
                if variant.stock < item.quantity:
                    error_message = f'Insufficient stock for {item.product.name} (Color: {item.color_name}, Size: {item.size}). Available: {variant.stock}'
                    logger.error(error_message)
                    if is_ajax:
                        return JsonResponse({'success': False, 'message': error_message, 'error_code': 'insufficient_stock'}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:checkout')

                # Check for ProductOffer
                product_offer = ProductOffer.objects.filter(
                    product=item.product,
                    is_active=True,
                    is_deleted=False,
                    start_date__lte=date.today(),
                    end_date__gte=date.today()
                ).first()

                # Check for CategoryOffer
                category_offer = CategoryOffer.objects.filter(
                    category=item.product.category,
                    is_active=True,
                    is_deleted=False,
                    start_date__lte=date.today(),
                    end_date__gte=date.today()
                ).first()

                # Determine the highest discount
                product_discount = Decimal('0.00')
                category_discount = Decimal('0.00')

                if product_offer:
                    product_discount = Decimal(product_offer.discount_percentage)
                    item_discount = original_price * (product_discount / Decimal('100'))
                    discounted_price = original_price - item_discount
                    applied_offer = f"Product Offer: {product_offer.name} ({product_offer.discount_percentage}%)"

                if category_offer:
                    category_discount = Decimal(category_offer.discount_percentage)
                    category_discount_amount = original_price * (category_discount / Decimal('100'))
                    if not product_offer or category_discount > product_discount:
                        item_discount = category_discount_amount
                        discounted_price = original_price - item_discount
                        applied_offer = f"Category Offer: {category_offer.name} ({category_offer.discount_percentage}%)"

                item_subtotal = original_price * item.quantity
                item_discounted_subtotal = discounted_price * item.quantity
                total_item_discount = item_subtotal - item_discounted_subtotal

                cart_items_with_discounts.append({
                    'item': item,
                    'variant': variant,
                    'original_price': original_price,
                    'discounted_price': discounted_price,
                    'subtotal': item_subtotal,
                    'discount': total_item_discount,
                    'applied_offer': applied_offer
                })

                subtotal += item_subtotal
                total_discount += total_item_discount

            # Check for regular coupon discounts
            coupon_discount = Decimal('0.00')
            applied_coupons = []
            coupon_code = None
            coupon_type = None
            coupon_discount_percentage = None
            if 'coupon_codes' in request.session and request.session['coupon_codes']:
                for coupon_code_item in request.session['coupon_codes'][:]:
                    try:
                        coupon = Coupon.objects.get(code=coupon_code_item)
                        if coupon.is_valid(request.user):
                            coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                            applied_coupons.append(coupon)
                            # Set fields for the last valid coupon
                            coupon_code = coupon.code
                            coupon_type = 'coupon'
                            coupon_discount_percentage = coupon.discount_percentage
                            logger.debug(f"Applied regular coupon: {coupon.code}, Discount: {coupon_discount}")
                        else:
                            error_message = f"Coupon {coupon_code_item} is no longer valid."
                            logger.warning(error_message)
                            request.session['coupon_codes'].remove(coupon_code_item)
                            request.session.modified = True
                            if is_ajax:
                                return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_coupon'}, status=400)
                            messages.error(request, error_message)
                            return redirect('userside:checkout')
                    except Coupon.DoesNotExist:
                        error_message = f"Coupon {coupon_code_item} is invalid."
                        logger.warning(error_message)
                        request.session['coupon_codes'].remove(coupon_code_item)
                        request.session.modified = True
                        if is_ajax:
                            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_coupon'}, status=400)
                        messages.error(request, error_message)
                        return redirect('userside:checkout')

            # Check for referral coupon discounts
            referral_coupon_discount = Decimal('0.00')
            applied_referral_coupons = []
            if 'referral_coupon_codes' in request.session and request.session['referral_coupon_codes']:
                for coupon_code_item in request.session['referral_coupon_codes'][:]:
                    try:
                        coupon = ReferralCoupon.objects.get(code=coupon_code_item, owner=request.user)
                        if coupon.is_valid():
                            referral_coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                            applied_referral_coupons.append(coupon)
                            # Set fields for the last valid coupon
                            coupon_code = coupon.code
                            coupon_type = 'referral'
                            coupon_discount_percentage = coupon.discount_percentage
                            logger.debug(f"Applied referral coupon: {coupon.code}, Discount: {referral_coupon_discount}")
                        else:
                            error_message = f"Referral coupon {coupon_code_item} is no longer valid."
                            logger.warning(error_message)
                            request.session['referral_coupon_codes'].remove(coupon_code_item)
                            request.session.modified = True
                            if is_ajax:
                                return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_referral_coupon'}, status=400)
                            messages.error(request, error_message)
                            return redirect('userside:checkout')
                    except ReferralCoupon.DoesNotExist:
                        error_message = f"Referral coupon {coupon_code_item} is invalid."
                        logger.warning(error_message)
                        request.session['referral_coupon_codes'].remove(coupon_code_item)
                        request.session.modified = True
                        if is_ajax:
                            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_referral_coupon'}, status=400)
                        messages.error(request, error_message)
                        return redirect('userside:checkout')

            # Calculate final totals
            tax = Decimal('0.00')  # Update with your tax logic
            shipping_price = Decimal('0.00')  # Update with your shipping logic
            total = subtotal - total_discount - coupon_discount - referral_coupon_discount + tax + shipping_price

            # Validate COD restriction
            if payment_method == 'COD' and total > Decimal('1000.00'):
                error_message = 'Cash on Delivery is not available for orders above ₹1000.'
                logger.warning(f"COD not allowed for order total {total} for user {request.user.id}")
                if is_ajax:
                    return JsonResponse({'success': False, 'message': error_message, 'error_code': 'cod_restriction'}, status=400)
                messages.error(request, error_message)
                return redirect('userside:checkout')

            # Validate wallet balance for Wallet payment
            if payment_method == 'Wallet':
                try:
                    wallet.debit(total)
                except ValueError as e:
                    error_message = f'Insufficient wallet balance. You need ₹{total - wallet.balance:.2f} more.'
                    logger.warning(f"Insufficient wallet balance for user {request.user.id}: {wallet.balance} < {total}")
                    if is_ajax:
                        return JsonResponse({'success': False, 'message': error_message, 'error_code': 'insufficient_wallet'}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:checkout')

            # Create order with snapshot address fields
            order = Order.objects.create(
                user=request.user,
                subtotal=subtotal,
                discount=total_discount,
                coupon_discount=coupon_discount,
                referral_coupon_discount=referral_coupon_discount,
                coupon_code=coupon_code,
                coupon_type=coupon_type,
                coupon_discount_percentage=coupon_discount_percentage,
                tax=tax,
                shipping_price=shipping_price,
                total=total,
                payment_method=payment_method,
                payment_gateway=payment_gateway if payment_method == 'Online' else None,
                status='pending',
                shipping_full_name=address.full_name,
                shipping_phone=address.phone,
                shipping_address_line1=address.address_line1,
                shipping_address_line2=address.address_line2 or '',
                shipping_city=address.city,
                shipping_state=address.state,
                shipping_postal_code=address.postal_code,
                shipping_country=address.country
            )

            # Save order items and decrease stock
            stock_changes = []
            for cart_item in cart_items_with_discounts:
                item = cart_item['item']
                variant = cart_item['variant']
                variant.stock -= item.quantity
                if variant.stock < 0:
                    error_message = f'Invalid stock update for {item.product.name} ({item.color_name}, {item.size})'
                    logger.error(f"Negative stock for product {item.product.name} ({item.color_name}, {item.size}) in order {order.order_id}")
                    if is_ajax:
                        return JsonResponse({'success': False, 'message': error_message, 'error_code': 'invalid_stock'}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:checkout')
                variant.save()
                stock_changes.append({
                    'product': item.product.name,
                    'variant': f'{item.color_name} - {item.size}',
                    'quantity': item.quantity,
                    'stock_after': variant.stock
                })
                OrderItem.objects.create(
                    order=order,
                    product=item.product,
                    variant=variant,
                    color_name=item.color_name,
                    size=item.size,
                    quantity=item.quantity,
                    price=cart_item['original_price'],
                    discounted_price=cart_item['discounted_price'],
                    applied_offer=cart_item['applied_offer']
                )

            # Log stock changes
            logger.info(f"ORDER_STOCK_DECREASED - Order: {order.order_id} - Stock Changes: {json.dumps(stock_changes, default=str)}")

            # Associate coupons with the order
            order.coupons.set(applied_coupons)
            order.referral_coupons.set(applied_referral_coupons)

            # Handle payment method
            if payment_method == 'Wallet':
                # Transaction already created via wallet.debit; create transaction record
                Transaction.objects.create(
                    wallet=wallet,
                    transaction_type='DEBIT',
                    amount=total,
                    description=f"Payment for order {order.order_id}",
                    source_order=order
                )
                logger.info(f"User {request.user.email} paid ₹{total} from wallet for order {order.order_id}")
                order.is_paid = True
                order.status = 'pending'
                order.save()

                # Mark coupons as used
                for coupon in applied_coupons:
                    coupon.used_by.add(request.user)
                    coupon.save()
                for coupon in applied_referral_coupons:
                    coupon.used = True
                    coupon.save()

                # Clear session data
                if 'coupon_codes' in request.session:
                    del request.session['coupon_codes']
                if 'referral_coupon_codes' in request.session:
                    del request.session['referral_coupon_codes']
                request.session.modified = True

                # Clear cart
                cart_items.delete()

                success_message = 'Order placed successfully using wallet!'
                if is_ajax:
                    return JsonResponse({
                        'success': True,
                        'message': success_message,
                        'order_id': order.id,
                        'redirect_url': reverse('userside:order_success', args=[order.id])
                    })
                messages.success(request, success_message)
                return redirect('userside:order_success', order_id=order.id)

            elif payment_method == 'Online':
                if payment_gateway == 'razorpay':
                    if is_ajax:
                        return JsonResponse({
                            'success': True,
                            'message': 'Proceeding to payment',
                            'order_id': order.id,
                            'redirect_url': reverse('userside:initiate_payment', args=[order.id])
                        })
                    return redirect('userside:initiate_payment', order_id=order.id)
                else:
                    error_message = 'Unsupported payment gateway selected.'
                    logger.warning(error_message)
                    if is_ajax:
                        return JsonResponse({'success': False, 'message': error_message, 'error_code': 'unsupported_gateway'}, status=400)
                    messages.error(request, error_message)
                    return redirect('userside:checkout')
            else:  # COD
                order.is_paid = False  # COD orders are unpaid until delivered
                order.status = 'pending'
                order.save()

                # Mark coupons as used for COD
                for coupon in applied_coupons:
                    coupon.used_by.add(request.user)
                    coupon.save()
                for coupon in applied_referral_coupons:
                    coupon.used = True
                    coupon.save()

                # Clear session data for COD
                if 'coupon_codes' in request.session:
                    del request.session['coupon_codes']
                if 'referral_coupon_codes' in request.session:
                    del request.session['referral_coupon_codes']
                request.session.modified = True

                # Clear cart
                cart_items.delete()

                success_message = 'Order placed successfully!'
                if is_ajax:
                    return JsonResponse({
                        'success': True,
                        'message': success_message,
                        'order_id': order.id,
                        'redirect_url': reverse('userside:order_success', args=[order.id])
                    })
                messages.success(request, success_message)
                return redirect('userside:order_success', order_id=order.id)

    except Exception as e:
        error_message = f'An unexpected error occurred: {str(e)}'
        logger.error(f"Error in place_order for user {request.user.id}: {str(e)}")
        if is_ajax:
            return JsonResponse({'success': False, 'message': error_message, 'error_code': 'unexpected_error'}, status=500)
        messages.error(request, error_message)
        return redirect('userside:checkout')
    
from django.shortcuts import render, get_object_or_404, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.contrib import messages
from pytz import timezone as pytz_timezone
from adminside.models import Order, OrderItem

@login_required
@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def order_detail(request, order_id):
    order = get_object_or_404(Order, order_id=order_id, user=request.user)
    
    # Check if all items are cancelled
    all_items_cancelled = all(item.is_cancelled for item in order.items.all())
    
    # Convert order creation time to IST
    ist_tz = pytz.timezone('Asia/Kolkata')
    order_time_ist = order.created_at.astimezone(ist_tz)
    
    # Calculate total refunded amount
    total_refunded = sum(item.refund_amount for item in order.items.all() if item.is_refunded_to_wallet)

    # Calculate original subtotal and total (all items, using discounted_price or price)
    original_subtotal = sum((item.discounted_price or item.price or Decimal('0.00')) * item.quantity for item in order.items.all())
    coupon_discount = order.coupon_discount or Decimal('0.00')
    referral_discount = order.referral_coupon_discount or Decimal('0.00')
    original_total = max(original_subtotal - coupon_discount - referral_discount, Decimal('0.00')).quantize(Decimal('0.01'))

    # Calculate adjusted subtotal (active items only)
    active_items = [item for item in order.items.all() if not item.is_cancelled and not item.is_returned]
    active_subtotal = sum((item.discounted_price or item.price or Decimal('0.00')) * item.quantity for item in active_items)
    active_items_count = len(active_items)
    
    # Count unique products
    unique_products_count = order.items.values('product__id').distinct().count()

    # Calculate per-product coupon and referral discounts
    coupon_discount_per_product = (coupon_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')
    referral_discount_per_product = (referral_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')

    # Annotate items with their coupon discount, referral discount, and adjusted subtotal
    items_with_discounts = []
    product_discounts = {}  # Track discounts per product_id
    for item in order.items.all():
        product_id = item.product.id
        if product_id not in product_discounts:
            product_discounts[product_id] = {
                'coupon_discount': coupon_discount_per_product,
                'referral_discount': referral_discount_per_product
            }
        item_coupon_discount = product_discounts[product_id]['coupon_discount']
        item_referral_discount = product_discounts[product_id]['referral_discount']
        item_subtotal = (item.discounted_price or item.price or Decimal('0.00')) * item.quantity
        items_with_discounts.append({
            'item': item,
            'coupon_discount': item_coupon_discount.quantize(Decimal('0.01')),
            'referral_discount': item_referral_discount.quantize(Decimal('0.01')),
            'adjusted_subtotal': max(
                item_subtotal - item_coupon_discount - item_referral_discount,
                Decimal('0.00')
            ).quantize(Decimal('0.01'))
        })

    # Calculate adjusted discount and total for active items
    if active_items_count > 0 and unique_products_count > 0:
        active_unique_products = len(set(item.product.id for item in active_items))
        total_discount_per_product = coupon_discount_per_product + referral_discount_per_product
        adjusted_discount = (total_discount_per_product * active_unique_products).quantize(Decimal('0.01'))
        adjusted_total = max(active_subtotal - adjusted_discount, Decimal('0.00')).quantize(Decimal('0.01'))
    else:
        adjusted_subtotal = Decimal('0.00')
        adjusted_discount = Decimal('0.00')
        adjusted_total = Decimal('0.00')

    logger.info(f"Order {order.order_id}: original_subtotal=₹{original_subtotal:.2f}, coupon_discount=₹{coupon_discount:.2f}, referral_discount=₹{referral_discount:.2f}, original_total=₹{original_total:.2f}")
    logger.info(f"Order {order.order_id}: active_subtotal=₹{active_subtotal:.2f}, active_items_count={active_items_count}, unique_products_count={unique_products_count}, adjusted_discount=₹{adjusted_discount:.2f}, adjusted_total=₹{adjusted_total:.2f}")
    logger.info(f"Order {order.order_id}: coupon_discount_per_product=₹{coupon_discount_per_product:.2f}, referral_discount_per_product=₹{referral_discount_per_product:.2f}")
    for entry in items_with_discounts:
        item = entry['item']
        logger.info(f"Item {item.id} (Product: {item.product.name}): adjusted_subtotal=₹{entry['adjusted_subtotal']:.2f}, coupon_discount=₹{entry['coupon_discount']:.2f}, referral_discount=₹{entry['referral_discount']:.2f}")

    context = {
        'order': order,
        'payment_method': order.get_payment_method_display() if order.payment_method else 'Not specified',
        'all_items_cancelled': all_items_cancelled,
        'order_time_ist': order_time_ist,
        'is_paid': order.is_paid,
        'total_refunded': total_refunded,
        'original_subtotal': original_subtotal,
        'coupon_discount': coupon_discount,
        'referral_discount': referral_discount,
        'original_total': original_total,
        'adjusted_subtotal': active_subtotal,
        'adjusted_discount': adjusted_discount,
        'adjusted_total': adjusted_total,
        'has_cancellations_or_returns': any(item.is_cancelled or item.is_returned for item in order.items.all()),
        'items_with_discounts': items_with_discounts,
    }
    return render(request, 'userside/orders/order_detail.html', context)

def log_payment_event(event_type, order_id, details=None):
    logger.info(f"Payment Event: {event_type} | Order ID: {order_id} | Details: {details or 'No details'}")

@login_required(login_url='userside:login')
def initiate_payment(request, order_id):
    """Initiate payment with validation for unlisted products/categories"""
    try:
        order = get_object_or_404(Order, id=order_id, user=request.user)
        
        # Validation checks
        if order.payment_method != 'Online':
            log_payment_event('INVALID_METHOD', order.order_id, {'method': order.payment_method})
            messages.error(request, "This order is not configured for online payment")
            return redirect('userside:checkout')
        
        if order.is_paid:
            log_payment_event('ALREADY_PAID', order.order_id)
            messages.success(request, "This order is already paid")
            return redirect('userside:order_success', order_id=order.id)
        
        # Check for unlisted products or categories
        order_items = OrderItem.objects.filter(order=order)
        unlisted_items = []
        for item in order_items:
            product = item.product
            category = product.category
            if not product.is_listed or not category.is_listed:
                unlisted_items.append({
                    'product_name': product.name,
                    'is_product_listed': product.is_listed,
                    'is_category_listed': category.is_listed
                })
        
        # Store unlisted items in session if any
        if unlisted_items:
            log_payment_event('UNLISTED_ITEM', order.order_id, {'unlisted_items': unlisted_items})
            request.session['unlisted_items_error'] = [
                f"Product '{item['product_name']}' is no longer available." 
                for item in unlisted_items
            ]
            request.session.modified = True
        
        # Initialize Razorpay client only if no unlisted items
        razorpay_order = None
        amount_in_paise = None
        if not unlisted_items:
            # Validate Razorpay configuration
            if not all([settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET]):
                log_payment_event('CONFIG_ERROR', order.order_id, {'error': 'Missing Razorpay credentials'})
                messages.error(request, "Payment service configuration error. Please contact support.")
                return redirect('userside:checkout')
            
            # Validate order amount
            if order.total <= 0:
                log_payment_event('INVALID_AMOUNT', order.order_id, {'amount': str(order.total)})
                messages.error(request, "Invalid order amount")
                return redirect('userside:checkout')
            
            # Initialize Razorpay client
            try:
                client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
                client.payment.all({'count': 1})  # Test credentials
            except razorpay.errors.BadRequestError as e:
                log_payment_event('AUTH_ERROR', order.order_id, error=str(e))
                messages.error(request, "Payment service authentication failed. Please contact support.")
                return redirect('userside:checkout')
            except Exception as e:
                log_payment_event('CLIENT_INIT_ERROR', order.order_id, error=str(e))
                messages.error(request, "Payment service is temporarily unavailable. Please try again later.")
                return redirect('userside:checkout')
            
            # Create Razorpay order
            amount_in_paise = int(order.total * 100)
            try:
                razorpay_order_data = {
                    "amount": amount_in_paise,
                    "currency": "INR",
                    "payment_capture": "1",
                    "notes": {
                        "order_id": str(order.order_id),
                        "user_id": str(request.user.id),
                        "user_email": str(request.user.email),
                        "created_at": timezone.now().isoformat()
                    }
                }
                
                log_payment_event('CREATING_RAZORPAY_ORDER', order.order_id, razorpay_order_data)
                razorpay_order = client.order.create(razorpay_order_data)
                log_payment_event('RAZORPAY_ORDER_CREATED', order.order_id, {
                    'razorpay_order_id': razorpay_order['id'],
                    'amount': razorpay_order['amount'],
                    'status': razorpay_order['status']
                })
                
            except razorpay.errors.BadRequestError as e:
                log_payment_event('RAZORPAY_BAD_REQUEST', order.order_id, error=str(e))
                error_detail = str(e)
                if 'amount' in error_detail.lower():
                    messages.error(request, f"Invalid payment amount: ₹{order.total}. Please contact support.")
                else:
                    messages.error(request, f"Payment request error: {error_detail}")
                return redirect('userside:order_failure', order_id=order.id)
                
            except razorpay.errors.GatewayError as e:
                log_payment_event('RAZORPAY_GATEWAY_ERROR', order.order_id, error=str(e))
                messages.error(request, "Payment gateway is temporarily unavailable. Please try again in a few minutes.")
                return redirect('userside:order_failure', order_id=order.id)
                
            except razorpay.errors.ServerError as e:
                log_payment_event('RAZORPAY_SERVER_ERROR', order.order_id, error=str(e))
                messages.error(request, "Payment service is temporarily down. Please try again later.")
                return redirect('userside:order_failure', order_id=order.id)
                
            except Exception as e:
                log_payment_event('RAZORPAY_UNEXPECTED_ERROR', order.order_id, error=str(e))
                messages.error(request, f"Failed to create payment request: {str(e)}")
                return redirect('userside:order_failure', order_id=order.id)
            
            # Store session data for verification
            session_key = f'razorpay_order_{order.id}'
            request.session[session_key] = {
                'razorpay_order_id': razorpay_order['id'],
                'amount': amount_in_paise,
                'created_at': timezone.now().isoformat()
            }
            request.session.modified = True
            log_payment_event('SESSION_STORED', order.order_id, {'session_key': session_key})
        
        return render(request, 'userside/payment_integration.html', {
            'order': order,
            'razorpay_key': settings.RAZORPAY_KEY_ID,
            'razorpay_amount': amount_in_paise,
            'razorpay_order_id': razorpay_order['id'] if razorpay_order else None,
            'has_unlisted_items': bool(unlisted_items),
            'debug': settings.DEBUG
        })
        
    except Exception as e:
        log_payment_event('INITIATE_UNEXPECTED_ERROR', order_id, error=str(e))
        messages.error(request, "An unexpected error occurred. Please try again.")
        return redirect('userside:checkout')

@require_POST
def clear_session_error(request):
    """Clear a specific session key"""
    try:
        data = json.loads(request.body)
        key = data.get('key')
        if key in request.session:
            del request.session[key]
            request.session.modified = True
            return JsonResponse({'success': True})
        return JsonResponse({'success': False, 'message': 'Key not found in session'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

@login_required(login_url='userside:login')
@require_POST
def verify_payment(request, order_id):
    """Enhanced payment verification with SweetAlert message and cart clearing"""
    try:
        order = get_object_or_404(Order, id=order_id, user=request.user)
        
        log_payment_event('VERIFY_PAYMENT_START', order.order_id, {
            'user_id': request.user.id,
            'is_paid': order.is_paid
        })
        
        if order.is_paid:
            log_payment_event('ALREADY_PAID_VERIFICATION', order.order_id)
            messages.success(request, 'Payment already verified!')
            return redirect('userside:order_success', order_id=order.id)
        
        razorpay_order_id = request.POST.get('razorpay_order_id', '').strip()
        razorpay_payment_id = request.POST.get('razorpay_payment_id', '').strip()
        razorpay_signature = request.POST.get('razorpay_signature', '').strip()
        
        payment_data = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'has_signature': bool(razorpay_signature)
        }
        log_payment_event('PAYMENT_DATA_RECEIVED', order.order_id, payment_data)
        
        if not all([razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            missing_fields = []
            if not razorpay_order_id: missing_fields.append('order_id')
            if not razorpay_payment_id: missing_fields.append('payment_id')
            if not razorpay_signature: missing_fields.append('signature')
            
            log_payment_event('MISSING_PAYMENT_DATA', order.order_id, {'missing': missing_fields})
            messages.error(request, f'Payment verification failed: Missing {", ".join(missing_fields)}.')
            return redirect('userside:order_failure', order_id=order.id)
        
        session_key = f'razorpay_order_{order.id}'
        session_data = request.session.get(session_key)
        
        if not session_data:
            log_payment_event('MISSING_SESSION_DATA', order.order_id)
            messages.error(request, 'Payment session expired. Please try again.')
            return redirect('userside:order_failure', order_id=order.id)
        
        if session_data['razorpay_order_id'] != razorpay_order_id:
            log_payment_event('ORDER_ID_MISMATCH', order.order_id, {
                'session_order_id': session_data['razorpay_order_id'],
                'received_order_id': razorpay_order_id
            })
            messages.error(request, 'Payment verification failed: Order reference mismatch.')
            return redirect('userside:order_failure', order_id=order.id)
        
        try:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        except Exception as e:
            log_payment_event('CLIENT_INIT_VERIFY_ERROR', order.order_id, error=str(e))
            messages.error(request, "Payment verification service unavailable.")
            return redirect('userside:order_failure', order_id=order.id)
        
        try:
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            
            log_payment_event('VERIFYING_SIGNATURE', order.order_id, {
                'payment_id': razorpay_payment_id[:10] + '...',
                'order_id': razorpay_order_id[:10] + '...'
            })
            
            client.utility.verify_payment_signature(params_dict)
            log_payment_event('SIGNATURE_VERIFIED', order.order_id, {'payment_id': razorpay_payment_id})
            
            try:
                payment = client.payment.fetch(razorpay_payment_id)
                payment_status_data = {
                    'status': payment['status'],
                    'amount': payment['amount'],
                    'method': payment.get('method', 'unknown'),
                    'bank': payment.get('bank', 'unknown'),
                    'created_at': payment.get('created_at')
                }
                log_payment_event('PAYMENT_DETAILS_FETCHED', order.order_id, payment_status_data)
                
                if payment['status'] not in ['captured', 'authorized']:
                    log_payment_event('PAYMENT_NOT_CAPTURED', order.order_id, {
                        'status': payment['status'],
                        'expected': 'captured or authorized'
                    })
                    messages.error(request, f'Payment status is {payment["status"]}. Please contact support.')
                    return redirect('userside:order_failure', order_id=order.id)
                
                if payment['amount'] != session_data['amount']:
                    log_payment_event('AMOUNT_MISMATCH', order.order_id, {
                        'payment_amount': payment['amount'],
                        'expected_amount': session_data['amount']
                    })
                    messages.error(request, 'Payment amount verification failed. Please contact support.')
                    return redirect('userside:order_failure', order_id=order.id)
                
            except razorpay.errors.BadRequestError as e:
                log_payment_event('PAYMENT_FETCH_ERROR', order.order_id, error=str(e))
            except Exception as e:
                log_payment_event('PAYMENT_FETCH_UNEXPECTED_ERROR', order.order_id, error=str(e))
            
            with transaction.atomic():
                order.refresh_from_db()
                
                if order.is_paid:
                    log_payment_event('ALREADY_PAID_DURING_VERIFICATION', order.order_id)
                    messages.success(request, 'Payment already processed!')
                    return redirect('userside:order_success', order_id=order.id)
                
                order.is_paid = True
                order.razorpay_payment_id = razorpay_payment_id
                order.razorpay_order_id = razorpay_order_id
                order.save()
                
                regular_coupons_processed = 0
                referral_coupons_processed = 0
                
                for coupon in order.coupons.all():
                    if request.user not in coupon.used_by.all():
                        coupon.used_by.add(request.user)
                        coupon.save()
                        regular_coupons_processed += 1
                
                for coupon in order.referral_coupons.all():
                    if not coupon.used:
                        coupon.used = True
                        coupon.save()
                        referral_coupons_processed += 1
                
                # Clear the cart for the user
                CartItem.objects.filter(user=request.user, is_listed=True).delete()
                log_payment_event('CART_CLEARED', order.order_id, {'user_id': request.user.id})
                
                session_keys_to_clear = [
                    'coupon_codes', 
                    'referral_coupon_codes', 
                    session_key
                ]
                cleared_keys = []
                for key in session_keys_to_clear:
                    if key in request.session:
                        del request.session[key]
                        cleared_keys.append(key)
                
                request.session.modified = True
                
                log_payment_event('ORDER_MARKED_PAID', order.order_id, {
                    'payment_id': razorpay_payment_id,
                    'cleared_session_keys': cleared_keys
                })
            
            # Add SweetAlert message for successful payment
            messages.success(request, 'Payment successful! Order confirmed.', extra_tags='sweetalert')
            return redirect('userside:order_success', order_id=order.id)
            
        except razorpay.errors.SignatureVerificationError as e:
            log_payment_event('SIGNATURE_VERIFICATION_FAILED', order.order_id, {
                'error': str(e),
                'payment_id': razorpay_payment_id[:10] + '...'
            })
            messages.error(request, 'Payment verification failed: Invalid payment signature.')
            return redirect('userside:order_failure', order_id=order.id)
            
        except Exception as e:
            log_payment_event('VERIFICATION_UNEXPECTED_ERROR', order.order_id, error=str(e))
            messages.error(request, f'Payment verification failed: {str(e)}')
            return redirect('userside:order_failure', order_id=order.id)
    
    except Exception as e:
        log_payment_event('VERIFY_PAYMENT_UNEXPECTED_ERROR', order_id, error=str(e))
        messages.error(request, "An unexpected error occurred during payment verification.")
        return redirect('userside:order_failure', order_id=order_id)

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@login_required(login_url='userside:login')
def order_success(request, order_id):
    """Enhanced order success page"""
    try:
        order = get_object_or_404(Order, id=order_id, user=request.user)
        
        if not order.is_paid and order.payment_method == 'Online':
            log_payment_event('SUCCESS_PAGE_UNPAID_ORDER', order.order_id, {
                'payment_method': order.payment_method,
                'is_paid': order.is_paid
            })
            messages.error(request, 'Payment not completed for this order.')
            return redirect('userside:order_failure', order_id=order.id)
        
        log_payment_event('SUCCESS_PAGE_ACCESSED', order.order_id)
        
        order_items = []
        for item in order.items.all():
            order_items.append({
                'name': item.product.name if item.product else "Deleted Product",
                'quantity': item.quantity,
                'original_price': item.price,
                'discounted_price': item.discounted_price or item.price,
                'total': (item.discounted_price or item.price) * item.quantity,
                'discount': (item.price - (item.discounted_price or item.price)) * item.quantity,
                'applied_offer': item.applied_offer,
                'size': item.size,
                'color_name': item.color_name
            })

        context = {
            'order': order,
            'order_items': order_items,
            'subtotal': order.subtotal,
            'total_discount': order.discount,
            'coupon_discount': order.coupon_discount,
            'referral_coupon_discount': order.referral_coupon_discount,
            'applied_coupons': {
                coupon.code: {
                    'code': coupon.code, 
                    'discount_percentage': coupon.discount_percentage
                } for coupon in order.coupons.all()
            },
            'applied_referral_coupons': {
                coupon.code: {
                    'code': coupon.code, 
                    'discount_percentage': coupon.discount_percentage
                } for coupon in order.referral_coupons.all()
            },
            'tax': order.tax,
            'shipping': order.shipping_price,
            'total': order.total
        }
        return render(request, 'userside/order_success.html', context)
    
    except Exception as e:
        log_payment_event('SUCCESS_PAGE_ERROR', order_id, error=str(e))
        messages.error(request, "Error loading order details.")
        return redirect('userside:checkout')

@login_required(login_url='userside:login')
def order_failure(request, order_id):
    """Enhanced order failure page with retry payment option"""
    try:
        order = get_object_or_404(Order, id=order_id, user=request.user)
        
        log_payment_event('FAILURE_PAGE_ACCESSED', order.order_id, {
            'payment_method': order.payment_method,
            'is_paid': order.is_paid,
            'stock_unchanged': True
        })
        
        return render(request, 'userside/order_failure.html', {
            'order': order,
            'retry_url': f"/payment/initiate/{order.id}/",
        })
    except Exception as e:
        log_payment_event('FAILURE_PAGE_ERROR', order_id, error=str(e))
        messages.error(request, "Error loading order details.")
        return redirect('userside:checkout')
    
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from adminside.models import Address
import re

@login_required
def save_address_checkout(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        phone = request.POST.get('phone', '').strip()
        address_line1 = request.POST.get('street_address', '').strip()  # Changed from address_line1 to street_address
        address_line2 = request.POST.get('address_line2', '').strip()
        city = request.POST.get('city', '').strip()
        state = request.POST.get('state', '').strip()
        postal_code = request.POST.get('postal_code', '').strip()
        country = request.POST.get('country', '').strip()

        # Server-side validation
        errors = []
        if not re.match(r'^[A-Za-z ]+$', full_name):
            errors.append("Full name must contain only letters and spaces.")
        if not re.match(r'^[0-9]{10}$', phone):
            errors.append("Phone must be exactly 10 digits.")
        if phone == '0000000000':
            errors.append("Phone number cannot be all zeros.")
        if not address_line1:
            errors.append("Address Line 1 is required.")
        if not city:
            errors.append("City is required.")
        if not state:
            errors.append("State is required.")
        if not postal_code:
            errors.append("Postal code is required.")
        if not country:
            errors.append("Country is required.")

        # Check for duplicate address
        if Address.objects.filter(
            user=request.user,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            postal_code=postal_code,
            country=country
        ).exists():
            errors.append("This address already exists.")

        if errors:
            return JsonResponse({'success': False, 'errors': errors}, status=400)

        # Create address
        address = Address.objects.create(
            user=request.user,
            full_name=full_name,
            phone=phone,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            postal_code=postal_code,
            country=country,
            is_default=(not Address.objects.filter(user=request.user).exists())  # Set as default if first address
        )
        return JsonResponse({
            'success': True,
            'address_id': address.id,
            'is_default': address.is_default,
            'message': 'Address saved successfully'
        })
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)


@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def address_list(request):
    addresses = Address.objects.filter(user=request.user)
    return render(request, 'userside/my_addresses.html', {'addresses': addresses})

# ===========================# Wishlist Views# ===========================
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from adminside.models import Product, Wishlist
from django.shortcuts import get_object_or_404

@require_POST
@login_required
def add_to_wishlist(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    wishlist_item, created = Wishlist.objects.get_or_create(
        user=request.user,
        product=product
    )
    if created:
        message = 'Product added to wishlist!'
    else:
        message = 'Product is already in your wishlist.'
    wishlist_count = Wishlist.objects.filter(user=request.user).count()
    return JsonResponse({
        'success': True,
        'message': message,
        'wishlist_count': wishlist_count,
        'is_in_wishlist': True
    })

@require_POST
@login_required
def remove_from_wishlist(request, product_id):
    Wishlist.objects.filter(user=request.user, product_id=product_id).delete()
    wishlist_count = Wishlist.objects.filter(user=request.user).count()
    return JsonResponse({
        'success': True,
        'message': 'Product removed from wishlist.',
        'wishlist_count': wishlist_count,
        'is_in_wishlist': False
    })

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def wishlist_page(request):
    wishlist_items = Wishlist.objects.filter(user=request.user).select_related('product')
    return render(request, 'userside/wishlist.html', {'wishlist_items': wishlist_items})

from django.shortcuts import get_object_or_404, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.contrib import messages
from django.db import transaction
from adminside.models import OrderItem, ProductVariant, Order
import logging

logger = logging.getLogger(__name__)

@login_required(login_url='userside:login')
@require_POST
def return_order_item(request, item_id):
    # Fetch the order item with validation
    item = get_object_or_404(
        OrderItem,
        id=item_id,
        order__user=request.user,
        is_cancelled=False,
        is_returned=False,
        is_refunded_to_wallet=False,
        order__status='delivered'
    )

    # Validate return reason
    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, "Please provide a reason for returning the item.")
        return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

    with transaction.atomic():
        try:
            # Calculate refund amount
            order = item.order
            # Count unique products in the order
            unique_products_count = order.items.values('product__id').distinct().count()
            if unique_products_count == 0:
                logger.error(f"No unique products found in order {order.order_id} for refund calculation.")
                messages.error(request, "Error: No items in the order.")
                return HttpResponseRedirect(reverse('userside:order_detail', args=[order.order_id]))

            # Base price: use discounted_price if available, else price
            item_price = item.discounted_price or item.price
            if item_price is None or item_price <= 0:
                logger.error(f"Invalid price for item {item.id}: discounted_price={item.discounted_price}, price={item.price}")
                messages.error(request, "Error: Invalid item price.")
                return HttpResponseRedirect(reverse('userside:order_detail', args=[order.order_id]))

            item_total = item_price * item.quantity
            logger.info(f"Item {item.id} (Product: {item.product.name}): Base price=₹{item_price:.2f}, Quantity={item.quantity}, Item total=₹{item_total:.2f}")

            # Equal distribution of order-level discounts by unique products
            coupon_discount = order.coupon_discount or Decimal('0.00')
            referral_discount = order.referral_coupon_discount or Decimal('0.00')
            coupon_discount_per_product = (coupon_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')
            referral_discount_per_product = (referral_discount / unique_products_count).quantize(Decimal('0.01')) if unique_products_count > 0 else Decimal('0.00')
            total_discount_per_product = coupon_discount_per_product + referral_discount_per_product

            logger.info(f"Order {order.order_id}: Unique products={unique_products_count}, Coupon discount=₹{coupon_discount:.2f}, Referral discount=₹{referral_discount:.2f}")
            logger.info(f"Item {item.id}: Coupon discount per product=₹{coupon_discount_per_product:.2f}, Referral discount per product=₹{referral_discount_per_product:.2f}, Total discount per product=₹{total_discount_per_product:.2f}")

            # Calculate refund amount
            refund_amount = (item_total - total_discount_per_product).quantize(Decimal('0.01'))
            refund_amount = max(refund_amount, Decimal('0.00'))  # Ensure non-negative refund
            logger.info(f"Item {item.id}: Refund amount after discounts=₹{refund_amount:.2f}")

            # Mark item as returned and store refund amount
            item.is_returned = True
            item.return_reason = reason
            item.refund_amount = refund_amount
            item.save()

            # Restore stock
            if item.variant:
                item.variant.stock += item.quantity
                item.variant.save()
                logger.info(f"Stock restored: {item.quantity} units for {item.product.name} ({item.color_name}, {item.size})")
            else:
                logger.warning(f"No variant for OrderItem {item.id}; stock not restored.")

            # Mark order as return requested
            order.return_requested = True
            order.save()

            # Check if any other items in the order are accepted (refunded)
            has_accepted_items = order.items.filter(is_refunded_to_wallet=True).exists()
            if has_accepted_items:
                # Mark rejected items as delivered (is_returned=False)
                rejected_items = order.items.filter(is_returned=False, return_reason__startswith='Rejected: ')
                for rejected_item in rejected_items:
                    rejected_item.return_reason = f"{rejected_item.return_reason} (Marked as delivered due to other accepted returns)"
                    rejected_item.save()
                    logger.info(f"Item {rejected_item.id} in order {order.order_id} marked as delivered due to other accepted returns.")

            messages.success(request, f"Return request for '{item.product.name}' submitted. Awaiting admin approval. Estimated refund: ₹{item.refund_amount:.2f}")
            logger.info(f"Return request for item {item.id} in order {order.order_id} completed successfully.")

        except Exception as e:
            logger.error(f"Error processing return for item {item.id} in order {order.order_id}: {str(e)}", exc_info=True)
            messages.error(request, f"Error processing return: {str(e)}")
            return HttpResponseRedirect(reverse('userside:order_detail', args=[order.order_id]))

    return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from adminside.models import ProductVariant
from django.http import JsonResponse
from adminside.models import ProductVariant, Size

def get_variant_stock(request, color_id, size):
    try:
        # Get size object based on size name (e.g., "M", "L")
        size_obj = Size.objects.get(name=size)
        
        # Get the matching product variant
        variant = ProductVariant.objects.get(color_variant_id=color_id, size=size_obj)
        
        # Return the stock
        return JsonResponse({'stock': variant.stock})
    
    except Size.DoesNotExist:
        return JsonResponse({'stock': -1, 'message': 'Invalid size selected.'}, status=400)

    except ProductVariant.DoesNotExist:
        return JsonResponse({'stock': 0, 'message': 'Variant not found.'}, status=404)

    except Exception as e:
        return JsonResponse({'stock': -1, 'message': 'Server error.'}, status=500)
    
# views.py
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from adminside.models import Product, ProductVariant, Size, ColorVariant

@require_GET
@login_required
def product_variants_api(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    size_filter = request.GET.get('size')
    variants = ProductVariant.objects.filter(product=product, is_listed=True).select_related('size', 'color_variant')

    if size_filter:
        variants = variants.filter(size__name=size_filter)

    # Get unique sizes for the product
    unique_sizes = Size.objects.filter(productvariant__product=product, productvariant__is_listed=True).distinct()
    size_options = [size.name for size in unique_sizes]

    # Prepare variant data
    variant_data = [{
        'size': variant.size.name,
        'color_variant': {
            'id': variant.color_variant.id,
            'color_name': variant.color_variant.color_name,
            'color_hex': variant.color_variant.color_hex  
        },
        'stock': variant.stock
    } for variant in variants]

    print(f"Product ID: {product_id}, Size Filter: {size_filter}, Sizes: {size_options}, Variants: {variant_data}")  # Debug log
    return JsonResponse({
        'success': True,
        'sizes': size_options,  # Send all available sizes
        'variants': variant_data
    })

from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils import timezone
import pytz
from decimal import Decimal
from datetime import date
from weasyprint import HTML
from adminside.models import Order, OrderItem, ProductOffer, CategoryOffer
import logging

logger = logging.getLogger(__name__)

def download_invoice(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    
    # Convert order creation time to IST
    ist_tz = pytz.timezone('Asia/Kolkata')
    order_time_ist = order.created_at.astimezone(ist_tz)
    
    # Fetch payment method
    payment_method = order.get_payment_method_display() if order.payment_method else 'Not specified'
    
    # Determine payment status for COD orders
    is_paid = order.is_paid
    if order.payment_method == 'COD':
        is_paid = order.status == 'delivered'
    
    # Get all items and delivered items
    all_items = order.items.all()
    delivered_items = order.items.filter(is_cancelled=False, is_returned=False)
    
    # Calculate original price and collect offer details for delivered items
    original_price = Decimal('0.00')
    offer_details = []
    
    for item in delivered_items:
        # Get the base price from the item
        base_price = item.price
        quantity = item.quantity
        item_original_total = base_price * quantity
        
        # Initialize discount details
        offer_applied = item.applied_offer
        discount_percentage = Decimal('0.00')
        discount_amount = Decimal('0.00')
        discounted_unit_price = item.discounted_price or base_price
        item_discounted_total = discounted_unit_price * quantity
        
        # Check for ProductOffer or CategoryOffer for additional context
        if not offer_applied and item.discounted_price and item.discounted_price < base_price:
            discount_amount = (base_price - item.discounted_price) * quantity
            discount_percentage = (discount_amount / item_original_total * 100).quantize(Decimal('0.01'))
            product_offer = ProductOffer.objects.filter(
                product=item.product,
                is_active=True,
                is_deleted=False,
                start_date__lte=date.today(),
                end_date__gte=date.today()
            ).first()
            category_offer = CategoryOffer.objects.filter(
                category=item.product.category,
                is_active=True,
                is_deleted=False,
                start_date__lte=date.today(),
                end_date__gte=date.today()
            ).first()
            if product_offer:
                offer_applied = f"Product Offer: {product_offer.name} ({discount_percentage}%)"
            elif category_offer:
                offer_applied = f"Category Offer: {category_offer.name} ({discount_percentage}%)"
            else:
                offer_applied = f"Offer ({discount_percentage}%)"
        
        original_price += item_original_total
        
        offer_details.append({
            'item': item,
            'original_price': item_original_total,
            'offer_applied': offer_applied,
            'discount_amount': discount_amount,
            'discounted_total': item_discounted_total,
            'discounted_unit_price': discounted_unit_price
        })
    
    # Initialize coupon information
    coupon_info = {
        'coupon_code': order.coupon_code or 'N/A',
        'discount_percentage': Decimal('0.00'),
        'discount_amount': Decimal('0.00'),
        'type': order.coupon_type or 'Coupon'
    }
    
    # Apportion coupon discount based on delivered items
    total_items_count = all_items.count()
    delivered_items_count = delivered_items.count()
    if total_items_count > 0 and delivered_items_count > 0:
        # Check for regular coupon first
        coupon = order.coupons.filter(
            valid_from__lte=date.today(),
            valid_until__gte=date.today()
        ).first()
        if coupon and order.coupon_discount and order.coupon_discount > 0:
            coupon_per_item = order.coupon_discount / total_items_count
            coupon_info['discount_amount'] = (coupon_per_item * delivered_items_count).quantize(Decimal('0.01'))
            coupon_info['coupon_code'] = coupon.code
            coupon_info['discount_percentage'] = coupon.discount_percentage
            coupon_info['type'] = 'Coupon'
        # Check for referral coupon
        elif order.referral_coupon_discount and order.referral_coupon_discount > 0:
            referral_coupon = order.referral_coupons.filter(
                valid_from__lte=date.today(),
                valid_until__gte=date.today(),
                used=False
            ).first()
            coupon_per_item = order.referral_coupon_discount / total_items_count
            coupon_info['discount_amount'] = (coupon_per_item * delivered_items_count).quantize(Decimal('0.01'))
            coupon_info['coupon_code'] = referral_coupon.code if referral_coupon else order.coupon_code or 'N/A'
            coupon_info['discount_percentage'] = (
                referral_coupon.discount_percentage if referral_coupon else
                order.coupon_discount_percentage or
                (order.referral_coupon_discount / original_price * 100).quantize(Decimal('0.01')) if original_price > 0 else Decimal('0.00')
            )
            coupon_info['type'] = 'Referral Coupon'
        # Fallback to stored coupon details if no active coupon is found but discount exists
        elif order.coupon_discount and order.coupon_discount > 0:
            coupon_per_item = order.coupon_discount / total_items_count
            coupon_info['discount_amount'] = (coupon_per_item * delivered_items_count).quantize(Decimal('0.01'))
            coupon_info['coupon_code'] = order.coupon_code or 'N/A'
            coupon_info['discount_percentage'] = (
                order.coupon_discount_percentage or
                (order.coupon_discount / original_price * 100).quantize(Decimal('0.01')) if original_price > 0 else Decimal('0.00')
            )
            coupon_info['type'] = order.coupon_type or 'Coupon'
    
    # Calculate final total (only delivered items)
    final_total = sum(item['discounted_total'] for item in offer_details) - coupon_info['discount_amount'] + order.shipping_price + order.tax
    
    context = {
        'order': order,
        'order_time_ist': order_time_ist,
        'payment_method': payment_method,
        'is_paid': is_paid,
        'request': request,
        'offer_details': offer_details,
        'coupon_info': coupon_info,
        'shipping_price': order.shipping_price,
        'tax': order.tax,
        'final_total': final_total
    }
    
    try:
        # Render the HTML template to a string
        html_string = render_to_string('userside/invoice.html', context)
        
        # Convert HTML to PDF
        pdf_file = HTML(string=html_string).write_pdf()
        
        # Create HTTP response with PDF
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="invoice_{order.order_id}.pdf"'
        response.write(pdf_file)
        
        logger.info(f"Invoice downloaded for order {order.order_id} by user {request.user.email}")
        return response
    
    except Exception as e:
        logger.error(f"Error generating invoice for order {order.order_id}: {e}", exc_info=True)
        messages.error(request, "Error generating invoice.")
        return redirect('userside:order_detail', order_id=order.order_id)
import logging
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from decimal import Decimal
from adminside.models import Wallet, Transaction

logger = logging.getLogger(__name__)

@login_required(login_url='userside:login')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def wallet(request):
    # Get or create the user's wallet
    wallet, created = Wallet.objects.get_or_create(user=request.user)

    # Handle form submission for adding money
    if request.method == 'POST' and 'add_money' in request.POST:
        try:
            amount = Decimal(request.POST.get('amount'))
            if amount <= 0:
                messages.error(request, "Amount must be greater than zero.")
            else:
                # Create a CREDIT transaction
                Transaction.objects.create(
                    wallet=wallet,
                    transaction_type='CREDIT',
                    amount=amount,
                    description="Manual wallet top-up",
                )
                wallet.credit(amount)
                logger.info(f"User {request.user.email} added ₹{amount} to wallet. New balance: ₹{wallet.balance}")
                messages.success(request, f"₹{amount:.2f} added to your wallet successfully!")
                return redirect('userside:wallet')
        except ValueError:
            logger.error(f"Invalid amount entered by {request.user.email}.")
            messages.error(request, "Invalid amount. Please enter a valid number.")
        except Exception as e:
            logger.error(f"Error adding money to wallet for {request.user.email}: {e}", exc_info=True)
            messages.error(request, f"Error adding money: {e}")

    # Get transactions for the user's wallet
    transactions = Transaction.objects.filter(wallet=wallet).select_related('source_order').order_by('-transaction_date')
    
    # Pagination
    paginator = Paginator(transactions, 10)  # Show 10 transactions per page
    page_number = request.GET.get('page')
    transactions_page = paginator.get_page(page_number)

    return render(request, 'userside/wallet.html', {
        'wallet': wallet,
        'transactions': transactions_page,
    })
