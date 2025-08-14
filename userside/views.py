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

def logout_view(request):
    logout(request)
    return redirect('userside:landing_page')

def login_redirect(request):
    if request.user.is_authenticated:
        return redirect('userside:landing_page')
    else:
        return redirect('userside:login')

# ===========================# Landing Page and Category Views# ===========================
@never_cache
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

logger = logging.getLogger(__name__)

def product_detail_view(request, id):
    product = get_object_or_404(Product, id=id, is_listed=True, is_deleted=False)
    if not product.is_active or not product.is_listed:
        return redirect('userside:product_list')

    color_variants = product.color_variants.filter(
        is_listed=True,
        variants__is_listed=True
    ).distinct()
    sizes = product.variants.filter(is_listed=True).values_list('size__name', flat=True).distinct()
    variants = product.variants.filter(is_listed=True)  # Filtered variants

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

    if product_offer:
        product_discount = Decimal(product_offer.discount_percentage)
        discount = original_price * (product_discount / Decimal('100'))
        discounted_price = original_price - discount
        offer = product_offer
        offer_type = 'Product Offer'
    elif category_offer:
        category_discount = Decimal(category_offer.discount_percentage)
        discount = original_price * (category_discount / Decimal('100'))
        discounted_price = original_price - discount
        offer = category_offer
        offer_type = 'Category Offer'

    related_products = Product.objects.filter(
        category=product.category, is_listed=True, is_deleted=False
    ).exclude(id=product.id)[:4]

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
    }
    return render(request, 'userside/product_detail.html', context)
def clear_filters(request):
    return redirect('userside:product_list')

# ===========================# User Profile and Address Management# ===========================
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from adminside.models import Order, Address

@login_required(login_url='userside:login')
def user_profile(request):
    user = request.user
    orders = Order.objects.filter(user=user).order_by('-created_at')
    user_addresses = Address.objects.filter(user=user)
    
    # Fix: Count users where this user is the referrer
    from django.contrib.auth import get_user_model
    User = get_user_model()
    referred_count = User.objects.filter(referred_by=user).count()

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

@login_required(login_url='login')
def edit_profile(request):
    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            new_email = form.cleaned_data.get('email')
            User = get_user_model()
            old_email = User.objects.get(pk=request.user.pk).email
            
            updated_user = form.save(commit=False)
            if new_email != old_email:
                otp = str(random.randint(100000, 999999))
                updated_user.otp = otp
                updated_user.temp_email = new_email # Store temporarily
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

@login_required(login_url='login')
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
@login_required(login_url='login')
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
    item = get_object_or_404(
        OrderItem,
        id=item_id,
        order__user=request.user,
        is_cancelled=False
    )

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, "Please provide a reason for cancellation.")
        return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

    with transaction.atomic():
        item.is_cancelled = True
        item.cancel_reason = reason
        item.save()

        # Restore stock for the specific ProductVariant
        if item.variant:
            item.variant.stock += item.quantity
            item.variant.save()
            messages.success(request, f"Item '{item.product.name} ({item.size})' cancelled successfully. Stock restored.")
        else:
            messages.warning(request, f"Item '{item.product.name} ({item.size})' cancelled, but no variant found to restore stock.")
            logger.warning(f"OrderItem {item.id} has no associated ProductVariant for stock update during cancellation.")

        # Credit wallet if payment was made via Wallet
        if item.order.payment_method == 'Wallet':
            wallet = get_object_or_404(Wallet, user=request.user)
            refund_amount = item.discounted_price * item.quantity
            wallet.credit(refund_amount)
            Transaction.objects.create(
                wallet=wallet,
                transaction_type='REFUND',
                amount=refund_amount,
                description=f"Refund for cancelled item '{item.product.name}' in order {item.order.order_id}",
                source_order=item.order
            )
            messages.success(request, f"₹{refund_amount:.2f} has been refunded to your wallet for the cancelled item.")

        # Update the parent order's status if all items are cancelled
        if all(i.is_cancelled for i in item.order.items.all()):
            item.order.status = 'cancelled'
            item.order.save()
            messages.info(request, f"Order {item.order.order_id} has been fully cancelled.")

    return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

@login_required(login_url='userside:login')
@require_POST
def cancel_entire_order(request, order_id):
    order = get_object_or_404(Order, order_id=order_id, user=request.user)
    reason = request.POST.get('reason', '').strip()

    if not reason:
        messages.error(request, "Please provide a reason to cancel the entire order.")
        return HttpResponseRedirect(reverse('userside:order_detail', args=[order.order_id]))

    if order.status in ['cancelled', 'delivered']:
        messages.warning(request, "This order cannot be cancelled.")
        return HttpResponseRedirect(reverse('userside:order_list'))

    with transaction.atomic():
        order.status = 'cancelled'
        order.cancel_reason = reason
        order.save()

        # Process each order item
        for item in order.items.all():
            if not item.is_cancelled:
                item.is_cancelled = True
                item.cancel_reason = reason
                item.save()

                if item.variant:
                    item.variant.stock += item.quantity
                    item.variant.save()
                else:
                    messages.warning(request, f"Warning: Item '{item.product.name} ({item.size})' in order {order.order_id} had no variant to restore stock.")
                    logger.warning(f"OrderItem {item.id} has no associated ProductVariant for stock update during entire order cancellation.")

        # Credit wallet if payment was made via Wallet
        if order.payment_method == 'Wallet':
            wallet = get_object_or_404(Wallet, user=request.user)
            refund_amount = order.total
            wallet.credit(refund_amount)
            Transaction.objects.create(
                wallet=wallet,
                transaction_type='REFUND',
                amount=refund_amount,
                description=f"Refund for cancelled order {order.order_id}",
                source_order=order
            )
            messages.success(request, f"₹{refund_amount:.2f} has been refunded to your wallet for the cancelled order.")

    messages.success(request, f"Order {order.order_id} has been fully cancelled.")
    return HttpResponseRedirect(reverse('userside:order_list'))
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
            size_name = request.POST.get('sizes[]') or request.POST.get('size')
            quantity = int(request.POST.get('quantity', 1))

            if not color_id or not size_name:
                return JsonResponse({'success': False, 'message': 'Please select both color and size.'}, status=400)

            color_variant = ColorVariant.objects.get(id=color_id)
            size = Size.objects.get(name=size_name)
            variant = ProductVariant.objects.get(product_id=product_id, color_variant=color_variant, size=size)

            if quantity <= 0:
                return JsonResponse({'success': False, 'message': 'Quantity must be greater than 0.'}, status=400)

            if quantity > variant.stock:
                return JsonResponse({'success': False, 'message': f'Requested quantity ({quantity}) exceeds available stock ({variant.stock}).'}, status=400)

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
                    return JsonResponse({'success': False, 'message': f'Exceeds stock limit. Maximum available is {variant.stock}.'}, status=400)
                cart_item.quantity = new_quantity
                cart_item.save()

            cart_count = CartItem.objects.filter(user=user).count()
            return JsonResponse({'success': True, 'message': 'Added to cart successfully.', 'cart_count': cart_count, 'product_name': cart_item.product.name})

        except ObjectDoesNotExist as e:
            logger.error("ObjectDoesNotExist error: %s", str(e))
            return JsonResponse({'success': False, 'message': f'Invalid data: {str(e)}'}, status=400)
        except ValueError as e:
            logger.error("ValueError: %s", str(e))
            return JsonResponse({'success': False, 'message': 'Invalid quantity value.'}, status=400)
        except Exception as e:
            logger.error("Unexpected error in add_to_cart: %s", str(e))
            traceback.print_exc()
            return JsonResponse({'success': False, 'message': 'An unexpected error occurred. Please try again later.'}, status=500)

@login_required(login_url='login')
def view_cart(request):
    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
    cart_items = cart_items.prefetch_related('product__variants')
    
    cart_items_with_stock = []
    total = Decimal('0.00')
    for item in cart_items:
        try:
            variant = item.product.variants.filter(
                color_variant__color_name=item.color_name,
                size__name=item.size
            ).first()
            item.stock = variant.stock if variant and variant.is_listed else 0
            
            # Calculate original and discounted prices
            item.original_price = item.product.price
            item.discounted_price = item.original_price
            item.discount = None
            item.offer = None
            item.offer_type = None

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
from django.db import transaction
from adminside.models import Coupon, Address, CartItem, ProductOffer, CategoryOffer, Order, OrderItem, ReferralCoupon, Wallet, Transaction

logger = logging.getLogger(__name__)

@login_required(login_url='userside:login')
def checkout_view(request):
    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
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
    return render(request, 'userside/checkout.html', context)
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

@login_required(login_url='userside:login')
def apply_referral_coupon(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            coupon_code = data.get('coupon_code', '').strip()
            
            if not coupon_code:
                return JsonResponse({'success': False, 'message': 'Please enter a referral coupon code.'})
            
            try:
                coupon = ReferralCoupon.objects.get(code=coupon_code, owner=request.user)
                if not coupon.is_valid():
                    return JsonResponse({'success': False, 'message': 'Referral coupon is invalid, expired, or already used.'})
                
                if 'referral_coupon_codes' not in request.session:
                    request.session['referral_coupon_codes'] = []
                
                if coupon_code in request.session['referral_coupon_codes']:
                    return JsonResponse({'success': False, 'message': 'Referral coupon already applied.'})
                
                request.session['referral_coupon_codes'].append(coupon_code)
                request.session.modified = True
                return JsonResponse({
                    'success': True,
                    'message': 'Referral coupon applied successfully!',
                    'coupon_discount': str(coupon.discount_percentage),
                    'coupon_code': coupon_code,
                    'coupon_type': 'referral'
                })
            except ReferralCoupon.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Invalid referral coupon code.'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid request.'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})



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

@login_required(login_url='userside:login')
def place_order(request):
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('userside:checkout')

    address_id = request.POST.get('address_id')
    payment_method = request.POST.get('payment_method')
    payment_gateway = request.POST.get('payment_gateway')

    # Validate inputs
    if not address_id:
        messages.error(request, 'Please select a shipping address.')
        return redirect('userside:checkout')

    if not payment_method:
        messages.error(request, 'Please select a payment method.')
        return redirect('userside:checkout')

    if payment_method == 'Online' and not payment_gateway:
        messages.error(request, 'Please select a payment gateway.')
        return redirect('userside:checkout')

    try:
        address = Address.objects.get(id=address_id, user=request.user)
    except Address.DoesNotExist:
        messages.error(request, 'Invalid address selected.')
        return redirect('userside:checkout')

    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
    if not cart_items:
        messages.error(request, 'Your cart is empty.')
        return redirect('userside:checkout')

    # Calculate totals and prepare order items
    subtotal = Decimal('0.00')
    total_discount = Decimal('0.00')
    cart_items_with_discounts = []

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
                messages.error(request, f'Invalid variant for {item.product.name} (Color: {item.color_name}, Size: {item.size})')
                return redirect('userside:checkout')

            # Check stock availability
            if variant.stock < item.quantity:
                messages.error(request, f'Insufficient stock for {item.product.name} (Color: {item.color_name}, Size: {item.size}). Available: {variant.stock}')
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
        if 'coupon_codes' in request.session and request.session['coupon_codes']:
            for coupon_code in request.session['coupon_codes'][:]:
                try:
                    coupon = Coupon.objects.get(code=coupon_code)
                    if coupon.is_valid(request.user):
                        coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                        applied_coupons.append(coupon)
                    else:
                        messages.error(request, f"Coupon {coupon_code} is no longer valid.")
                        request.session['coupon_codes'].remove(coupon_code)
                        request.session.modified = True
                except Coupon.DoesNotExist:
                    messages.error(request, f"Coupon {coupon_code} is invalid.")
                    request.session['coupon_codes'].remove(coupon_code)
                    request.session.modified = True

        # Check for referral coupon discounts
        referral_coupon_discount = Decimal('0.00')
        applied_referral_coupons = []
        if 'referral_coupon_codes' in request.session and request.session['referral_coupon_codes']:
            for coupon_code in request.session['referral_coupon_codes'][:]:
                try:
                    coupon = ReferralCoupon.objects.get(code=coupon_code, owner=request.user)
                    if coupon.is_valid():
                        referral_coupon_discount += (subtotal * coupon.discount_percentage) / Decimal('100.00')
                        applied_referral_coupons.append(coupon)
                    else:
                        messages.error(request, f"Referral coupon {coupon_code} is no longer valid.")
                        request.session['referral_coupon_codes'].remove(coupon_code)
                        request.session.modified = True
                except ReferralCoupon.DoesNotExist:
                    messages.error(request, f"Referral coupon {coupon_code} is invalid.")
                    request.session['referral_coupon_codes'].remove(coupon_code)
                    request.session.modified = True

        # Calculate final totals
        tax = Decimal('0.00')  # Update with your tax logic
        shipping_price = Decimal('0.00')  # Update with your shipping logic
        total = subtotal - total_discount - coupon_discount - referral_coupon_discount + tax + shipping_price

        # Validate COD restriction
        if payment_method == 'COD' and total > Decimal('1000.00'):
            messages.error(request, 'Cash on Delivery is not available for orders above ₹1000.')
            return redirect('userside:checkout')

        # Validate wallet balance for Wallet payment
        if payment_method == 'Wallet':
            try:
                wallet.debit(total)  # This checks balance and raises ValueError if insufficient
            except ValueError as e:
                messages.error(request, f'Insufficient wallet balance. You need ₹{total - wallet.balance:.2f} more.')
                return redirect('userside:checkout')

        # Create order
        order = Order.objects.create(
            user=request.user,
            address=address,
            subtotal=subtotal,
            discount=total_discount,
            coupon_discount=coupon_discount,
            referral_coupon_discount=referral_coupon_discount,
            tax=tax,
            shipping_price=shipping_price,
            total=total,
            payment_method=payment_method,
            payment_gateway=payment_gateway if payment_method == 'Online' else None,
            status='pending'
        )

        # Save order items and decrease stock
        stock_changes = []
        for cart_item in cart_items_with_discounts:
            item = cart_item['item']
            variant = cart_item['variant']
            variant.stock -= item.quantity
            if variant.stock < 0:
                logger.error(f"Negative stock for product {item.product.name} ({item.color_name}, {item.size}) in order {order.order_id}")
                messages.error(request, f'Invalid stock update for {item.product.name} ({item.color_name}, {item.size})')
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

            messages.success(request, 'Order placed successfully using wallet!')
            return redirect('userside:order_success', order_id=order.id)

        elif payment_method == 'Online':
            if payment_gateway == 'razorpay':
                # Clear cart for online payment after successful payment (handled in initiate_payment)
                return redirect('userside:initiate_payment', order_id=order.id)
            else:
                messages.error(request, 'Unsupported payment gateway selected.')
                return redirect('userside:checkout')
        else:  # COD
            # Mark COD orders as paid
            order.is_paid = True
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

            messages.success(request, 'Order placed successfully!')
            return redirect('userside:order_success', order_id=order.id)

    return redirect('userside:checkout')

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from pytz import timezone as pytz_timezone

from django.shortcuts import render, get_object_or_404, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.contrib import messages
from pytz import timezone as pytz_timezone
from adminside.models import Order, OrderItem

@login_required
def order_detail(request, order_id):
    order = get_object_or_404(Order, order_id=order_id, user=request.user)
    
    # Fetch address
    address = order.address if order.address else None
    
    # Fetch payment method
    payment_method = order.get_payment_method_display() if order.payment_method else 'Not specified'
    
    # Check if all items are cancelled individually
    all_items_cancelled = all(item.is_cancelled for item in order.items.all())
    
    # Convert order creation time to IST
    ist_tz = pytz_timezone('Asia/Kolkata')
    order_time_ist = order.created_at.astimezone(ist_tz)
    
    # Determine payment status for COD orders
    is_paid = order.is_paid
    if order.payment_method == 'cod' and order.status != 'delivered':
        is_paid = False
    elif order.payment_method == 'cod' and order.status == 'delivered':
        is_paid = True
    
    context = {
        'order': order,
        'address': address,
        'payment_method': payment_method,
        'all_items_cancelled': all_items_cancelled,
        'order_time_ist': order_time_ist,
        'is_paid': is_paid,
    }
    return render(request, 'userside/orders/order_detail.html', context)
@login_required(login_url='userside:login')
def initiate_payment(request, order_id):
    """Enhanced payment initiation without stock deduction"""
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
        
        # Initialize Razorpay client with detailed error handling
        try:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            client.payment.all({'count': 1})  # Simple API call to test credentials
        except razorpay.errors.BadRequestError as e:
            log_payment_event('AUTH_ERROR', order.order_id, error=str(e))
            messages.error(request, "Payment service authentication failed. Please contact support.")
            return redirect('userside:checkout')
        except Exception as e:
            log_payment_event('CLIENT_INIT_ERROR', order.order_id, error=str(e))
            messages.error(request, "Payment service is temporarily unavailable. Please try again later.")
            return redirect('userside:checkout')
        
        # Create Razorpay order with enhanced error handling
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
            'razorpay_order_id': razorpay_order['id'],
            'debug': settings.DEBUG
        })
        
    except Exception as e:
        log_payment_event('INITIATE_UNEXPECTED_ERROR', order_id, error=str(e))
        messages.error(request, "An unexpected error occurred. Please try again.")
        return redirect('userside:checkout')

@login_required(login_url='userside:login')
@require_POST
def verify_payment(request, order_id):
    """Enhanced payment verification with SweetAlert message"""
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
                
                log_payment_event('COUPONS_PROCESSED', order.order_id, {
                    'regular_coupons': regular_coupons_processed,
                    'referral_coupons': referral_coupons_processed
                })
                
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
                'name': item.product.name,
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
import re

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
    item = get_object_or_404(
        OrderItem,
        id=item_id,
        order__user=request.user,
        is_cancelled=False,
        is_returned=False,
        is_refunded_to_wallet=False,
        order__status='delivered'
    )

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, "Please provide a reason for returning the item.")
        return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

    with transaction.atomic():
        # Mark item as returned
        item.is_returned = True
        item.return_reason = reason
        item.save()

        # Restore stock
        if item.variant:
            item.variant.stock += item.quantity
            item.variant.save()
            logger.info(f"Stock restored: {item.quantity} units for {item.product.name} ({item.color_name}, {item.size})")
        else:
            logger.warning(f"No variant for OrderItem {item.id}; stock not restored.")

        # Mark order as return requested
        order = item.order
        order.return_requested = True
        order.save()

        messages.success(request, f"Return request for '{item.product.name}' submitted. Awaiting admin approval.")

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

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from weasyprint import HTML
from adminside.models import Order
from django.contrib.auth.decorators import login_required
from pytz import timezone as pytz_timezone

@login_required
def download_invoice(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    
    # Convert order creation time to IST
    ist_tz = pytz_timezone('Asia/Kolkata')
    order_time_ist = order.created_at.astimezone(ist_tz)
    
    # Fetch payment method consistent with order_detail view
    payment_method = order.get_payment_method_display() if order.payment_method else 'Not specified'
    
    # Determine payment status for COD orders
    is_paid = order.is_paid
    if order.payment_method == 'cod' and order.status != 'delivered':
        is_paid = False
    elif order.payment_method == 'cod' and order.status == 'delivered':
        is_paid = True

    context = {
        'order': order,
        'order_time_ist': order_time_ist,
        'payment_method': payment_method,
        'address': order.address,
        'request': request,
        'is_paid': is_paid,  # Add is_paid to context for consistency
    }
    
    # Render the HTML template to a string
    html_string = render_to_string('userside/invoice.html', context)
    
    # Convert HTML to PDF
    pdf_file = HTML(string=html_string).write_pdf()
    
    # Create HTTP response with PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="invoice_{order.order_id}.pdf"'
    response.write(pdf_file)
    
    return response

import logging
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from decimal import Decimal
from adminside.models import Wallet, Transaction

logger = logging.getLogger(__name__)

@login_required
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
                logger.info(f"User {request.user.email} added ₹{amount} to wallet.")
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