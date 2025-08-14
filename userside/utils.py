from django.core.mail import send_mail
import random
from django.utils import timezone
from .models import EmailOTP
from django.conf import settings
from datetime import timedelta

def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, purpose='registration'):
    """Send OTP to user's email."""
    subject = "Your OTP Verification Code" if purpose == 'registration' else "Your Password Reset OTP"
    message = f"Your OTP is {otp}. Use this to {'verify your email' if purpose == 'registration' else 'reset your password'}. It is valid for 10 minutes."
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list, fail_silently=False)

def create_otp_for_user(user, purpose='registration'):
    """Generate and save OTP for user."""
    otp = generate_otp()
    expires_at = timezone.now() + timedelta(minutes=10)
    email_otp = EmailOTP.objects.create(
        user=user,
        otp=otp,
        purpose=purpose,
        expires_at=expires_at
    )
    send_otp_email(user.email, otp, purpose)
    return otp