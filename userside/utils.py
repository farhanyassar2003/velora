# userside/utils.py

from django.core.mail import send_mail
import random

def send_otp_email(email, otp):
    subject = "Your OTP Verification Code"
    message = f"Your OTP is {otp}. Use this to verify your email."
    from_email = "noreply@example.com"  # Replace with your actual sender
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)
