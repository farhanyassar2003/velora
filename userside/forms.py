from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from .models import CustomUser

# ===========================# User Authentication Forms# ===========================

from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    referral_code = forms.CharField(max_length=10, required=False, label="Referral Code (Optional)")

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'password1', 'password2')

    def clean_referral_code(self):
        referral_code = self.cleaned_data.get('referral_code', '').strip().upper()
        if referral_code:
            if not CustomUser.objects.filter(referral_code__iexact=referral_code).exists():
                raise forms.ValidationError("Invalid referral code.")
        return referral_code

    def clean_email(self):
        email = self.cleaned_data.get('email').strip()
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number').strip()
        if not phone_number:
            raise forms.ValidationError("Phone number is required.")
        return phone_number

from django import forms
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import get_user_model

User = get_user_model()

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control with-icon',
            'id': 'id_email',
            'placeholder': 'Enter your email'
        })
    )

    def clean_email(self):
        email = self.cleaned_data['email']
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("No account found with this email.")
        return email

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True)

class ResetPasswordForm(SetPasswordForm):
    class Meta:
        model = User
        fields = ['new_password1', 'new_password2']

# ===========================# User Profile Management Forms# ===========================

from django import forms
from .models import CustomUser

class EditProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'profile_image']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure profile_image is not required
        self.fields['profile_image'].required = False

class ChangePasswordForm(PasswordChangeForm):
    pass