from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from .models import CustomUser

# ===========================# User Authentication Forms# ===========================

from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser
from django.core.exceptions import ValidationError

class CustomUserCreationForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=False)
    email = forms.EmailField(required=True)
    phone_number = forms.CharField(max_length=15, required=True)
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'password1', 'password2')

    def clean_phone_number(self):
        phone_number = self.cleaned_data['phone_number']

        # Must be digits only
        if not phone_number.isdigit():
            raise forms.ValidationError("Phone number must contain only digits.")

        # Must be exactly 10 digits
        if len(phone_number) != 10:
            raise forms.ValidationError("Phone number must be exactly 10 digits.")

        # Cannot be all zeros
        if phone_number == "0000000000":
            raise forms.ValidationError("Phone number cannot be all zeros.")

        return phone_number

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.phone_number = self.cleaned_data['phone_number']
        if commit:
            user.save()
        return user


class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True)

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True)

# ===========================# User Profile Management Forms# ===========================

class EditProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email','phone_number', 'profile_image']

class ChangePasswordForm(PasswordChangeForm):
    pass