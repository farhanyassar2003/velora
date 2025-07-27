from django import forms
from django.forms import modelformset_factory, inlineformset_factory
from django.forms.widgets import ClearableFileInput
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
import re

from .models import (
    Product, ProductImage,
    Category, UserProfile, ProductVariant, ColorVariant, Size
)

# --------------------------
# Admin User Creation Form
# --------------------------
class AdminUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    is_staff = forms.BooleanField(required=False, initial=True)
    is_superuser = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name", "is_staff", "is_superuser", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        user.is_staff = self.cleaned_data["is_staff"]
        user.is_superuser = self.cleaned_data["is_superuser"]
        if commit:
            user.save()
        return user

# --------------------------
# User Filtering & Status
# --------------------------
class UserFilterForm(forms.Form):
    search = forms.CharField(required=False)
    status = forms.ChoiceField(
        required=False,
        choices=[('all', 'All'), ('active', 'Active'), ('blocked', 'Blocked')]
    )

class UserStatusForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['status']
        widgets = {
            'status': forms.Select(choices=(('active', 'Active'), ('blocked', 'Blocked')))
        }

    def __init__(self, *args, **kwargs):
        super(UserStatusForm, self).__init__(*args, **kwargs)
        if self.instance and hasattr(self.instance, 'user'):
            self.fields['status'].initial = self.instance.status

# --------------------------
# Product Image Upload
# --------------------------
class MultiFileInput(ClearableFileInput):
    allow_multiple_selected = True

    def value_from_datadict(self, data, files, name):
        return files.getlist(name)

ProductImageFormSet = modelformset_factory(
    ProductImage,
    fields=('image',),
    extra=3,
    max_num=3,
    widgets={
        'image': ClearableFileInput(attrs={
            'class': 'form-control',
            'multiple': False,
        })
    }
)

# --------------------------
# Category Form
# --------------------------
class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description', 'is_listed', 'is_deleted']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter category name'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter category description (optional)'
            }),
            'is_listed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_deleted': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name:
            raise ValidationError("Category name is required.")

        # Unique check case-insensitive
        qs = Category.objects.filter(name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("A category with this name already exists.")
        return name

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('is_listed') and cleaned_data.get('is_deleted'):
            raise ValidationError("A category cannot be both listed and deleted at the same time.")
        return cleaned_data

# --------------------------
# Product Form
# --------------------------
# forms.py - Updated forms with fixes

from django import forms
from django.forms import inlineformset_factory
from .models import Product, ProductVariant, ProductImage, Size, ColorVariant, Category
import re

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = [
            'name', 'category', 'description', 'price', 'materials',  # Added materials field
            'is_active', 'is_listed', 'is_deleted'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter product name'
            }),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter product description'
            }),
            'price': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter price'
            }),
            'materials': forms.TextInput(attrs={  # Added materials widget
                'class': 'form-control',
                'placeholder': 'Enter materials (e.g., Cotton, Polyester)'
            }),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_listed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_deleted': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].queryset = Category.objects.filter(is_listed=True, is_deleted=False)
        self.fields['materials'].required = False  # Make materials optional

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not re.match(r'^[A-Za-z\s]+$', name):
            raise forms.ValidationError("Product name should contain only alphabets and spaces.")
        return name

    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is None or price <= 0:
            raise forms.ValidationError("Price must be a positive number.")
        return price

# In adminside/forms.py
from django import forms
from .models import ProductVariant, ColorVariant, Size

class ProductVariantForm(forms.ModelForm):
    color_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter color name'
        }),
        required=True
    )
    
    color_hex = forms.CharField(
        max_length=7,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'type': 'color',
            'placeholder': '#000000'
        }),
        required=False,
        initial='#000000'
    )

    class Meta:
        model = ProductVariant
        fields = ['color_name', 'color_hex', 'size', 'stock']
        widgets = {
            'size': forms.Select(attrs={'class': 'form-control'}),
            'stock': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter stock quantity',
                'min': 0
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['size'].queryset = Size.objects.all()
        if self.instance and self.instance.pk and self.instance.color_variant:
            self.fields['color_name'].initial = self.instance.color_variant.color_name
            self.fields['color_hex'].initial = self.instance.color_variant.color_hex

    def clean(self):
        cleaned_data = super().clean()
        color_name = cleaned_data.get('color_name')
        if not color_name:
            raise forms.ValidationError("Color name is required.")
        return cleaned_data

    def save(self, commit=True, product=None):
        if not self.is_valid():
            raise forms.ValidationError(f"Form is invalid: {self.errors.as_text()}")
        
        color_name = self.cleaned_data.get('color_name')
        color_hex = self.cleaned_data.get('color_hex', '#000000')
        instance = super().save(commit=False)
        
        if product:
            color_variant, _ = ColorVariant.objects.get_or_create(
                product=product,
                color_name=color_name,
                defaults={'color_hex': color_hex}
            )
            if color_hex and color_variant.color_hex != color_hex:
                color_variant.color_hex = color_hex
                color_variant.save()
            
            instance.color_variant = color_variant
        
        if commit:
            instance.save()
        return instance


class ProductImageForm(forms.ModelForm):
    class Meta:
        model = ProductImage
        fields = ['image']
        widgets = {
            'image': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            })
        }


# Formsets
ProductVariantFormSet = inlineformset_factory(
    Product, ProductVariant,
    form=ProductVariantForm,
    extra=1,
    can_delete=True,
    min_num=1,
    validate_min=True
)

ProductImageFormSet = inlineformset_factory(
    Product, ProductImage,
    form=ProductImageForm,
    extra=3,  # Allow exactly 3 images
    max_num=3,
    can_delete=True,
    min_num=3,
    validate_min=True
)