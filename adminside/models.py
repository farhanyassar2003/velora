from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from django.conf import settings
from django import forms
from PIL import Image
import uuid
from django.contrib.auth import get_user_model
from django.db.models import Sum
 

# ===========================# Global/Utility Definitions# ===========================
User = get_user_model()


class EmailAuthenticationForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

# ===========================# AUTH & USER PROFILE# ===========================
class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    mobile = models.CharField(max_length=15)
    status = models.CharField(
        max_length=10,
        choices=(('active', 'active'), ('blocked', 'blocked')),
        default='active'
    )
    def __str__(self):
        return self.user.email

# ===========================# CATEGORY MODEL# ===========================
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    is_listed = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False) # Soft delete flag
    def __str__(self):
        return self.name

# ===========================# PRODUCT, IMAGE, SIZE, REVIEW# ===========================
from django.db import models
from django.db.models import Sum

class Size(models.Model):
    name = models.CharField(max_length=10, unique=True)  # e.g., XS, S, M, L, XL
    def __str__(self):
        return self.name



class Product(models.Model):
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    description = models.TextField(blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='products/', blank=True, null=True)
    materials = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    is_listed = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    reviews = models.ManyToManyField('Review', related_name='products_with_review')

    def __str__(self):
        return self.name

    def get_primary_image(self):
        image_obj = self.product_images.first()
        return image_obj.image.url if image_obj else None

    @property
    def total_stock(self):
        return self.variants.aggregate(total=Sum('stock'))['total'] or 0

class ColorVariant(models.Model):
    is_listed = models.BooleanField(default=True)
    product = models.ForeignKey(Product, related_name='color_variants', on_delete=models.CASCADE)
    color_name = models.CharField(max_length=50)
    color_hex = models.CharField(max_length=7)  # e.g., #FF5733
    image = models.ImageField(upload_to='product_colors/', blank=True, null=True)

    def __str__(self):
        return f"{self.product.name} - {self.color_name}"

class ProductVariant(models.Model):
    product = models.ForeignKey(Product, related_name='variants', on_delete=models.CASCADE)
    is_listed = models.BooleanField(default=True)
    color_variant = models.ForeignKey(ColorVariant, on_delete=models.CASCADE, related_name='variants')
    size = models.ForeignKey(Size, on_delete=models.CASCADE)
    stock = models.PositiveIntegerField()

    class Meta:
        unique_together = ('product', 'color_variant', 'size')

    def __str__(self):
        return f"{self.product.name} - {self.color_variant.color_name} - {self.size.name}"

class ProductImage(models.Model):
    image = models.ImageField(upload_to='products_image/', blank=True, null=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product_images', null=True, blank=True)
    color_variant = models.ForeignKey(ColorVariant, on_delete=models.CASCADE, related_name='images', null=True, blank=True)

    def __str__(self):
        return f"Image for {self.product.name} {'- ' + self.color_variant.color_name if self.color_variant else ''}"

class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product_reviews')
    rating = models.PositiveIntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"Review for {self.product.name}"

# ===========================# WALLET & ADDRESS# ===========================
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    def credit(self, amount):
        self.balance += amount
        self.save()

class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.full_name}, {self.city}, {self.country}"

# ===========================# ORDER MANAGEMENT# ===========================
class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('shipped', 'Shipped'),
        ('out_for_delivery', 'Out for Delivery'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
        ('returned', 'Returned'),
    ]
    PAYMENT_METHOD_CHOICES = [
        ('COD', 'Cash on Delivery'),
        ('Online', 'Online Payment'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.ForeignKey('Address', on_delete=models.SET_NULL, null=True)
    order_id = models.CharField(max_length=20, unique=True,blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reason = models.TextField(blank=True, null=True)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    payment_method = models.CharField(max_length=30, choices=PAYMENT_METHOD_CHOICES, default='COD')
    is_paid = models.BooleanField(default=False)
    return_requested = models.BooleanField(default=False)
    return_verified = models.BooleanField(default=False)
    def save(self, *args, **kwargs):
        if not self.order_id:
            self.order_id = str(uuid.uuid4()).split('-')[0].upper()
        super().save(*args, **kwargs)

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    variant = models.ForeignKey(ProductVariant, on_delete=models.SET_NULL, null=True, blank=True)
    size = models.CharField(max_length=10)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_cancelled = models.BooleanField(default=False)
    is_returned = models.BooleanField(default=False)
    cancel_reason = models.TextField(blank=True, null=True)
    return_reason = models.TextField(blank=True, null=True)

    @property
    def total(self):
        return self.price * self.quantity
# ===========================# SHOPPING & USER INTERACTION# ===========================
class CartItem(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cart_items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    color_name = models.CharField(max_length=50, blank=True, null=True)  # Added color
    size = models.CharField(max_length=10, blank=True, null=True)        # Added size
    quantity = models.PositiveIntegerField(default=1)
    is_listed = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'product', 'color_name', 'size')  # Unique for each color/size

    def subtotal(self):
        return self.product.price * self.quantity  # Use product price directly

    def __str__(self):
        return f"{self.product.name} ({self.quantity}) - Size: {self.size or 'N/A'}, Color: {self.color_name or 'N/A'}"

class Wishlist(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='wishlist_items'
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='wishlisted_by'
    )
    added_at = models.DateTimeField(auto_now_add=True) 
    class Meta:
        unique_together = ('user', 'product') 
        ordering = ['-added_at'] 
    def __str__(self):
        return f"{self.user.email} - {self.product.name}"