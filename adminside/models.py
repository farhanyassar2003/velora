from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from django.conf import settings
from django import forms
from PIL import Image
import uuid
from django.contrib.auth import get_user_model
from django.db.models import Sum
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import date

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
    is_deleted = models.BooleanField(default=False)  # Soft delete flag

    def __str__(self):
        return self.name

# ===========================# PRODUCT, IMAGE, SIZE, REVIEW# ===========================
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
from django.db import models
from django.conf import settings
import uuid

class Wallet(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def credit(self, amount):
        self.balance += amount
        self.save()

    def debit(self, amount):
        if self.balance >= amount:
            self.balance -= amount
            self.save()
        else:
            raise ValueError("Insufficient wallet balance")

    def __str__(self):
        return f"{self.user.email}'s Wallet"

class Transaction(models.Model):
    TRANSACTION_TYPES = (
        ('CREDIT', 'Credit'),
        ('DEBIT', 'Debit'),
        ('REFUND', 'Refund'),
    )

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    transaction_id = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_date = models.DateTimeField(auto_now_add=True)
    source_order = models.ForeignKey('Order', on_delete=models.SET_NULL, null=True, blank=True, related_name='transactions')
    description = models.TextField(blank=True)

    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4()).split('-')[0].upper()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type}"

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
    
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import date

class Coupon(models.Model):
    code = models.CharField(max_length=10, unique=True)
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    valid_from = models.DateField(default=date.today)
    valid_until = models.DateField()
    used_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='used_coupons',
        blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Coupon {self.code} ({self.discount_percentage}% off)"

    def is_valid(self, user):
        today = date.today()
        return (self.valid_from <= today <= self.valid_until and
                not self.used_by.filter(id=user.id).exists())
        
class ReferralCoupon(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='referral_coupons'
    )
    code = models.CharField(max_length=10, unique=True, blank=True)
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        default=5.00
    ) 
    valid_from = models.DateField(default=date.today)
    valid_until = models.DateField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.code:
            while True:
                code = str(uuid.uuid4())[:8].upper()
                if not ReferralCoupon.objects.filter(code=code).exists():
                    self.code = code
                    break
        super().save(*args, **kwargs)
        
    def clean(self):
        if self.discount_percentage <= 0:
            raise ValidationError("Discount percentage must be positive")
        if self.valid_until <= self.valid_from:
            raise ValidationError("Valid until date must be after valid from date.")

    def __str__(self):
        return f"Referral Coupon {self.code} ({self.discount_percentage}% off) for {self.owner.email}"

    def is_valid(self):
        today = date.today()
        return (self.valid_from <= today <= self.valid_until and not self.used)

# ===========================# ORDER MANAGEMENT# ===========================
COUPON_TYPE_CHOICES = [
    ('coupon', 'Coupon'),
    ('referral', 'Referral Coupon'),
]
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
    PAYMENT_GATEWAY_CHOICES = [
        ('razorpay', 'Razorpay'),
        # Add more gateways as needed, e.g., ('stripe', 'Stripe'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order_id = models.CharField(max_length=20, unique=True, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    coupon_discount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00) 
    referral_coupon_discount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00) 
    tax = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    shipping_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    reason = models.TextField(blank=True, null=True)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    payment_method = models.CharField(max_length=30, choices=PAYMENT_METHOD_CHOICES, default='COD')
    payment_gateway = models.CharField(max_length=30, choices=PAYMENT_GATEWAY_CHOICES, null=True, blank=True)
    razorpay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    coupons = models.ManyToManyField(Coupon, blank=True)
    referral_coupons = models.ManyToManyField(ReferralCoupon, blank=True)
    is_paid = models.BooleanField(default=False)
    return_requested = models.BooleanField(default=False)
    return_verified = models.BooleanField(default=False)
    coupon_code = models.CharField(max_length=50, null=True, blank=True)
    coupon_discount_percentage = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    coupon_type = models.CharField(max_length=20, choices=COUPON_TYPE_CHOICES, null=True, blank=True)

    
    
    
    shipping_full_name = models.CharField(max_length=100, blank=True)
    shipping_phone = models.CharField(max_length=20, blank=True)
    shipping_address_line1 = models.CharField(max_length=255, blank=True)
    shipping_address_line2 = models.CharField(max_length=255, blank=True)
    shipping_city = models.CharField(max_length=100, blank=True)
    shipping_state = models.CharField(max_length=100, blank=True)
    shipping_postal_code = models.CharField(max_length=20, blank=True)
    shipping_country = models.CharField(max_length=100, blank=True)

    def save(self, *args, **kwargs):
        if not self.order_id:
            self.order_id = str(uuid.uuid4()).split('-')[0].upper()
        # Set is_paid for COD orders when status is delivered
        if self.payment_method == 'COD' and self.status == 'delivered':
            self.is_paid = True
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f"Order {self.order_id} by {self.user.email}"
    
    def get_shipping_address(self):
        """Helper method to display snapped address."""
        return (
            f"{self.shipping_full_name}, {self.shipping_address_line1}, "
            f"{self.shipping_address_line2}, {self.shipping_city}, "
            f"{self.shipping_state}, {self.shipping_postal_code}, "
            f"{self.shipping_country}"
        ).replace(", ,", ",").strip(", ")

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name='items', on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.SET_NULL, null=True)
    variant = models.ForeignKey(ProductVariant, on_delete=models.SET_NULL, null=True, blank=True)
    color_name = models.CharField(max_length=50, blank=True, null=True)
    size = models.CharField(max_length=10)
    quantity = models.PositiveIntegerField()
    discounted_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # Discounted unit price
    applied_offer = models.CharField(max_length=255, null=True, blank=True)  # Offer description
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_cancelled = models.BooleanField(default=False)
    is_returned = models.BooleanField(default=False)
    cancel_reason = models.TextField(blank=True, null=True)
    return_reason = models.TextField(blank=True, null=True)
    is_refunded_to_wallet = models.BooleanField(default=False)
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, help_text="Amount to be refunded for this item")

    @property
    def total(self):
        return (self.discounted_price or self.price) * self.quantity  # Use discounted_price if available

    def __str__(self):
        return f"{self.product.name} (x{self.quantity})"
# ===========================# SHOPPING & USER INTERACTION# ===========================
from django.db import models
from django.conf import settings
from decimal import Decimal
from datetime import date

class CartItem(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='cart_items'
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE
    )
    color_name = models.CharField(max_length=50, blank=True, null=True)
    size = models.CharField(max_length=10, blank=True, null=True)
    quantity = models.PositiveIntegerField(default=1)
    is_listed = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'product', 'color_name')
        verbose_name = 'Cart Item'
        verbose_name_plural = 'Cart Items'

    def subtotal(self):
        # Get the original price
        price = self.product.price
        # Check for an active ProductOffer
        offer = ProductOffer.objects.filter(
            product=self.product,
            is_active=True,
            is_deleted=False,
            start_date__lte=date.today(),
            end_date__gte=date.today()
        ).first()
        if offer:
            discount_percentage = Decimal(offer.discount_percentage)
            price = price * (Decimal('100') - discount_percentage) / Decimal('100')
        return price * self.quantity

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

# ===========================# OFFERS & PROMOTIONS# ===========================
class ProductOffer(models.Model):
    name = models.CharField(max_length=100, unique=True)
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='product_offers'
    )
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Discount percentage (0-100)"
    )
    start_date = models.DateField(default=date.today)
    end_date = models.DateField()
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Product Offer'
        verbose_name_plural = 'Product Offers'

    def __str__(self):
        return f"{self.name} - {self.product.name} ({self.discount_percentage}%)"

    def is_valid(self):
        today = date.today()
        return self.is_active and self.start_date <= today <= self.end_date

class CategoryOffer(models.Model):
    name = models.CharField(max_length=100, unique=True)
    category = models.ForeignKey(
        Category,
        on_delete=models.CASCADE,
        related_name='category_offers'
    )
    discount_percentage = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Discount percentage (0-100)"
    )
    start_date = models.DateField(default=date.today)
    end_date = models.DateField()
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Category Offer'
        verbose_name_plural = 'Category Offers'

    def __str__(self):
        return f"{self.name} - {self.category.name} ({self.discount_percentage}%)"

    def is_valid(self):
        today = date.today()
        return self.is_active and self.start_date <= today <= self.end_date