# ===========================# Django and Third-Party Imports# ===========================
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, get_user_model, update_session_auth_hash
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

# ===========================# App Imports# ===========================
from .forms import CustomUserCreationForm, EditProfileForm, ChangePasswordForm
from .models import EmailOTP, CustomUser
from adminside.models import Product, Category, Order, Address, CartItem, Wishlist, OrderItem
from .models import FeaturedSection
from .utils import send_otp_email # Moved from inside edit_profile function

# ===========================# Utility Functions# ===========================
def generate_otp():
    return str(random.randint(100000, 999999))

# ===========================# User Registration & OTP Verification# ===========================
@never_cache
def register(request):
    if request.user.is_authenticated:
        return redirect('userside:home')
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            otp = generate_otp()
            request.session['registration_data'] = {
                'email': form.cleaned_data['email'],
                'password1': form.cleaned_data['password1'],
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'phone_number': form.cleaned_data['phone_number'],
            }
            request.session['registration_otp'] = otp
            send_mail(
                'Your OTP Code',
                f'Your OTP is {otp}',
                'farhanyassar2003@gmail.com',
                [email],
                fail_silently=False,
            )
            messages.success(request, 'An OTP has been sent to your email. Please verify to complete registration.')
            return redirect('userside:verify_otp')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()
    response = render(request, 'userside/register.html', {'form': form})
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

import time
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail

def generate_otp():
    import random
    return str(random.randint(100000, 999999))

def otp_verify(request):
    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            # Handle Resend OTP logic
            data = request.session.get('registration_data')
            if not data:
                messages.error(request, 'Session expired. Please register again.')
                return redirect('userside:register')

            last_sent = request.session.get('otp_last_sent')
            now = timezone.now().timestamp()
            if last_sent and now - last_sent < 60:
                wait = int(60 - (now - last_sent))
                messages.error(request, f'Please wait {wait} seconds before resending OTP.')
                return redirect('userside:verify_otp')

            new_otp = generate_otp()
            request.session['registration_otp'] = new_otp
            request.session['otp_last_sent'] = now

            send_mail(
                'Your OTP Code',
                f'Your new OTP is {new_otp}',
                'farhanyassar2003@gmail.com',
                [data['email']],
                fail_silently=False,
            )
            messages.success(request, 'A new OTP has been sent to your email.')
            return redirect('userside:verify_otp')

        # Normal OTP submit
        input_otp = request.POST.get('otp')
        session_otp = request.session.get('registration_otp')
        data = request.session.get('registration_data')

        if input_otp == session_otp:
            User = get_user_model()
            user = User.objects.create_user(
                email=data['email'],
                password=data['password1'],
                first_name=data['first_name'],
                last_name=data['last_name'],
                phone_number=data['phone_number']
            )
            EmailOTP.objects.create(user=user, otp=session_otp)
            request.session.pop('registration_data', None)
            request.session.pop('registration_otp', None)
            request.session.pop('otp_last_sent', None)
            messages.success(request, 'Registration complete!')
            return redirect('userside:login')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'userside/otp_verify.html')


def otp_page(request):
    user_id = request.session.get('otp_user_id')
    if not user_id:
        return redirect('register')
    if request.method == 'POST':
        otp_entered = request.POST['otp']
        try:
            otp_instance = EmailOTP.objects.get(user_id=user_id)
            if otp_instance.otp == otp_entered:
                user = otp_instance.user
                login(request, user)
                del request.session['otp_user_id']
                return redirect('home')
            else:
                messages.error(request, "Invalid OTP")
        except EmailOTP.DoesNotExist:
            messages.error(request, "OTP not found")
    return render(request, 'userside/otp_page.html')

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
        return redirect('adminside:admin_dashboard')
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
    page_number = request.GET.get('page', 1)
    paginator = Paginator(products, 8)
    page_obj = paginator.get_page(page_number)
    context = {
        'page_obj': page_obj,
        'products': page_obj.object_list,
        'categories': categories,
        'search_query': search_query,
        'selected_category': category_filter,
        'selected_sort': sort_by,
        'total_products': paginator.count,
        'has_filters': bool(search_query or (category_filter and category_filter != 'all')),
    }
    response = render(request, 'userside/product_list.html', context)
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

from django.db.models import Avg, Sum
from collections import defaultdict
from adminside.models import Product, ColorVariant, Size, ProductVariant
import logging

logger = logging.getLogger(__name__)

def product_detail_view(request, id):
    logger.info("product_detail_view called for product id: %s", id)
    product = get_object_or_404(Product, id=id, is_listed=True, is_deleted=False)
    
    if not product.is_active or not product.is_listed:
        logger.warning("Product %s is not active or listed, redirecting to product_list", id)
        return redirect('userside:product_list')

    # Get color variants that have listed ProductVariant records
    color_variants = product.color_variants.filter(
        is_listed=True,
        variants__is_listed=True
    ).distinct()
    logger.debug("Color variants for product %s: %s", product.id, 
                 [(cv.id, cv.color_name, cv.color_hex) for cv in color_variants])

    # Get distinct size names directly from ProductVariant
    sizes = product.variants.filter(is_listed=True).values_list('size__name', flat=True).distinct()
    logger.debug("Sizes for product %s: %s", product.id, list(sizes))

    # Group variants by size name (optional, not used in current template)
    size_variant_map = defaultdict(list)
    for variant in product.variants.filter(is_listed=True):
        size_variant_map[variant.size.name].append(variant)

    # Calculate discount (assuming no original_price field in Product model)
    discount = None  # Set to None since original_price is not in the model
    original_price = None  # Set to None to avoid AttributeError
    logger.debug("Discount for product %s: %s", product.id, discount)

    # Get related products
    related_products = Product.objects.filter(
        category=product.category, is_listed=True, is_deleted=False
    ).exclude(id=product.id)[:4]
    logger.debug("Related products: %s", [rp.id for rp in related_products])

    context = {
        'product': product,
        'color_variants': color_variants,
        'sizes': sizes,  # List of size names (e.g., ["S", "M", "L"])
        'size_variant_map': dict(size_variant_map),  # Kept for potential future use
        'related_products': related_products,
        'reviews': product.reviews.all(),
        'avg_rating': product.reviews.aggregate(avg=Avg('rating'))['avg'] or 0.0,
        'discount': discount,
        'original_price': original_price,
    }

    logger.debug("Context for product %s: %s variants, %s sizes, avg_rating=%s",
                 product.id, color_variants.count(), len(sizes), context['avg_rating'])

    return render(request, 'userside/product_detail.html', context)


def clear_filters(request):
    return redirect('userside:product_list')

# ===========================# User Profile and Address Management# ===========================
@login_required(login_url='login')
def user_profile(request):
    user = request.user
    orders = Order.objects.filter(user=user).order_by('-created_at')
    user_addresses = Address.objects.filter(user=user)
    context = {
        'user': user,
        'orders': orders,
        'addresses': user_addresses,
    }
    return render(request, 'userside/profile.html', context)

def my_addresses(request):
    addresses = Address.objects.filter(user=request.user)
    return render(request, 'userside/my_addresses.html', {'addresses': addresses})

@login_required(login_url='login')
def save_address(request):
    if request.method == 'POST':
        address_id = request.POST.get('address_id')
        if address_id:
            address = get_object_or_404(Address, id=address_id, user=request.user)
        else:
            address = Address(user=request.user)
        address.name = request.POST['name']
        address.street = request.POST['street']
        address.city = request.POST['city']
        address.state = request.POST['state']
        address.zip = request.POST['zip']
        address.save()
        return redirect('userside:user_profile')

@login_required(login_url='login')
def delete_address(request, address_id):
    address = get_object_or_404(Address, id=address_id, user=request.user)
    address.delete()
    return redirect('userside:user_profile')

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
    return render(request, 'userside/order_list.html', {'orders': orders})

def order_detail(request, order_id):
    order = get_object_or_404(Order, order_id=order_id, user=request.user)
    return render(request, 'userside/orders/order_detail.html', {'order': order})

@login_required(login_url='login')
@require_POST
def cancel_order_item(request, item_id):
    item = get_object_or_404(OrderItem, id=item_id, order__user=request.user)
    item.is_cancelled = True
    item.cancel_reason = request.POST.get('reason')
    item.product.stock_quantity += item.quantity
    item.product.save()
    item.save()
    return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

@login_required(login_url='login')
@require_POST
def return_order_item(request, item_id):
    item = get_object_or_404(OrderItem, id=item_id, order__user=request.user, order__status='Delivered')
    reason = request.POST.get('reason')
    if not reason:
        return HttpResponse("Return reason required", status=400)
    item.is_returned = True
    item.return_reason = reason
    item.product.stock_quantity += item.quantity
    item.product.save()
    item.save()
    return HttpResponseRedirect(reverse('userside:order_detail', args=[item.order.order_id]))

@login_required(login_url='login')
@require_POST
def cancel_entire_order(request, order_id):
    order = get_object_or_404(Order, order_id=order_id, user=request.user)
    reason = request.POST.get('reason')
    order.status = 'Cancelled'
    order.reason = reason
    order.save()
    for item in order.items.all():
        if not item.is_cancelled:
            item.is_cancelled = True
            item.cancel_reason = reason
            item.product.stock_quantity += item.quantity
            item.product.save()
            item.save()
    return HttpResponseRedirect(reverse('userside:order_list'))

# ===========================# Cart Views# ==========================

from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
import traceback
from django.core.exceptions import ObjectDoesNotExist

@csrf_protect
def add_to_cart(request, product_id):
    if request.method == 'POST':
        try:
            print("POST data received:", request.POST)  # Debug incoming data
            user = request.user
            color_id = request.POST.get('color_id')
            # Check for both 'size' and 'sizes[]' to support different page inputs
            size_name = request.POST.get('sizes[]') or request.POST.get('size')
            quantity = int(request.POST.get('quantity', 1))

            if not color_id or not size_name:
                return JsonResponse({'success': False, 'message': 'Please select both color and size.'}, status=400)

            # Fetch related objects
            color_variant = ColorVariant.objects.get(id=color_id)
            size = Size.objects.get(name=size_name)
            variant = ProductVariant.objects.get(product_id=product_id, color_variant=color_variant, size=size)

            if quantity <= 0:
                return JsonResponse({'success': False, 'message': 'Quantity must be greater than 0.'}, status=400)

            if quantity > variant.stock:
                return JsonResponse({'success': False, 'message': f'Requested quantity ({quantity}) exceeds available stock ({variant.stock}).'}, status=400)

            # Use color_name instead of color_variant
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
            print(f"ObjectDoesNotExist error: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Invalid data: {str(e)}'}, status=400)
        except ValueError as e:
            print(f"ValueError: {str(e)}")
            return JsonResponse({'success': False, 'message': 'Invalid quantity value.'}, status=400)
        except Exception as e:
            print(f"Unexpected error in add_to_cart: {str(e)}")
            traceback.print_exc()
            return JsonResponse({'success': False, 'message': 'An unexpected error occurred. Please try again later.'}, status=500)

@login_required(login_url='login')
def view_cart(request):
    cart_items = CartItem.objects.filter(user=request.user, is_listed=True).select_related('product')
    # Prefetch related ProductVariant data
    cart_items = cart_items.prefetch_related('product__variants')
    
    # Calculate stock for each item using color_name and size
    cart_items_with_stock = []
    for item in cart_items:
        try:
            variant = item.product.variants.filter(
                color_variant__color_name=item.color_name,
                size__name=item.size
            ).first()
            item.stock = variant.stock if variant and variant.is_listed else 0
        except Exception as e:
            item.stock = 0
            print(f"Error fetching stock for item {item.id}: {str(e)}")
        cart_items_with_stock.append(item)
    
    total = sum(item.subtotal() for item in cart_items_with_stock)
    return render(request, 'userside/cart.html', {
        'cart_items': cart_items_with_stock,
        'total': total,
    })

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404

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
@login_required(login_url='login')
def checkout_view(request):
    cart_items = CartItem.objects.filter(user=request.user)
    addresses = Address.objects.filter(user=request.user)
    default_address = addresses.filter(is_default=True).first()
    subtotal = sum(item.subtotal() for item in cart_items)

    tax = 0  # Set default tax
    shipping = 0  # Set default shipping
    total = subtotal + tax + shipping

    context = {
        'cart_items': cart_items,
        'addresses': addresses,
        'default_address': default_address,
        'subtotal': subtotal,
        'tax': tax,
        'shipping': shipping,
        'total': total,
    }
    return render(request, 'userside/checkout.html', context)

@login_required(login_url='login')
def place_order(request):
    if request.method == 'POST':
        address_id = request.POST.get('address_id')
        address = get_object_or_404(Address, id=address_id, user=request.user)

        cart_items = CartItem.objects.filter(user=request.user)
        if not cart_items:
            messages.error(request, "Your cart is empty.")
            return redirect('userside:view_cart')

        # Check stock availability
        for item in cart_items:
            if item.variant.stock < item.quantity:
                messages.error(request, f"Not enough stock for {item.variant}.")
                return redirect('userside:view_cart')

        # Calculate totals
        subtotal = sum(item.subtotal() for item in cart_items)
        total = subtotal

        # Create order
        order = Order.objects.create(
            user=request.user,
            address=address,
            total=total,
            payment_method='COD',
            is_paid=False,
        )

        # Create order items and update stock
        for item in cart_items:
            OrderItem.objects.create(
                order=order,
                product=item.product,
                variant=item.variant,
                size=item.size,
                quantity=item.quantity,
                price=item.product.price
            )

            # Deduct stock from ProductVariant
            item.variant.stock -= item.quantity
            item.variant.save()

        # Clear cart
        cart_items.delete()

        return redirect('userside:order_success', order_id=order.id)

    return redirect('userside:checkout')


def order_success(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    # Calculate item totals
    order_items = []
    for item in order.items.all():
        item_total = item.quantity * item.price
        order_items.append({
            'name': item.product.name,
            'quantity': item.quantity,
            'price': item.price,
            'total': item_total,
        })
    return render(request, 'userside/order_success.html', {
        'order': order,
        'order_items': order_items
    })

from django.http import JsonResponse, HttpResponseBadRequest
import re

@login_required
def save_address_checkout(request):
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        phone = request.POST.get('phone', '').strip()
        address_line1 = request.POST.get('address_line1', '').strip()
        address_line2 = request.POST.get('address_line2', '').strip()
        city = request.POST.get('city', '').strip()
        state = request.POST.get('state', '').strip()
        postal_code = request.POST.get('postal_code', '').strip()
        country = request.POST.get('country', '').strip()

        # ✅ Server-side validation
        errors = []
        if not re.match(r'^[A-Za-z ]+$', full_name):
            errors.append("Full name must contain only letters and spaces.")
        if not re.match(r'^[0-9]{10}$', phone):
            errors.append("Phone must be exactly 10 digits.")
        if phone == '0000000000':
            errors.append("Phone number cannot be all zeros.")
        
        if errors:
            return JsonResponse({'status': 'error', 'errors': errors}, status=400)

        # ✅ Create address
        Address.objects.create(
            user=request.user,
            full_name=full_name,
            phone=phone,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            postal_code=postal_code,
            country=country,
        )
        return JsonResponse({'status': 'success', 'message': 'Address saved successfully'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


@login_required
def address_list(request):
    addresses = Address.objects.filter(user=request.user)
    return render(request, 'userside/my_addresses.html', {'addresses': addresses})

# ===========================# Wishlist Views# ===========================
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
    # Return updated count
    wishlist_count = Wishlist.objects.filter(user=request.user).count()
    return JsonResponse({'success': True, 'message': message, 'wishlist_count': wishlist_count})

@require_POST
@login_required
def remove_from_wishlist(request, product_id):
    Wishlist.objects.filter(user=request.user, product_id=product_id).delete()
    # Return updated count
    wishlist_count = Wishlist.objects.filter(user=request.user).count()
    return JsonResponse({'success': True, 'message': 'Product removed from wishlist.', 'wishlist_count': wishlist_count})

@login_required
def wishlist_page(request):
    wishlist_items = Wishlist.objects.filter(user=request.user).select_related('product')
    return render(request, 'userside/wishlist.html', {'wishlist_items': wishlist_items})

# ===========================# Duplicate Functions (Original Code Preserved)# ===========================
# Note: These functions have the same name as others above but with different implementations
# or contexts in your original input. They are kept here as per your instruction
# "don't delete any code from it". You might want to refactor these in your project.

@login_required(login_url='login')
@require_POST
def return_order_item(request, item_id):
    item = get_object_or_404(OrderItem, id=item_id, order__user=request.user, order__status='Delivered')
    reason = request.POST.get('reason')
    if not reason:
        return HttpResponse("Return reason required", status=400)
    item.is_returned = True
    item.return_reason = reason
    item.product.stock_quantity += item.quantity
    item.product.save()
    item.save()
    return HttpResponseRedirect(reverse('order_detail', args=[item.order.order_id]))

@login_required
def save_address(request):
    if request.method == 'POST':
        address_id = request.POST.get('address_id')
        full_name = request.POST.get('full_name')
        phone = request.POST.get('phone')
        address_line1 = request.POST.get('address_line1')
        address_line2 = request.POST.get('address_line2')
        city = request.POST.get('city')
        state = request.POST.get('state')
        postal_code = request.POST.get('postal_code')
        country = request.POST.get('country')
        if address_id: # Edit existing
            address = Address.objects.get(id=address_id, user=request.user)
            address.full_name = full_name
            address.phone = phone
            address.address_line1 = address_line1
            address.address_line2 = address_line2
            address.city = city
            address.state = state
            address.postal_code = postal_code
            address.country = country
            address.save()
        else: # New address
            print("DEBUG POST DATA:", request.POST)
            print("full_name =", full_name)
            Address.objects.create(
                user=request.user,
                full_name=full_name,
                phone=phone,
                address_line1=address_line1,
                address_line2=address_line2,
                city=city,
                state=state,
                postal_code=postal_code,
                country=country,
            )
        return redirect('userside:address_list')

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required

@login_required
def delete_address(request, address_id):
    address = get_object_or_404(Address, id=address_id, user=request.user)
    address.delete()
    messages.success(request, "deleted")  # Send a simple flag for toast
    return redirect('userside:address_list')


@login_required
def return_order_item(request, item_id):
    item = get_object_or_404(OrderItem, id=item_id, order__user=request.user)
    order = item.order
    if request.method == "POST":
        if order.status != "delivered":
            messages.error(request, "You can only return items from delivered orders.")
        elif item.is_returned:
            messages.info(request, "This item has already been marked for return.")
        else:
            reason = request.POST.get('reason', '').strip()
            if not reason:
                messages.error(request, "Please provide a reason for return.")
            else:
                item.is_returned = True
                item.return_reason = reason
                item.save()
                order.return_requested = True # Let admin know return is pending
                order.save()
                messages.success(request, "Your return request has been submitted.")
        return redirect('userside:order_detail', order_id=order.order_id)
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
            'color_hex': variant.color_variant.color_hex  # Use hex for display
        },
        'stock': variant.stock
    } for variant in variants]

    print(f"Product ID: {product_id}, Size Filter: {size_filter}, Sizes: {size_options}, Variants: {variant_data}")  # Debug log
    return JsonResponse({
        'success': True,
        'sizes': size_options,  # Send all available sizes
        'variants': variant_data
    })