import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache, patch_cache_control
from django.forms import modelformset_factory

# ===========================# App Imports# ===========================
from .models import Product, ProductImage,Category, Order,Wallet 
from .forms import ProductForm, CategoryForm, UserFilterForm

User = get_user_model()
logger = logging.getLogger(__name__)

# ===========================# Admin Authentication# ===========================
@never_cache
def admin_login(request):
    # Redirect authenticated staff to dashboard
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('adminside:admin_dashboard')
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, email=user_obj.email, password=password)
            if user is not None and user.is_staff:
                login(request, user)
                return redirect('adminside:admin_dashboard')
            else:
                messages.error(request, 'Invalid credentials or unauthorized access.')
        except User.DoesNotExist:
            messages.error(request, 'Invalid credentials or unauthorized access.')
    response = render(request, 'adminside/login.html')
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

def is_admin(user):
    return user.is_staff

@never_cache
@login_required(login_url='adminside:admin_login')
@user_passes_test(is_admin, login_url='adminside:admin_login')
def admin_dashboard(request):
    response = render(request, 'adminside/dashboard.html')
    patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

@never_cache
def admin_logout_view(request):
    logout(request)
    response = redirect('adminside:admin_login')
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

# ===========================# User Management# ===========================
def user_list(request):
    form = UserFilterForm(request.GET or None)
    users = User.objects.filter(is_superuser=False, is_staff=False)
    if form.is_valid():
        search = form.cleaned_data.get('search')
        status = form.cleaned_data.get('status')
        if search:
            users = users.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        if status and status != 'all':
            users = users.filter(status=status)
    return render(request, 'adminside/user_list.html', {'form': form, 'users': users})

@require_POST
@csrf_exempt
def toggle_status(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    action = request.POST.get('action')
    if action == 'block' and user.status == 'active':
        user.status = 'blocked'
    elif action == 'unblock' and user.status == 'blocked':
        user.status = 'active'
    else:
        return JsonResponse({'success': False, 'error': 'Invalid action or status'}, status=400)
    user.save()
    return JsonResponse({'status': user.status, 'success': True})

# ===========================# Product Management# ===========================

from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils.cache import patch_cache_control

from .models import Product, ProductImage, ProductVariant, Category
from .forms import ProductForm, ProductVariantFormSet
import logging

logger = logging.getLogger(__name__)
MIN_IMAGE_COUNT = 3
ALLOWED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/webp']

# views.py
# views.py
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.views.decorators.cache import cache_control
from django.db.models import Sum, Prefetch
from .models import Product, Category, ColorVariant, ProductImage
from .forms import ProductForm, ProductVariantFormSet, ProductImageFormSet
from django.core.files import File

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def product_list(request):
    if request.method == 'POST':
        product_form = ProductForm(request.POST, request.FILES)
        variant_formset = ProductVariantFormSet(request.POST, instance=None)
        
        if product_form.is_valid() and variant_formset.is_valid():
            # Save the product
            product = product_form.save()
            # Handle cropped images from request.FILES.getlist('images')
            for i, image in enumerate(request.FILES.getlist('images')):
                ProductImage.objects.create(product=product, image=image)
            # Process variant formset
            for form in variant_formset:
                if form.cleaned_data and not form.cleaned_data.get('DELETE'):
                    color_name = form.cleaned_data['color_name']
                    color_hex = form.cleaned_data['color_hex']
                    size = form.cleaned_data['size']
                    stock = form.cleaned_data['stock']
                    # Create or get ColorVariant
                    color_variant, _ = ColorVariant.objects.get_or_create(
                        product=product,
                        color_name=color_name,
                        color_hex=color_hex
                    )
                    # Create ProductVariant
                    ProductVariant.objects.create(
                        product=product,
                        color_variant=color_variant,
                        size=size,
                        stock=stock
                    )
            return redirect('adminside:product_list')
        # If invalid, pass forms back to template
    else:
        product_form = ProductForm()
        variant_formset = ProductVariantFormSet(instance=None)

    search_query = request.GET.get('search', '')
    products = Product.objects.filter(is_deleted=False).prefetch_related(
        Prefetch('variants', queryset=ProductVariant.objects.select_related('color_variant', 'size'))
    )
    if search_query:
        products = products.filter(name__icontains=search_query)

    categories = Category.objects.filter(is_listed=True, is_deleted=False)
    paginator = Paginator(products, 10)
    page_number = request.GET.get('page')
    products_page = paginator.get_page(page_number)

    response = render(request, 'adminside/product_list.html', {
        'form': product_form,
        'variant_formset': variant_formset,
        'products': products_page,
        'categories': categories,
        'search_query': search_query
    })

    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response



# views.py - Enhanced debugging version

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.db import transaction
from .forms import ProductForm, ProductVariantFormSet
from .models import Product, ProductImage, ProductVariant, ColorVariant
import logging

logger = logging.getLogger(__name__)

MIN_VARIANT_IMAGE_COUNT = 4
ALLOWED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/jpg']

@login_required 
@require_http_methods(["GET", "POST"])
def add_product(request):
    logger.info("add_product view called with method: %s", request.method)
    
    if request.method == 'POST':
        print("=== DEBUG: POST DATA ===")
        for key, value in request.POST.items():
            print(f"{key}: {value}")
        
        print("=== DEBUG: FILES DATA ===")
        for key, files in request.FILES.lists():
            print(f"{key}: {[f.name for f in files]}")
        
        product_form = ProductForm(request.POST)
        variant_formset = ProductVariantFormSet(request.POST, request.FILES)
        
        # Handle variant images
        variant_images = {}
        for key in request.FILES:
            if key.startswith('variant-') and key.endswith('-images'):
                index = key.split('-')[1]
                variant_images[index] = request.FILES.getlist(key)
                print(f"=== DEBUG: Variant {index} Images received: {len(variant_images[index])} ===")
                for i, img in enumerate(variant_images[index]):
                    print(f"Variant {index} Image {i+1}: {img.name}, Size: {img.size}, Type: {img.content_type}")
        
        # Validate forms
        product_valid = product_form.is_valid()
        variant_valid = variant_formset.is_valid()
        
        print(f"=== DEBUG: Form Validity ===")
        print(f"Product form valid: {product_valid}")
        print(f"Variant formset valid: {variant_valid}")
        
        if not product_valid:
            print("=== DEBUG: Product Form Errors ===")
            for field, errors in product_form.errors.items():
                print(f"Field '{field}': {errors}")
        
        if not variant_valid:
            print("=== DEBUG: Variant Formset Errors ===")
            print(f"Non-form errors: {variant_formset.non_form_errors()}")
            for i, form in enumerate(variant_formset):
                if form.errors:
                    print(f"Variant form {i} errors: {form.errors}")
        
        # Validate variant image counts
        for index, images in variant_images.items():
            if len(images) != MIN_VARIANT_IMAGE_COUNT:
                print(f"=== DEBUG: Variant {index} Image count validation failed. Expected: {MIN_VARIANT_IMAGE_COUNT}, Got: {len(images)} ===")
                messages.error(request, f'Please upload exactly {MIN_VARIANT_IMAGE_COUNT} images for variant {int(index) + 1}.')
                return render(request, 'adminside/add_product.html', {
                    'product_form': product_form,
                    'variant_formset': variant_formset,
                })
        
        # Validate variant image types
        for index, images in variant_images.items():
            for i, img in enumerate(images):
                if img.content_type not in ALLOWED_IMAGE_TYPES:
                    print(f"=== DEBUG: Variant {index} Image {i+1} type validation failed: {img.content_type} ===")
                    messages.error(request, f'Invalid image format for variant {int(index) + 1} image {i+1}. Only PNG, JPEG, and WebP are allowed.')
                    return render(request, 'adminside/add_product.html', {
                        'product_form': product_form,
                        'variant_formset': variant_formset,
                    })

        if product_valid and variant_valid:
            try:
                with transaction.atomic():
                    # Save the product
                    product = product_form.save()
                    print(f"=== DEBUG: Product saved: {product.name} (ID: {product.id}) ===")

                    # Save variants and their images
                    variants_saved = 0
                    for i, form in enumerate(variant_formset):
                        if form.cleaned_data and not form.cleaned_data.get('DELETE'):
                            print(f"=== DEBUG: Saving variant with data: {form.cleaned_data} ===")
                            variant = form.save(commit=False, product=product)
                            variant.product = product
                            variant.save()
                            variants_saved += 1
                            print(f"=== DEBUG: Variant saved: {variant.color_variant.color_name} - {variant.size.name} ===")
                            
                            # Save variant images
                            if str(i) in variant_images:
                                for j, image in enumerate(variant_images[str(i)]):
                                    ProductImage.objects.create(
                                        product=product,
                                        image=image,
                                        color_variant=variant.color_variant
                                    )
                                    print(f"=== DEBUG: Variant {i} Image {j+1} saved: {image.name} ===")
                    
                    if variants_saved == 0:
                        print("=== DEBUG: No valid variants provided ===")
                        raise ValueError("At least one valid variant is required.")
                    
                    print(f"=== DEBUG: Total variants saved: {variants_saved} ===")
                    messages.success(request, 'Product and variants added successfully!')
                    print("=== DEBUG: Redirecting to product list ===")
                    return redirect('adminside:product_list')
                    
            except Exception as e:
                print(f"=== DEBUG: Exception during save: {str(e)} ===")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error creating product: {str(e)}')
                
        else:
            print("=== DEBUG: Form validation failed, staying on same page ===")
            for field, errors in product_form.errors.items():
                for error in errors:
                    messages.error(request, f'Product {field}: {error}')
            
            for i, form in enumerate(variant_formset):
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f'Variant {i+1} {field}: {error}')
            
            for error in variant_formset.non_form_errors():
                messages.error(request, f'Variant error: {error}')
    else:
        product_form = ProductForm()
        variant_formset = ProductVariantFormSet(queryset=ProductVariant.objects.none())

    context = {
        'product_form': product_form,
        'variant_formset': variant_formset,
    }
    return render(request, 'adminside/add_product.html', context)



# adminside/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import transaction
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
import logging
from .forms import ProductForm, ProductVariantFormSet
from .models import Product, ProductImage, ColorVariant

logger = logging.getLogger(__name__)
MIN_VARIANT_IMAGE_COUNT = 4
ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg']

@login_required
@require_http_methods(["GET", "POST"])
def edit_product(request, product_id):
    logger.info("edit_product view called with method: %s", request.method)
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        print("=== DEBUG: POST DATA ===")
        for key, value in request.POST.items():
            print(f"{key}: {value}")
        print("=== DEBUG: FILES DATA ===")
        for key, files in request.FILES.lists():
            print(f"{key}: {[f.name for f in files]}")

        product_form = ProductForm(request.POST, request.FILES, instance=product)
        variant_formset = ProductVariantFormSet(request.POST, request.FILES, instance=product)

        # Collect variant images and deletions
        variant_images = {}
        variant_deletions = {}
        for key in request.FILES:
            if key.startswith('variant-') and key.endswith('-images'):
                index = key.split('-')[1]
                variant_images[index] = request.FILES.getlist(key)
                print(f"=== DEBUG: Variant {index} Images received: {len(variant_images[index])} ===")
                for i, img in enumerate(variant_images[index]):
                    print(f"Variant {index} Image {i+1}: {img.name}, Size: {img.size}, Type: {img.content_type}")

        for key in request.POST:
            if key.startswith('variant-') and key.endswith('-delete_image_'):
                index = key.split('-')[1]
                image_id = key.split('_')[-1]
                variant_deletions.setdefault(index, []).append(image_id)
                print(f"=== DEBUG: Marked image ID {image_id} for deletion in variant {index} ===")

        if product_form.is_valid() and variant_formset.is_valid():
            try:
                with transaction.atomic():
                    # Save the product
                    product = product_form.save()
                    print(f"=== DEBUG: Product saved: {product.name} (ID: {product.id}) ===")

                    # Save/update variants
                    variants_saved = 0
                    for i, form in enumerate(variant_formset):
                        if form.cleaned_data and not form.cleaned_data.get('DELETE'):
                            print(f"=== DEBUG: Saving variant with data: {form.cleaned_data} ===")
                            variant = form.save(commit=False, product=product)  # Pass product to form.save
                            if variant is None:
                                print(f"=== DEBUG: Variant {i} save returned None ===")
                                raise ValueError(f"Failed to save variant {i + 1}: Form save returned None.")
                            variant.save()
                            variants_saved += 1
                            # print(f'=== DEBUG: Variant saved: {variant.color_variant.color_name} - {variant.size.name'} ===)

                            # Handle image deletions
                            existing_images = ProductImage.objects.filter(color_variant=variant.color_variant)
                            current_image_count = existing_images.count()
                            images_to_delete = variant_deletions.get(str(i), [])
                            for image_id in images_to_delete:
                                logger.debug(f"Deleting image ID {image_id} for variant {i}")
                                print(f"=== DEBUG: Deleting image ID {image_id} for variant {i} ===")
                                ProductImage.objects.filter(id=image_id, color_variant=variant.color_variant).delete()

                            # Handle images
                            if str(i) in variant_images:
                                new_images = variant_images[str(i)]
                                remaining_images = current_image_count - len(images_to_delete)
                                total_images = remaining_images + len(new_images)
                                # print(f=== DEBUG: Variant {i} - Current images: {current_image_count}, Deleting: {len(images_to_delete)}, Adding: {len(new_images)}, Total: {total_images} ===)

                                # Allow partial updates: only add new images if total is <= MIN_VARIANT_IMAGE_COUNT
                                if total_images > MIN_VARIANT_IMAGE_COUNT:
                                    raise ValueError(f"Too many images for variant {i + 1}. Expected up to {MIN_VARIANT_IMAGE_COUNT}, got {total_images}.")
                                if total_images < MIN_VARIANT_IMAGE_COUNT:
                                    print('f=== DEBUG: Warning: Variant {i + 1} has {total_images} images, expected {MIN_VARIANT_IMAGE_COUNT}. Keeping existing images. ===')

                                for j, image in enumerate(new_images):
                                    if image.content_type not in ALLOWED_IMAGE_TYPES:
                                        raise ValueError(f"Invalid image format for variant {i + 1} image {j + 1}. Only PNG, JPEG, and WebP are allowed.")
                                    ProductImage.objects.create(
                                        product=product,
                                        color_variant=variant.color_variant,
                                        image=image
                                    )
                                    print('f=== DEBUG: Variant {i} Image {j+1} saved: {image.name} ===')

                    if variants_saved == 0:
                        print("=== DEBUG: No valid variants provided ===")
                        raise ValueError("At least one valid variant is required.")

                    print(f"=== DEBUG: Total variants saved: {variants_saved} ===")
                    messages.success(request, "Product updated successfully.")
                    print("=== DEBUG: Redirecting to product list ===")
                    return redirect('adminside:product_list')

            except ValueError as e:
                logger.error(f"Validation error while saving product/variants: {str(e)}")
                print('f=== DEBUG: Validation error: {str(e)} ===')
                messages.error(request, f"Validation error: {str(e)}")
            except Exception as e:
                logger.exception("Unexpected error while editing product")
                print('f=== DEBUG: Exception during save: {str(e)} ===')
                import traceback
                traceback.print_exc()
                messages.error(request, f"Something went wrong: {str(e)}")

        else:
            if product_form.errors:
                logger.error(f"Product form errors: {product_form.errors}")
                print("=== DEBUG: Product Form Errors ===")
                for field, errors in product_form.errors.items():
                    print(f"Field '{field}': {errors}")
                    messages.error(request, f'Product {field}: {errors.as_text()}')

            if variant_formset.non_form_errors():
                logger.error(f"Variant formset non-form errors: {variant_formset.non_form_errors()}")
                print('f=== DEBUG: Variant Formset Non-Form Errors: {variant_formset.non_form_errors()} ===')
                messages.error(request, f'Variant formset errors: {variant_formset.non_form_errors()}')

            for i, form in enumerate(variant_formset):
                if form.errors:
                    logger.error(f"Variant form {i} errors: {form.errors}")
                    print('f=== DEBUG: Variant Form {i} Errors: {form.errors} ===')
                    for field, errors in form.errors.items():
                        messages.error(request, f'Variant {i+1} {field}: {errors.as_text()}')

    else:
        product_form = ProductForm(instance=product)
        variant_formset = ProductVariantFormSet(instance=product)

        print('f=== DEBUG: Product form initial: {product_form.initial} ===')
        for i, form in enumerate(variant_formset):
            print('f=== DEBUG: Variant form {i} initial: {form.initial} ===')

    return render(request, 'adminside/edit_product.html', {
        'product': product,
        'product_form': product_form,
        'variant_formset': variant_formset
    })
@login_required
def delete_product_image(request, image_id):
    if request.method == 'POST':
        image = get_object_or_404(ProductImage, id=image_id)
        product_id = image.product.id
        image.delete()
        return redirect('adminside:edit_product', product_id=product_id)
    return redirect('adminside:product_list')

def delete_product(request, product_id):
    product = get_object_or_404(Product, id=product_id, is_deleted=False)
    if request.method == 'POST':
        product.is_deleted = True
        product.save()
        return redirect('adminside:product_list')
    return render(request, 'adminside/delete_product.html', {'product': product})

def toggle_is_active(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    product.is_active = not product.is_active
    product.save()
    messages.success(request, f"Product '{product.name}' active status changed.")
    return redirect('adminside:product_list')

def toggle_is_listed(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    product.is_listed = not product.is_listed
    product.save()
    messages.success(request, f"Product '{product.name}' listed status changed.")
    return redirect('adminside:product_list')

# ===========================# Category Management# ===========================
def category_list(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('adminside:category_list')
    else:
        form = CategoryForm()
    search_query = request.GET.get('search', '')
    categories = Category.objects.all().order_by('is_deleted', '-is_listed', 'name')
    if search_query:
        categories = categories.filter(name__icontains=search_query)
    paginator = Paginator(categories, 10)
    page_number = request.GET.get('page')
    categories_page = paginator.get_page(page_number)
    return render(request, 'adminside/category.html', {
        'form': form,
        'categories': categories_page,
        'search_query': search_query
    })

def add_category(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('adminside:category_list')
    else:
        form = CategoryForm()
    return render(request, 'adminside/add_category.html', {'form': form})

def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id, is_deleted=False)
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            return redirect('adminside:category_list')
    else:
        form = CategoryForm(instance=category)
    return render(request, 'adminside/edit_category.html', {'form': form, 'category': category})

def delete_category(request, category_id):
    category = get_object_or_404(Category, id=category_id, is_deleted=False)
    if request.method == 'POST':
        category.is_deleted = True
        category.save()
        return redirect('adminside:category_list')
    return render(request, 'adminside/delete_category.html', {'category': category})

def toggle_list_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    category.is_listed = not category.is_listed
    category.save()
    return redirect('adminside:category_list')

def toggle_delete_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    category.is_deleted = not category.is_deleted
    category.save()
    return redirect('adminside:category_list')

# ===========================# Order Management# ===========================
def admin_order_list(request):
    search_query = request.GET.get('q', '')
    status_filter = request.GET.get('status', '')
    orders = Order.objects.all().order_by('-created_at')
    if search_query:
        orders = orders.filter(
            Q(order_id__icontains=search_query) |
            Q(user__email__icontains=search_query)
        )
    if status_filter:
        orders = orders.filter(status=status_filter.lower())
    paginator = Paginator(orders, 10)
    page = request.GET.get('page')
    orders = paginator.get_page(page)
    return render(request, 'adminside/order_list.html', {
        'orders': orders,
        'search_query': search_query,
        'status_filter': status_filter,
        'status_choices': Order.STATUS_CHOICES, # ✅ Add this
    })

def admin_order_detail(request, order_id):
    order = get_object_or_404(Order, order_id=order_id)
    
    if request.method == "POST":
        new_status = request.POST.get("status")
        verify_return = request.POST.get("verify_return") == "on"

        # Prevent status change if already delivered
        if order.status != "delivered":
            # Prevent going back to 'pending' once status has moved forward
            if new_status == "pending" and order.status != "pending":
                messages.error(request, "Cannot change status back to 'Pending'.")
                return redirect('adminside:admin_order_detail', order_id=order.order_id)

            if new_status and new_status != order.status:
                order.status = new_status

        # Handle return verification
        if verify_return and order.return_requested and not order.return_verified:
            try:
                wallet_instance, _ = Wallet.objects.get_or_create(user=order.user)
                refund_amount = sum(item.quantity * item.price for item in order.items.all())
                if hasattr(wallet_instance, 'credit') and callable(wallet_instance.credit):
                    wallet_instance.credit(refund_amount)
                else:
                    wallet_instance.balance += refund_amount
                    wallet_instance.save()
                order.return_verified = True
            except NameError:
                logger.error("Wallet model/class not found. Cannot process return refund.")
                messages.error(request, "Wallet system not configured. Cannot process return refund.")

        order.save()
        return redirect('adminside:admin_order_detail', order_id=order.order_id)

    # Add subtotal to each order item for template use
    for item in order.items.all():
        item.subtotal = item.quantity * item.price

    return render(request, 'adminside/order_detail.html', {
        'order': order,
        'status_choices': Order.STATUS_CHOICES,
    })


@login_required
def confirm_return(request, order_id):
    order = get_object_or_404(Order, order_id=order_id)
    if request.method == 'POST':
        order.return_verified = True
        order.status = 'returned'
        order.save()
        messages.success(request, "Return confirmed and wallet credited.")
        return redirect('adminside:admin_order_detail', order_id=order_id)
    return render(request, 'adminside/confirm_return.html', {'order': order})

