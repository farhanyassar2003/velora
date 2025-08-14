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
import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

def admin_login(request):
    # Redirect authenticated staff to dashboard
    if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
        return redirect('adminside:sales_report')

    if request.method == 'POST':
        logger.debug(f"POST data: {request.POST}")  # Log POST data for debugging
        email = request.POST.get('email')  # Changed from 'username' to 'email'
        password = request.POST.get('password')

        if not email or not password:
            logger.warning(f"Admin login attempt with missing email or password: {request.POST}")
            return render(request, 'adminside/login.html')

        try:
            User = get_user_model()  # Reference userside.CustomUser
            # Try to find user by email (primary identifier)
            try:
                user_obj = User.objects.get(email=email)
            except User.DoesNotExist:
                # Fallback to username for flexibility
                user_obj = User.objects.get(username=email)

            if not (user_obj.is_staff or user_obj.is_superuser):
                logger.warning(f"Non-admin user attempted login: {email}")
                return render(request, 'adminside/login.html')

            # Authenticate using email as username (since USERNAME_FIELD = 'email')
            user = authenticate(request, username=user_obj.email, password=password)
            if user is not None:
                login(request, user)
                logger.info(f"Admin login successful: {email}")
                return redirect('adminside:sales_report')
            else:
                logger.warning(f"Invalid password for admin login: {email}")
                return render(request, 'adminside/login.html')
        except User.DoesNotExist:
            logger.warning(f"Admin login attempt with non-existent user: {email}")
            return render(request, 'adminside/login.html')
        except Exception as e:
            logger.error(f"Error during admin login: {str(e)}")
            return render(request, 'adminside/login.html')

    return render(request, 'adminside/login.html')

def is_admin(user):
    return user.is_staff

from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.db.models import Sum, Count
from datetime import datetime, timedelta
import json
from adminside.models import Order
from django.utils.cache import patch_cache_control

def is_admin(user):
    return user.is_authenticated and user.is_staff and user.is_superuser

@never_cache
def admin_logout_view(request):
    logout(request)
    response = redirect('adminside:admin_login')
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Sum, Count, DecimalField, ExpressionWrapper, F
from django.db.models.functions import Coalesce  # Correct import
from django.http import HttpResponse
from django.utils import timezone
from .models import Order, OrderItem, Product, Category
from datetime import datetime, timedelta, date
import json
import logging
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment
from django.utils import timezone
from datetime import datetime, timedelta, time
import io

# Set up logging for debugging
logger = logging.getLogger(__name__)

def is_admin(user):
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(is_admin)
def sales_report(request):
    report_type = request.GET.get('report_type', 'daily')
    download_format = request.GET.get('download_format')
    today = timezone.localdate()

    # Determine start and end dates
    if report_type == 'custom':
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except Exception:
            start_date = end_date = today
    elif report_type == 'weekly':
        start_date = today - timedelta(days=6)
        end_date = today
    elif report_type == 'monthly':
        start_date = today.replace(day=1)
        end_date = today
    elif report_type == 'yearly':
        start_date = today.replace(month=1, day=1)
        end_date = today
    else:
        start_date = end_date = today

    # Ensure start <= end
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    # Timezone-aware datetime range
    start_datetime = timezone.make_aware(datetime.combine(start_date, time.min))
    end_datetime = timezone.make_aware(datetime.combine(end_date + timedelta(days=1), time.min))

    # Get orders
    orders = Order.objects.filter(
        status='delivered',
        created_at__gte=start_datetime,
        created_at__lt=end_datetime
    )

    # Calculate metrics
    total_orders = orders.count()
    total_sales = orders.aggregate(total=Sum('total'))['total'] or 0
    total_discount = orders.aggregate(total=Sum('discount'))['total'] or 0
    total_coupon_discount = orders.aggregate(total=Sum('coupon_discount'))['total'] or 0
    total_referral_discount = orders.aggregate(total=Sum('referral_coupon_discount'))['total'] or 0
    total_discount_all = total_discount + total_coupon_discount + total_referral_discount

    # Chart data for sales and orders
    chart_labels, sales_data, orders_data = [], [], []
    current_date = start_date
    while current_date <= end_date:
        day_start = timezone.make_aware(datetime.combine(current_date, time.min))
        day_end = timezone.make_aware(datetime.combine(current_date + timedelta(days=1), time.min))
        day_orders = orders.filter(created_at__gte=day_start, created_at__lt=day_end)
        chart_labels.append(current_date.strftime('%Y-%m-%d'))
        sales_data.append(float(day_orders.aggregate(total=Sum('total'))['total'] or 0))
        orders_data.append(day_orders.count())
        current_date += timedelta(days=1)

    # Best selling products (top 10 by quantity sold)
    top_products = OrderItem.objects.filter(
        order__status='delivered',
        order__created_at__gte=start_datetime,
        order__created_at__lt=end_datetime,
        is_cancelled=False,  # Exclude cancelled items
        is_returned=False    # Exclude returned items
    ).values('product__name').annotate(
        total_quantity=Sum('quantity'),
        total_revenue=Sum(
            ExpressionWrapper(
                F('quantity') * Coalesce(F('discounted_price'), F('price')),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        )
    ).order_by('-total_quantity')[:10]

    # Best selling categories (top 10 by quantity sold)
    top_categories = OrderItem.objects.filter(
        order__status='delivered',
        order__created_at__gte=start_datetime,
        order__created_at__lt=end_datetime,
        is_cancelled=False,  # Exclude cancelled items
        is_returned=False    # Exclude returned items
    ).values('product__category__name').annotate(
        total_quantity=Sum('quantity'),
        total_revenue=Sum(
            ExpressionWrapper(
                F('quantity') * Coalesce(F('discounted_price'), F('price')),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        )
    ).order_by('-total_quantity')[:10]

    # Chart data for top products
    top_products_labels = [p['product__name'] for p in top_products]
    top_products_quantities = [p['total_quantity'] for p in top_products]
    top_products_revenues = [float(p['total_revenue'] or 0) for p in top_products]

    # Chart data for top categories
    top_categories_labels = [c['product__category__name'] for c in top_categories]
    top_categories_quantities = [c['total_quantity'] for c in top_categories]
    top_categories_revenues = [float(c['total_revenue'] or 0) for c in top_categories]

    # Prepare report data for orders
    report_data = [['Order ID', 'Date', 'Customer', 'Subtotal', 'Discount', 'Coupon Discount', 'Referral Discount', 'Total']]
    for order in orders:
        report_data.append([
            order.order_id,
            order.created_at.strftime('%Y-%m-%d'),
            order.user.email,
            f"${float(order.subtotal):.2f}",
            f"${float(order.discount):.2f}",
            f"${float(order.coupon_discount):.2f}",
            f"${float(order.referral_coupon_discount):.2f}",
            f"${float(order.total):.2f}",
        ])

    # === PDF Download ===
    if download_format == 'pdf':
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                                topMargin=0.5 * inch, bottomMargin=0.5 * inch)
        styles = getSampleStyleSheet()
        elements = []

        title_style = ParagraphStyle('TitleStyle', parent=styles['Title'], fontSize=18, alignment=1, spaceAfter=12)
        subtitle_style = ParagraphStyle('SubtitleStyle', parent=styles['Normal'], fontSize=12, alignment=1, spaceAfter=20)
        footer_style = ParagraphStyle('FooterStyle', parent=styles['Normal'], fontSize=10, alignment=1)

        elements.append(Paragraph("Velora Clotting", title_style))
        elements.append(Paragraph(f"Sales Report ({start_date} to {end_date})", subtitle_style))
        elements.append(Spacer(1, 0.2 * inch))

        summary = [
            ['Metric', 'Value'],
            ['Total Orders', str(total_orders)],
            ['Total Sales', f"${float(total_sales):.2f}"],
            ['Total Discount', f"${float(total_discount_all):.2f}"],
            ['Coupon Discount', f"${float(total_coupon_discount):.2f}"],
        ]
        summary_table = Table(summary, colWidths=[2.5 * inch, 2.5 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.gray),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.25 * inch))

        # Add top products to PDF
        elements.append(Paragraph("Top 10 Best Selling Products", subtitle_style))
        top_products_data = [['Product', 'Quantity Sold', 'Revenue']]
        for p in top_products:
            top_products_data.append([p['product__name'], p['total_quantity'], f"${float(p['total_revenue']):.2f}"])
        top_products_table = Table(top_products_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        top_products_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(top_products_table)
        elements.append(Spacer(1, 0.25 * inch))

        # Add top categories to PDF
        elements.append(Paragraph("Top 10 Best Selling Categories", subtitle_style))
        top_categories_data = [['Category', 'Quantity Sold', 'Revenue']]
        for c in top_categories:
            top_categories_data.append([c['product__category__name'], c['total_quantity'], f"${float(c['total_revenue']):.2f}"])
        top_categories_table = Table(top_categories_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        top_categories_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(top_categories_table)
        elements.append(Spacer(1, 0.25 * inch))

        data_table = Table(report_data, repeatRows=1)
        data_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A8A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(data_table)
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))

        doc.build(elements)
        buffer.seek(0)
        return HttpResponse(buffer.read(), content_type='application/pdf', headers={
            'Content-Disposition': f'attachment; filename="sales_report_{start_date}_to_{end_date}.pdf"',
        })

    # === Excel Download ===
    elif download_format == 'excel':
        wb = Workbook()
        ws = wb.active
        ws.title = "Sales Report"

        ws.append(['Sales Report', f"{start_date} to {end_date}"])
        ws.append([])
        ws.append(['Metric', 'Value'])
        ws.append(['Total Orders', total_orders])
        ws.append(['Total Sales', f"${float(total_sales):.2f}"])
        ws.append(['Total Discount', f"${float(total_discount_all):.2f}"])
        ws.append(['Coupon Discount', f"${float(total_coupon_discount):.2f}"])
        ws.append([])

        # Add top products to Excel
        ws.append(['Top 10 Best Selling Products'])
        ws.append(['Product', 'Quantity Sold', 'Revenue'])
        for p in top_products:
            ws.append([p['product__name'], p['total_quantity'], f"${float(p['total_revenue']):.2f}"])
        ws.append([])

        # Add top categories to Excel
        ws.append(['Top 10 Best Selling Categories'])
        ws.append(['Category', 'Quantity Sold', 'Revenue'])
        for c in top_categories:
            ws.append([c['product__category__name'], c['total_quantity'], f"${float(c['total_revenue']):.2f}"])
        ws.append([])

        for row in report_data:
            ws.append(row)

        for col in ws.columns:
            max_length = max(len(str(cell.value or '')) for cell in col)
            ws.column_dimensions[col[0].column_letter].width = max_length + 2

        buffer = io.BytesIO()
        wb.save(buffer)
        buffer.seek(0)
        return HttpResponse(buffer.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', headers={
            'Content-Disposition': f'attachment; filename="sales_report_{start_date}_to_{end_date}.xlsx"',
        })

    # === Render to dashboard ===
    context = {
        'report_type': report_type,
        'start_date': start_date,
        'end_date': end_date,
        'orders': orders,
        'total_orders': total_orders,
        'total_sales': total_sales,
        'total_discount': total_discount_all,
        'total_coupon_discount': total_coupon_discount,
        'total_referral_discount': total_referral_discount,
        'top_products': top_products,
        'top_categories': top_categories,
        'chart_data': {
            'labels': json.dumps(chart_labels),
            'sales': json.dumps(sales_data),
            'orders': json.dumps(orders_data),
        },
        'top_products_chart': {
            'labels': json.dumps(top_products_labels),
            'quantities': json.dumps(top_products_quantities),
            'revenues': json.dumps(top_products_revenues),
        },
        'top_categories_chart': {
            'labels': json.dumps(top_categories_labels),
            'quantities': json.dumps(top_categories_quantities),
            'revenues': json.dumps(top_categories_revenues),
        },
    }

    return render(request, 'adminside/dashboard.html', context)


# ===========================# User Management# ===========================
from django.core.paginator import Paginator
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.db.models import Q
import logging
from .forms import UserFilterForm  # Ensure this is correctly imported

logger = logging.getLogger(__name__)

@never_cache
def user_list(request):
    if not (request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser)):
        logger.warning(f"Unauthorized access to user_list by {request.user.email if request.user.is_authenticated else 'anonymous'}")
        messages.error(request, 'You are not authorized to access this page.')
        return redirect('adminside:admin_login')

    try:
        User = get_user_model()  # Reference userside.CustomUser
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

        # Pagination
        paginator = Paginator(users, 10)  # 10 users per page
        page_number = request.GET.get('page')
        users_page = paginator.get_page(page_number)

        context = {
            'form': form,
            'users': users_page,
        }
        return render(request, 'adminside/user_list.html', context)
    except Exception as e:
        logger.error(f"Error in user_list: {str(e)}")
        messages.error(request, f'An error occurred: {str(e)}')
        return render(request, 'adminside/user_list.html', {'form': form, 'users': []})

from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse

@require_POST
@csrf_exempt
def toggle_status(request, user_id):
    User = get_user_model()  # Dynamically get the active user model
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

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
MAX_IMAGES_PER_VARIANT = 50  # Optional: Set a reasonable limit

@login_required
@require_http_methods(["GET", "POST"])
def add_product(request):
    logger.info("add_product view called with method: %s", request.method)

    if request.method == 'POST':
        logger.debug("=== DEBUG: POST DATA ===")
        for key, value in request.POST.items():
            logger.debug("%s: %s", key, value)

        logger.debug("=== DEBUG: FILES DATA ===")
        for key, files in request.FILES.lists():
            logger.debug("%s: %s", key, [f.name for f in files])

        product_form = ProductForm(request.POST)
        variant_formset = ProductVariantFormSet(request.POST, request.FILES)

        # Handle variant images
        variant_images = {}
        for key in request.FILES:
            if key.startswith('variant-') and key.endswith('-images'):
                index = key.split('-')[1]
                variant_images[index] = request.FILES.getlist(key)
                logger.debug("=== DEBUG: Variant %s Images received: %s ===", index, len(variant_images[index]))
                for i, img in enumerate(variant_images[index]):
                    logger.debug("Variant %s Image %s: %s, Size: %s, Type: %s", index, i+1, img.name, img.size, img.content_type)

        # Validate image count
        for index, images in variant_images.items():
            if len(images) > MAX_IMAGES_PER_VARIANT:
                logger.warning("=== DEBUG: Variant %s has too many images: %s > %s ===", index, len(images), MAX_IMAGES_PER_VARIANT)
                messages.error(request, f'Variant {int(index) + 1} has too many images. Maximum allowed is {MAX_IMAGES_PER_VARIANT}.')
                return render(request, 'adminside/add_product.html', {
                    'product_form': product_form,
                    'variant_formset': variant_formset,
                })

        # Validate image types
        for index, images in variant_images.items():
            for i, img in enumerate(images):
                if img.content_type not in ALLOWED_IMAGE_TYPES:
                    logger.warning("=== DEBUG: Variant %s Image %s type validation failed: %s ===", index, i+1, img.content_type)
                    messages.error(request, f'Invalid image format for variant {int(index) + 1} image {i+1} ({img.name}). Only PNG, JPEG, and WebP are allowed.')
                    return render(request, 'adminside/add_product.html', {
                        'product_form': product_form,
                        'variant_formset': variant_formset,
                    })

        # Validate forms
        product_valid = product_form.is_valid()
        variant_valid = variant_formset.is_valid()

        logger.debug("=== DEBUG: Form Validity ===")
        logger.debug("Product form valid: %s", product_valid)
        logger.debug("Variant formset valid: %s", variant_valid)

        if not product_valid:
            logger.debug("=== DEBUG: Product Form Errors ===")
            for field, errors in product_form.errors.items():
                logger.debug("Field '%s': %s", field, errors)

        if not variant_valid:
            logger.debug("=== DEBUG: Variant Formset Errors ===")
            logger.debug("Non-form errors: %s", variant_formset.non_form_errors())
            for i, form in enumerate(variant_formset):
                if form.errors:
                    logger.debug("Variant form %s errors: %s", i, form.errors)
                else:
                    logger.debug("Variant form %s data: %s", i, form.cleaned_data)

        if product_valid and variant_valid:
            try:
                with transaction.atomic():
                    # Save the product
                    product = product_form.save()
                    logger.info("=== DEBUG: Product saved: %s (ID: %s) ===", product.name, product.id)

                    # Save variants and their images
                    variants_saved = 0
                    for i, form in enumerate(variant_formset):
                        logger.debug("=== DEBUG: Processing variant form %s with data: %s ===", i, form.cleaned_data)
                        if form.cleaned_data and not form.cleaned_data.get('DELETE', False):
                            # Ensure the form has valid data
                            variant = form.save(commit=False, product=product)
                            variant.product = product
                            variant.save()
                            variants_saved += 1
                            logger.info("=== DEBUG: Variant saved: %s - %s ===", 
                                       variant.color_variant.color_name if variant.color_variant else 'No ColorVariant', 
                                       variant.size.name if variant.size else 'No Size')

                            # Save variant images
                            if str(i) in variant_images:
                                for j, image in enumerate(variant_images[str(i)]):
                                    ProductImage.objects.create(
                                        product=product,
                                        image=image,
                                        color_variant=variant.color_variant
                                    )
                                    logger.info("=== DEBUG: Variant %s Image %s saved: %s ===", i, j+1, image.name)
                        else:
                            logger.debug("=== DEBUG: Variant form %s skipped (empty: %s, DELETE: %s) ===", 
                                        i, 
                                        not form.cleaned_data, 
                                        form.cleaned_data.get('DELETE', False) if form.cleaned_data else 'N/A')

                    logger.info("=== DEBUG: Total variants saved: %s ===", variants_saved)
                    if variants_saved == 0:
                        logger.warning("=== DEBUG: No variants saved, possibly due to all being marked for deletion or empty ===")
                        messages.error(request, "At least one variant must be provided.")
                        product.delete()  # Roll back product creation if no variants
                        return render(request, 'adminside/add_product.html', {
                            'product_form': product_form,
                            'variant_formset': variant_formset,
                        })

                    messages.success(request, 'Product and variants added successfully!')
                    logger.info("=== DEBUG: Redirecting to product list ===")
                    return redirect('adminside:product_list')

            except Exception as e:
                logger.error("=== DEBUG: Exception during save: %s ===", str(e), exc_info=True)
                messages.error(request, f'Error creating product: {str(e)}')

        else:
            logger.warning("=== DEBUG: Form validation failed, staying on same page ===")
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
        # Initialize formset with one empty form
        variant_formset = ProductVariantFormSet(queryset=ProductVariant.objects.none())

    context = {
        'product_form': product_form,
        'variant_formset': variant_formset,
    }
    return render(request, 'adminside/add_product.html', context)



# views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import transaction
from .forms import ProductForm, ProductVariantFormSet
from .models import Product, ProductImage, ColorVariant, Category, Size
import logging

logger = logging.getLogger(__name__)

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']
MAX_IMAGES_PER_VARIANT = 50  # Optional: Set a reasonable upper limit to prevent abuse

def get_variant_images_for_template(product):
    variant_images = {}
    for variant in product.variants.all():
        images = ProductImage.objects.filter(product=product, color_variant=variant.color_variant)
        variant_images[variant.id] = [img.image.url for img in images]
    return variant_images

def edit_product(request, product_id):
    logger.info("edit_product view called with method: %s, product_id: %s", request.method, product_id)
    
    product = get_object_or_404(Product, id=product_id)
    
    if request.method == 'POST':
        logger.debug("=== DEBUG: POST DATA ===")
        for key, value in request.POST.items():
            logger.debug("%s: %s", key, value)
        
        logger.debug("=== DEBUG: FILES DATA ===")
        for key, files in request.FILES.lists():
            logger.debug("%s: %s", key, [f.name for f in files])
        
        product_form = ProductForm(request.POST, request.FILES, instance=product)
        variant_formset = ProductVariantFormSet(request.POST, request.FILES, instance=product)
        
        # Handle variant images and deletions
        variant_images = {}
        variant_image_deletions = {}
        
        # Process image deletions
        for key in request.POST:
            if key.startswith('variant-') and '-delete_image_' in key:
                parts = key.split('-')
                if len(parts) >= 2:
                    index = parts[1]
                    image_id = key.split('_')[-1]
                    variant_image_deletions.setdefault(index, []).append(image_id)
                    logger.debug(f"=== DEBUG: Marked image {image_id} for deletion in variant {index} ===")
        
        # Process new images
        for key in request.FILES:
            if key.startswith('variant-') and key.endswith('-images'):
                index = key.split('-')[1]
                variant_images[index] = request.FILES.getlist(key)
                logger.debug(f"=== DEBUG: Variant {index} Images received: {len(variant_images[index])} ===")
                for i, img in enumerate(variant_images[index]):
                    logger.debug("Variant %s Image %s: %s, Size: %s, Type: %s", index, i+1, img.name, img.size, img.content_type)
        
        # Validate image count (optional upper limit)
        for index, images in variant_images.items():
            if len(images) > MAX_IMAGES_PER_VARIANT:
                logger.warning("=== DEBUG: Variant %s has too many images: %s > %s ===", index, len(images), MAX_IMAGES_PER_VARIANT)
                messages.error(request, f'Variant {int(index) + 1} has too many images. Maximum allowed is {MAX_IMAGES_PER_VARIANT}.')
                return render(request, 'adminside/edit_product.html', {
                    'product_form': product_form,
                    'variant_formset': variant_formset,
                    'product': product,
                    'categories': Category.objects.filter(is_listed=True, is_deleted=False),
                    'sizes': Size.objects.all(),
                    'variant_images': get_variant_images_for_template(product),
                })

        # Validate image types
        for index, images in variant_images.items():
            for i, img in enumerate(images):
                if img.content_type not in ALLOWED_IMAGE_TYPES:
                    logger.warning("=== DEBUG: Variant %s Image %s type validation failed: %s ===", index, i+1, img.content_type)
                    messages.error(request, f'Invalid image format for variant {int(index) + 1} image {i+1} ({img.name}). Only PNG, JPEG, and WebP are allowed.')
                    return render(request, 'adminside/edit_product.html', {
                        'product_form': product_form,
                        'variant_formset': variant_formset,
                        'product': product,
                        'categories': Category.objects.filter(is_listed=True, is_deleted=False),
                        'sizes': Size.objects.all(),
                        'variant_images': get_variant_images_for_template(product),
                    })

        # Validate forms
        product_valid = product_form.is_valid()
        variant_valid = variant_formset.is_valid()
        
        logger.debug("=== DEBUG: Form Validity ===")
        logger.debug(f"Product form valid: {product_valid}")
        logger.debug(f"Variant formset valid: {variant_valid}")
        
        if not product_valid:
            logger.debug("=== DEBUG: Product Form Errors ===")
            for field, errors in product_form.errors.items():
                logger.debug(f"Field '{field}': {errors}")
        
        if not variant_valid:
            logger.debug("=== DEBUG: Variant Formset Errors ===")
            logger.debug(f"Non-form errors: {variant_formset.non_form_errors()}")
            for i, form in enumerate(variant_formset):
                if form.errors:
                    logger.debug(f"Variant form {i} errors: {form.errors}")
        
        if product_valid and variant_valid:
            try:
                with transaction.atomic():
                    # Save the product
                    product = product_form.save()
                    logger.info(f"=== DEBUG: Product updated: {product.name} (ID: {product.id}) ===")

                    # Handle variant image deletions first
                    for index, image_ids in variant_image_deletions.items():
                        for image_id in image_ids:
                            try:
                                image = ProductImage.objects.get(id=image_id, product=product)
                                logger.debug(f"=== DEBUG: Deleting image ID {image_id} ===")
                                image.delete()
                            except ProductImage.DoesNotExist:
                                logger.debug(f"=== DEBUG: Image ID {image_id} not found for deletion ===")
                    
                    # Save variants and handle their images
                    variants_saved = 0
                    for i, form in enumerate(variant_formset):
                        if form.cleaned_data:
                            if form.cleaned_data.get('DELETE'):
                                if form.instance.pk:
                                    logger.debug(f"=== DEBUG: Deleting variant {form.instance.pk} ===")
                                    ProductImage.objects.filter(
                                        product=product,
                                        color_variant=form.instance.color_variant
                                    ).delete()
                                    form.instance.delete()
                                continue
                            
                            logger.debug(f"=== DEBUG: Processing variant {i} with data: {form.cleaned_data} ===")
                            
                            # Save the variant
                            variant = form.save(commit=False, product=product)
                            variant.product = product
                            variant.save()
                            variants_saved += 1
                            logger.info(f"=== DEBUG: Variant saved: {variant.color_variant.color_name} - {variant.size.name} (ID: {variant.id}) ===")
                            
                            # Handle new variant images
                            if str(i) in variant_images:
                                for j, image_file in enumerate(variant_images[str(i)]):
                                    product_image = ProductImage.objects.create(
                                        product=product,
                                        image=image_file,
                                        color_variant=variant.color_variant
                                    )
                                    logger.info(f"=== DEBUG: Created ProductImage ID {product_image.id} for variant {i}, image {j+1}: {image_file.name} ===")
                    
                    if variants_saved == 0:
                        existing_variants = product.variants.filter(is_listed=True).count()
                        if existing_variants == 0:
                            raise ValueError("At least one valid variant is required.")
                    
                    logger.info(f"=== DEBUG: Total variants processed: {variants_saved} ===")
                    messages.success(request, 'Product and variants updated successfully!')
                    return redirect('adminside:product_list')
                    
            except Exception as e:
                logger.error(f"=== DEBUG: Exception during save: {str(e)} ===", exc_info=True)
                messages.error(request, f'Error updating product: {str(e)}')
                
        else:
            logger.warning("=== DEBUG: Form validation failed ===")
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
        product_form = ProductForm(instance=product)
        variant_formset = ProductVariantFormSet(instance=product)

    context = {
        'product_form': product_form,
        'variant_formset': variant_formset,
        'product': product,
        'categories': Category.objects.filter(is_listed=True, is_deleted=False),
        'sizes': Size.objects.all(),
        'variant_images': get_variant_images_for_template(product),
    }
    return render(request, 'adminside/edit_product.html', context)
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

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Product

def toggle_is_active(request, product_id):
    try:
        product = get_object_or_404(Product, pk=product_id)
        product.is_active = not product.is_active
        product.save()
        return JsonResponse({
            'success': True,
            'is_active': product.is_active,
            'message': f"Product '{product.name}' {'activated' if product.is_active else 'deactivated'} successfully."
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)

def toggle_is_listed(request, product_id):
    try:
        product = get_object_or_404(Product, pk=product_id)
        product.is_listed = not product.is_listed
        product.save()
        return JsonResponse({
            'success': True,
            'is_listed': product.is_listed,
            'message': f"Product '{product.name}' {'listed' if product.is_listed else 'unlisted'} successfully."
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f"Error: {str(e)}"
        }, status=500)
# ===========================# Category Management# ===========================

from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import Category
from .forms import CategoryForm

def category_list(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect(reverse('adminside:category_list') + '?success=true')  # Correctly append query parameter
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
        'search_query': search_query,
        'success': request.GET.get('success', False)
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
            # Redirect with a specific query parameter for a successful edit
            return redirect(reverse('adminside:category_list') + '?edit_success=true')
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
        'status_choices': Order.STATUS_CHOICES, 
    })

import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from decimal import Decimal
from django.utils import timezone
from .models import Order, OrderItem, Wallet, Product, ProductVariant, ColorVariant, ProductImage, Address, Transaction

logger = logging.getLogger(__name__)

@login_required(login_url='adminside:admin_login')
def admin_order_detail(request, order_id):
    # Use select_related and prefetch_related for efficient data retrieval
    order = get_object_or_404(
        Order.objects.select_related('user', 'address').prefetch_related(
            'items',
            'items__product',
            'items__variant__color_variant',
            'items__variant__size',
            'items__product__product_images'
        ),
        order_id=order_id
    )

    if request.method == "POST":
        new_status = request.POST.get("status")

        # Prevent status change if already delivered, cancelled, or returned
        if order.status not in ["delivered", "cancelled", "returned"]:
            # Prevent going back to 'pending' once status has moved forward
            if new_status == "pending" and order.status != "pending":
                messages.error(request, "Cannot change status back to 'Pending'.")
                request.session['toast_message'] = {
                    'message': "Cannot change status back to 'Pending'.",
                    'bgColor': '#EF4444',  # Red for error
                    'textColor': '#FFFFFF'
                }
                return redirect('adminside:admin_order_detail', order_id=order.order_id)

            if new_status and new_status != order.status and new_status != "returned":
                with transaction.atomic():
                    order.status = new_status
                    if new_status == 'cancelled':
                        for item in order.items.all():
                            if not item.is_cancelled:
                                item.is_cancelled = True
                                item.save()
                                if item.variant:
                                    item.variant.stock += item.quantity
                                    item.variant.save()
                        # Create refund transaction for paid orders (Wallet only)
                        if order.is_paid and order.payment_method == 'Wallet':
                            try:
                                wallet, _ = Wallet.objects.get_or_create(user=order.user)
                                refund_amount = order.total
                                wallet.credit(refund_amount)
                                Transaction.objects.create(
                                    wallet=wallet,
                                    transaction_type='REFUND',
                                    amount=refund_amount,
                                    source_order=order,
                                    description=f"Refund for cancelled order {order.order_id} (Wallet)"
                                )
                                logger.info(f"Refund transaction created for order {order.order_id}: ₹{refund_amount}")
                                messages.success(request, f"Refunded ₹{refund_amount:.2f} to {order.user.email}'s wallet.")
                            except Exception as e:
                                logger.error(f"Error creating refund transaction for order {order.order_id}: {e}", exc_info=True)
                                messages.error(request, f"Error processing refund: {e}")
                                request.session['toast_message'] = {
                                    'message': f"Error processing refund: {e}",
                                    'bgColor': '#EF4444',
                                    'textColor': '#FFFFFF'
                                }
                                return redirect('adminside:admin_order_detail', order_id=order.order_id)
                    order.save()
                    messages.success(request, f"Order status updated to {order.get_status_display()}!")
                    request.session['toast_message'] = {
                        'message': f"Order status updated to {order.get_status_display()} successfully!",
                        'bgColor': '#4B0082',  # Indigo for success
                        'textColor': '#FFFFFF'
                    }
            else:
                messages.error(request, "Invalid status change.")
                request.session['toast_message'] = {
                    'message': "Invalid status change.",
                    'bgColor': '#EF4444',
                    'textColor': '#FFFFFF'
                }
        else:
            messages.error(request, f"Order is {order.get_status_display()}. Status changes are disabled.")
            request.session['toast_message'] = {
                'message': f"Order is {order.get_status_display()}. Status changes are disabled.",
                'bgColor': '#EF4444',
                'textColor': '#FFFFFF'
            }

        return redirect('adminside:admin_order_detail', order_id=order.order_id)

    # Add subtotal to each order item for template use
    for item in order.items.all():
        item.subtotal = item.quantity * item.price

    # Get toast message from session and clear it
    toast_message = request.session.pop('toast_message', None)

    return render(request, 'adminside/order_detail.html', {
        'order': order,
        'status_choices': [(k, v) for k, v in Order.STATUS_CHOICES if k != 'returned'],
        'toast_message': toast_message
    })

@login_required(login_url='adminside:admin_login')
@require_POST
def confirm_return(request, order_id):
    order = get_object_or_404(Order, order_id=order_id)

    # Check if return is already verified or no return requested
    if not order.return_requested:
        messages.warning(request, "No return request exists for this order.")
        return redirect('adminside:admin_order_detail', order_id=order_id)
    if order.return_verified:
        messages.warning(request, "This return has already been confirmed.")
        return redirect('adminside:admin_order_detail', order_id=order_id)

    verify_return = request.POST.get("verify_return") == "on"
    if not verify_return:
        messages.warning(request, "Return verification cancelled. Please check the 'Verify Return & Refund Wallet' box to confirm.")
        return redirect('adminside:admin_order_detail', order_id=order_id)

    with transaction.atomic():
        try:
            # Calculate refund amount for returned items
            refund_amount = 0
            returned_items = order.items.filter(is_returned=True, is_refunded_to_wallet=False)
            for item in returned_items:
                refund_amount += item.total  # Uses discounted_price or price * quantity

            # Credit wallet for all payment methods (COD, Wallet, Razorpay)
            if refund_amount > 0 and order.is_paid:
                wallet, _ = Wallet.objects.get_or_create(user=order.user)
                wallet.credit(refund_amount)
                Transaction.objects.create(
                    wallet=wallet,
                    transaction_type='REFUND',
                    amount=refund_amount,
                    source_order=order,
                    description=f"Refund for returned order {order.order_id} ({order.payment_method}, {order.payment_gateway or 'N/A'})"
                )
                for item in returned_items:
                    item.is_refunded_to_wallet = True
                    item.save()
                logger.info(f"Return confirmed and refund transaction created for order {order.order_id}: ₹{refund_amount} ({order.payment_method}, {order.payment_gateway or 'N/A'})")
                messages.success(request, f"Refunded ₹{refund_amount:.2f} to {order.user.email}'s wallet.")

            # Skip stock restoration (handled in return_order_item)
            for item in order.items.all():
                if item.is_returned and not item.is_cancelled:
                    if not item.variant:
                        logger.warning(f"Admin confirmed return for OrderItem {item.id}, but no ProductVariant found. Product: {item.product.name}")
                elif item.is_cancelled:
                    logger.info(f"OrderItem {item.id} was cancelled, not returned. Stock assumed to be restored during cancellation.")
                else:
                    logger.info(f"OrderItem {item.id} is not marked as returned or cancelled, skipping.")

            # Update order status
            order.return_verified = True
            if all(i.is_returned or i.is_cancelled for i in order.items.all()):
                order.status = 'returned'
            order.save()

            # Send notification
            if refund_amount > 0:
                try:
                    send_mail(
                        'Refund Credited to Wallet',
                        f'Your return for order {order.order_id} has been approved. ₹{refund_amount:.2f} has been credited to your wallet.',
                        settings.DEFAULT_FROM_EMAIL,
                        [order.user.email],
                        fail_silently=True,
                    )
                    logger.info(f"Refund notification sent to {order.user.email} for order {order.order_id}")
                except Exception as e:
                    logger.error(f"Failed to send refund notification to {order.user.email}: {str(e)}")

            messages.success(request, f"Return for order {order.order_id} confirmed.")

            return redirect('adminside:admin_order_detail', order_id=order_id)

        except Exception as e:
            logger.error(f"Error confirming return for order {order_id}: {e}", exc_info=True)
            messages.error(request, f"An error occurred while confirming the return: {e}")
            return redirect('adminside:admin_order_detail', order_id=order_id)

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from .models import Product, Category, ProductOffer, CategoryOffer
from django.db.models import Q
import json
from datetime import date

@login_required
def product_offers(request):
    # Fetch all products for the add/edit modal
    products = Product.objects.filter(is_deleted=False)
    
    # Handle search query
    product_search_query = request.GET.get('product_search', '')
    product_offers = ProductOffer.objects.filter(is_deleted=False)
    if product_search_query:
        product_offers = product_offers.filter(
            Q(name__icontains=product_search_query) |
            Q(product__name__icontains=product_search_query)
        )
    
    # Pagination
    paginator = Paginator(product_offers, 10)  # 10 offers per page
    page_number = request.GET.get('product_page', 1)
    product_offers_page = paginator.get_page(page_number)
    
    context = {
        'products': products,
        'product_offers': product_offers_page,
        'product_search_query': product_search_query,
    }
    return render(request, 'adminside/product_offers.html', context)

@login_required
def category_offers(request):
    # Fetch all categories for the add/edit modal
    categories = Category.objects.filter(is_deleted=False)
    
    # Handle search query
    category_search_query = request.GET.get('category_search', '')
    category_offers = CategoryOffer.objects.filter(is_deleted=False)
    if category_search_query:
        category_offers = category_offers.filter(
            Q(name__icontains=category_search_query) |
            Q(category__name__icontains=category_search_query)
        )
    
    # Pagination
    paginator = Paginator(category_offers, 10)  # 10 offers per page
    page_number = request.GET.get('category_page', 1)
    category_offers_page = paginator.get_page(page_number)
    
    context = {
        'categories': categories,
        'category_offers': category_offers_page,
        'category_search_query': category_search_query,
    }
    return render(request, 'adminside/category_offers.html', context)

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.db import IntegrityError
from django.core.exceptions import ObjectDoesNotExist
from .models import Category, Product, ProductOffer, CategoryOffer
import json
import logging

logger = logging.getLogger(__name__)

@login_required
@csrf_protect
def manage_offer(request, offer_type):
    if request.method == 'GET':
        offer_id = request.GET.get('id')
        if offer_type == 'product' and offer_id:
            try:
                offer = ProductOffer.objects.get(id=offer_id, is_deleted=False)
                return JsonResponse({
                    'success': True,
                    'name': offer.name,
                    'product_id': offer.product.id,
                    'discount_percentage': str(offer.discount_percentage),
                    'start_date': offer.start_date.isoformat(),
                    'end_date': offer.end_date.isoformat(),
                    'is_active': offer.is_active
                })
            except ProductOffer.DoesNotExist:
                logger.error(f"ProductOffer not found: id={offer_id}")
                return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
            except Exception as e:
                logger.error(f"Error in manage_offer GET (product, id={offer_id}): {str(e)}")
                return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)
        elif offer_type == 'category' and offer_id:
            try:
                offer = CategoryOffer.objects.get(id=offer_id, is_deleted=False)
                return JsonResponse({
                    'success': True,
                    'name': offer.name,
                    'category_id': offer.category.id,
                    'discount_percentage': str(offer.discount_percentage),
                    'start_date': offer.start_date.isoformat(),
                    'end_date': offer.end_date.isoformat(),
                    'is_active': offer.is_active
                })
            except CategoryOffer.DoesNotExist:
                logger.error(f"CategoryOffer not found: id={offer_id}")
                return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
            except Exception as e:
                logger.error(f"Error in manage_offer GET (category, id={offer_id}): {str(e)}")
                return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)
        logger.warning(f"Invalid GET request: offer_type={offer_type}, id={offer_id}")
        return JsonResponse({'success': False, 'message': 'Invalid request.'}, status=400)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            logger.info(f"manage_offer POST received data: {data}")
            offer_id = data.get('id')
            name = data.get('name')
            discount_percentage = data.get('discount_percentage')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            is_active = data.get('is_active', True)

            if offer_type == 'product':
                product_id = data.get('product_id')
                if not all([name, product_id, discount_percentage, start_date, end_date]):
                    logger.warning(f"Missing fields in product offer: {data}")
                    return JsonResponse({'success': False, 'message': 'All fields are required.'}, status=400)

                try:
                    discount_percentage = float(discount_percentage)
                    if not (0 <= discount_percentage <= 100):
                        logger.warning(f"Invalid discount_percentage: {discount_percentage}")
                        return JsonResponse({'success': False, 'message': 'Discount percentage must be between 0 and 100.'}, status=400)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid discount_percentage format: {discount_percentage}")
                    return JsonResponse({'success': False, 'message': 'Discount percentage must be a valid number.'}, status=400)

                try:
                    product = Product.objects.get(id=product_id, is_deleted=False)
                except Product.DoesNotExist:
                    logger.warning(f"Product not found: {product_id}")
                    return JsonResponse({'success': False, 'message': 'Selected product does not exist.'}, status=404)

                if offer_id:
                    try:
                        offer = ProductOffer.objects.get(id=offer_id, is_deleted=False)
                        offer.name = name
                        offer.product = product
                        offer.discount_percentage = discount_percentage
                        offer.start_date = start_date
                        offer.end_date = end_date
                        offer.is_active = is_active
                        offer.save()
                        message = 'Product offer updated successfully.'
                    except ProductOffer.DoesNotExist:
                        logger.warning(f"ProductOffer not found: {offer_id}")
                        return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
                    except IntegrityError:
                        logger.warning(f"IntegrityError updating product offer: name={name}")
                        return JsonResponse({'success': False, 'message': 'An offer with this name already exists.'}, status=400)
                else:
                    try:
                        offer = ProductOffer.objects.create(
                            name=name,
                            product=product,
                            discount_percentage=discount_percentage,
                            start_date=start_date,
                            end_date=end_date,
                            is_active=is_active
                        )
                        message = 'Product offer created successfully.'
                    except IntegrityError:
                        logger.warning(f"IntegrityError creating product offer: name={name}")
                        return JsonResponse({'success': False, 'message': 'An offer with this name already exists.'}, status=400)

            elif offer_type == 'category':
                category_id = data.get('category_id')
                if not all([name, category_id, discount_percentage, start_date, end_date]):
                    logger.warning(f"Missing fields in category offer: {data}")
                    return JsonResponse({'success': False, 'message': 'All fields are required.'}, status=400)

                try:
                    discount_percentage = float(discount_percentage)
                    if not (0 <= discount_percentage <= 100):
                        logger.warning(f"Invalid discount_percentage: {discount_percentage}")
                        return JsonResponse({'success': False, 'message': 'Discount percentage must be between 0 and 100.'}, status=400)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid discount_percentage format: {discount_percentage}")
                    return JsonResponse({'success': False, 'message': 'Discount percentage must be a valid number.'}, status=400)

                try:
                    category = Category.objects.get(id=category_id, is_deleted=False)
                except Category.DoesNotExist:
                    logger.warning(f"Category not found: {category_id}")
                    return JsonResponse({'success': False, 'message': 'Selected category does not exist.'}, status=404)

                if offer_id:
                    try:
                        offer = CategoryOffer.objects.get(id=offer_id, is_deleted=False)
                        offer.name = name
                        offer.category = category
                        offer.discount_percentage = discount_percentage
                        offer.start_date = start_date
                        end_date_str = end_date
                        offer.end_date = end_date
                        offer.is_active = is_active
                        offer.save()
                        message = 'Category offer updated successfully.'
                    except CategoryOffer.DoesNotExist:
                        logger.warning(f"CategoryOffer not found: {offer_id}")
                        return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
                    except IntegrityError:
                        logger.warning(f"IntegrityError updating category offer: name={name}")
                        return JsonResponse({'success': False, 'message': 'An offer with this name already exists.'}, status=400)
                else:
                    try:
                        offer = CategoryOffer.objects.create(
                            name=name,
                            category=category,
                            discount_percentage=discount_percentage,
                            start_date=start_date,
                            end_date=end_date,
                            is_active=is_active
                        )
                        message = 'Category offer created successfully.'
                    except IntegrityError:
                        logger.warning(f"IntegrityError creating category offer: name={name}")
                        return JsonResponse({'success': False, 'message': 'An offer with this name already exists.'}, status=400)
                    except ValueError as e:
                        logger.warning(f"ValueError creating category offer: {str(e)}")
                        return JsonResponse({'success': False, 'message': f'Invalid data: {str(e)}'}, status=400)

            else:
                logger.warning(f"Invalid offer type: {offer_type}")
                return JsonResponse({'success': False, 'message': 'Invalid offer type.'}, status=400)

            logger.info(f"Offer {offer_type} {offer_id or 'new'} saved successfully: {message}")
            return JsonResponse({'success': True, 'message': message})

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in manage_offer: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Invalid JSON data: {str(e)}'}, status=400)
        except ObjectDoesNotExist:
            logger.warning(f"Object not found: {data}")
            return JsonResponse({'success': False, 'message': 'Selected object does not exist.'}, status=404)
        except Exception as e:
            logger.error(f"Unexpected error in manage_offer POST: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)

    logger.warning(f"Invalid request method: {request.method}")
    return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=400)

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from .models import ProductOffer, CategoryOffer
import logging

logger = logging.getLogger(__name__)

@login_required
@csrf_protect
def delete_offer(request, offer_type, offer_id):
    if request.method == 'POST':
        try:
            if offer_type == 'product':
                try:
                    offer = ProductOffer.objects.get(id=offer_id, is_deleted=False)
                    offer.delete()  # Permanent deletion
                    logger.info(f"ProductOffer permanently deleted: id={offer_id}")
                    return JsonResponse({'success': True, 'message': 'Product offer deleted successfully.'})
                except ProductOffer.DoesNotExist:
                    logger.warning(f"ProductOffer not found: id={offer_id}")
                    return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
            elif offer_type == 'category':
                try:
                    offer = CategoryOffer.objects.get(id=offer_id, is_deleted=False)
                    offer.delete()  # Permanent deletion
                    logger.info(f"CategoryOffer permanently deleted: id={offer_id}")
                    return JsonResponse({'success': True, 'message': 'Category offer deleted successfully.'})
                except CategoryOffer.DoesNotExist:
                    logger.warning(f"CategoryOffer not found: id={offer_id}")
                    return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
            else:
                logger.warning(f"Invalid offer type: {offer_type}")
                return JsonResponse({'success': False, 'message': 'Invalid offer type.'}, status=400)

        except Exception as e:
            logger.error(f"Error in delete_offer: offer_type={offer_type}, id={offer_id}, error={str(e)}")
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)

    logger.warning(f"Invalid request method: {request.method}")
    return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=400)
@login_required
@csrf_protect
def toggle_active_offer(request, offer_type, offer_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            logger.info(f"toggle_active_offer received data: {data}")
            is_active = data.get('is_active', False)
            
            if offer_type == 'product':
                offer = ProductOffer.objects.get(id=offer_id, is_deleted=False)
            elif offer_type == 'category':
                offer = CategoryOffer.objects.get(id=offer_id, is_deleted=False)
            elif offer_type == 'referral':
                offer = ReferralOffer.objects.get(id=offer_id, is_deleted=False)
            else:
                logger.warning(f"Invalid offer type in toggle_active_offer: {offer_type}")
                return JsonResponse({'success': False, 'message': 'Invalid offer type.'}, status=400)
            
            offer.is_active = is_active
            offer.save()
            logger.info(f"Offer {offer_type} {offer_id} toggled to is_active={is_active}")
            return JsonResponse({
                'success': True,
                'message': f'Offer {"activated" if is_active else "deactivated"} successfully.'
            })
        
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in toggle_active_offer: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Invalid JSON data: {str(e)}'}, status=400)
        except (ProductOffer.DoesNotExist, CategoryOffer.DoesNotExist, ReferralOffer.DoesNotExist):
            logger.warning(f"Offer not found in toggle_active_offer: {offer_type} {offer_id}")
            return JsonResponse({'success': False, 'message': 'Offer not found.'}, status=404)
        except Exception as e:
            logger.error(f"Error in toggle_active_offer: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Unexpected error: {str(e)}'}, status=500)
    
    logger.warning(f"Invalid request method in toggle_active_offer: {request.method}")
    return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=400)

from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.shortcuts import render
from django.db.models import Q
from .models import Coupon
import json
import logging
from datetime import datetime, date

logger = logging.getLogger(__name__)

@csrf_protect
def coupon_management(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        logger.warning(f"Unauthorized access attempt by user: {request.user}")
        return JsonResponse({
            'success': False,
            'message': 'Unauthorized access. Admin privileges required.'
        }, status=403)

    if request.method == 'POST':
        try:
            logger.debug(f"Request headers: {dict(request.headers)}")
            content_type = request.headers.get('Content-Type', '')
            logger.debug(f"Content-Type: {content_type}")

            if 'application/json' in content_type.lower():
                request_body = request.body.decode('utf-8', errors='ignore')
                logger.debug(f"JSON Request body: {request_body}")
                if not request_body:
                    logger.error("Empty JSON request body")
                    return JsonResponse({
                        'success': False,
                        'message': 'Empty request body. Please check the form submission.'
                    }, status=400)
                data = json.loads(request_body)
            else:
                data = request.POST
                logger.debug(f"FormData POST data: {dict(data)}")

            logger.debug(f"Parsed data: {dict(data)}")
            action = data.get('action')

            if not action:
                logger.warning(f"Invalid action: {action}")
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid action.'
                }, status=400)

            if action == 'create':
                code = data.get('code', '').strip()
                discount_percentage = data.get('discount_percentage')
                valid_from_str = data.get('valid_from')
                valid_until_str = data.get('valid_until')

                if not code:
                    logger.warning("Coupon code is missing")
                    return JsonResponse({
                        'success': False,
                        'message': 'Coupon code is required.'
                    }, status=400)

                if len(code) > 10:
                    logger.warning(f"Coupon code too long: {code}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Coupon code must be 10 characters or less.'
                    }, status=400)

                if Coupon.objects.filter(code=code).exists():
                    logger.warning(f"Duplicate coupon code: {code}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Coupon code already exists.'
                    }, status=400)

                try:
                    discount_percentage = float(discount_percentage)
                    if not (0 <= discount_percentage <= 100):
                        logger.warning(f"Invalid discount percentage: {discount_percentage}")
                        return JsonResponse({
                            'success': False,
                            'message': 'Discount percentage must be between 0 and 100.'
                        }, status=400)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid discount percentage format: {discount_percentage}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid discount percentage.'
                    }, status=400)

                try:
                    valid_from = datetime.strptime(valid_from_str, '%Y-%m-%d').date()
                    valid_until = datetime.strptime(valid_until_str, '%Y-%m-%d').date()
                    today = date.today()
                    if valid_from < today:
                        logger.warning(f"Valid from date in past: {valid_from}")
                        return JsonResponse({
                            'success': False,
                            'message': 'Valid from date cannot be in the past.'
                        }, status=400)
                    if valid_until < valid_from:
                        logger.warning(f"Valid until date before valid from: {valid_until} < {valid_from}")
                        return JsonResponse({
                            'success': False,
                            'message': 'Valid until date must be after valid from date.'
                        }, status=400)
                except ValueError as e:
                    logger.warning(f"Invalid date format: {valid_from_str}, {valid_until_str}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid date format. Use YYYY-MM-DD.'
                    }, status=400)

                coupon = Coupon(
                    code=code,
                    discount_percentage=discount_percentage,
                    valid_from=valid_from,
                    valid_until=valid_until
                )
                coupon.save()
                logger.info(f"Coupon created: {coupon.code}")

                return JsonResponse({
                    'success': True,
                    'message': 'Coupon created successfully.',
                    'coupon': {
                        'id': coupon.id,
                        'code': coupon.code,
                        'discount_percentage': float(coupon.discount_percentage),
                        'valid_from': coupon.valid_from.strftime('%Y-%m-%d'),
                        'valid_until': coupon.valid_until.strftime('%Y-%m-%d'),
                        'used_by_count': coupon.used_by.count()
                    }
                })

            elif action == 'delete':
                coupon_id = data.get('coupon_id')
                if not coupon_id:
                    logger.warning("No coupon_id provided in delete request")
                    return JsonResponse({
                        'success': False,
                        'message': 'Coupon ID is required.'
                    }, status=400)
                try:
                    coupon_id = int(coupon_id)  # Ensure coupon_id is an integer
                    coupon = Coupon.objects.get(id=coupon_id)
                    coupon.delete()
                    logger.info(f"Coupon deleted: {coupon_id}")
                    return JsonResponse({
                        'success': True,
                        'message': 'Coupon deleted successfully.'
                    })
                except ValueError:
                    logger.warning(f"Invalid coupon_id format: {coupon_id}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid coupon ID format.'
                    }, status=400)
                except Coupon.DoesNotExist:
                    logger.warning(f"Coupon not found: {coupon_id}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Coupon not found.'
                    }, status=404)

            else:
                logger.warning(f"Invalid action: {action}")
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid action.'
                }, status=400)

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON data. Please check the form submission.'
            }, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': f'Error: {str(e)}'
            }, status=500)

    coupons = Coupon.objects.all()
    search_query = request.GET.get('search', '')
    if search_query:
        coupons = coupons.filter(
            Q(code__icontains=search_query)
        )

    paginator = Paginator(coupons, 10)
    page_number = request.GET.get('page')
    coupons_page = paginator.get_page(page_number)

    context = {
        'coupons': coupons_page,
        'search_query': search_query,
    }
    return render(request, 'adminside/coupon_management.html', context)

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from decimal import Decimal
from .models import Wallet, Transaction, Order
import logging

logger = logging.getLogger(__name__)

def is_admin(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)

@login_required
@user_passes_test(is_admin)
def wallet_list(request):
    wallets = Wallet.objects.select_related('user').all()
    search_query = request.GET.get('search', '')
    if search_query:
        wallets = wallets.filter(
            Q(user__email__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query)
        )
    paginator = Paginator(wallets, 10)
    page_number = request.GET.get('page')
    wallets_page = paginator.get_page(page_number)
    return render(request, 'adminside/wallet_list.html', {
        'wallets': wallets_page,
        'search_query': search_query
    })

@login_required
@user_passes_test(is_admin)
def transaction_list(request):
    transactions = Transaction.objects.select_related('wallet__user', 'source_order').order_by('-transaction_date')
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    if search_query:
        transactions = transactions.filter(
            Q(transaction_id__icontains=search_query) |
            Q(wallet__user__email__icontains=search_query)
        )
    if status_filter:
        transactions = transactions.filter(transaction_type=status_filter.upper())
    paginator = Paginator(transactions, 10)
    page_number = request.GET.get('page')
    transactions_page = paginator.get_page(page_number)
    return render(request, 'adminside/transaction_list.html', {
        'transactions': transactions_page,
        'search_query': search_query,
        'status_filter': status_filter,
        'transaction_types': Transaction.TRANSACTION_TYPES
    })

@login_required
@user_passes_test(is_admin)
def transaction_detail(request, transaction_id):
    transaction = get_object_or_404(Transaction, transaction_id=transaction_id)
    return render(request, 'adminside/transaction_detail.html', {'transaction': transaction})