from django.contrib import admin
from .models import Product, ProductImage, Category, ColorVariant, ProductVariant, Size, Order, OrderItem


class ProductImageInline(admin.TabularInline):
    model = ProductImage
    extra = 1
    fields = ['image', 'color_variant', 'product']
    readonly_fields = ['product']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'color_variant':
            # Limit color_variant choices to those associated with the current product
            if request._obj_:
                kwargs['queryset'] = ColorVariant.objects.filter(product=request._obj_)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class ProductVariantInline(admin.TabularInline):
    model = ProductVariant
    extra = 1
    fields = ['color_variant', 'size', 'stock', 'is_listed']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'color_variant':
            # Limit color_variant choices to those associated with the current product
            if request._obj_:
                kwargs['queryset'] = ColorVariant.objects.filter(product=request._obj_)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'price', 'is_active', 'is_listed', 'is_deleted', 'total_stock']
    list_editable = ['is_active', 'is_listed']
    list_filter = ['category', 'is_active', 'is_listed', 'is_deleted']
    search_fields = ['name', 'description']
    inlines = [ProductImageInline, ProductVariantInline]
    
    def get_form(self, request, obj=None, **kwargs):
        # Store the current object for use in inlines
        request._obj_ = obj
        return super().get_form(request, obj, **kwargs)


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_listed', 'is_deleted', 'description']
    list_filter = ['is_listed', 'is_deleted']
    search_fields = ['name', 'description']


@admin.register(ColorVariant)
class ColorVariantAdmin(admin.ModelAdmin):
    list_display = ['product', 'color_name', 'color_hex', 'is_listed']
    list_filter = ['is_listed', 'product']
    search_fields = ['color_name', 'product__name']
    list_editable = ['is_listed']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'product':
            kwargs['queryset'] = Product.objects.filter(is_deleted=False)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(ProductVariant)
class ProductVariantAdmin(admin.ModelAdmin):
    list_display = ['product', 'color_variant', 'size', 'stock', 'is_listed']
    list_filter = ['is_listed', 'product', 'color_variant', 'size']
    search_fields = ['product__name', 'color_variant__color_name', 'size__name']
    list_editable = ['stock', 'is_listed']
    
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'product':
            kwargs['queryset'] = Product.objects.filter(is_deleted=False)
        elif db_field.name == 'color_variant':
            kwargs['queryset'] = ColorVariant.objects.filter(is_listed=True)
        elif db_field.name == 'size':
            kwargs['queryset'] = Size.objects.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


@admin.register(Size)
class SizeAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = (
        'order_id', 'user', 'status', 'payment_method',
        'total', 'is_paid', 'created_at'
    )
    list_filter = ('status', 'payment_method', 'is_paid', 'created_at')
    search_fields = ('order_id', 'user__username', 'user__email')
    ordering = ('-created_at',)
    readonly_fields = ('order_id', 'created_at')
    fields = (
        'user', 'address', 'order_id', 'created_at',
        'status', 'payment_method', 'is_paid',
        'total', 'reason', 'return_requested', 'return_verified'
    )


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = (
        'order', 'product', 'size', 'quantity', 'price',
        'is_cancelled', 'is_returned'
    )
    list_filter = ('is_cancelled', 'is_returned')
    search_fields = ('order__order_id', 'product__name', 'size__name')