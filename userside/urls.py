from django.urls import path
from . import views
from .views import product_variants_api

app_name = 'userside'

urlpatterns = [
    # ===========================# Authentication & OTP URLs# ===========================
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify_otp/', views.otp_verify, name='verify_otp'),
    path('dashboard/', views.login_redirect, name='login_redirect'),
    path('validate_referral_code/', views.validate_referral_code, name='validate_referral_code'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/', views.reset_password, name='reset_password'),

    # ===========================# Home & Landing Page URLs# ===========================
    path('', views.landing_page, name='landing_page'),
    path('home/', views.landing_page, name='home'),

    # ===========================# Product Views URLs# ===========================
    path('products/', views.product_list, name='product_list'),
    path('clear-filters/', views.clear_filters, name='clear_filters'),
    path('product/<int:id>/', views.product_detail_view, name='product_detail'),
    path('api/product-variants/<int:product_id>/', product_variants_api, name='product_variants_api'),

    # ===========================# Category URLs# ===========================
    path('category/<str:category_name>/', views.category_redirect, name='category_redirect'),
    path('category/<int:id>/', views.category_products, name='category_products'),
    path('apply_referral_coupon/', views.apply_referral_coupon, name='apply_referral_coupon'),

    # ===========================# User Profile & Address Management URLs# ===========================
    path('profile/', views.user_profile, name='user_profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('verify-email/', views.verify_email_otp, name='verify_email'),
    path('my-addresses/', views.my_addresses, name='my_addresses'),
    path('address/save/', views.save_address, name='save_address'), 
    path('address/delete/<int:address_id>/', views.delete_address, name='delete_address'), 
    path('addresses/', views.address_list, name='address_list'),
    path('save-address-checkout/', views.save_address_checkout, name='save_address_checkout'),

    # ===========================# Cart URLs# ===========================
    path('cart/', views.view_cart, name='view_cart'),
    path('add-to-cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/update/<int:cart_item_id>/<str:action>/', views.update_cart_quantity, name='update_cart_quantity'),
    path('cart/remove/<int:cart_item_id>/', views.remove_from_cart, name='remove_from_cart'),

    # ===========================# Checkout & Order Placement URLs# ===========================
    path('checkout/', views.checkout_view, name='checkout'),
    path('place-order/', views.place_order, name='place_order'),
    path('order-success/<int:order_id>/', views.order_success, name='order_success'),
    path('apply-coupon/', views.apply_coupon, name='apply_coupon'),
    path('remove-coupon/', views.remove_coupon, name='remove_coupon'),

    # ===========================# Order Management URLs# ===========================
    path('orders/', views.order_list, name='order_list'),
    path('orders/<str:order_id>/', views.order_detail, name='order_detail'),
    path('orders/<str:order_id>/cancel/', views.cancel_entire_order, name='cancel_entire_order'),
    path('orders/item/<int:item_id>/cancel/', views.cancel_order_item, name='cancel_order_item'),
    path('orders/item/<int:item_id>/return/', views.return_order_item, name='return_order_item'),
    path('payment/<int:order_id>/', views.initiate_payment, name='initiate_payment'),
    path('order/failure/<int:order_id>/', views.order_failure, name='order_failure'),
    path('payment/verify/<int:order_id>/', views.verify_payment, name='verify_payment'),
    path('order/<int:order_id>/invoice/', views.download_invoice, name='download_invoice'),
    path('wallet/', views.wallet, name='wallet'),

    # ===========================# Wishlist URLs# ===========================
    path('add-to-wishlist/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('wishlist/', views.wishlist_page, name='wishlist_page'),
    path('remove-from-wishlist/<int:product_id>/', views.remove_from_wishlist, name='remove_from_wishlist'),
    path('get-variant-stock/<int:color_id>/<str:size>/', views.get_variant_stock, name='get_variant_stock'),
]