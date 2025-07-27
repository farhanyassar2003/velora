from django.urls import path
from  .import views

app_name = 'adminside'

urlpatterns = [
    # ===========================# Admin Authentication# ===========================
    path('', views.admin_login, name='admin_login'),
    path('logout/', views.admin_logout_view, name='admin_logout'),
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),

    # ===========================# User Management# ===========================
    path('users/', views.user_list, name='user_list'),
    path('users/toggle_status/<int:user_id>/', views.toggle_status, name='toggle_status'),

    # ===========================# Product Management# ===========================
    path('products/', views.product_list, name='product_list'),
    path('products/add/', views.add_product, name='add_product'),
    path('products/edit/<int:product_id>/', views.edit_product, name='edit_product'),
    path('products/delete/<int:product_id>/', views.delete_product, name='delete_product'),
    path('products/<int:product_id>/toggle-active/', views.toggle_is_active, name='toggle_is_active'),
    path('products/<int:product_id>/toggle-listed/', views.toggle_is_listed, name='toggle_is_listed'),

    # ===========================# Category Management# ===========================
    path('categories/', views.category_list, name='category_list'),
    path('categories/add/', views.add_category, name='add_category'),
    path('categories/edit/<int:category_id>/', views.edit_category, name='edit_category'),
    path('categories/delete/<int:category_id>/', views.delete_category, name='delete_category'),
    path('toggle-list-category/<int:category_id>/', views.toggle_list_category, name='toggle_list_category'),
    path('toggle-delete-category/<int:category_id>/', views.toggle_delete_category, name='toggle_delete_category'),

    # ===========================# Order Management# ===========================
    path('orders/', views.admin_order_list, name='admin_order_list'),
    path('orders/<str:order_id>/', views.admin_order_detail, name='admin_order_detail'),
    path('order/<str:order_id>/confirm-return/', views.confirm_return, name='confirm_return'),
]


