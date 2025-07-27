
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

# -------------------------------
# Custom User Admin
# -------------------------------
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active', 'email_verified')
    list_filter = ('is_staff', 'is_active')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    
    readonly_fields = ('otp',)

    fieldsets = (
        (None, {'fields': ('email', 'password', 'first_name', 'last_name', 'phone_number', 'otp')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'first_name', 'last_name', 'phone_number', 
                'password1', 'password2', 'is_staff', 'is_active'
            ),
        }),
    )

# -------------------------------
# Optional Category Delete Logic (Note: Not registered or used)
# -------------------------------
def delete(self, *args, **kwargs):
    # Mark category as unlisted
    self.is_listed = False
    self.save()

    # Optionally unlist related products
    self.products.update(is_listed=False)

    





