# context_processors.py
from adminside.models import CartItem

def cart_item_count(request):
    if request.user.is_authenticated:
        count = CartItem.objects.filter(user=request.user).count()
    else:
        count = 0
    return {'cart_item_count': count}

from adminside.models import Wishlist

def wishlist_count(request):
    if request.user.is_authenticated:
        return {
            'wishlist_count': Wishlist.objects.filter(user=request.user).count()
        }
    return {'wishlist_count': 0}
