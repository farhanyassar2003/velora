from django import template

register = template.Library()

@register.filter
def dict_key(value, key):
    if isinstance(value, dict):
        return key in value
    return any(coupon.code == key if hasattr(coupon, 'code') else coupon == key for coupon in value)

@register.filter
def multiply(value, arg):
    return float(value) * float(arg)

@register.filter
def divide(value, arg):
    return float(value) / float(arg)