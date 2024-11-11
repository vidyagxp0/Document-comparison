import os
from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(f"{key}")

@register.filter
def basename(value):
    return os.path.basename(value)

@register.filter
def getOriginal(url):
    if url :
        index_ = url.rfind("_")
        name = url[:index_]
    else:
        name = "Unknown"
    return f"{name}.xlsx"
        