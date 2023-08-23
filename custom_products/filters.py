from .models import Order, Category, Shop, ProductInfo
from django_filters import rest_framework as filters
from django.db.models import Q


class OrderFilter(filters.FilterSet):
    keyword = filters.CharFilter(method='filter_by_keyword', label='Поиск по словам')

    @staticmethod
    def filter_by_keyword(queryset, name, value):
        return queryset.filter(
            Q(ordered_items__product_info__product__name__icontains=value) |
            Q(ordered_items__product_info__product__category__name__icontains=value)
        )

    class Meta:
        model = Order
        fields = ['dt', 'state']


class CategoryFilter(filters.FilterSet):
    keyword = filters.CharFilter(method='filter_by_keyword', label='Поиск по словам')

    @staticmethod
    def filter_by_keyword(queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) |
            Q(shops__name__icontains=value)
        )

    class Meta:
        model = Category
        fields = []


class ShopFilter(filters.FilterSet):
    keyword = filters.CharFilter(method='filter_by_keyword', label='Поиск по словам')

    @staticmethod
    def filter_by_keyword(queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) |
            Q(admin_email__icontains=value) |
            Q(user__username__icontains=value)
        )

    class Meta:
        model = Shop
        fields = ['state', 'admin_email']


class ProductFilter(filters.FilterSet):
    keyword = filters.CharFilter(method='filter_by_keyword', label='Поиск по словам')

    @staticmethod
    def filter_by_keyword(queryset, name, value):
        return queryset.filter(
            Q(product__name__icontains=value) |
            Q(product__category__name__icontains=value)
        )

    class Meta:
        model = ProductInfo
        fields = ['product_id']
