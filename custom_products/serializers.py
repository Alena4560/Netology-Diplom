from rest_framework import serializers

from custom_products.models import User, Category, Shop, ProductInfo, Product, ProductParameter, OrderItem, Order, Contact
from django.contrib.auth.tokens import default_token_generator
from rest_framework.authtoken.models import Token
from django.db.models import Sum, F


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user', 'phone')
        read_only_fields = ('id',)
        extra_kwargs = {
            'user': {'write_only': True}
        }


class UserSerializer(serializers.ModelSerializer):
    contacts = ContactSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'company', 'position', 'contacts', 'type')
        read_only_fields = ('id',)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name',)
        read_only_fields = ('id',)


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state',)
        read_only_fields = ('id',)


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('name', 'category',)


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)
    shop_name = serializers.CharField(source='shop.name', read_only=True)

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop_name', 'quantity', 'price', 'price_rrc', 'product_parameters',)
        read_only_fields = ('id',)


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ('id', 'product_info', 'quantity', 'order',)
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }


class OrderItemCreateSerializer(OrderItemSerializer):
    product_info = ProductInfoSerializer(read_only=True)


class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemCreateSerializer(read_only=True, many=True)

    total_sum = serializers.SerializerMethodField()
    contact = ContactSerializer(read_only=True)

    @staticmethod
    def get_total_sum(obj):
        total_sum = obj.ordered_items.aggregate(
            total_sum=Sum(F('quantity') * F('product_info__price'))
        )['total_sum']
        return total_sum

    class Meta:
        model = Order
        fields = ('id', 'ordered_items', 'state', 'dt', 'total_sum', 'contact',)
        read_only_fields = ('id',)


class ConfirmEmailTokenSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    token = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        token = data.get('token')

        if not email or not token:
            raise serializers.ValidationError("Не указаны все необходимые аргументы")

        user = User.objects.filter(email=email).first()

        if not user or not default_token_generator.check_token(user, token):
            raise serializers.ValidationError("Неправильно указан токен или email")

        return data

    class Meta:
        model = Token
        fields = ('email', 'token')
