from distutils.util import strtobool

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from rest_framework.filters import OrderingFilter

from custom_products.filters import OrderFilter, CategoryFilter, ShopFilter, ProductFilter
from django_filters import rest_framework as filters
from rest_framework.parsers import MultiPartParser
import yaml
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.db import transaction
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.views import APIView
from custom_products.models import Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
    Contact, USER_TYPE_CHOICES
from custom_products.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer
from custom_products.signals import new_user_registered, new_order, updated_order


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


class AllViews(APIView):
    """
    Класс для просмотра доступных страниц API для неавторизованных пользователей
    """
    @staticmethod
    def get(request):
        base_url = request.build_absolute_uri('/')
        register_url = f'{base_url}custom_products/user/register'
        login_url = f'{base_url}custom_products/user/login'
        category_url = f'{base_url}custom_products/categories'
        shop_url = f'{base_url}custom_products/shops'
        product_url = f'{base_url}custom_products/products'
        return Response({'message': 'Добро пожаловать! Вы можете зарегистрироваться.',
                         'register_url': register_url,
                         'message_2': 'Если вы уже зарегистрированы, то Вы можете авторизоваться.',
                         'login_url': login_url,
                         'message_3': 'Вы можете просмотреть список доступных категорий товаров.',
                         'category_url': category_url,
                         'message_4': 'Вы можете просмотреть список доступных магазинов.',
                         'shop_url': shop_url,
                         'message_5': 'Вы можете просмотреть список доступных товаров.',
                         'product_url': product_url},
                         status=status.HTTP_200_OK)


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def post(request):
        required_keys = {'email', 'password'}
        if required_keys.issubset(request.data.keys()):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None and user.is_active:

                base_url = request.build_absolute_uri('/')
                order_url = f'{base_url}custom_products/order'

                return Response({'Status': True,
                                 'message': 'Вы успешно авторизованы. Теперь вы можете сделать заказ.',
                                 'order_url': order_url}, status=status.HTTP_200_OK)
            else:
                return Response({'Status': False, 'Errors': 'Неверный email или пароль'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)


class RegisterAccount(APIView):
    """
    Для регистрации покупателей
    """

    def post(self, request, request_format=None):

        required_fields = {'first_name', 'last_name', 'email', 'password', 'company', 'position'}
        if required_fields.issubset(request.data):
            errors = {}

            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return Response({'Status': False, 'Errors': {'password': error_array}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    base_url = request.build_absolute_uri('/')
                    login_url = f'{base_url}custom_products/user/login'
                    return Response({'Status': True,
                                     'message': 'Вы успешно зарегистрированы. Теперь вы можете авторизоваться.',
                                     'login_url': login_url}, status=status.HTTP_201_CREATED)
                else:
                    return Response({'Status': False, 'Errors': user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """

    serializer_class = CategorySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CategoryFilter
    queryset = Category.objects.all()
    pagination_class = CustomPagination


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    serializer_class = ShopSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = ShopFilter
    queryset = Shop.objects.filter(state=True)
    pagination_class = CustomPagination


class ProductInfoView(ListAPIView):
    """
    Класс для поиска товаров
    """

    queryset = ProductInfo.objects.filter(shop__state=True)
    serializer_class = ProductInfoSerializer
    filterset_class = ProductFilter
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ['price']
    pagination_class = CustomPagination

    def get_queryset(self):
        queryset = super().get_queryset()
        shop_id = self.request.query_params.get('shop_id')
        category_id = self.request.query_params.get('category_id')

        if shop_id:
            queryset = queryset.filter(shop_id=shop_id)

        if category_id:
            queryset = queryset.filter(product__category_id=category_id)

        return queryset.select_related('shop', 'product__category').prefetch_related('product_parameters__parameter')


class BasketView(APIView):
    """
    Класс для работы с корзиной пользователя
    """
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def get_basket(user_id):
        return Order.objects.filter(user_id=user_id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        basket = self.get_basket(request.user.id)
        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    @staticmethod
    def post(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_dict = request.data.get('items')
        if not items_dict:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                            status=status.HTTP_400_BAD_REQUEST)

        auth_header = request.META.get('HTTP_AUTHORIZATION')
        auth_token = auth_header.split()[1]
        user_id = Token.objects.get(key=auth_token).user_id

        contact_id = Contact.objects.get(user_id=user_id).id
        basket, _ = Order.objects.get_or_create(user_id=user_id, contact_id=contact_id, state='basket')
        objects_created = 0
        for order_item in items_dict:
            product_name = order_item.get('name')
            quantity = order_item.get('quantity')

            if product_name is not None and quantity is not None:
                product = Product.objects.get(name=product_name).id
                product_id = ProductInfo.objects.get(product_id=product).id

                order_item_data = {
                        'order': basket.id,
                        'product_info': product_id,
                        'quantity': quantity
                    }

                serializer = OrderItemSerializer(data=order_item_data)
                if serializer.is_valid():
                    try:
                        serializer.save()
                    except IntegrityError as error:
                        return Response({'Status': False, 'Errors': str(error)}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        objects_created += 1
                else:
                    return Response({'Status': False, 'Errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'Status': False, 'Errors': 'Недостаточно данных для создания заказа'},
                                status=status.HTTP_400_BAD_REQUEST)

        return Response({'Status': True, 'Создано объектов': objects_created})

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        order_id = data.get('order_id')
        items_list = data.get('items')

        if not order_id or not items_list:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                            status=status.HTTP_400_BAD_REQUEST)

        objects_deleted = 0
        order_items_to_delete = OrderItem.objects.filter(order_id=order_id)
        for product_name in items_list:
            try:
                product = Product.objects.get(name=product_name).id
                product_info = ProductInfo.objects.get(product_id=product).id
                deleted_count = order_items_to_delete.filter(product_info_id=product_info).delete()[0]
                objects_deleted += deleted_count
            except ObjectDoesNotExist:
                return Response({'Status': False, 'Errors': f'Не найдены товары "{product_name}" для удаления'},
                                status=status.HTTP_400_BAD_REQUEST)

        if objects_deleted > 0:
            return Response({'Status': True, 'Удалено объектов': objects_deleted})

        return Response({'Status': False, 'Errors': 'Не найдены товары для удаления'},
                        status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def put(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_dict = request.data.get('items')
        if not items_dict:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)

        auth_header = request.META.get('HTTP_AUTHORIZATION')
        auth_token = auth_header.split()[1]
        user_id = Token.objects.get(key=auth_token).user_id

        contact_id = Contact.objects.get(user_id=user_id).id
        basket, _ = Order.objects.get_or_create(user_id=user_id, contact_id=contact_id, state='basket')
        objects_updated = 0

        for order_item in items_dict:
            if 'name' in order_item and 'quantity' in order_item:
                product_name = order_item['name']
                new_quantity = order_item['quantity']

                try:
                    product = Product.objects.get(name=product_name).id
                    product_id = ProductInfo.objects.get(product_id=product).id
                    order_item_obj, created = OrderItem.objects.update_or_create(
                        order=basket,
                        product_info_id=product_id,
                        defaults={'quantity': new_quantity}
                    )
                    order_item_obj.save()
                    objects_updated += 1
                except ObjectDoesNotExist:
                    return Response({'Status': False, 'Errors': 'Заказ не найден'})

        return Response({'Status': True, 'Обновлено объектов': objects_updated})


class OrderView(APIView):
    """
    Класс для получения, размещения и удаления заказов пользователями
    """

    serializer_class = OrderSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ['total_sum']
    filterset_class = OrderFilter
    pagination_class = CustomPagination
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        return Order.objects.filter(
            user_id=self.request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    def get(self, request):
        if request.user.is_authenticated:
            queryset = self.get_queryset()
            serializer = OrderSerializer(queryset, many=True)
            return Response(serializer.data)
        else:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

    def post(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'contact', 'items'}.issubset(request.data):
            with transaction.atomic():
                try:
                    contact_list = request.data.get('contact', [])

                    for contact_data in contact_list:
                        contact_phone = contact_data['phone']
                        contact_city = contact_data['city']
                        contact_street = contact_data['street']
                        contact_house = contact_data['house']
                        contact_apartment = contact_data['apartment']
                        user_id = request.user.id
                        contact, created = Contact.objects.get_or_create(user_id=user_id,
                                                                         phone=contact_phone, city=contact_city,
                                                                         street=contact_street, house=contact_house,
                                                                         apartment=contact_apartment)

                    user_email = request.user.email
                    order = Order.objects.create(user=request.user, contact_id=contact.id, state='new')
                    items = request.data['items']
                    for item in items:
                        product_name = item['name']
                        product_quantity = item['quantity']
                        product = Product.objects.get(name=product_name)
                        product_info = ProductInfo.objects.get(product=product)
                        product_id = Product.objects.get(name=product_name).id

                        OrderItem.objects.create(order=order, product_info=product_info, quantity=product_quantity)
                        shop = ProductInfo.objects.get(product_id=product_id).shop_id
                        shop1 = Shop.objects.get(id=shop)
                        admin_email = shop1.admin_email
                        if admin_email:
                            new_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                           admin_emails=[admin_email])

                    base_url = request.build_absolute_uri('/')
                    order_url = f'{base_url}custom_products/order'
                    order_id = order.id
                    response_data = {
                        'Status': True,
                        'Message': f'Спасибо за заказ! Номер вашего заказа: {order_id}. '
                                   f'Наш оператор свяжется с вами в ближайшее время для уточнения деталей заказа.',
                        'OrderDetails': f'Статус заказов вы можете посмотреть в разделе "Заказы" по ссылке: {order_url}'
                    }
                    return Response(response_data)

                except ObjectDoesNotExist:
                    return Response({'Status': False, 'Errors': 'Ошибка при создании заказа'})
                except Exception as e:
                    return Response({'Status': False, 'Errors': str(e)})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_list = request.data.get('items')
        if items_list:
            query = Q()
            objects_deleted = False
            for order_id in items_list:
                if isinstance(order_id, int):
                    query = query | Q(user_id=request.user.id, id=order_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Order.objects.filter(query).delete()[0]
                OrderItem.objects.filter(order_id__in=items_list).delete()
                return Response({'Status': True, 'Заказ удалён. Удалено объектов': deleted_count})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                        status=status.HTTP_400_BAD_REQUEST)


class OrderConfirmationView(APIView):
    """
    Класс для подтверждения, обновления и отображения деталей заказа
    """
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user).exclude(state='basket').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)
        orders = Order.objects.filter(user=self.request.user).exclude(state='basket').select_related('contact')
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    def put(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'id', 'contact', 'items'}.issubset(request.data):
            if isinstance(request.data['id'], int):
                try:
                    order = Order.objects.get(user=request.user, id=request.data['id'])
                    contact_phone = request.data['contact']
                    contact = Contact.objects.get(phone=contact_phone).id
                    order.contact_id = contact
                    order.state = 'new'
                    order.save()
                    items = request.data['items']
                    for item in items:
                        product_name = item['name']
                        product_quantity = item['quantity']
                        product = Product.objects.get(name=product_name).id
                        product_id = ProductInfo.objects.get(product_id=product).id

                        try:
                            order_item = OrderItem.objects.get(order=order, product_info_id=product_id)
                            order_item.quantity = product_quantity
                            order_item.save()
                        except ObjectDoesNotExist:
                            OrderItem.objects.create(order=order, product_info_id=product_id, quantity=product_quantity)
                        user_email = request.user.email
                        shop = ProductInfo.objects.get(product_id=product_id).shop_id
                        shop1 = Shop.objects.get(id=shop)
                        admin_email = shop1.admin_email
                        if admin_email:
                            updated_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                               admin_emails=[admin_email])

                except ObjectDoesNotExist:
                    return Response({'Status': False, 'Errors': 'Заказ не найден'})
                except Exception as e:
                    return Response({'Status': False, 'Errors': str(e)})
                else:
                    base_url = request.build_absolute_uri('/')
                    order_url = f'{base_url}custom_products/order'
                    response_data = {
                        'Status': True,
                        'Message': f'Ваш заказ был изменён.',
                        'OrderDetails': f'Статус заказов вы можете посмотреть в разделе "Заказы" по ссылке: {order_url}'
                    }
                    return Response(response_data)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class AccountDetails(APIView):
    """
        Класс для работы с данными пользователя: изменение пароля, типа пользователя и удаление пользователя
    """

    authentication_classes = [TokenAuthentication]

    @staticmethod
    def get(request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @staticmethod
    def put(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        user = request.user
        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                return Response({'Status': False, 'Errors': {'password': password_error.messages}},
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                user.set_password(request.data['password'])

        user_serializer = UserSerializer(user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()

            if 'type' in request.data:
                new_type = request.data['type']
                if new_type in dict(USER_TYPE_CHOICES):
                    user.type = new_type
                    user.save()
            return Response({'Status': True})
        else:
            return Response({'Status': False, 'Errors': user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        user = request.user
        try:
            user.auth_token.delete()
            user.delete()
            return Response({'Status': True, 'message': 'Пользователь успешно удален'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Status': False, 'Errors': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """
    parser_classes = [MultiPartParser]
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def post(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return Response({'Status': False, 'Error': 'Только для магазинов'}, status=status.HTTP_403_FORBIDDEN)

        yaml_file = request.FILES.get('file')
        if not yaml_file:
            return Response({'Status': False, 'Errors': 'Не указан файл'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                data = yaml.safe_load(yaml_file.read())

                shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)

                Category.objects.filter(shops=shop).delete()
                for category in data['categories']:
                    category_object, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)

                ProductInfo.objects.filter(shop=shop).delete()
                for item in data['goods']:
                    product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])

                    product_info = ProductInfo.objects.create(product=product,
                                                              external_id=item['id'],
                                                              model=item['model'],
                                                              price=item['price'],
                                                              price_rrc=item['price_rrc'],
                                                              quantity=item['quantity'],
                                                              shop=shop)

                    for name, value in item['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info=product_info,
                                                        parameter=parameter_object,
                                                        value=value)

        except Exception as e:
            return Response({'Status': False, 'Errors': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'Status': True})


class PartnerState(APIView):
    """
    Класс для работы со статусом поставщика
    """

    SUCCESS_STATUS = {'Status': True}
    ERROR_STATUS = {'Status': False}
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse(self.ERROR_STATUS, status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return JsonResponse({'Error': 'Только для магазинов'}, status=status.HTTP_403_FORBIDDEN)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse(self.ERROR_STATUS, status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return JsonResponse({'Error': 'Только для магазинов'}, status=status.HTTP_403_FORBIDDEN)

        state = request.data.get('state')
        if state is not None:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse(self.SUCCESS_STATUS)
            except ValueError as error:
                return JsonResponse({'Errors': str(error)}, status=status.HTTP_400_BAD_REQUEST)

        return JsonResponse({'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
    """
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def get(request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        orders = Order.objects.filter(
            ordered_items__product_info__shop__user=request.user,
            state__exact='basket'
        ).prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related(
            'contact'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()

        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class ContactView(APIView):
    """
    Класс для работы с контактами покупателей
    """
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def get(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        contact = Contact.objects.filter(user_id=request.user.id)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data)

    @staticmethod
    def post(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        if {'city', 'street', 'phone'}.issubset(request.data):
            data = request.data.copy()

            try:
                token = request.META.get('HTTP_AUTHORIZATION', '').split()[1]
                token_obj = Token.objects.get(key=token)
                user_id = token_obj.user_id
            except Token.DoesNotExist:
                return Response({'Status': False, 'Error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            data['user'] = user_id
            serializer = ContactSerializer(data=data)

            if serializer.is_valid():
                serializer.save()
                return Response({'Status': True})
            else:
                return Response({'Status': False, 'Errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                        status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_list = request.data.get('items')
        if items_list:
            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if isinstance(contact_id, int):
                    query = query | Q(user_id=request.user.id, id=contact_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Contact.objects.filter(query).delete()[0]
                return Response({'Status': True, 'Удалено объектов': deleted_count})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                        status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def put(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        if 'id' in request.data:
            if isinstance(request.data['id'], int):
                contact = Contact.objects.filter(id=request.data['id'], user_id=request.user.id).first()

                if contact:
                    serializer = ContactSerializer(contact, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return Response({'Status': True})
                    else:
                        return Response({'Status': False, 'Errors': serializer.errors},
                                        status=status.HTTP_400_BAD_REQUEST)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                        status=status.HTTP_400_BAD_REQUEST)
