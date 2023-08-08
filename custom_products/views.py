from distutils.util import strtobool


from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, ObjectDoesNotExist

from custom_products.filters import OrderFilter, CategoryFilter, ShopFilter, ProductFilter
from django_filters import rest_framework as filters
from rest_framework.parsers import MultiPartParser
from rest_framework.authtoken.models import Token
import yaml
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from django.db import transaction
from rest_framework.exceptions import NotFound
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from ujson import loads as load_json

from custom_products.models import Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
    Contact, ConfirmEmailToken, USER_TYPE_CHOICES
from custom_products.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer, ConfirmEmailTokenSerializer
from custom_products.signals import new_user_registered, new_order, updated_order


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """
    @staticmethod
    def post(request):
        required_keys = {'email', 'password'}
        if required_keys.issubset(request.data.keys()):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None and user.is_active:
                token, _ = Token.objects.get_or_create(user=user)
                base_url = request.build_absolute_uri('/')
                order_url = f'{base_url}custom_products/order/'
                return Response({'Status': True,
                                 'Token': token.key,
                                 'message': 'Вы успешно авторизованы. Теперь вы можете сделать заказ.',
                                 'order_url': order_url}, status=status.HTTP_200_OK)

            return Response({'Status': False, 'Errors': 'Неверный email или пароль'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)


class RegisterAccount(APIView):
    """
    Для регистрации покупателей
    """

    def post(self, request, request_format=None):

        required_fields = {'first_name', 'last_name', 'email', 'password', 'company', 'position'}
        if required_fields.issubset(request.data):
            errors = {}

            # Проверяем сложность пароля
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return Response({'Status': False, 'Errors': {'password': error_array}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # Проверяем данные для уникальности имени пользователя
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    # Сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    return Response({'Status': True}, status=status.HTTP_201_CREATED)
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

        items_sting = request.data.get('items')
        if not items_sting:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            items_dict = load_json(items_sting)
        except ValueError:
            return Response({'Status': False, 'Errors': 'Неверный формат запроса'}, status=status.HTTP_400_BAD_REQUEST)

        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        objects_created = 0
        for order_item in items_dict:
            order_item.update({'order': basket.id})
            serializer = OrderItemSerializer(data=order_item)
            if serializer.is_valid():
                try:
                    serializer.save()
                except IntegrityError as error:
                    return Response({'Status': False, 'Errors': str(error)}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    objects_created += 1
            else:
                return Response({'Status': False, 'Errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'Status': True, 'Создано объектов': objects_created})

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_sting = request.data.get('items')
        if not items_sting:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)

        items_list = items_sting.split(',')
        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        query = Q()
        objects_deleted = False
        for order_item_id in items_list:
            if order_item_id.isdigit():
                query = query | Q(order_id=basket.id, id=order_item_id)
                objects_deleted = True

        if objects_deleted:
            deleted_count = OrderItem.objects.filter(query).delete()[0]
            return Response({'Status': True, 'Удалено объектов': deleted_count})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def put(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=status.HTTP_403_FORBIDDEN)

        items_sting = request.data.get('items')
        if not items_sting:
            return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            items_dict = load_json(items_sting)
        except ValueError:
            return Response({'Status': False, 'Errors': 'Неверный формат запроса'}, status=status.HTTP_400_BAD_REQUEST)

        basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        objects_updated = 0
        for order_item in items_dict:
            if type(order_item['id']) == int and type(order_item['quantity']) == int:
                objects_updated += OrderItem.objects.filter(order_id=basket.id, id=order_item['id']).update(
                    quantity=order_item['quantity'])

        return Response({'Status': True, 'Обновлено объектов': objects_updated})


class OrderView(APIView):
    """
    Класс для получения и размещения заказов пользователями
    """

    serializer_class = OrderSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = OrderFilter
    pagination_class = CustomPagination

    def get_queryset(self):
        return Order.objects.filter(
            user_id=self.request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    def get(self, request):
        queryset = self.get_queryset()
        serializer = OrderSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'contact', 'items'}.issubset(request.data):
            # Используем транзакцию, чтобы гарантировать атомарность операций
            with transaction.atomic():
                try:
                    # Создаем новый заказ
                    contact_id = request.data['contact']
                    order = Order.objects.create(user=request.user, contact_id=contact_id, state='new')

                    # Добавляем товары к заказу
                    items = request.data['items']
                    for item in items:
                        product_info_id = item['product_info']
                        quantity = item['quantity']
                        OrderItem.objects.create(order=order, product_info_id=product_info_id, quantity=quantity)

                    # Извлекаем email пользователя, создавшего заказ
                    user_email = request.user.email

                    # Извлекаем магазины, связанные с товарами из заказа
                    related_shops = Shop.objects.filter(products__ordered_items__order=order).distinct()

                    # Извлекаем email администраторов магазинов
                    admin_emails = list(
                        related_shops.filter(admin_email__isnull=False).values_list('admin_email', flat=True))

                    # Отправляем сигнал new_order_signal для отправки писем
                    new_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                   admin_emails=admin_emails)

                    return Response({'Status': True})

                except ObjectDoesNotExist:
                    return Response({'Status': False, 'Errors': 'Ошибка при создании заказа'})
                except Exception as e:
                    return Response({'Status': False, 'Errors': str(e)})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class OrderConfirmationView(APIView):
    """
    Класс для подтверждения заказа, обновления и отображения деталей заказа
    """

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user).exclude(state='basket').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    @staticmethod
    def get(request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        # Получить заказы пользователя, исключая состояние 'basket'
        orders = Order.objects.filter(user=request.user).exclude(state='basket').select_related('contact')

        # Выполнить сериализацию заказов
        serializer = OrderSerializer(orders, many=True)

        return Response(serializer.data)

    @staticmethod
    def post(self, request):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'id', 'contact', 'items'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    order = Order.objects.get(user=request.user, id=request.data['id'])
                    order.contact_id = request.data['contact']
                    order.state = 'new'
                    order.save()

                    # Изменить количество товаров в заказе
                    items = request.data['items']
                    for item in items:
                        product_info_id = item['product_info']
                        quantity = item['quantity']

                        try:
                            order_item = OrderItem.objects.get(order=order, product_info_id=product_info_id)
                            order_item.quantity = quantity
                            order_item.save()
                        except ObjectDoesNotExist:
                            # Обработка случая, если товар не был найден в заказе
                            OrderItem.objects.create(order=order, product_info_id=product_info_id, quantity=quantity)

                    # Извлекаем email пользователя, создавшего заказ
                    user_email = request.user.email

                    # Извлекаем магазины, связанные с товарами из заказа
                    related_shops = Shop.objects.filter(products__ordered_items__order=order).distinct()

                    # Извлекаем email администраторов магазинов
                    admin_emails = list(
                        related_shops.filter(admin_email__isnull=False).values_list('admin_email', flat=True))

                    # Отправляем сигнал new_order_signal для отправки писем
                    updated_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                       admin_emails=admin_emails)

                except ObjectDoesNotExist:
                    return Response({'Status': False, 'Errors': 'Заказ не найден'})
                except Exception as e:
                    return Response({'Status': False, 'Errors': str(e)})
                else:
                    return Response({'Status': True})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса
    """
    # Регистрация методом POST
    @staticmethod
    def post(request):
        serializer = ConfirmEmailTokenSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError:
            return Response({'Status': False, 'Errors': 'Ошибка валидации данных'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = ConfirmEmailToken.objects.get(user__email=request.data['email'], key=request.data['token'])
        except ObjectDoesNotExist:
            raise NotFound('Заказ не найден')

        token.user.is_active = True
        token.user.save()
        token.delete()

        return Response({'Status': True})


class AccountDetails(APIView):
    """
    Класс для работы с данными пользователя
    """
    permission_classes = [IsAuthenticated]

    @staticmethod
    def get(request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @staticmethod
    def put(request):
        user = request.user

        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                return Response({'Status': False, 'Errors': {'password': password_error.messages}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user.set_password(request.data['password'])

        user_serializer = UserSerializer(user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()

            # Проверка на изменение поля "type"
            if 'type' in request.data:
                new_type = request.data['type']
                if new_type in dict(USER_TYPE_CHOICES):
                    user.type = new_type
                    user.save()
            return Response({'Status': True})
        else:
            return Response({'Status': False, 'Errors': user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """
    parser_classes = [MultiPartParser]

    def post(self, request, *args, **kwargs):
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

                Category.objects.filter(shops=shop).clear()
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

    # Получить текущий статус
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse(self.ERROR_STATUS, status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return JsonResponse({'Error': 'Только для магазинов'}, status=status.HTTP_403_FORBIDDEN)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    # Изменить текущий статус
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

    @staticmethod
    def get(request):
        # Проверяем, аутентифицирован ли пользователь
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        # Проверяем тип пользователя
        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        # Получаем список заказов, связанных с текущим магазином
        orders = Order.objects.filter(
            ordered_items__product_info__shop__user=request.user,
            state__exclude='basket'
        ).prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related(
            'contact'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))
        ).distinct()

        # Сериализируем список заказов и возвращаем результат в формате JSON
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class ContactView(APIView):
    """
    Класс для работы с контактами покупателей
    """

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
            request.data._mutable = True
            request.data.update({'user': request.user.id})
            serializer = ContactSerializer(data=request.data)

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

        items_sting = request.data.get('items')
        if items_sting:
            items_list = items_sting.split(',')
            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if contact_id.isdigit():
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
            if request.data['id'].isdigit():
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
