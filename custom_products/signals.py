from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail

from custom_products.models import ConfirmEmailToken

new_user_registered = Signal()
new_order = Signal()
updated_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):
    """
    Отправляем письмо с токеном для сброса пароля
    When a token is created, an e-mail needs to be sent to the user
    :param sender: View Class that sent the signal
    :param instance: View Instance that sent the signal
    :param reset_password_token: Token Model Object
    :param kwargs:
    :return:
    """
    # send an e-mail to the user

    msg = EmailMultiAlternatives(
        # title:
        f"Password Reset Token for {reset_password_token.user}",
        # message:
        reset_password_token.key,
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [reset_password_token.user.email]
    )
    msg.send()


@receiver(new_user_registered)
def new_user_registered_signal(user_id, **kwargs):
    """
    Отправляем письмо с подтверждением почты
    """
    # send an e-mail to the user
    token, _ = ConfirmEmailToken.objects.get_or_create(user_id=user_id)

    msg = EmailMultiAlternatives(
        # title:
        f"Password Reset Token for {token.user.email}",
        # message:
        token.key,
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [token.user.email]
    )
    msg.send()


@receiver(new_order)
def new_order_signal(sender, admin_emails, **kwargs):
    """
    Отправляем письмо при изменении статуса заказа
    """
    # Получаем значение user_email из атрибутов сигнала
    user_email = sender.user_email

    # Отправка письма на email клиента (подтверждение приема заказа)
    send_mail(
        f"Подтверждение заказа",
        "Ваш заказ был успешно размещен.",
        settings.EMAIL_HOST_USER,
        [user_email],
        fail_silently=False,
    )

    # Отправка письма на email администратора(ов) (для исполнения заказа)
    send_mail(
        f"Заказ от пользователя {user_email}",
        "У вас есть новый заказ для исполнения.",
        settings.EMAIL_HOST_USER,
        admin_emails,
        fail_silently=False,
    )


@receiver(updated_order)
def updated_order_signal(sender, admin_emails, **kwargs):
    """
    Отправляем письмо при изменении статуса заказа
    """
    # Получаем значение user_email из атрибутов сигнала
    user_email = sender.user_email

    # Отправка письма на email клиента (подтверждение приема заказа)
    send_mail(
        f"Обновление заказа",
        "Ваш заказ был обновлен.",
        settings.EMAIL_HOST_USER,
        [user_email],
        fail_silently=False,
    )

    # Отправка письма на email администратора(ов) (для исполнения заказа)
    send_mail(
        f"Изменение заказа от пользователя {user_email}",
        "У вас есть измененный заказ для исполнения.",
        settings.EMAIL_HOST_USER,
        admin_emails,
        fail_silently=False,
    )
