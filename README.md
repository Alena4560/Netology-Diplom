# Проект "Интернет-магазин"

Этот проект представляет собой API Сервис заказа товаров для розничных сетей.

## Настройка отправки писем на email

Для того, чтобы настроить отправку писем на email пользователя и администратора магазина о создании/обновлении заказа, выполните следующие шаги:

1. Получите пароль приложения в вашем почтовом ящике, который вы указываете в качестве `EMAIL_HOST_USER` в файле `.env`.
2. Отредактируйте файл `.env`, укажите все необходимые значения, а также полученный пароль в качестве значения переменной `EMAIL_HOST_PASSWORD`.

## Загрузка YAML-файла для обновления прайса от поставщика

Для загрузки YAML-файла для обновления прайса от поставщика, выполните следующие шаги:

1. Отправьте POST-запрос на соответствующий эндпоинт, передав файл в параметрах запроса под ключом "file".
2. Принимайте и обрабатывайте загруженный файл в соответствующем представлении.

Пример запроса:

```http
POST /custom_products/partner/update HTTP/1.1
Host: example.com
Content-Type: multipart/form-data
Authorization: Bearer YOUR_ACCESS_TOKEN

Content-Disposition: form-data; name="file"; filename="shop1.yaml"
Content-Type: application/x-yaml

[содержимое файла shop1.yaml]
```
Остальные примеры запросов на разные эндпоинты в файле `http-requests-examples.txt`.