# Generated by Django 4.2.2 on 2023-08-05 11:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custom_products', '0002_alter_productinfo_options_alter_order_dt_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='type',
            field=models.CharField(choices=[('shop', 'Магазин'), ('buyer', 'Покупатель')], default='buyer', max_length=5, verbose_name='Тип пользователя'),
        ),
    ]
