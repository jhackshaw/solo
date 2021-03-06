# Generated by Django 3.0.4 on 2020-03-25 06:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('solo_rog_api', '0015_status_received_by'),
    ]

    operations = [
        migrations.AddField(
            model_name='status',
            name='locator',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='statuses', to='solo_rog_api.Locator'),
        ),
        migrations.AddField(
            model_name='status',
            name='subinventory',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='statuses', to='solo_rog_api.SubInventory'),
        ),
    ]
