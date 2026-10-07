import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('actions', '0003_scheduled_job_runs'),
    ]

    operations = [
        migrations.AddField(
            model_name='actionoutbox',
            name='delivery_kind',
            field=models.CharField(
                choices=[('webhook', 'Webhook'), ('email', 'Email')],
                db_index=True,
                default='webhook',
                max_length=16,
            ),
        ),
        migrations.AlterField(
            model_name='actionoutbox',
            name='action_rule',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='outbox_rows',
                to='actions.actionrule',
            ),
        ),
    ]
