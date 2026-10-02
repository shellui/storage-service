from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('actions', '0002_event_log'),
    ]

    operations = [
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
