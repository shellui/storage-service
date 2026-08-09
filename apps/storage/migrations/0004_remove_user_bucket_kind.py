# Generated manually — drop legacy personal bucket kind.

from django.db import migrations, models


def delete_user_buckets(apps, schema_editor):
    Bucket = apps.get_model('storage', 'Bucket')
    Bucket.objects.filter(kind='user').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('storage', '0003_one_company_bucket_grants_and_share_links'),
    ]

    operations = [
        migrations.RunPython(delete_user_buckets, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='bucket',
            name='kind',
            field=models.CharField(
                choices=[
                    ('company', 'Company'),
                    ('connector', 'External connector'),
                ],
                db_index=True,
                default='company',
                max_length=32,
            ),
        ),
    ]
