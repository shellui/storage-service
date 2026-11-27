"""Label private files that agents stored as "user 0".

Before this release every MCP agent acted as user 0, so the files an agent uploaded carry
``allow user 0 admin`` and ``deny company read`` grants. Nobody is user 0, so those files
would be unreachable. Access control treats a USER grant for subject ``0`` as "company
owners and staff" (see ``apps.storage.access.LEGACY_UNOWNED_SUBJECT``), so the files stay and
owners can read, share, reassign or delete them.

Storage keeps no record that ties an upload to an agent or to the agent's creator (the event
log stores no agent id), so nothing can be reassigned automatically here. Use
``manage.py reassign_unowned_files`` to give a company's unowned files to a named user.
"""

from django.db import migrations

LEGACY_NOTE = 'Stored by an agent before agents acted as their creator. Managed by company owners.'


def label_unowned_grants(apps, schema_editor):
    Grant = apps.get_model('storage', 'StorageAccessGrant')
    Grant.objects.filter(subject_type='user', subject_id='0').update(notes=LEGACY_NOTE)


class Migration(migrations.Migration):

    dependencies = [
        ('storage', '0007_connector_safe_settings_and_issues'),
    ]

    operations = [
        migrations.RunPython(label_unowned_grants, migrations.RunPython.noop),
    ]
