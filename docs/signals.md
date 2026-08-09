# Signals

REST uploads, copies, and WebDAV `PUT` share the same service layer and emit Django signals.

## Built-in signals

| Signal | When |
|--------|------|
| `storage_object_uploaded` | After create or upsert (`created=True/False`) |
| `storage_object_updated` | Reserved for non-upload metadata updates |
| `storage_object_deleted` | After DB row + blob removal |

Import from `apps.storage.signals`.

## Example: Markdown sidecar

On upload of `text/markdown` (or `.md`), a receiver reads the blob, renders Markdown, and stores truncated plain text in `object.metadata['markdown_text']` for indexing hooks.

Add your own receivers in an app `ready()`:

```python
from django.dispatch import receiver
from apps.storage.signals import storage_object_uploaded

@receiver(storage_object_uploaded)
def on_upload(sender, instance, created, **kwargs):
    if instance.mime_type.startswith('image/'):
        ...
```
