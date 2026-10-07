---
description: The company bucket, folder prefixes, uploads, and the signals that run after a file is stored.
---

# Buckets, folders, and files

A company has one bucket. Files live at paths inside it. This page is how those rows are created, listed, moved, and removed.

You call the API with `Authorization: Bearer your_access_token_here`. The token comes from identity-service and must include `company_id`. Who may see a path after it exists is in [Access grants](access.md).

## The company bucket

The bucket name is `company`. The first request that needs it creates the row and emits `storage.bucket.created`, attributed to the caller who provisioned it. `GET /storage/v1/bucket` lists the buckets that caller may see. `GET /storage/v1/bucket/company` returns one bucket.

`POST /storage/v1/bucket` returns 403 `bucket_create_disabled`. `PUT` and `DELETE` on a bucket return 403 `bucket_immutable`. You do not add a second bucket for a project or a user.

`public` on the bucket is always false. `GET /storage/v1/object/public/…` returns 403 `public_download_disabled`. Anonymous download uses a [share link](sharing.md).

Each bucket response includes an `access` object (`audience`, `shareable`, `grants_enabled`, `can_write`) for the Files UI.

A bucket may set `file_size_limit` and `allowed_mime_types`. An empty MIME list allows every type. Otherwise the list is exact types or prefixes such as `image/*`. A rejected type returns 415 `invalid_mime_type`. The per-bucket size cannot exceed `MAX_UPLOAD_BYTES` (default `5G`).

## Connector buckets

`kind=connector` is reserved for a read-only mount such as SharePoint or Dropbox. No sync client ships in this service. If a connector row exists, company members can read it and cannot write it. Create and delete of buckets through the API stay disabled, so a connector row is an operator record in Django admin, not an API call.

## Folders

A folder is a path prefix. An empty folder is a `StorageObject` whose name ends with `.emptyFolderPlaceholder`. Uploading `hr/.emptyFolderPlaceholder` creates the `hr` folder. Grants on a folder point at that marker.

`GET /storage/v1/object/prefix/company?prefix=hr` returns counts for that prefix. `POST` with `from` and `to` renames it. `DELETE` removes the prefix recursively. List objects with `POST /storage/v1/object/list/company`. Prefix stats omit objects you cannot read.

`GET /storage/v1/object/id/{uuid}` resolves a file or a folder marker by its stable id. That is the picker path: the id does not change when you rename the prefix.

## Upload

Send the bytes to `/storage/v1/object/company/{path}`:

- `POST` creates the object. If the path exists, the response is 400 `resource_already_exists`, unless the `x-upsert` header is `true`, `1`, or `yes`.
- `PUT` overwrites. Upsert is the default on `PUT`.

The body is raw bytes or a multipart file. MIME type comes from `Content-Type`, then from the file name. A body larger than the cap returns 413 `payload_too_large`. A company or per-user quota overflow returns 413 `company_quota_exceeded` or `user_quota_exceeded`.

On create, with no grants on an ancestor folder, the new file or folder is private to the creator. Under a folder that already has grants, a new folder copies the parent folder's grants, and a new file inherits them by path. You cannot open a nested path to the whole company while an ancestor folder stays private (`400 parent_folder_private`).

WebDAV `PUT` and `MKCOL` use this same write path.

## Move, copy, and delete

`POST /storage/v1/object/move` and `POST /storage/v1/object/copy` take a source and a destination in the company bucket. Copy checks quota before it writes. Move and copy refuse a path in another company.

`DELETE /storage/v1/object/company/{path}` removes one object. `DELETE /storage/v1/object/company` removes many paths in the body. Both require write access on each path. The blob is deleted, `used_bytes` goes down, and `storage.object.deleted` is emitted. Folder placeholders are omitted from that event.

Django admin delete uses the same function. The REST API still cannot delete the bucket itself.

## Upload signals

REST uploads, copies, and WebDAV `PUT` emit Django signals from `apps.storage.signals`:

| Signal | When |
| --- | --- |
| `storage_object_uploaded` | After create or overwrite. `created` is true or false |
| `storage_object_updated` | Reserved for a metadata change that is not an upload |
| `storage_object_deleted` | After the row is removed and the blob is already gone |

A built-in receiver handles Markdown. When the MIME type is `text/markdown` or `text/x-markdown`, or the name ends in `.md` or `.markdown`, it reads up to 2 MB, renders the text, and stores the first 50000 characters of plain text in `metadata.markdown_text`. `metadata.markdown_chars` is the full plain-text length. The update does not emit another upload.

Shellui Actions webhooks listen to the same uploads and deletes. Payloads and delivery are in [Webhooks](actions.md). Add another receiver from an app `ready()` if you run a fork:

```python
import logging
from django.dispatch import receiver
from apps.storage.signals import storage_object_uploaded

logger = logging.getLogger(__name__)

@receiver(storage_object_uploaded)
def on_upload(sender, instance, created, **kwargs):
    logger.info("uploaded %s created=%s", instance.name, created)
```
