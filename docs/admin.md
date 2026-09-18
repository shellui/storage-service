# Admin panel

The Django admin at `/admin/` includes an **upload statistics** dashboard for operators.

## Access

1. Create the first superuser:

```bash
uv run python manage.py createsuperuser
```

With `DEBUG=true` (local default), the home page also shows a one-time web form on first visit. In production (`DEBUG=false`), the form is hidden unless you set `SETUP_TOKEN` and open `/?setup_token=<token>` once.

2. Open `http://localhost:8001/admin/` and sign in.
3. Full report: `http://localhost:8001/admin/statistics/`

## What you see

| Section | Contents |
|---------|----------|
| Overview cards | Total objects, document count/size, buckets, uploads (24h / 7d) |
| Daily chart | Uploads over the last 14–30 days |
| MIME families | Images, Text/Markdown, Office/PDF, Video, … |
| Top MIME types | Exact content types |
| By company / bucket | Usage breakdown |
| Quotas | Used vs limit with usage meters |
| Recent uploads | Latest files (documents tagged) |

Model changelists (buckets, objects, quotas) remain available below the dashboard on the admin index.
