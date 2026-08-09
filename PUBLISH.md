# Publish checklist (Docker Hub)

1. Bump `VERSION` in `config/settings.py` and add a `CHANGELOG.md` section.
2. Build and tag:

```bash
docker build -t shellui/storage-service:0.1.0 -t shellui/storage-service:latest .
docker push shellui/storage-service:0.1.0
docker push shellui/storage-service:latest
```

3. Tag the git release (`v0.1.0`) so docs deploy workflows can run when configured.
