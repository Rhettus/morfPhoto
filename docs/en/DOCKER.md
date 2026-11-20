# Deploy morfPhoto with Docker

*Read in another language: **English** (this document) · [Français](../fr/DOCKER.md).*

The image contains everything morfPhoto needs (Qt, the SQLite driver and ExifTool). It runs on `linux/amd64`
and `linux/arm64`, including most NAS devices.

## Requirements

- Docker with the Compose plugin (`docker compose version` should print a version).
- A photo directory on the host.

## 1. Get the files

Create a directory for the deployment, then copy [`docker-compose.yml`](../../docker-compose.yml) and
[`.env.example`](../../.env.example) from this repository into it.

```sh
mkdir morfphoto && cd morfphoto
# copy docker-compose.yml and .env.example here
cp .env.example .env
```

## 2. Configure

Edit `.env`:

| Setting | Required | Description |
|---------|----------|-------------|
| `PHOTOS_DIR` | Yes | Absolute path of the photo directory on the host. It must already exist. |
| `PUID`, `PGID` | No | Account the service runs as. It must be able to read `PHOTOS_DIR`. Default `1000`. |
| `MORFPHOTO_PORT` | No | Port published on the host. Default `8793`. |
| `MORFPHOTO_API_KEY` | No | Key that protects the API, in images with API key support. Empty means no key. |
| `MORFPHOTO_IMAGE` | No | Image to run, for example to pin a version. |

To find the right `PUID` and `PGID`, run `id` as a user who can read the photos:

```sh
id
# uid=1000(photos) gid=1000(photos) ...
```

To generate an API key:

```sh
openssl rand -hex 32
```

Keep `.env` private if it holds a key.

## 3. Start

```sh
docker compose pull
docker compose up -d
```

On first start, morfPhoto registers `/photos` and begins indexing. A large library can take a while, because
metadata is read from every photo. The NAS image extracts EXIF with up to two
ExifTool processes. On later starts, the container serves the saved
index immediately. Live watching handles changes while it runs. A daily scan
catches changes made while it was stopped. To catch up sooner, request an
incremental scan with `POST /api/v1/index`.

## 4. Check that it works

```sh
docker compose ps                                       # STATUS should become "healthy"
curl http://127.0.0.1:8793/healthz                      # {"status":"ok"}
curl http://127.0.0.1:8793/api/v1/index/status          # indexing progress
curl http://127.0.0.1:8793/api/v1/photos/summary        # photo counters
```

If you set an API key, add it to API requests:

```sh
curl -H "Authorization: Bearer YOUR_KEY" http://127.0.0.1:8793/api/v1/photos/summary
```

## Update

```sh
docker compose pull
docker compose up -d
```

The database is kept.

## Back up the database

```sh
docker compose stop
docker run --rm -v morfphoto-data:/data:ro -v "$PWD":/backup debian:trixie-slim \
    tar czf /backup/morfphoto-data.tar.gz -C /data .
docker compose start
```

## Remove

```sh
docker compose down      # removes the container and keeps the database
docker compose down -v   # also deletes the database
```

Your photos are never modified or deleted.

## Limitations

- The photo directory is mounted read-only, so `PUT` and `DELETE /api/v1/context` return an error. Existing
  `.morfphoto.json` files are still read.
- SMB sources (`POST /api/v1/sources`) are not available in the container. Mount the share on the host and
  point `PHOTOS_DIR` at it instead.
- LAN announcement through morfBeacon is turned off.

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| `Set PHOTOS_DIR in .env` | `.env` is missing, or it is not in the same directory as `docker-compose.yml`. |
| The bind mount fails at start | `PHOTOS_DIR` does not exist on the host. |
| No photos are found | Check that `PUID` and `PGID` can read `PHOTOS_DIR`, then read `docker compose logs morfphoto`. |
| The port is already in use | Change `MORFPHOTO_PORT` in `.env`, then run `docker compose up -d`. |
| `docker compose pull` is denied | The image is private or the name is wrong. Check `MORFPHOTO_IMAGE`. |
