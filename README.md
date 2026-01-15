# VPN Portal (student-simple Flask project)

Features:
- Register / Login (username + password)
- User dashboard
- One user can have max 1 key
- "Get key" assigns one free VLESS key from DB, balanced by server (min assigned count)
- "Delete key" unassigns it, user can request again
- Admin panel: users, servers stats, keys list, log tail
- Database via Flask-SQLAlchemy
- Logger via app.logger (RotatingFileHandler)
- 2 unit tests + 2 integration tests (pytest)
- Docker Compose: Flask + Postgres in separate containers, configs via env vars

## Persistent database as files
This version stores Postgres data in the project folder:

- `./pgdata/` is mounted to `/var/lib/postgresql/data` inside Postgres container.

So data survives `docker compose down` and rebuilds.

To reset DB completely:
```bash
docker compose down
rm -rf pgdata
mkdir pgdata
docker compose up --build
```

## Run with Docker Compose
```bash
docker compose up --build
```

Open:
- http://localhost:5050/

Admin:
- http://localhost:5050/admin
- username/password from env in docker-compose.yml (default: admin / admin12345)

## Add servers and keys
Admin panel:
- Add server
- Add keys (one per line)

## Run tests locally (without Docker)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```


## Admin: delete keys
In `/admin` keys table there is a **Delete** button for each key (removes the key record from DB).