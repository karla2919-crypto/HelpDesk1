# Help Desk (Flask + MySQL)

Roles: **admin**, **moderador** y **usuario**. Los moderadores reclaman tickets; el ticket reclamado solo lo ven su moderador y el admin. El chat del staff es solo para moderadores y admin.

## Variables de entorno
| Variable | Uso |
|---|---|
| `MYSQLHOST`, `MYSQLUSER`, `MYSQLPASSWORD`, `MYSQLDATABASE`, `MYSQLPORT` | Conexión a MySQL (Railway las crea al agregar el plugin MySQL) |
| `SECRET_KEY` | Clave larga y aleatoria para las sesiones |
| `ADMIN_USER`, `ADMIN_PASS`, `ADMIN_EMAIL` | Cuenta admin inicial (se crea una sola vez; por defecto `admin` / `admin12345`) |

## Local
```
pip install -r requirements.txt
# crea la base: CREATE DATABASE helpdesk CHARACTER SET utf8mb4;
python app.py
```
Las tablas se crean solas al iniciar (`database.sql`).

## Railway
1. Sube esta carpeta a GitHub y crea un proyecto desde el repositorio.
2. Agrega un servicio MySQL; Railway comparte las variables `MYSQL*`.
3. Define `SECRET_KEY` y `ADMIN_PASS`.
4. El `Procfile` ya arranca con gunicorn.

Entra con el admin, crea los moderadores en **Moderadores**, y los usuarios se registran en `/registro`.
