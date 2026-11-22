import os
import secrets
from functools import wraps

import pymysql
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambia-esta-clave-en-produccion")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

CFG = dict(
    host=os.environ.get("MYSQLHOST", "localhost"),
    user=os.environ.get("MYSQLUSER", "root"),
    password=os.environ.get("MYSQLPASSWORD", ""),
    database=os.environ.get("MYSQLDATABASE", "helpdesk"),
    port=int(os.environ.get("MYSQLPORT", 3306)),
    charset="utf8mb4",
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
)
ET = {"abierto": "Abierto", "proceso": "En proceso", "cerrado": "Cerrado"}
PRI = ("baja", "media", "alta")
CATS = ("Hardware", "Software", "Red", "Cuenta y accesos", "Otro")
app.jinja_env.globals.update(ET=ET, CATS=CATS, csrf=lambda: session.get("csrf", ""))


# ---------- base de datos ----------
def init_db():
    c = pymysql.connect(**CFG)
    with c.cursor() as cur:
        ruta = os.path.join(os.path.dirname(__file__), "database.sql")
        with open(ruta, encoding="utf-8") as f:
            for s in f.read().split(";"):
                if s.strip():
                    cur.execute(s)
        cur.execute("SELECT id FROM users WHERE rol='admin' LIMIT 1")
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users(nombre,usuario,email,pass_hash,rol) VALUES(%s,%s,%s,%s,'admin')",
                ("Administrador", os.environ.get("ADMIN_USER", "admin"),
                 os.environ.get("ADMIN_EMAIL", "admin@helpdesk.local"),
                 generate_password_hash(os.environ.get("ADMIN_PASS", "admin12345"))))
    c.close()


def conn():
    if "db" not in g:
        g.db = pymysql.connect(**CFG)
    return g.db


@app.teardown_appcontext
def cerrar(_):
    db = g.pop("db", None)
    if db:
        db.close()


def q(sql, args=(), one=False):
    with conn().cursor() as c:
        c.execute(sql, args)
        return c.fetchone() if one else c.fetchall()


def run(sql, args=()):
    with conn().cursor() as c:
        c.execute(sql, args)
        return c.lastrowid, c.rowcount


# ---------- seguridad ----------
@app.before_request
def proteger():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        t = request.form.get("csrf") or request.headers.get("X-CSRF", "")
        if not secrets.compare_digest(t, session["csrf"]):
            abort(400)


def acceso(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session:
                return redirect(url_for("login"))
            if roles and session["rol"] not in roles:
                abort(403)
            return f(*a, **k)
        return w
    return deco


def get_ticket(tid):
    """Devuelve el ticket solo si el usuario actual tiene derecho a verlo."""
    t = q("""SELECT t.*, u.nombre AS cliente, u.email, u.tel, m.nombre AS moderador
             FROM tickets t JOIN users u ON u.id=t.user_id
             LEFT JOIN users m ON m.id=t.mod_id WHERE t.id=%s""", (tid,), True)
    if not t:
        abort(404)
    rol, uid = session["rol"], session["uid"]
    mio = t["mod_id"] == uid
    if rol == "client" and t["user_id"] != uid:
        abort(404)
    if rol == "mod" and not (mio or (t["mod_id"] is None and t["estado"] != "cerrado")):
        abort(404)  # 404 para no revelar que el ticket existe
    t["gestiona"] = rol == "admin" or (rol == "mod" and mio)
    t["libre"] = t["mod_id"] is None
    if rol == "mod" and not mio:
        t["cliente"] = t["email"] = t["tel"] = None
    return t


def gestionable(tid):
    t = get_ticket(tid)
    if not t["gestiona"]:
        abort(403)
    return t


# ---------- cuentas ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("usuario", "").strip().lower()
        u = q("SELECT * FROM users WHERE LOWER(usuario)=%s OR LOWER(email)=%s", (ident, ident), True)
        if u and u["activo"] and check_password_hash(u["pass_hash"], request.form.get("clave", "")):
            session.clear()
            session.update(uid=u["id"], rol=u["rol"], nombre=u["nombre"], csrf=secrets.token_hex(16))
            return redirect(url_for("index"))
        flash("Usuario o contraseña incorrectos, o la cuenta está desactivada.")
    return render_template("auth.html", registro=False)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("nombre", "usuario", "email", "tel")}
        clave = request.form.get("clave", "")
        if not f["nombre"] or not f["usuario"] or "@" not in f["email"] or len(clave) < 8:
            flash("Completa nombre, usuario y correo válido. La contraseña necesita al menos 8 caracteres.")
        elif q("SELECT id FROM users WHERE usuario=%s OR email=%s", (f["usuario"], f["email"]), True):
            flash("Ese usuario o correo ya está registrado.")
        else:
            run("INSERT INTO users(nombre,usuario,email,tel,pass_hash,rol) VALUES(%s,%s,%s,%s,%s,'client')",
                (f["nombre"], f["usuario"], f["email"], f["tel"], generate_password_hash(clave)))
            flash("Cuenta creada. Ya puedes iniciar sesión.")
            return redirect(url_for("login"))
    return render_template("auth.html", registro=True)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if "uid" not in session:
        return redirect(url_for("login"))
    v = {"admin": "todos", "mod": "cola", "client": "mios"}[session["rol"]]
    return redirect(url_for("tickets", v=v))


# ---------- tickets ----------
@app.route("/tickets")
@acceso()
def tickets():
    rol, uid = session["rol"], session["uid"]
    v, est = request.args.get("v", ""), request.args.get("estado", "")
    args = []
    if rol == "client":
        v, cond, args = "mios", "t.user_id=%s", [uid]
    elif rol == "mod" and v == "mios":
        cond, args = "t.mod_id=%s", [uid]
    elif rol == "mod":
        v, cond = "cola", "t.mod_id IS NULL AND t.estado<>'cerrado'"
    else:
        v, cond = "todos", "1=1"
    if est in ET and v != "cola":
        cond += " AND t.estado=%s"
        args.append(est)
    rows = q("""SELECT t.id,t.asunto,t.categoria,t.prioridad,t.estado,t.creado,m.nombre AS moderador
                FROM tickets t LEFT JOIN users m ON m.id=t.mod_id
                WHERE """ + cond + " ORDER BY t.creado DESC", args)
    titulo = {"cola": "Tickets sin reclamar", "mios": "Mis tickets" if rol == "mod" else "Mis solicitudes",
              "todos": "Todos los tickets"}[v]
    return render_template("tickets.html", rows=rows, vista=v, estado=est, titulo=titulo)


@app.route("/nuevo", methods=["GET", "POST"])
@acceso("client")
def nuevo():
    if request.method == "POST":
        asunto = request.form.get("asunto", "").strip()
        desc = request.form.get("descripcion", "").strip()
        cat, pri = request.form.get("categoria"), request.form.get("prioridad")
        if not asunto or not desc or cat not in CATS or pri not in PRI:
            flash("Escribe el asunto y la descripción para enviar la solicitud.")
        else:
            tid, _ = run("INSERT INTO tickets(user_id,asunto,categoria,prioridad,descripcion) VALUES(%s,%s,%s,%s,%s)",
                         (session["uid"], asunto[:120], cat, pri, desc[:2000]))
            flash("Solicitud enviada. Un moderador la atenderá pronto.")
            return redirect(url_for("ticket", tid=tid))
    return render_template("nuevo.html", PRI=PRI)


@app.route("/ticket/<int:tid>")
@acceso()
def ticket(tid):
    t = get_ticket(tid)
    notas, mods = [], []
    if t["gestiona"]:
        notas = q("""SELECT n.*, u.nombre FROM notas n JOIN users u ON u.id=n.user_id
                     WHERE n.ticket_id=%s ORDER BY n.creado DESC""", (tid,))
    if session["rol"] == "admin":
        mods = q("SELECT id,nombre FROM users WHERE rol='mod' AND activo=1 ORDER BY nombre")
    return render_template("ticket.html", t=t, notas=notas, mods=mods)


@app.post("/ticket/<int:tid>/reclamar")
@acceso("mod")
def reclamar(tid):
    get_ticket(tid)
    # UPDATE atómico: solo uno gana si dos moderadores reclaman a la vez
    _, n = run("UPDATE tickets SET mod_id=%s, estado='proceso' WHERE id=%s AND mod_id IS NULL AND estado<>'cerrado'",
               (session["uid"], tid))
    flash("Ticket reclamado. Ahora es tuyo." if n else "Otro moderador ya reclamó este ticket.")
    return redirect(url_for("ticket", tid=tid) if n else url_for("tickets", v="cola"))


@app.post("/ticket/<int:tid>/soltar")
@acceso("mod")
def soltar(tid):
    gestionable(tid)
    run("UPDATE tickets SET mod_id=NULL, estado='abierto' WHERE id=%s AND mod_id=%s", (tid, session["uid"]))
    flash("Ticket devuelto a la cola.")
    return redirect(url_for("tickets", v="cola"))


@app.post("/ticket/<int:tid>/estado")
@acceso("mod", "admin")
def estado(tid):
    gestionable(tid)
    e = request.form.get("estado")
    if e in ET:
        run("UPDATE tickets SET estado=%s WHERE id=%s", (e, tid))
    return redirect(url_for("ticket", tid=tid))


@app.post("/ticket/<int:tid>/nota")
@acceso("mod", "admin")
def nota(tid):
    gestionable(tid)
    txt = request.form.get("texto", "").strip()
    if txt:
        run("INSERT INTO notas(ticket_id,user_id,texto) VALUES(%s,%s,%s)", (tid, session["uid"], txt[:1000]))
    return redirect(url_for("ticket", tid=tid))


@app.post("/ticket/<int:tid>/asignar")
@acceso("admin")
def asignar(tid):
    m = request.form.get("mod_id", "")
    if m and not q("SELECT id FROM users WHERE id=%s AND rol='mod' AND activo=1", (m,), True):
        abort(400)
    run("UPDATE tickets SET mod_id=%s, estado=IF(%s IS NOT NULL AND estado='abierto','proceso',estado) WHERE id=%s",
        (m or None, m or None, tid))
    return redirect(url_for("ticket", tid=tid))


@app.post("/ticket/<int:tid>/eliminar")
@acceso("admin")
def eliminar(tid):
    run("DELETE FROM tickets WHERE id=%s", (tid,))
    flash("Ticket eliminado.")
    return redirect(url_for("tickets"))


# ---------- administración ----------
@app.route("/admin/usuarios")
@acceso("admin")
def usuarios():
    rows = q("""SELECT u.id,u.nombre,u.usuario,u.email,u.tel,u.creado,u.activo,
                COUNT(t.id) AS total, MAX(t.creado) AS ultimo
                FROM users u LEFT JOIN tickets t ON t.user_id=u.id
                WHERE u.rol='client' GROUP BY u.id ORDER BY u.creado DESC""")
    return render_template("usuarios.html", rows=rows)


@app.route("/admin/mods", methods=["GET", "POST"])
@acceso("admin")
def mods():
    if request.method == "POST":
        a, f = request.form.get("accion"), request.form
        if a == "crear":
            nombre, usuario, email = f.get("nombre", "").strip(), f.get("usuario", "").strip(), f.get("email", "").strip()
            if not nombre or not usuario or "@" not in email or len(f.get("clave", "")) < 8:
                flash("Completa nombre, usuario y correo válido. La contraseña necesita al menos 8 caracteres.")
            elif q("SELECT id FROM users WHERE usuario=%s OR email=%s", (usuario, email), True):
                flash("Ese usuario o correo ya existe.")
            else:
                run("INSERT INTO users(nombre,usuario,email,pass_hash,rol) VALUES(%s,%s,%s,%s,'mod')",
                    (nombre, usuario, email, generate_password_hash(f["clave"])))
                flash("Moderador creado.")
        elif a == "toggle":
            run("UPDATE users SET activo=1-activo WHERE id=%s AND rol='mod'", (f.get("id"),))
        elif a == "clave" and len(f.get("clave", "")) >= 8:
            run("UPDATE users SET pass_hash=%s WHERE id=%s AND rol='mod'",
                (generate_password_hash(f["clave"]), f.get("id")))
            flash("Contraseña actualizada.")
        return redirect(url_for("mods"))
    rows = q("""SELECT u.id,u.nombre,u.usuario,u.email,u.activo,
                (SELECT COUNT(*) FROM tickets t WHERE t.mod_id=u.id AND t.estado<>'cerrado') AS activos
                FROM users u WHERE u.rol='mod' ORDER BY u.nombre""")
    return render_template("mods.html", rows=rows)


# ---------- chat del staff ----------
@app.route("/chat")
@acceso("mod", "admin")
def chat():
    return render_template("chat.html")


@app.route("/chat/mensajes")
@acceso("mod", "admin")
def chat_mensajes():
    desde = request.args.get("desde", 0, type=int)
    rows = q("""SELECT c.id, c.texto, c.user_id, u.nombre, u.rol,
                DATE_FORMAT(c.creado,'%%d/%%m %%H:%%i') AS hora
                FROM chat c JOIN users u ON u.id=c.user_id WHERE c.id>%s ORDER BY c.id LIMIT 200""", (desde,))
    return jsonify(yo=session["uid"], mensajes=rows)


@app.post("/chat/enviar")
@acceso("mod", "admin")
def chat_enviar():
    txt = request.form.get("texto", "").strip()[:500]
    if txt:
        run("INSERT INTO chat(user_id,texto) VALUES(%s,%s)", (session["uid"], txt))
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
