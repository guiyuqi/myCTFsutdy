import base64
import hashlib
import hmac
import json
import os
import pickle
import random
import threading
import time

import pydash
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from runtime_secrets import SECRET_KEY, rotate_flag

app = Flask(__name__, static_folder=None)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.route("/static/<path:filename>", endpoint="static")
def static_files(filename, _dir=STATIC_DIR):
    return send_from_directory(_dir, filename)


JWT_ALG = "HS256"
JWT_TTL = 7200


def _secret() -> str:
    return SECRET_KEY


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(("%s:%s" % (salt, password)).encode()).hexdigest()


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict) -> str:
    header = {"alg": JWT_ALG, "typ": "JWT"}
    segs = [
        _b64e(json.dumps(header, separators=(",", ":")).encode()),
        _b64e(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segs).encode()
    sig = hmac.new(_secret().encode(), signing_input, hashlib.sha256).digest()
    segs.append(_b64e(sig))
    return ".".join(segs)


def jwt_decode(token: str):
    try:
        h, p, s = token.split(".")
        if json.loads(_b64d(h)).get("alg") != JWT_ALG:
            return None
        expected = _b64e(
            hmac.new(
                _secret().encode(), ("%s.%s" % (h, p)).encode(), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(expected, s):
            return None
        payload = json.loads(_b64d(p))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except Exception:
        return None


def current_user():
    token = request.cookies.get("token")
    return jwt_decode(token) if token else None


class User:
    def __init__(
        self, username, password, role="user", email="", phone="", nickname=""
    ):
        self.username = username
        self.salt = os.urandom(16).hex()
        self.password = hash_password(password, self.salt)
        self.role = role
        self.email = email
        self.phone = phone
        self.nickname = nickname

    def profile(self):
        return {
            "username": self.username,
            "role": self.role,
            "email": self.email,
            "phone": self.phone,
            "nickname": self.nickname,
        }


USERS_LOCK = threading.Lock()
ORDERS = []

PRODUCTS = [
    {"id": "p1001", "name": "旗舰版机械键盘", "price": 899.00, "icon": "⌨️"},
    {"id": "p1002", "name": "4K 显示器 27寸", "price": 1899.00, "icon": "🖥️"},
    {"id": "p1003", "name": "人体工学椅", "price": 2499.00, "icon": "🪑"},
    {"id": "p1004", "name": "降噪耳机 Pro", "price": 1299.00, "icon": "🎧"},
    {"id": "p1005", "name": "便携固态硬盘 2TB", "price": 699.00, "icon": "💾"},
    {"id": "p1006", "name": "机械臂咖啡机", "price": 3699.00, "icon": "☕"},
]


@app.route("/")
def index():
    return render_template("index.html", user=current_user(), products=PRODUCTS[:3])


@app.route("/shop")
def shop():
    user = current_user()
    is_admin = bool(user) and user.get("role") == "admin"
    demo_cart = ""
    if is_admin:
        demo_cart = base64.b64encode(
            pickle.dumps([p["id"] for p in PRODUCTS[:2]], protocol=0)
        ).decode()
    return render_template(
        "shop.html",
        user=user,
        products=PRODUCTS,
        is_admin=is_admin,
        demo_cart=demo_cart,
    )


@app.route("/login")
def login_page():
    if current_user():
        return redirect(url_for("profile"))
    return render_template("login.html", user=None)


@app.route("/register")
def register_page():
    if current_user():
        return redirect(url_for("profile"))
    return render_template("register.html", user=None)


@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))
    record = USERS.get(user.get("username"))
    return render_template(
        "profile.html",
        user=user,
        is_admin=(user.get("role") == "admin"),
        record=record.profile() if record else {},
    )


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("token")
    return resp


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()

    if not (3 <= len(username) <= 32) or len(password) < 6:
        return jsonify({"ok": False, "msg": "用户名 3-32 位，密码至少 6 位"}), 400

    with USERS_LOCK:
        if username in USERS:
            return jsonify({"ok": False, "msg": "用户名已被注册"}), 409

        USERS[username] = User(username, password, role="user", email=email)
    return jsonify({"ok": True, "msg": "注册成功，请登录"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    user = USERS.get(username)
    if not user or user.password != hash_password(
        data.get("password") or "", user.salt
    ):
        return jsonify({"ok": False, "msg": "用户名或密码错误"}), 401

    now = int(time.time())
    payload = {
        "username": user.username,
        "role": user.role,
        "iat": now,
        "exp": now + JWT_TTL,
    }
    resp = make_response(
        jsonify({"ok": True, "msg": "登录成功", "redirect": "/profile"})
    )
    resp.set_cookie(
        "token", jwt_encode(payload), httponly=True, samesite="Lax", max_age=JWT_TTL
    )
    return resp


@app.route("/api/user/update", methods=["POST"])
def api_user_update():
    payload = current_user()
    if not payload:
        return jsonify({"ok": False, "msg": "请先登录"}), 401

    me = USERS.get(payload.get("username"))
    if not me:
        return jsonify({"ok": False, "msg": "用户不存在"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    value = data.get("value")
    if not isinstance(key, str) or not key:
        return jsonify({"ok": False, "msg": "参数错误"}), 400

    if "__builtins__" in key:
        return jsonify({"ok": False, "msg": "字段路径非法: 该路径被禁止修改"}), 400

    username, role = me.username, me.role
    try:
        pydash.set_(me, key, value)
    except Exception as e:
        return jsonify({"ok": False, "msg": "字段路径非法: %s" % e}), 400

    me.username, me.role = username, role

    now = int(time.time())
    resp = make_response(
        jsonify({"ok": True, "msg": "资料已更新", "profile": me.profile()})
    )
    resp.set_cookie(
        "token",
        jwt_encode(
            {"username": me.username, "role": me.role, "iat": now, "exp": now + JWT_TTL}
        ),
        httponly=True,
        samesite="Lax",
        max_age=JWT_TTL,
    )
    return resp


@app.route("/api/order/buy", methods=["POST"])
def api_order_buy():
    payload = current_user()
    if not payload:
        return jsonify({"ok": False, "msg": "请先登录"}), 401
    if payload.get("role") != "admin":
        return jsonify({"ok": False, "msg": "下单结算仅对管理员（admin）开放"}), 403

    raw = request.form.get("cart") or ""
    if not raw:
        return jsonify({"ok": False, "msg": "缺少 cart 参数"}), 400
    try:
        cart = pickle.loads(base64.b64decode(raw))
    except Exception as e:
        return jsonify({"ok": False, "msg": "购物车数据无法解析: %s" % e}), 400

    if not isinstance(cart, list):
        return jsonify({"ok": False, "msg": "购物车格式错误"}), 400

    by_id = {p["id"]: p for p in PRODUCTS}
    items, total = [], 0.0
    for pid in cart:
        p = by_id.get(pid)
        if p:
            items.append(p)
            total += p["price"]
    if not items:
        return jsonify({"ok": False, "msg": "购物车里没有有效商品"}), 400

    order = {
        "order_id": "SO%d" % random.randint(10**8, 10**9 - 1),
        "username": payload.get("username"),
        "items": [i["name"] for i in items],
        "total": round(total, 2),
        "ts": int(time.time()),
    }
    ORDERS.append(order)
    return jsonify({"ok": True, "msg": "下单成功", "order": order})


@app.route("/api/order/list")
def api_order_list():
    payload = current_user()
    if not payload:
        return jsonify({"ok": False, "msg": "请先登录"}), 401
    if payload.get("role") != "admin":
        return jsonify({"ok": False, "msg": "无权限"}), 403
    return jsonify({"ok": True, "orders": ORDERS[-20:]})


if __name__ == "__main__":
    print("=" * 62)
    print(" SimpleShop - 商城靶机")
    print(" Flask + pydash %s" % pydash.__version__)
    print("=" * 62, flush=True)
    threading.Thread(target=rotate_flag, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, threaded=True)
