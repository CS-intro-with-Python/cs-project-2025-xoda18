from app import create_app, db, Server, VlessKey, User
from werkzeug.security import generate_password_hash

def test_admin_delete_key_unassigns_users():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test",
    })

    with app.app_context():
        db.create_all()
        admin = User(username="adminx", password_hash=generate_password_hash("adminpass"), is_admin=True)
        user = User(username="u1", password_hash=generate_password_hash("secret12"), is_admin=False)
        db.session.add_all([admin, user])
        db.session.commit()

        s = Server(name="S1")
        db.session.add(s)
        db.session.commit()

        k = VlessKey(server_id=s.id, key_text="vless://to_delete")
        db.session.add(k)
        db.session.commit()

        user.key_id = k.id
        db.session.commit()
        key_id = k.id
        user_id = user.id

    client = app.test_client()
    r = client.post("/login", data={"username": "adminx", "password": "adminpass"})
    assert r.status_code in (302, 303)

    r = client.post(f"/admin/delete_key/{key_id}")
    assert r.status_code in (302, 303)

    with app.app_context():
        assert VlessKey.query.get(key_id) is None
        u = User.query.get(user_id)
        assert u.key_id is None
