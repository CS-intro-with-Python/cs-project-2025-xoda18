from app import create_app, db, Server, VlessKey, User
from werkzeug.security import generate_password_hash

def test_key_create_and_delete_flow():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test",
    })

    with app.app_context():
        db.create_all()
        u = User(username="user2", password_hash=generate_password_hash("secret12"), is_admin=False)
        db.session.add(u)
        db.session.commit()

        s1 = Server(name="S1")
        s2 = Server(name="S2")
        db.session.add_all([s1, s2])
        db.session.commit()

        db.session.add_all([
            VlessKey(server_id=s1.id, key_text="vless://k1"),
            VlessKey(server_id=s2.id, key_text="vless://k2"),
        ])
        db.session.commit()

    client = app.test_client()

    r = client.post("/login", data={"username": "user2", "password": "secret12"})
    assert r.status_code in (302, 303)

    r = client.post("/api/key")
    assert r.status_code == 200
    data = r.get_json()
    assert data["key"].startswith("vless://")

    r2 = client.post("/api/key")
    assert r2.status_code == 200
    data2 = r2.get_json()
    assert data2["key_id"] == data["key_id"]

    rd = client.post("/api/key/delete")
    assert rd.status_code == 200
    assert rd.get_json()["ok"] is True

    rd2 = client.post("/api/key/delete")
    assert rd2.status_code == 404
