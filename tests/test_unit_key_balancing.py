from app import create_app, db, Server, VlessKey, User, pick_key_balanced
from werkzeug.security import generate_password_hash


def test_pick_key_balanced_prefers_less_users():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test",
    })

    with app.app_context():
        db.create_all()
        s = Server(name="S1")
        db.session.add(s)
        db.session.commit()

        k1 = VlessKey(server_id=s.id, key_text="k1")
        k2 = VlessKey(server_id=s.id, key_text="k2")
        db.session.add_all([k1, k2])
        db.session.commit()

        u = User(username="u1", password_hash=generate_password_hash("secret12"), is_admin=False, key_id=k1.id)
        db.session.add(u)
        db.session.commit()

        chosen = pick_key_balanced()
        assert chosen.id == k2.id
