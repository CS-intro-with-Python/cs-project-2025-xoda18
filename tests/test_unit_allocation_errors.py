from app import create_app, db, Server, VlessKey, pick_server_with_free_keys

def test_pick_server_with_free_keys_prefers_less_assigned():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test",
    })

    with app.app_context():
        db.create_all()
        s1 = Server(name="S1")
        s2 = Server(name="S2")
        db.session.add_all([s1, s2])
        db.session.commit()

        k1 = VlessKey(server_id=s1.id, key_text="k1", assigned_user_id=1)
        k2 = VlessKey(server_id=s1.id, key_text="k2", assigned_user_id=None)

        k3 = VlessKey(server_id=s2.id, key_text="k3", assigned_user_id=None)
        k4 = VlessKey(server_id=s2.id, key_text="k4", assigned_user_id=None)

        db.session.add_all([k1, k2, k3, k4])
        db.session.commit()

        chosen = pick_server_with_free_keys()
        assert chosen.id == s2.id
