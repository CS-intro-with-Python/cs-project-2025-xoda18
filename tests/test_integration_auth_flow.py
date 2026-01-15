from app import create_app, db


def test_register_login_dashboard():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test",
    })

    with app.app_context():
        db.create_all()

    client = app.test_client()

    r = client.post("/register", data={"username": "user1", "password": "secret12"}, follow_redirects=False)
    assert r.status_code in (302, 303)

    r = client.post("/login", data={"username": "user1", "password": "secret12"}, follow_redirects=False)
    assert r.status_code in (302, 303)

    r = client.get("/dashboard")
    assert r.status_code == 200
    assert b"Dashboard" in r.data
