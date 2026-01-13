from app import validate_username_password

def test_validate_username_password_required():
    assert validate_username_password("", "") == "username and password are required"
    assert validate_username_password("user", "") == "username and password are required"
    assert validate_username_password("", "secret12") == "username and password are required"

def test_validate_username_password_lengths():
    assert validate_username_password("ab", "secret12") == "username is too short"
    assert validate_username_password("alex", "12345") == "password is too short"
    assert validate_username_password("alex", "123456") is None
