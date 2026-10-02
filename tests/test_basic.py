def test_addition_passes():
    assert 1 + 1 == 2

def test_string_upper_passes():
    assert "abc".upper() == "ABC"

def test_assertion_failure():
    # Intentional failure: wrong expected value
    assert 2 + 2 == 5

def test_missing_key_failure():
    # Intentional failure: simulates a malformed response
    response = {"status": "ok"}
    assert response["data"] == []