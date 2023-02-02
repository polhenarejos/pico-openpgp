import pytest

@pytest.fixture(scope="module",autouse=True)
def check_kdfreq(card):
    if card.kdf_required:
        pytest.skip("Token requires KDF setup", allow_module_level=True)
