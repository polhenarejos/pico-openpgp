import pytest

@pytest.fixture(scope="module",autouse=True)
def check_kdf_support(card):
    if not card.kdf_supported:
        pytest.skip("No KDF support", allow_module_level=True)
