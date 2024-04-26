from client import RelayClient
import pytest

@pytest.fixture
def wc_conn() -> RelayClient:
    return RelayClient()

@pytest.fixture
def wc_shop(wc_conn: RelayClient) -> RelayClient:
    wc_conn.register_shop()
    wc_conn.enroll_key_card()
    return wc_conn

@pytest.fixture
def wc_auth() -> RelayClient:
    conn = RelayClient()
    conn.register_shop()
    conn.enroll_key_card()
    assert len(conn.all_key_cards) == 1
    conn.login()
    assert conn.logged_in == True
    return conn

from typing import Generator, Callable, Tuple, Any

@pytest.fixture
def make_client() -> Generator[Callable[..., RelayClient], Any, Any]:
    created_clients = []
    def _make_client(name: str, shop=None, guest:bool=False, private_key:bytes|None=None):
        c = RelayClient(name=name, guest=guest, wallet_private_key=private_key)
        if shop is not None:
            c.shop_token_id = shop
        created_clients.append(c)
        return c
    yield _make_client
    for c in created_clients:
        c.close()
    print("client closed")

@pytest.fixture
def cleanup():
    to_close = []
    yield to_close
    for c in to_close:
        print(f"closing {c.name}")
        c.close()

@pytest.fixture
def make_two_clients(make_client, cleanup) -> Generator[Tuple[RelayClient, RelayClient], Any, Any]:
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    a2 = make_client("alice.2")
    cleanup.append(a1)
    cleanup.append(a2)
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a2.shop_token_id = shop_id
    a2.enroll_key_card()
    a1.login()
    a2.login()
    assert a1.errors == 0
    assert a2.errors == 0
    assert len(a1.all_key_cards) == 2
    assert len(a2.all_key_cards) == 2
    assert a1.all_key_cards == a2.all_key_cards
    a1.create_shop_manifest()
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0
    big_token_id = int.from_bytes(a2.manifest.shop_token_id, "big")
    owner_addr = a2.shopReg.functions.ownerOf(big_token_id).call()
    assert owner_addr == a1.account.address
    yield (a1, a2)
