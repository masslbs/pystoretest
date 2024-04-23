from client import RelayClient
import pytest

@pytest.fixture
def wc_conn():
    return RelayClient()

@pytest.fixture
def wc_store(wc_conn: RelayClient):
    wc_conn.register_store()
    wc_conn.enroll_key_card()
    return wc_conn

@pytest.fixture
def wc_auth():
    conn = RelayClient()
    conn.register_store()
    conn.enroll_key_card()
    assert len(conn.all_key_cards) == 1
    conn.login()
    assert conn.logged_in == True
    return conn

@pytest.fixture
def make_client():
    created_clients = []
    def _make_client(name):
        c = RelayClient(name=name)
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
def make_two_clients(make_client, cleanup):
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    a2 = make_client("alice.2")
    cleanup.append(a1)
    cleanup.append(a2)
    store_id = a1.register_store()
    a1.enroll_key_card()
    a2.store_token_id = store_id
    a2.enroll_key_card()
    a1.login()
    a2.login()
    assert a1.errors == 0
    assert a2.errors == 0
    assert len(a1.all_key_cards) == 2
    assert len(a2.all_key_cards) == 2
    assert a1.all_key_cards == a2.all_key_cards
    a1.create_store_manifest()
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0
    big_token_id = int.from_bytes(a2.manifest.store_token_id, "big")
    owner_addr = a2.storeReg.functions.ownerOf(big_token_id).call()
    assert owner_addr == a1.account.address
    yield (a1, a2)
