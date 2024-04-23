import time

from client import RelayClient, RelayException

from websockets.exceptions import ConnectionClosedError

def test_register_store(wc_conn: RelayClient):
    wc_conn.register_store()
    wc_conn.close()

def test_keycard_login(wc_store: RelayClient):
    wc_store.login()
    wc_store.handle_all()
    assert wc_store.logged_in == True
    wc_store.close()

def test_pingpong(wc_store: RelayClient):
    wc_store.login()
    wc_store.handle_all()
    assert wc_store.logged_in == True
    have_pongs = False
    while not have_pongs:
        wc_store.handle_all()
        have_pongs = wc_store.pongs > 0
        time.sleep(1)
    assert have_pongs
    wc_store.close()

def test_no_pong_disconnects(wc_store: RelayClient):
    assert wc_store.logged_in == False
    assert wc_store.connected == True
    time.sleep(35) # wait until the sever disconnects us
    try:
        wc_store.handle_all()
    except ConnectionClosedError:
        assert wc_store.connected == False
    else:
        assert False, "Should have raised ConnectionClosedError"

# A user can dis- and re-connect multiple times
def test_reconnect(wc_store: RelayClient):
    wc_store.login()
    wc_store.handle_all()
    assert wc_store.logged_in == True
    wc_store.close()
    assert wc_store.connected == False
    wc_store.login()
    assert wc_store.connected == True
    wc_store.handle_all()
    assert wc_store.logged_in == True
    wc_store.close()

def test_cant_connect_twice_with_same_keycard(make_client):
    a1 = make_client("alice.1")
    a2 = make_client("alice.2")
    store_id = a1.register_store()
    a1.enroll_key_card()
    a2.store_token_id = store_id
    # re-use the same keycard
    a2.own_key_card = a1.own_key_card
    a1.login()
    assert a1.logged_in == True
    try:
        a2.login()
    except RelayException as e:
        assert e.code == "alreadyConnected"
    else:
        assert False, "Should have raised RelayException"
    assert a2.logged_in == False
    a1.close()
    a2.close()
