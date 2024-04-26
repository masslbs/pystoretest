import time
from websockets.exceptions import ConnectionClosedError
from massmarket_hash_event import error_pb2
from client import RelayClient, RelayException

def test_register_shop(wc_conn: RelayClient):
    wc_conn.register_shop()
    wc_conn.close()

def test_keycard_login(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.close()

def test_pingpong(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    have_pongs = False
    while not have_pongs:
        wc_shop.handle_all()
        have_pongs = wc_shop.pongs > 0
        time.sleep(1)
    assert have_pongs
    wc_shop.close()

def test_no_pong_disconnects(wc_shop: RelayClient):
    assert wc_shop.logged_in == False
    assert wc_shop.connected == True
    time.sleep(7) # wait until the sever disconnects us
    try:
        wc_shop.handle_all()
    except ConnectionClosedError:
        assert wc_shop.connected == False
    else:
        assert False, "Should have raised ConnectionClosedError"

# A user can dis- and re-connect multiple times
def test_reconnect(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.close()
    assert wc_shop.connected == False
    assert wc_shop.logged_in == False
    wc_shop.login()
    assert wc_shop.connected == True
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.close()

def test_cant_connect_twice_with_same_keycard(make_client):
    a1 = make_client("alice.1")
    a2 = make_client("alice.2")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a2.shop_token_id = shop_id
    # re-use the same keycard
    a2.own_key_card = a1.own_key_card
    a1.login()
    assert a1.logged_in == True
    try:
        a2.login()
    except RelayException as e:
        assert e.code == error_pb2.ERROR_CODES_ALREADY_CONNECTED
    else:
        assert False, "Should have raised RelayException"
    assert a2.logged_in == False
    a1.close()
    a2.close()
