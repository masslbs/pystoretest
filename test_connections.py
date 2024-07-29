import time
import datetime
import pytest

from websockets.exceptions import ConnectionClosedError
from eth_keys import keys

from massmarket_hash_event import error_pb2
import siwe

from client import RelayClient, RelayException, EnrollException

def test_register_shop(wc_conn: RelayClient):
    wc_conn.register_shop()
    wc_conn.close()

def test_keycard_login(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.close()

def test_keycard_invalid():
    rc = RelayClient(auto_connect=False)
    rc.register_shop()

    # repeating enroll_key_card() internals
    keyCard = keys.PrivateKey(rc.own_key_card.key)
    kc_hex = keyCard.public_key.to_hex()
    enroll_url = rc.relay_addr._replace(path="/v2/enroll_key_card").geturl()
    now = datetime.datetime.utcnow().isoformat() + 'Z'

    def make():
        return siwe.SiweMessage(
            issued_at=now,
            domain=rc.relay_addr.netloc,
            address=rc.account.address,
            uri=enroll_url,
            version='1',
            chain_id=rc.chain_id,
            nonce="00000000", # keyCards can only be enrolled once
            statement=f"keyCard: {kc_hex}",
            resources=[
                f"mass-relayid:{rc.relay_token_id}",
                f"mass-shopid:{rc.shop_token_id}",
                f"mass-keycard:{kc_hex}",
            ])

    with pytest.raises(EnrollException) as e:
        m = make()
        m.domain = "some.where.else"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException) as e:
        m = make()
        m.uri = "https://not.the.relay/foo"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException) as e:
        m = make()
        m.uri += "/messed/up/the/path"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException) as e:
        m = make()
        m.address="0x"+"00"*20
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException):
        m = make()
        m.nonce = "12345678"
        rc.enroll_key_card(siwe_msg=m)

    # drop one of the resources
    for i in range(3):
        with pytest.raises(EnrollException):
            m = make()
            m.resources.remove(m.resources[i])
            rc.enroll_key_card(siwe_msg=m)

    # mess with the schema
    for i in range(3):
        with pytest.raises(EnrollException):
            m = make()
            m.resources[i] = m.resources[i].replace("mass-", "bad-")
            rc.enroll_key_card(siwe_msg=m)

    # invalidate relay- and shop-id
    # (changing the keycard doesnt make sense)
    for i in range(2):
        with pytest.raises(EnrollException):
            m = make()
            m.resources[i] += "FOOBAR"
            rc.enroll_key_card(siwe_msg=m)

    # shorten/extend keycard data
    with pytest.raises(EnrollException):
        m = make()
        kc = m.resources[2]
        kc = kc[:len(kc)-10]
        m.resources[2] = kc
        rc.enroll_key_card(siwe_msg=m)
    with pytest.raises(EnrollException):
        m = make()
        kc = m.resources[2]
        kc = kc + "00"*5
        m.resources[2] = kc
        rc.enroll_key_card(siwe_msg=m)

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
    with pytest.raises(ConnectionClosedError):
        wc_shop.handle_all()
    assert wc_shop.connected == False

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
    with pytest.raises(RelayException) as e:
        a2.login()
    assert e.code == error_pb2.ERROR_CODES_ALREADY_CONNECTED
    assert a2.logged_in == False
    a1.close()
    a2.close()
