import datetime
import requests
import time
import pytest

from websockets.exceptions import ConnectionClosedError
from eth_keys import keys
import siwe

from massmarket_hash_event import envelope_pb2, subscription_pb2, base_types_pb2

from client import RelayClient, RelayException, EnrollException


def test_register_shop(wc_conn: RelayClient):
    wc_conn.register_shop()
    wc_conn.close()


def test_keycard_login(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.close()


def test_keycard_invalid(account_manager):
    ta = account_manager.get_test_account()
    rc = RelayClient(auto_connect=False, wallet_account=ta)
    rc.register_shop()

    # repeating enroll_key_card() internals
    keyCard = keys.PrivateKey(rc.own_key_card.key)
    kc_hex = keyCard.public_key.to_hex()
    enroll_url = rc.relay_addr._replace(path="/v3/enroll_key_card").geturl()
    now = datetime.datetime.utcnow().isoformat() + "Z"

    def make():
        return siwe.SiweMessage(
            issued_at=now,
            domain=rc.relay_addr.netloc,
            address=rc.account.address,
            uri=enroll_url,
            version="1",
            chain_id=rc.chain_id,
            nonce="00000000",  # keyCards can only be enrolled once
            statement=f"keyCard: {kc_hex}",
            resources=[
                f"mass-relayid:{rc.relay_token_id}",
                f"mass-shopid:{rc.shop_token_id}",
                f"mass-keycard:{kc_hex}",
            ],
        )

    with pytest.raises(EnrollException):
        m = make()
        m.domain = "some.where.else"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException):
        m = make()
        m.uri = "https://not.the.relay/foo"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException):
        m = make()
        m.uri += "/messed/up/the/path"
        rc.enroll_key_card(siwe_msg=m)

    with pytest.raises(EnrollException):
        m = make()
        m.address = "0x" + "00" * 20
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
        kc = kc[: len(kc) - 10]
        m.resources[2] = kc
        rc.enroll_key_card(siwe_msg=m)
    with pytest.raises(EnrollException):
        m = make()
        kc = m.resources[2]
        kc = kc + "00" * 5
        m.resources[2] = kc
        rc.enroll_key_card(siwe_msg=m)


def test_keycard_cant_enroll_twice(wc_shop: RelayClient):
    # first works
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    wc_shop.handle_all()

    # 2nd enroll fails
    other_client = RelayClient(
        name="other",
        wallet_private_key=wc_shop.account.key,
        key_card_private_key=wc_shop.own_key_card.key,
        auto_connect=False,
    )
    other_client.shop_token_id = wc_shop.shop_token_id
    with pytest.raises(EnrollException) as e:
        other_client.enroll_key_card()
    assert e.type is EnrollException
    assert e.value.http_code == 409

    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    assert wc_shop.connected == True
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
    time.sleep(20)  # wait until the sever disconnects us
    with pytest.raises(ConnectionClosedError):
        wc_shop.handle_all()
    assert wc_shop.connected == False


# A user can dis- and re-connect multiple times
# TODO: keep track of seqno across connections
def skip_test_reconnect(wc_shop: RelayClient):
    wc_shop.login()
    wc_shop.handle_all()
    assert wc_shop.logged_in == True
    # wait for session to flush so that we dont get the first message sent twice
    # TODO: we could be smarter about skipping multiple messages
    for i in range(15):
        time.sleep(2)
        wc_shop.handle_all()
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
    expect = "Already connected from this device in another session"
    with pytest.raises(RelayException, match=expect):
        a2.login()
    assert a2.logged_in == False
    a1.close()
    a2.close()


def test_clerk_blob_upload(wc_auth: RelayClient):
    req_id = wc_auth.get_blob_upload_url()
    wc_auth.handle_all()
    while "waiting" in wc_auth.outgoingRequests[req_id]:
        print("waiting")
        wc_auth.handle_all()
        assert wc_auth.errors == 0
    urlResp = wc_auth.outgoingRequests[req_id]
    files = {
        "file": ("filename.txt", open("testcat.jpg", "rb"), "application/octet-stream")
    }
    uploadResp = requests.post(urlResp["url"], files=files)
    assert uploadResp.status_code == 201
    uploadJson = uploadResp.json()
    assert (
        uploadJson["ipfs_path"]
        == "/ipfs/Qma8tx56NLeSi2we2R41C8haSNj9kyRooxrJptyLvncbWf"
    )
    wc_auth.close()


def test_invalid_envelope(wc_auth: RelayClient):
    msg = subscription_pb2.SubscriptionRequest(start_shop_seq_no=42)
    no_req_id = envelope_pb2.Envelope(
        subscription_request=msg,
    )
    data = no_req_id.SerializeToString()

    with pytest.raises(ConnectionClosedError) as e:
        wc_auth.connection.send(data)
        wc_auth.handle_all()
    assert wc_auth.connected == False

    # reconnect
    wc_auth.connect()
    assert wc_auth.connected == True

    no_msg = envelope_pb2.Envelope(
        request_id=base_types_pb2.RequestId(raw=42),
    )
    data = no_msg.SerializeToString()

    with pytest.raises(ConnectionClosedError) as e:
        wc_auth.connection.send(data)
        wc_auth.handle_all()
    assert wc_auth.connected == False
