import binascii
import time
import os
from pprint import pprint
import pytest
from massmarket_hash_event import (
    subscription_pb2,
    shop_events_pb2,
    error_pb2,
    base_types_pb2 as mtypes,
)

from client import RelayClient, new_object_id

from test_orders import wait_for_finalization

from typing import Callable, Tuple, Generator


@pytest.fixture
def make_two_guests(
    make_client: Callable[[str], RelayClient]
) -> Generator[Tuple[RelayClient, RelayClient, RelayClient], None, None]:
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create two guests
    guest1 = make_client("guest1", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest1.enroll_key_card()
    guest1.login(subscribe=False)
    guest1.handle_all()
    guest1.subscribe_customer()
    assert guest1.errors == 0

    guest2 = make_client("guest2", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest2.enroll_key_card()
    guest2.login(subscribe=False)
    guest2.handle_all()
    guest2.subscribe_customer()
    assert guest2.errors == 0

    yield (charlie, guest1, guest2)

    charlie.close()
    guest1.close()
    guest2.close()


def test_guest_subscribe_to_inventory_fails(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest1", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.expect_error = True
    guest.subscribe(
        [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_INVENTORY"
            )
        ]
    )
    assert guest.errors == 1


def test_guest_subscribe_before_auth(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.subscribe_visitor()
    guest.handle_all()
    assert guest.errors == 0

    # create a listing
    id = charlie.create_listing("book", 1)
    charlie.change_inventory(id, 10)
    assert charlie.errors == 0

    # fetch the listing
    guest.handle_all()
    assert id.raw in guest.listings


def test_guest_subscribe_to_accounts(make_client):
    # create the owner/clerk
    clerk = make_client("clerk")
    shop_id = clerk.register_shop()
    clerk.enroll_key_card()
    clerk.login()
    clerk.create_shop_manifest()
    assert clerk.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.handle_all()
    assert guest.errors == 0

    guest.subscribe(
        [subscription_pb2.SubscriptionRequest.Filter(object_type="OBJECT_TYPE_ACCOUNT")]
    )
    assert guest.errors == 0

    # check both received the keycard from clerk
    guest.handle_all()
    assert len(guest.all_key_cards) == 1
    clerk.handle_all()
    assert len(clerk.all_key_cards) == 1

    # once guest enrolls, clerk should receive the keycard too
    guest.enroll_key_card()
    guest.handle_all()
    clerk.handle_all()
    assert len(guest.all_key_cards) == 2
    assert len(clerk.all_key_cards) == 2


def test_guest_subscribe_orders_needs_auth(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    assert guest.errors == 0

    # make sure we cant subscribe to orders yet
    guest.expect_error = True
    guest.subscribe_order()
    assert guest.errors == 1

    # reset error state
    guest.expect_error = False
    guest.errors = 0

    # make a guest keycard
    guest.enroll_key_card()
    guest.authenticate()

    # now we should
    guest.subscribe_order()
    assert guest.errors == 0


def test_guest_subscribe_only_one_subscription(make_client):
    # create the owner/clerk
    clerk = make_client("clerk")
    shop_id = clerk.register_shop()
    clerk.enroll_key_card()
    clerk.login()
    clerk.create_shop_manifest()
    assert clerk.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    sub_id = guest.subscribe_visitor()
    assert guest.errors == 0

    # make sure we cant subscribe twice
    guest.expect_error = True
    guest.subscribe_visitor()
    assert guest.errors == 1

    # reset error state
    guest.expect_error = False
    guest.errors = 0

    # stop old
    guest.cancel_subscription(sub_id)
    assert guest.errors == 0

    before = len(guest.listings)
    clerk.create_listing("book", 1)
    assert clerk.errors == 0
    guest.handle_all()
    after = len(guest.listings)
    assert before == after

    # create new subscription
    guest.subscribe_visitor()
    assert guest.errors == 0
    guest.handle_all()
    assert len(guest.listings) == after + 1


def test_guest_user_create_order(make_two_guests):
    clerk, guest1, guest2 = make_two_guests

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    # guest1 adds an item to their cart
    order1 = guest1.create_order()
    assert guest1.errors == 0
    assert order1.raw in guest1.orders
    assert len(guest1.orders[order1.raw].items) == 0
    guest1.add_to_order(order1, id, 1)
    assert guest1.errors == 0
    assert len(guest1.orders[order1.raw].items) == 1

    # guest2 tries to view guest1's order
    guest2.handle_all()
    assert order1.raw not in guest2.orders


def test_guest_user_commit_order(
    make_two_guests: Tuple[RelayClient, RelayClient, RelayClient]
):
    clerk, guest1, guest2 = make_two_guests

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    order1 = guest1.create_order()
    assert guest1.errors == 0
    guest1.add_to_order(order1, id, 2)
    assert guest1.errors == 0

    # guest2 tries to commit guest1's order
    guest2.expect_error = True
    guest2.commit_items(order1)
    assert guest2.errors == 1
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
    # reset error state
    guest2.errors = 0
    guest2.last_error = None

    # now guest1 commits it for the next test step
    guest1.commit_items(order1)
    assert guest1.errors == 0
    addr = mtypes.AddressDetails()
    addr.name = "Max Mustermann"
    addr.address1 = "Somestreet 1"
    addr.city = "City"
    addr.postal_code = "12345"
    addr.country = "Isla de Muerta"
    addr.phone_number = "+0155512345"
    addr.email_address = "some1@no.where"
    guest1.update_address_for_order(order1, invoice=addr)
    guest1.choose_payment(order1)
    assert guest1.errors == 0

    order = wait_for_finalization(guest1, order1)
    assert order.total == 2
    # order has payment details
    pr = {
        "ttl": order.payment_ttl,
        "order": bytes(32),
        "currency": clerk.default_currency.address.raw,
        "amount": order.total,
        "payeeAddress": clerk.default_payee.address.raw,
        "chainId": clerk.chain_id,
        "isPaymentEndpoint": False,
        "shopId": clerk.shop_token_id,
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = guest1.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    # guest2 tries to abandon guest1's order
    guest2.abandon_order(order1)
    assert guest2.errors == 1
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_listing(make_two_guests):
    _, guest1, _ = make_two_guests

    guest1.expect_error = True
    guest1.create_listing("unauthorized_item", "1000")
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_update_listing(make_two_guests):
    clerk, guest1, _ = make_two_guests

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    guest1.expect_error = True
    new_price = mtypes.Uint256(raw=int(1).to_bytes(32, "big"))
    guest1.update_listing(id, price=new_price)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_or_update_tag(make_two_guests):
    clerk, guest1, _ = make_two_guests

    guest1.expect_error = True
    tag_id = guest1.create_tag("unauthorized_tag")
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    # Assume clerk creates a tag
    clerk_tag_id = clerk.create_tag("actual tag")
    assert clerk.errors == 0

    guest1.expect_error = True
    guest1.add_to_tag(clerk_tag_id, new_object_id())
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_or_update_shop_manifest(make_two_guests):
    _, guest1, _ = make_two_guests

    guest1.expect_error = True
    sm = shop_events_pb2.Manifest(
        token_id=mtypes.Uint256(raw=guest1.shop_token_id.to_bytes(32)),
        pricing_currency=guest1.default_currency,
    )
    guest1._write_event(manifest=sm)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    guest1.expect_error = True
    p = mtypes.Payee(
        name="totall-legit",
        address=mtypes.EthereumAddress(
            raw=binascii.unhexlify(guest1.account.address[2:]),
        ),
        chain_id=guest1.chain_id,
    )
    guest1.update_shop_manifest(add_payee=p)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
