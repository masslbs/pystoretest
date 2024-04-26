import time
import os
import pytest
from massmarket_hash_event import shop_events_pb2, error_pb2

@pytest.fixture
def make_two_guests(make_client):
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
    guest1.login()
    guest1.handle_all()
    assert guest1.errors == 0

    guest2 = make_client("guest2", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest2.enroll_key_card()
    guest2.login()
    guest2.handle_all()
    assert guest2.errors == 0

    yield (charlie, guest1, guest2)

    charlie.close()
    guest1.close()
    guest2.close()

def test_guest_user_create_order(make_two_guests):
    clerk, guest1, guest2 = make_two_guests

    item_id = clerk.create_item('book', 1)
    clerk.change_stock([(item_id, 10)])
    assert clerk.errors == 0

    # guest1 adds an item to their cart
    order1 = guest1.create_order()
    assert guest1.errors == 0
    assert order1 in guest1.orders
    assert len(guest1.orders[order1].items) == 0
    guest1.add_to_order(order1, item_id, 1)
    assert guest1.errors == 0
    assert len(guest1.orders[order1].items) == 1

    # guest2 tries to view guest1's order
    guest2.handle_all()
    assert order1 not in guest2.orders


def test_guest_user_commit_order(make_two_guests):
    clerk, guest1, guest2 = make_two_guests

    item_id = clerk.create_item('book', 1)
    clerk.change_stock([(item_id, 10)])
    assert clerk.errors == 0

    order1 = guest1.create_order()
    assert guest1.errors == 0
    guest1.add_to_order(order1, item_id, 2)
    assert guest1.errors == 0

    # guest2 tries to commit guest1's order
    guest2.expect_error = True
    guest2.commit_order(order1)
    assert guest2.errors == 1
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # now guest1 commits it for the next test step
    guest1.commit_order(order1)
    assert guest1.errors == 0

    # guests receives finalization
    for _ in range(5):
        guest1.handle_all()
        order = guest1.orders[order1]
        assert order is not None
        if order.finalized:
            break
        time.sleep(2)
    order = guest1.orders[order1]
    assert order.finalized

    # reset error state
    guest2.errors = 0
    guest2.last_error = None

    # guest2 tries to abandon guest1's order
    guest2.abandon_order(order1)
    assert guest2.errors == 1
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

def test_guest_cannot_create_item(make_two_guests):
    _, guest1, _ = make_two_guests

    guest1.expect_error = True
    guest1.create_item('unauthorized_item', '1000')
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

def test_guest_cannot_update_item(make_two_guests):
    clerk, guest1, _ = make_two_guests

    item_id = clerk.create_item('book', 1)
    clerk.change_stock([(item_id, 10)])
    assert clerk.errors == 0

    guest1.expect_error = True
    guest1.update_item(item_id, price=2000)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

def test_guest_cannot_create_or_update_tag(make_two_guests):
    clerk, guest1, _ = make_two_guests

    guest1.expect_error = True
    tag_id = guest1.create_tag('unauthorized_tag')
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    # Assume clerk creates a tag
    clerk_tag_id = clerk.create_tag('actual tag')
    assert clerk.errors == 0

    guest1.expect_error = True
    guest1.add_item_to_tag(clerk_tag_id, os.urandom(32))
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

def test_guest_cannot_create_or_update_shop_manifest(make_two_guests):
    _, guest1, _ = make_two_guests

    guest1.expect_error = True
    # this fn also creates a tag
    #guest1.create_shop_manifest()
    eid = os.urandom(32)
    tid = os.urandom(32)
    sm = shop_events_pb2.ShopManifest(event_id=eid,
                                        shop_token_id=guest1.shop_token_id.to_bytes(32),
                                        domain="socks.mass.market",
                                        published_tag_id=tid)
    evt = shop_events_pb2.ShopEvent(shop_manifest=sm)
    guest1._write_event(evt)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    guest1.expect_error = True
    guest1.update_shop_manifest(domain="unauthorized.domain")
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
