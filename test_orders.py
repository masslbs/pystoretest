# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time
from pprint import pprint
from typing import Tuple, Callable
from massmarket import (
    error_pb2,
)
import massmarket.cbor.base_types as mbase
import massmarket.cbor.order as morder
import massmarket.cbor.listing as mlisting
import massmarket.cbor.patch as mpatch
from client import RelayClient, new_object_id
import copy


def now():
    return time.time()


def since(start):
    return now() - start


def new_uint256(i):
    assert isinstance(i, int)
    return mbase.Uint256(value=i)


def prepare_order(c: RelayClient):
    assert c.shop is not None, "shop not initialized"
    # a1 writes an a few events
    iid1 = c.create_listing("sneakers", int(0.001 * 10**18))  # 0.001 ETH
    iid2 = c.create_listing("caps", int(0.0005 * 10**18))  # 0.0005 ETH
    c.change_inventory(iid1, 3)
    c.change_inventory(iid2, 5)
    assert c.errors == 0

    oid = c.create_order()
    assert c.errors == 0
    order = c.shop.orders.get(oid)
    assert order is not None
    assert len(order.items) == 0

    c.add_to_order(oid, iid1, 1)
    assert c.errors == 0

    c.add_to_order(oid, iid2, 2)
    assert c.errors == 0

    order = c.shop.orders.get(oid)
    assert order is not None
    assert len(order.items) == 2
    item_ids = [item.listing_id for item in order.items]
    assert iid1 in item_ids
    assert iid2 in item_ids

    return oid, iid1, iid2


def wait_for_finalization(c: RelayClient, order_id: int):
    assert c.shop is not None, "shop not initialized"
    for _ in range(5):
        c.handle_all()
        assert c.errors == 0
        order = c.shop.orders.get(order_id)
        assert order is not None
        if order.state == morder.OrderState.UNPAID:
            assert order.payment_details is not None
            return order
        print(f"{c.name} waiting for order {order_id} to be finalized")
        pprint(order.__dict__)
        time.sleep(2)
    raise Exception(f"order not finalized in time")


def wait_for_order_paid(c: RelayClient, oid: int, items, ping=None, retry=15):
    assert c.shop is not None, "shop not initialized"
    # wait for payment to be processed
    for _ in range(retry):
        c.handle_all()
        assert c.errors == 0
        order = c.shop.orders.get(oid)
        assert order is not None
        if order.state == morder.OrderState.PAID:
            break

        # TODO: the eth_byCall variant needs new blocks to be yielded.
        # we might also be to do this with an anvil argument but this works for now
        if ping:
            ping["nonce"] = c.w3.eth.get_transaction_count(c.account.address)
            tx_hash = c.w3.eth.send_transaction(ping)
            c.check_tx(tx_hash)

        print("waiting for payment to be noticed by the relay...")
        time.sleep(2)

    order = c.shop.orders.get(oid)
    assert order is not None
    # pprint(order.__dict__)
    assert order.state == morder.OrderState.PAID, f"{oid} wasn't paid in time"
    # stock updated
    for id, want in items:
        assert c.check_inventory(id) == want


default_addr = morder.AddressDetails(
    name="Max Mustermann",
    address1="Somestreet 1",
    city="City",
    postal_code="12345",
    country="Isla de Muerta",
    phone_number="+0155512345",
    email_address="some1@no.where",
)

tax_code = mbase.PriceModifier(
    # title="20% tax",
    modification_percent=new_uint256(120),
)

shipping = mbase.PriceModifier(
    # title="default shipping - 5EDD",
    modification_absolute=mbase.ModificationAbsolute(
        amount=new_uint256(500),
        plus=True,
    ),
)

region_tax_and_ship = mbase.ShippingRegion(
    country=default_addr.country,
    postal_code=default_addr.postal_code,
    city=default_addr.city,
    price_modifiers={
        "tax-and-ship": tax_code,
        "shipping": shipping,
    },
)


# this is some helper code to create a bunch of unpayed orders for a relay refactor
def test_orders_unpayed(make_client):
    alice: RelayClient = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_listing("sneakers", 10)
    alice.change_inventory(iid, 20)
    assert alice.errors == 0

    for _ in range(3):
        oid = alice.create_order()
        alice.add_to_order(oid, iid, 1)
        alice.commit_items(oid)
        alice.update_address_for_order(oid, invoice=default_addr)
        alice.choose_payment(oid)
        assert alice.errors == 0
        print(f"finalized eth order {oid}")

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    erc20_ethaddr = mbase.EthereumAddress(value=erc20_addr)
    curr = mbase.ChainAddress(address=erc20_ethaddr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currency=curr)
    assert alice.errors == 0

    for _ in range(3):
        oid = alice.create_order()
        alice.add_to_order(oid, iid, 1)
        alice.commit_items(oid)
        alice.update_address_for_order(oid, invoice=default_addr)
        alice.choose_payment(oid, currency=curr)
        assert alice.errors == 0
        print(f"finalized erc20 order {oid}")


def test_orders_no_currency(make_client):
    alice: RelayClient = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_listing("sneakers", 10)
    alice.change_inventory(iid, 20)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0
    alice.commit_items(oid)
    assert alice.errors == 0
    alice.update_address_for_order(oid, invoice=default_addr)
    assert alice.errors == 0

    alice.expect_error = True

    # manually craft the checkout without a currency
    alice._write_patch(
        type=mpatch.ObjectType.ORDER,
        object_id=oid,
        op=mpatch.OpString.REPLACE,
        fields=["State"],
        obj=morder.OrderState.PAYMENT_CHOSEN,
    )
    assert alice.errors == 1
    assert alice.last_error is not None
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_orders_nonexistent_items(make_client):
    alice: RelayClient = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # Create a valid listing for comparison
    valid_iid = alice.create_listing("sneakers", 10)
    alice.change_inventory(valid_iid, 20)
    assert alice.errors == 0

    # Create an order
    oid = alice.create_order()
    assert alice.errors == 0

    # Try to add a non-existent item to the order
    nonexistent_iid = new_object_id()  # Generate a random ID that doesn't exist

    # Expect an error when adding non-existent item
    alice.expect_error = True
    alice.add_to_order(oid, nonexistent_iid, 1)
    assert alice.errors == 1
    assert alice.last_error is not None
    assert alice.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # Reset error state
    alice.expect_error = False
    alice.errors = 0
    alice.last_error = None

    # Add a valid item to ensure the order still works
    alice.add_to_order(oid, valid_iid, 1)
    assert alice.errors == 0

    # Try to add another non-existent item after a valid one
    another_nonexistent_iid = new_object_id()
    alice.expect_error = True
    alice.add_to_order(oid, another_nonexistent_iid, 2)
    assert alice.errors == 1
    assert alice.last_error is not None
    assert alice.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # Verify the order still contains the valid item
    order = alice.shop.orders.get(oid)
    assert order is not None
    assert len(order.items) == 1
    assert order.items[0].listing_id == valid_iid


def test_orders_no_matching_region(make_client):
    alice: RelayClient = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_listing("sneakers", 10)
    alice.change_inventory(iid, 20)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0
    alice.commit_items(oid)
    assert alice.errors == 0
    addr = copy.deepcopy(default_addr)
    addr.country = "somewhere else"
    alice.update_address_for_order(oid, invoice=addr)
    assert alice.errors == 0

    # remove the default region
    alice.update_shop_manifest(remove_region="default")

    alice.expect_error = True
    alice.choose_payment(oid)
    assert alice.errors == 1

    alice.expect_error = False
    alice.errors = 0

    # country mismatch
    alice.update_shop_manifest(add_region=("taxed", region_tax_and_ship))
    assert alice.errors == 0

    alice.expect_error = True
    alice.choose_payment(oid)
    # TODO: relay should not allow this. Re-enable region rating
    assert alice.errors == 1


def test_orders_shipping_costs(make_client):
    alice: RelayClient = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # configure regions
    alice.start_batch()
    alice.update_shop_manifest(remove_region="default")
    alice.update_shop_manifest(add_region=("taxed", region_tax_and_ship))
    iid = alice.create_listing("sneakers", 10000, wait=False)
    alice.flush_batch()
    assert alice.errors == 0

    alice.change_inventory(iid, 5)

    alice.start_batch()
    alice.expect_error = True
    oid = alice.create_order(wait=False)
    alice.add_to_order(oid, iid, 3)

    alice.commit_items(oid)

    addr = copy.deepcopy(default_addr)
    alice.update_address_for_order(oid, invoice=addr)

    alice.choose_payment(oid)
    assert alice.errors == 0
    alice.expect_error = False
    alice.flush_batch()
    assert alice.errors == 0

    order = wait_for_finalization(alice, oid)
    assert order.payment_details is not None
    total = order.payment_details.total
    # TODO: decimals
    assert total == 36600 or total == 36500  # = (300 * 1.2 + 5) * 100


def test_orders_shipping_address(make_client):
    alice: RelayClient = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_listing("sneakers", 10)
    alice.change_inventory(iid, 20)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0

    alice.commit_items(oid)
    assert alice.errors == 0

    addr = copy.deepcopy(default_addr)
    alice.update_address_for_order(oid, invoice=addr)
    assert alice.errors == 0

    # try to leave out some fields
    alice.expect_error = True

    # address2 and phone_number are optional
    fields = ["name", "address1", "city", "postal_code", "country", "email_address"]
    for f in fields:
        # reset error state
        alice.errors = 0
        alice.last_error = None

        invalid_addr = copy.deepcopy(addr)
        setattr(invalid_addr, f, "")

        print(f"trying addr with field {f} set empty:")
        pprint(invalid_addr)

        alice.update_address_for_order(oid, shipping=invalid_addr)
        assert alice.errors == 1, f"failed on field {f}"
        assert alice.last_error is not None


def test_clerk_check_shipping_region(make_client: Callable[[str], RelayClient]):
    a = make_client("alice")
    a.register_shop()
    a.enroll_key_card()
    a.login()
    a.create_shop_manifest()
    assert a.errors == 0

    # Verify no shipping regions initially
    a.update_shop_manifest(remove_region="default")
    assert len(a.shop.manifest.shipping_regions) == 0

    # Helper function to attempt a complete order flow
    def attempt_order(country=None, expect_to_fail=False):
        # Create a listing if we don't have one yet
        if not hasattr(attempt_order, "listing_id"):
            attempt_order.listing_id = a.create_listing("test item", 1000)
            a.change_inventory(attempt_order.listing_id, 5)

        # Set error expectation
        if expect_to_fail:
            a.expect_error = True
        else:
            a.expect_error = False

        # Reset error state
        a.errors = 0
        a.last_error = None

        # Create and process order
        order_id = a.create_order()
        a.add_to_order(order_id, attempt_order.listing_id, 1)
        a.commit_items(order_id)

        # Create address with specified country
        addr = copy.deepcopy(default_addr)
        if country:
            addr.country = country

        a.update_address_for_order(order_id, invoice=addr)
        a.choose_payment(order_id)

        # Return success status
        return a.errors == 0

    # Orders should fail if there are no shipping regions
    assert not attempt_order(expect_to_fail=True)
    assert a.last_error.code == error_pb2.ERROR_CODES_INVALID

    # Add a default region with empty country
    a.expect_error = False
    a.errors = 0
    default_region = mbase.ShippingRegion("", "", "")
    a.update_shop_manifest(add_region=("default", default_region))
    assert a.errors == 0
    a.handle_all()

    # Orders should now be accepted
    assert attempt_order()

    # Remove default and add specific country
    a.update_shop_manifest(remove_region="default")
    test_region = mbase.ShippingRegion("Test", "", "")
    a.update_shop_manifest(add_region=("Test", test_region))
    assert a.errors == 0
    a.handle_all()

    # Orders with matching country should be accepted
    assert attempt_order(country="Test")

    # Orders with non-matching country should be rejected
    assert not attempt_order(country="other", expect_to_fail=True)
    assert a.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_orders_invalid(
    make_two_clients: Tuple[RelayClient, RelayClient],
    make_client: Callable[[str], RelayClient],
):
    a1, a2 = make_two_clients
    assert a1.shop is not None
    assert a2.shop is not None

    # a1 writes an a few listings
    iid1 = a1.create_listing("sneakers", 1000)
    iid2 = a1.create_listing("caps", 1000)
    a1.change_inventory(iid1, 3)
    a1.change_inventory(iid2, 5)
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 starts a order
    oid = a2.create_order()
    assert a2.errors == 0
    assert a2.shop.orders.has(oid)
    a1.handle_all()
    assert a1.errors == 0
    assert a1.shop.orders.has(oid)

    # a2 tries to add non-existent listing to order
    a2.expect_error = True
    a2.add_to_order(oid, new_object_id(), 1)
    assert a2.errors == 1
    assert a2.last_error is not None
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to use non-existent order
    a2.expect_error = True
    a2.add_to_order(new_object_id(), iid1, 1)
    assert a2.errors == 1
    assert a2.last_error is not None
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # create a 2nd shop
    bob = make_client("bob")
    bob.register_shop()
    bob.enroll_key_card()
    bob.login()
    bob.create_shop_manifest()
    foreignListingId = bob.create_listing("flute", 1000)
    assert bob.errors == 0

    # a2 tries to add listing from other shop to order
    a2.errors = 0
    a2.expect_error = True
    a2.add_to_order(oid, foreignListingId, 1)
    assert a2.errors == 1
    assert a2.last_error is not None
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # cant commit empty orders
    order = a1.shop.orders.get(oid)
    assert order is not None
    assert len(order.items) == 0
    a1.update_address_for_order(oid, invoice=default_addr)
    assert a1.errors == 0
    a1.expect_error = True
    a1.commit_items(oid)
    assert a1.errors == 1
    assert a1.last_error is not None
    assert a1.last_error.code == error_pb2.ERROR_CODES_INVALID

    # reset error state
    a1.expect_error = False
    a1.errors = 0
    a1.last_error = None

    # a1 finalizes the order and then tries to change it
    a1.handle_all()
    assert a1.errors == 0
    a1.add_to_order(oid, iid1, 1)
    assert a1.errors == 0
    a1.commit_items(oid)
    a1.update_address_for_order(oid, invoice=default_addr)
    a1.choose_payment(oid)
    assert a1.errors == 0
    a1.expect_error = True
    a1.add_to_order(oid, iid1, 1)
    assert a1.errors == 1
    assert a1.last_error is not None
    assert a1.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_orders_happy_eth_byCall(make_client):
    alice = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    assert alice.errors == 0
    alice.update_address_for_order(oid, invoice=default_addr)
    assert alice.errors == 0
    alice.choose_payment(oid)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = int(order.payment_details.total)
    assert total == 0.002 * 10**18

    # pay the order (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    beforePaid = alice.w3.eth.get_balance(alice.account.address)

    pr = {
        "ttl": int(order.payment_details.ttl),
        "order": bytes(32),
        "currency": "0x" + "00" * 20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": int(alice.shop_token_id),
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId.to_bytes(32, "big") == order.payment_details.payment_id

    tx = alice.payments.functions.pay(pr).transact({"value": total})
    alice.check_tx(tx)

    took = since(start_send)
    print(f"sending tx={tx.hex()} took {took}")

    wait_for_order_paid(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPaid = alice.w3.eth.get_balance(alice.account.address)

    assert afterPaid <= beforePaid


def test_orders_happy_eth_byAddress(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = int(order.payment_details.total)
    assert total == 0.002 * 10**18

    pr = {
        "ttl": int(order.payment_details.ttl),
        "order": bytes(32),
        "currency": "0x" + "00" * 20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": int(alice.shop_token_id),
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    # check we got the same payment
    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId.to_bytes(32, "big") == order.payment_details.payment_id

    # pay the order (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    purchase_address = alice.payments.functions.getPaymentAddress(
        pr, alice.account.address
    ).call()
    print(f"sending tx to {purchase_address}")
    transaction = {
        "to": purchase_address,
        "value": total,
        "gas": 25000,
        "maxFeePerGas": alice.w3.to_wei(50, "gwei"),
        "maxPriorityFeePerGas": alice.w3.to_wei(5, "gwei"),
        "nonce": alice.w3.eth.get_transaction_count(alice.account.address),
        "chainId": alice.chain_id,
    }
    tx_hash = alice.w3.eth.send_transaction(transaction)
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    # trigger new blocks so the watcher subscription is triggered again
    transaction["value"] = 1
    transaction["to"] = alice.account.address

    wait_for_order_paid(alice, oid, [(iid1, 2), (iid2, 3)], ping=transaction)

    afterPaid = alice.w3.eth.get_balance(alice.account.address)

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    # TODO: this is annoying....
    # the gas costs of processPayment outweig the income of the payment
    # afterSweep = alice.w3.eth.get_balance(alice.account.address)
    # assert afterPaid < afterSweep


def test_orders_happy_erc20_byAddress(make_client: Callable[[str], RelayClient]):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(
        alice.account.address, 50000000000000000000
    ).transact()
    alice.check_tx(tx)

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    erc20_ethaddr = mbase.EthereumAddress(value=erc20_addr)
    curr = mbase.ChainAddress(address=erc20_ethaddr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currency=curr)
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = int(order.payment_details.total)
    assert total == 300 # fixed price conversion of 1 eth == 1500 fiat => 3 fiat == 300 fiat cents

    # wait for next block so we dont pay before the the watcher is waiting
    # unless next-block time is less then a second this shouldnt be a problem in reality
    # ie. the client will not be able to pay before the relay has setup it's subscription for new events
    for _ in range(5):
        alice.handle_all()
        assert alice.errors == 0
        time.sleep(1)

    beforePaid = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # construct PaymentRequest
    pr = {
        "ttl": int(order.payment_details.ttl),
        "order": bytes(32),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": int(alice.shop_token_id),
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId.to_bytes(32, "big") == order.payment_details.payment_id

    purchase_address = alice.payments.functions.getPaymentAddress(
        pr, alice.account.address
    ).call()

    # transfer erc20 tokens to the shop
    start_send = now()
    tx_hash = alice.erc20Token.functions.transfer(purchase_address, total).transact()
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    wait_for_order_paid(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPaid = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPaid < beforePaid

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    afterSweep = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPaid <= afterSweep


def test_orders_happy_erc20_byCall(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(
        alice.account.address, 50000000000000000000
    ).transact()
    alice.check_tx(tx)

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    erc20_ethaddr = mbase.EthereumAddress(value=erc20_addr)
    curr = mbase.ChainAddress(address=erc20_ethaddr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currency=curr)
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = int(order.payment_details.total)
    assert total == 300 # fixed price conversion of 1 eth == 1500 fiat => 3 fiat == 300 fiat cents

    beforePaid = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # pay the order
    tx = alice.erc20Token.functions.approve(alice.payments.address, total).transact()
    alice.check_tx(tx)

    pr = {
        "ttl": int(order.payment_details.ttl),
        "order": bytes(32),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": int(alice.shop_token_id),
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId.to_bytes(32, "big") == order.payment_details.payment_id

    tx = alice.payments.functions.pay(pr).transact()
    alice.check_tx(tx)

    wait_for_order_paid(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPaid = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPaid == beforePaid


def test_orders_choose_payment_twice(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(
        alice.account.address, 50000000000000000000
    ).transact()
    alice.check_tx(tx)

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    erc20_ethaddr = mbase.EthereumAddress(value=erc20_addr)
    erc20_curr = mbase.ChainAddress(address=erc20_ethaddr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currency=erc20_curr)
    assert alice.errors == 0

    oid, _, _ = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid, currency=erc20_curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = int(order.payment_details.total)
    assert total == 300 # fixed price conversion of 1 eth == 1500 fiat => 3 fiat == 300 fiat cents

    # choose payment again
    eth_curr = mbase.ChainAddress(address=bytes(20), chain_id=alice.chain_id)
    alice.choose_payment(oid, currency=eth_curr)
    assert alice.errors == 0


def test_orders_item_locking(make_two_clients: Tuple[RelayClient, RelayClient]):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    print("Creating listing for caps with inventory of 3")
    caps_id = alice.create_listing("caps", 1)
    alice.change_inventory(caps_id, 3)
    assert alice.errors == 0

    print("Alice creating order")
    order_id1 = alice.create_order()
    assert alice.errors == 0
    order1 = alice.shop.orders.get(order_id1)
    assert order1 is not None
    assert len(order1.items) == 0
    print(f"Alice adding 2 caps to order {order_id1}")
    alice.add_to_order(order_id1, caps_id, 2)
    assert alice.errors == 0

    print("Bob creating order")
    order_id2 = bob.create_order()
    assert bob.errors == 0
    order2 = bob.shop.orders.get(order_id2)
    assert order2 is not None
    assert len(order2.items) == 0
    print(f"Bob adding 2 caps to order {order_id2}")
    bob.add_to_order(order_id2, caps_id, 2)
    assert bob.errors == 0

    # see the others order (alice and bob are the same user essentially)
    print("Syncing state between clients")
    alice.handle_all()
    bob.handle_all()
    assert len(order1.items) == 1
    assert len(order2.items) == 1

    # commit the first order
    print("Alice committing her order")
    alice.commit_items(order_id1)
    assert alice.errors == 0

    # commit the second order and expect an error
    print("Bob trying to commit his order (should fail due to insufficient inventory)")
    bob.expect_error = True
    bob.commit_items(order_id2)
    assert bob.errors == 1
    assert bob.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK
    assert bob.last_error.additional_info.object_id == caps_id
    print(f"Got expected error: {bob.last_error.message}")

    # reset error state
    print("Resetting Bob's error state")
    bob.expect_error = False
    bob.errors = 0
    bob.last_error = None

    # alice's customer vanished
    print("Alice abandoning her order")
    alice.abandon_order(order_id1)
    assert alice.errors == 0
    print("Bob syncing state")
    bob.handle_all()
    assert bob.errors == 0

    # now bob can commit his order
    print("Bob now committing his order (should succeed)")
    bob.commit_items(order_id2)
    assert bob.errors == 0
    print("Bob updating address for order")
    bob.update_address_for_order(order_id2, invoice=default_addr)
    assert bob.errors == 0
    print("Bob choosing payment method")
    bob.choose_payment(order_id2, payee=alice.default_payee)
    assert bob.errors == 0


def test_orders_variations_simple(make_two_clients: Tuple[RelayClient, RelayClient]):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    caps_id = alice.create_listing("caps", 1)
    color_option = mlisting.ListingOption(
        title="color",
        variations={
            "red": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="red",
                    description="red color",
                ),
                price_modifier=mbase.PriceModifier(
                    modification_absolute=mbase.ModificationAbsolute(
                        amount=new_uint256(1),
                        plus=True,
                    ),
                ),
            ),
        },
    )
    alice.update_listing(caps_id, add_option=("color", color_option))
    assert alice.errors == 0

    alice.change_inventory(caps_id, 3, ["red"])
    assert alice.errors == 0

    bob.handle_all()
    assert bob.errors == 0
    assert bob.shop is not None

    order1 = bob.create_order()

    # try_nonexistent
    bob.expect_error = True
    bob.add_to_order(order1, caps_id, 2, ["nonexistent"])
    assert bob.errors == 1
    bob.errors = 0
    bob.add_to_order(order1, caps_id, 2, ["red", "nonexistent"])
    assert bob.errors == 1
    bob.errors = 0
    bob.expect_error = False

    # commit
    bob.add_to_order(order1, caps_id, 2, ["red"])
    assert bob.errors == 0
    bob.commit_items(order1)
    bob.update_address_for_order(order1, invoice=default_addr)
    bob.choose_payment(order1, payee=alice.default_payee)
    assert bob.errors == 0

    # check price
    o = bob.shop.orders.get(order1)
    assert o is not None
    assert o.payment_details is not None
    assert o.payment_details.total == 4
    assert len(o.payment_details.listing_hashes) == 1


# TODO: fix go patcher logic for canceling an item
def skip_test_orders_variations_cancel_on_remove(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    caps_id = alice.create_listing("caps", 1)
    color_option = mlisting.ListingOption(
        title="color",
        variations={
            "red": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="red",
                    description="red color",
                ),
                price_modifier=mbase.PriceModifier(
                    modification_absolute=mbase.ModificationAbsolute(
                        amount=new_uint256(1),
                        plus=True,
                    ),
                ),
            ),
        },
    )
    alice.update_listing(caps_id, add_option=("color", color_option))
    assert alice.errors == 0

    alice.change_inventory(caps_id, 3, ["red"])
    assert alice.errors == 0

    bob.handle_all()
    assert bob.errors == 0

    order1 = bob.create_order()
    # commit and check price
    bob.add_to_order(order1, caps_id, 2, ["red"])
    assert bob.errors == 0

    bob.commit_items(order1)
    bob.update_address_for_order(order1, invoice=default_addr)
    bob.choose_payment(order1, payee=alice.default_payee)
    assert bob.errors == 0

    # remove the variation => order should be canceled
    alice.update_listing(caps_id, remove_variation=("color", "red"))
    assert alice.errors == 0
    bob.handle_all()
    assert bob.errors == 0

    o = bob.shop.orders.get(order1)
    assert o is not None
    assert o.state == morder.OrderState.CANCELED


def test_order_not_committed(
    make_two_guests: Tuple[RelayClient, RelayClient, RelayClient],
):
    clerk, guest1, guest2 = make_two_guests

    # Create a listing with clerk
    listing_id = clerk.create_listing("Test Item", 1000)
    assert clerk.errors == 0

    # Set inventory to 1
    clerk.change_inventory(listing_id, 1)
    assert clerk.errors == 0

    # First guest creates an order and adds the item
    order_id1 = guest1.create_order()
    assert guest1.errors == 0
    order2 = guest1.shop.orders.get(order_id1)
    assert order2 is not None
    assert len(order2.items) == 0

    # Add item to first order
    guest1.add_to_order(order_id1, listing_id, 1)
    assert guest1.errors == 0

    # Commit first order
    guest1.commit_items(order_id1)
    assert guest1.errors == 0

    # Second guest tries to order the same item that's now out of stock
    order_id2 = guest2.create_order()
    assert guest2.errors == 0
    order2 = guest2.shop.orders.get(order_id2)
    assert order2 is not None
    assert len(order2.items) == 0

    # Add item to second order
    guest2.add_to_order(order_id2, listing_id, 1)
    assert guest2.errors == 0

    # Try to commit second order - should fail due to inventory
    guest2.expect_error = True
    guest2.commit_items(order_id2)
    assert guest2.errors == 1
    assert guest2.last_error is not None
    assert guest2.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK

    # Reset error state
    guest2.expect_error = False
    guest2.errors = 0
    guest2.last_error = None

    # Should be able to remove the item from the second order
    guest2.remove_from_order(order_id2, listing_id, 1)
    assert guest2.errors == 0


def test_orders_item_locking_with_removal(
    make_two_clients: Tuple[RelayClient, RelayClient],
):
    alice, bob = make_two_clients

    # Create two different listings
    caps_id = alice.create_listing("caps", 1)
    shirts_id = alice.create_listing("shirts", 2)
    alice.change_inventory(caps_id, 3)
    alice.change_inventory(shirts_id, 5)

    print("Alice creating order with caps and shirts")
    order_id1 = alice.create_order()
    assert alice.errors == 0
    order1 = alice.shop.orders.get(order_id1)
    assert order1 is not None
    assert len(order1.items) == 0

    print(f"Alice adding 2 caps and 1 shirt to order {order_id1}")
    alice.add_to_order(order_id1, caps_id, 2)
    assert alice.errors == 0
    alice.add_to_order(order_id1, shirts_id, 1)
    assert alice.errors == 0

    print("Bob creating order for caps only")
    order_id2 = bob.create_order()
    assert bob.errors == 0
    order2 = bob.shop.orders.get(order_id2)
    assert order2 is not None
    assert len(order2.items) == 0

    print(f"Bob adding 2 caps to order {order_id2}")
    bob.add_to_order(order_id2, caps_id, 2)
    assert bob.errors == 0

    print("Syncing state between clients")
    alice.handle_all()
    bob.handle_all()
    assert len(order1.items) == 2  # caps and shirts
    assert len(order2.items) == 1  # caps only

    print("Bob committing his order first")
    bob.commit_items(order_id2)
    assert bob.errors == 0

    print(
        "Alice trying to commit her order (should fail due to insufficient caps inventory)"
    )
    alice.expect_error = True
    alice.commit_items(order_id1)
    assert alice.errors == 1
    assert alice.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK
    assert alice.last_error.additional_info.object_id == caps_id
    print(f"Got expected error: {alice.last_error.message}")

    # reset error state
    print("Resetting Alice's error state")
    alice.expect_error = False
    alice.errors = 0
    alice.last_error = None

    print("Alice removing caps from her order but keeping the shirts")
    alice.remove_from_order(order_id1, caps_id, 2)
    assert alice.errors == 0

    # Alice now commits her order
    print("Alice committing her order")
    alice.commit_items(order_id1)
    assert alice.errors == 0

    print("Both syncing state")
    alice.handle_all()
    bob.handle_all()
    assert alice.errors == 0
    assert bob.errors == 0

    # Verify order contents after all operations
    alice_order = alice.shop.orders.get(order_id1)
    assert alice_order is not None
    assert len(alice_order.items) == 1  # only shirts now
    assert alice_order.items[0].listing_id == shirts_id

    bob_order = bob.shop.orders.get(order_id2)
    assert bob_order is not None
    assert len(bob_order.items) == 1  # caps
    assert bob_order.items[0].listing_id == caps_id
