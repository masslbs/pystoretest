import time
from pprint import pprint

from sha3 import keccak_256

from massmarket_hash_event import (
    base_types_pb2 as mtypes,
    shop_events_pb2 as mevents,
    error_pb2,
)

from client import RelayClient, new_object_id


def now():
    return time.time()


def since(start):
    return now() - start


def new_uint256(i):
    return mtypes.Uint256(raw=int(i).to_bytes(32, "big"))


def prepare_order(c: RelayClient):
    # a1 writes an a few events
    iid1 = c.create_listing("sneakers", 10)
    iid2 = c.create_listing("caps", 5)
    c.change_inventory(iid1, 3)
    c.change_inventory(iid2, 5)
    assert c.errors == 0

    oid = c.create_order()
    assert c.errors == 0
    assert oid.raw in c.orders
    assert len(c.orders[oid.raw].items) == 0

    c.add_to_order(oid, iid1, 1)
    assert c.errors == 0

    c.add_to_order(oid, iid2, 2)
    assert c.errors == 0

    order = c.orders[oid.raw]
    assert len(order.items) == 2
    assert order.items[iid1.raw] == 1
    assert order.items[iid2.raw] == 2

    return oid, iid1, iid2


def wait_for_finalization(c: RelayClient, order_id: mtypes.ObjectId):
    for _ in range(5):
        c.handle_all()
        order = c.orders[order_id.raw]
        assert order is not None
        if order.state == "unpayed":
            return order
        print(f"{c.name} waiting for order {order_id.raw} to be finalized")
        pprint(order.__dict__)
        time.sleep(2)
    raise Exception(f"order not finalized in time")


def wait_for_order_payed(
    c: RelayClient, oid: mtypes.ObjectId, items, ping=None, retry=15
):
    # wait for payment to be processed
    for _ in range(retry):
        c.handle_all()
        assert c.errors == 0
        if c.orders[oid.raw].state == "payed":
            break

        # TODO: the eth_byCall variant needs new blocks to be yielded.
        # we might also be to do this with an anvil argument but this works for now
        if ping:
            ping["nonce"] = c.w3.eth.get_transaction_count(c.account.address)
            tx_hash = c.w3.eth.send_transaction(ping)
            c.check_tx(tx_hash)

        print("waiting for payment to be noticed by the relay...")
        time.sleep(2)

    order = c.orders[oid.raw]
    # pprint(order.__dict__)
    assert order.state == "payed", f"{oid.raw} wasn't payed in time"
    # stock updated
    for id, want in items:
        assert c.check_inventory(id) == want


default_addr = mtypes.AddressDetails()
default_addr.name = "Max Mustermann"
default_addr.address1 = "Somestreet 1"
default_addr.city = "City"
default_addr.postal_code = "12345"
default_addr.country = "Isla de Muerta"
default_addr.phone_number = "+0155512345"
default_addr.email_address = "some1@no.where"

tax_code = mtypes.OrderPriceModifier(
    title="20% tax",
    percentage=new_uint256(120),
)

shipping = mtypes.OrderPriceModifier(
    title="default shipping - 5EDD",
    absolute=mtypes.PlusMinus(
        plus_sign=True,
        # TODO: parameter for decimals
        diff=new_uint256(500),
    ),
)

region_tax_and_ship = mtypes.ShippingRegion(
    name="tax-and-ship",
    country=default_addr.country,
    order_price_modifiers=[
        tax_code,
        shipping,
    ],
)


# this is some helper code to create a bunch of unpayed orders for a relay refactor
def test_orders_unpayed(make_client):
    alice = make_client("alice")
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
    erc20_ethaddr = mtypes.EthereumAddress(raw=erc20_addr)
    curr = mtypes.ShopCurrency(address=erc20_ethaddr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    for _ in range(3):
        oid = alice.create_order()
        alice.add_to_order(oid, iid, 1)
        alice.commit_items(oid)
        alice.update_address_for_order(oid, invoice=default_addr)
        alice.choose_payment(oid, curr)
        assert alice.errors == 0
        print(f"finalized erc20 order {oid}")


def test_orders_no_currency(make_client):
    alice = make_client("alice")
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
    commit = mevents.UpdateOrder(
        id=oid,
        choose_payment=mevents.UpdateOrder.ChoosePaymentMethod(
            payee=alice.default_payee
        ),
    )
    alice._write_event(update_order=commit)
    assert alice.errors == 1


def test_orders_no_matching_region(make_client):
    alice = make_client("alice")
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
    addr = default_addr.__deepcopy__()
    addr.country = "somewhere else"
    alice.update_address_for_order(oid, invoice=addr)
    assert alice.errors == 0

    alice.update_shop_manifest(remove_regions=["all"])

    alice.expect_error = True
    alice.choose_payment(oid)
    assert alice.errors == 1

    alice.expect_error = False
    alice.errors = 0

    # country mismatch
    alice.update_shop_manifest(add_regions=[region_tax_and_ship])
    assert alice.errors == 0

    alice.expect_error = True
    alice.choose_payment(oid)
    assert alice.errors == 1


def test_orders_shipping_costs(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    alice.update_shop_manifest(add_regions=[region_tax_and_ship])

    iid = alice.create_listing("sneakers", 10000)
    alice.change_inventory(iid, 5)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 3)
    assert alice.errors == 0

    alice.commit_items(oid)
    assert alice.errors == 0

    addr = default_addr.__deepcopy__()
    alice.update_address_for_order(oid, invoice=addr)
    assert alice.errors == 0

    alice.choose_payment(oid)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = order.total
    # TODO: decimals
    assert total == (300 * 1.2 + 5) * 100


def test_orders_shipping_address(make_client):
    alice = make_client("alice")
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

    addr = default_addr.__deepcopy__()
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

        invalid_addr = mtypes.AddressDetails()
        invalid_addr.CopyFrom(addr)
        setattr(invalid_addr, f, "")

        print(f"trying addr with field {f} set empty:")
        pprint(invalid_addr)

        alice.update_address_for_order(oid, invalid_addr)
        assert alice.errors == 1, f"failed on field {f}"
        assert alice.last_error is not None


def test_orders_invalid(make_two_clients, make_client):
    a1, a2 = make_two_clients

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
    assert oid.raw in a2.orders
    a1.handle_all()
    assert a1.errors == 0
    assert oid.raw in a1.orders

    # a2 tries to add non-existant listing to order
    a2.expect_error = True
    a2.add_to_order(oid, new_object_id(), 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to use non-existant order
    a2.expect_error = True
    a2.add_to_order(new_object_id(), iid1, 1)
    assert a2.errors == 1
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
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # cant commit empty orders
    order = a1.orders[oid.raw]
    assert len(order.items) == 0
    a1.update_address_for_order(oid, invoice=default_addr)
    assert a1.errors == 0
    a1.expect_error = True
    a1.commit_items(oid)
    assert a1.errors == 1
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
    total = order.total
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == 20

    # pay the order (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    beforePayed = alice.w3.eth.get_balance(alice.account.address)

    pr = {
        "ttl": order.payment_ttl,
        "order": bytes(32),
        "currency": "0x" + "00" * 20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    tx = alice.payments.functions.pay(pr).transact({"value": total})
    alice.check_tx(tx)

    took = since(start_send)
    print(f"sending tx={tx.hex()} took {took}")

    wait_for_order_payed(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    assert afterPayed <= beforePayed


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
    total = order.total
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == 20

    pr = {
        "ttl": order.payment_ttl,
        "order": bytes(32),
        "currency": "0x" + "00" * 20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    # check we got the same payment
    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

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

    wait_for_order_payed(alice, oid, [(iid1, 2), (iid2, 3)], ping=transaction)

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    # TODO: this is annoying....
    # the gas costs of processPayment outweig the income of the payment
    # afterSweep = alice.w3.eth.get_balance(alice.account.address)
    # assert afterPayed < afterSweep


def test_orders_happy_erc20_byAddress(make_client):
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
    erc20_addr_pb = mtypes.EthereumAddress(raw=erc20_addr)
    curr = mtypes.ShopCurrency(address=erc20_addr_pb, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = order.total
    assert total == 40

    # wait for next block so we dont pay before the the watcher is waiting
    # unless next-block time is less then a second this shouldnt be a problem in reality
    # ie. the client will not be able to pay before the relay has setup it's subscription for new events
    for _ in range(5):
        alice.handle_all()
        assert alice.errors == 0
        time.sleep(1)

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # construct PaymentRequest
    pr = {
        "ttl": order.payment_ttl,
        "order": bytes(32),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    purchase_address = alice.payments.functions.getPaymentAddress(
        pr, alice.account.address
    ).call()

    # transfer erc20 tokens to the shop
    start_send = now()
    tx_hash = alice.erc20Token.functions.transfer(purchase_address, total).transact()
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    wait_for_order_payed(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed < beforePayed

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    afterSweep = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed <= afterSweep


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
    erc20_addr_pb = mtypes.EthereumAddress(raw=erc20_addr)
    curr = mtypes.ShopCurrency(address=erc20_addr_pb, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    oid, iid1, iid2 = prepare_order(alice)

    alice.commit_items(oid)
    alice.update_address_for_order(oid, invoice=default_addr)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, oid)
    total = order.total
    assert total == 40

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # pay the order
    tx = alice.erc20Token.functions.approve(alice.payments.address, total).transact()
    alice.check_tx(tx)

    pr = {
        "ttl": order.payment_ttl,
        "order": bytes(32),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    tx = alice.payments.functions.pay(pr).transact()
    alice.check_tx(tx)

    wait_for_order_payed(alice, oid, [(iid1, 2), (iid2, 3)])

    afterPayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed == beforePayed


def test_orders_item_locking(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    caps_id = alice.create_listing("caps", 1)
    alice.change_inventory(caps_id, 3)
    assert alice.errors == 0

    order1 = alice.create_order()
    assert alice.errors == 0
    assert order1.raw in alice.orders
    assert len(alice.orders[order1.raw].items) == 0
    alice.add_to_order(order1, caps_id, 2)
    assert alice.errors == 0

    order2 = bob.create_order()
    assert bob.errors == 0
    assert order2.raw in bob.orders
    assert len(bob.orders[order2.raw].items) == 0
    bob.add_to_order(order2, caps_id, 2)
    assert bob.errors == 0

    # see the others order
    alice.handle_all()
    bob.handle_all()
    assert len(alice.orders[order1.raw].items) == 1
    assert len(alice.orders[order2.raw].items) == 1
    assert len(bob.orders[order1.raw].items) == 1
    assert len(bob.orders[order2.raw].items) == 1

    # commit the first order
    alice.commit_items(order1)
    assert alice.errors == 0

    # commit the second order and expect an error
    bob.expect_error = True
    bob.commit_items(order2)
    assert bob.errors == 1
    assert bob.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK

    # reset error state
    bob.expect_error = False
    bob.errors = 0
    bob.last_error = None

    # alice's customer vanished
    alice.abandon_order(order1)
    assert alice.errors == 0
    bob.handle_all()
    assert bob.errors == 0

    # now bob can commit his order
    bob.commit_items(order2)
    assert bob.errors == 0
    bob.update_address_for_order(order2, invoice=default_addr)
    assert bob.errors == 0
    bob.choose_payment(order2)
    assert bob.errors == 0


def test_orders_variations_simple(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    caps_id = alice.create_listing("caps", 1)
    red_id = new_object_id()
    color_option = mtypes.ListingOption(
        id=new_object_id(),
        title="color",
        variations=[
            mtypes.ListingVariation(
                id=red_id,
                variation_info=mtypes.ListingMetadata(
                    title="red",
                    description="red color",
                ),
                diff=mtypes.PlusMinus(
                    plus_sign=True,
                    diff=new_uint256(1),
                ),
            ),
        ],
    )
    alice.update_listing(caps_id, add_option=color_option)
    assert alice.errors == 0

    alice.change_inventory(caps_id, 3, [red_id])
    assert alice.errors == 0

    bob.handle_all()
    assert bob.errors == 0

    order1 = bob.create_order()

    # try_nonexistent
    bob.expect_error = True
    bob.add_to_order(order1, caps_id, 2, [new_object_id()])
    assert bob.errors == 1
    bob.errors = 0
    bob.add_to_order(order1, caps_id, 2, [red_id, new_object_id()])
    assert bob.errors == 1
    bob.errors = 0
    bob.expect_error = False

    # commit
    bob.add_to_order(order1, caps_id, 2, [red_id])
    assert bob.errors == 0
    bob.commit_items(order1)
    bob.update_address_for_order(order1, invoice=default_addr)
    bob.choose_payment(order1)
    assert bob.errors == 0

    # check price
    o = bob.orders[order1.raw]
    assert o is not None
    assert o.total == 4
    assert len(o.listing_hashes) == 1
    assert o.listing_hashes[0].cid[:2] == "Qm"


def test_orders_variations_cancel_on_remove(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in inventory, let's create two orders with 2 each
    caps_id = alice.create_listing("caps", 1)
    red_id = new_object_id()
    color_option = mtypes.ListingOption(
        id=new_object_id(),
        title="color",
        variations=[
            mtypes.ListingVariation(
                id=red_id,
                variation_info=mtypes.ListingMetadata(
                    title="red",
                    description="red color",
                ),
                diff=mtypes.PlusMinus(
                    plus_sign=True,
                    diff=new_uint256(1),
                ),
            ),
        ],
    )
    alice.update_listing(caps_id, add_option=color_option)
    assert alice.errors == 0

    alice.change_inventory(caps_id, 3, [red_id])
    assert alice.errors == 0

    bob.handle_all()
    assert bob.errors == 0

    order1 = bob.create_order()
    # commit and check price
    bob.add_to_order(order1, caps_id, 2, [red_id])
    assert bob.errors == 0

    bob.commit_items(order1)
    bob.update_address_for_order(order1, invoice=default_addr)
    bob.choose_payment(order1)
    assert bob.errors == 0

    # remove the variation => order should be canceled
    alice.update_listing(caps_id, remove_variation=red_id)
    assert alice.errors == 0
    bob.handle_all()
    assert bob.errors == 0

    o = bob.orders[order1.raw]
    assert o.state == "canceled"
