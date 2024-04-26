import time
import os
from pprint import pprint

from client import new_request_id
from sha3 import keccak_256
from massmarket_hash_event import shop_pb2, shop_events_pb2, shop_requests_pb2, error_pb2

def now():
    return time.time()

def since(start):
    return now() - start

# this is some helper code to create a bunch of unpayed orders for a relay refactor
def test_orders_unpayed(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_item('sneakers', 10)
    alice.change_stock([(iid, 20)])
    assert alice.errors == 0

    for i in range(3):
        cid = alice.create_order()
        alice.add_to_order(cid, iid, 1)
        alice.commit_order(cid)
        assert alice.errors == 0
        print(f'finalized eth order {cid}')

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    for i in range(3):
        cid = alice.create_order()
        alice.add_to_order(cid, iid, 1)
        alice.commit_order(cid, curr)
        assert alice.errors == 0
        print(f'finalized erc20 order {cid}')

def test_orders_no_currency(make_client):
    alice = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_item('sneakers', 10)
    alice.change_stock([(iid, 20)])
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0

    alice.expect_error = True

    # manually craft the checkout without a currency
    ccr = shop_requests_pb2.CommitItemsToOrderRequest(
        request_id=new_request_id(),
        order_id=oid,
        payee_name="default")
    data = b"\x20" + ccr.SerializeToString()
    alice.connection.send(data)

def test_orders_shipping(make_client):
    alice = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_item('sneakers', 10)
    alice.change_stock([(iid, 20)])
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0

    alice.commit_order(oid)
    assert alice.errors == 0

    addr = shop_events_pb2.UpdateOrder.AddressDetails(
        name = "test name",
        address1 = "Some Street 1",
        city = "City",
        postal_code = "1234",
        country = "Country",
        phone_number = "1234567"
    )
    alice.update_shipping_address_for_order(oid, addr)
    assert alice.errors == 0

    # try to leave out some fields
    alice.expect_error = True

    # address2 is optional
    fields = ["name", "address1", "city", "postal_code", "country", "phone_number"]
    for f in fields:
        # reset error state
        alice.errors = 0
        alice.last_error = None

        invalid_addr = shop_events_pb2.UpdateOrder.AddressDetails()
        invalid_addr.CopyFrom(addr)
        setattr(invalid_addr, f, "")

        print(f"trying addr with field {f} set empty:")
        pprint(invalid_addr)

        alice.update_shipping_address_for_order(oid, invalid_addr)
        assert alice.errors == 1, f"failed on field {f}"
        assert alice.last_error is not None

def test_orders_invalid(make_two_clients, make_client):
    a1, a2 = make_two_clients

    # a1 writes an a few items
    iid1 = a1.create_item('sneakers', 1000)
    iid2 = a1.create_item('caps', 1000)
    a1.change_stock([(iid1, 3), (iid2, 5)])
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 starts a order
    cid = a2.create_order()
    assert a2.errors == 0
    assert cid in a2.orders
    a1.handle_all()
    assert a1.errors == 0
    assert cid in a1.orders

    # a2 tries to add non-existant item to order
    a2.expect_error = True
    a2.add_to_order(cid, os.urandom(32), 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to use non-existant order
    a2.expect_error = True
    a2.add_to_order(os.urandom(32), iid1, 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # add more items then in stock
    a2.expect_error = True
    a2.add_to_order(cid, iid1, 4)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_INVALID

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # remove more items then in order
    a2.expect_error = True
    a2.remove_from_order(cid, iid1, 2)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_INVALID

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # create a 2nd shop
    bob = make_client("bob")
    bob.register_shop()
    bob.enroll_key_card()
    bob.login()
    bob.create_shop_manifest()
    foreignItemId = bob.create_item('flute', 1000)
    assert bob.errors == 0

    # a2 tries to add item from other shop to order
    a2.errors = 0
    a2.expect_error = True
    a2.add_to_order(cid, foreignItemId, 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # cant commit empty orders
    order = a1.orders[cid]
    assert len(order.items) == 0
    a1.expect_error = True
    a1.commit_order(cid)
    assert a1.errors == 1
    assert a1.last_error.code == error_pb2.ERROR_CODES_INVALID

    # reset error state
    a1.expect_error = False
    a1.errors = 0
    a1.last_error = None

    # a1 finalizes the order and then tries to change it
    a1.handle_all()
    assert a1.errors == 0
    a1.add_to_order(cid, iid1, 1)
    assert a1.errors == 0
    a1.commit_order(cid)
    assert a1.errors == 0
    a1.expect_error = True
    a1.add_to_order(cid, iid1, 1)
    assert a1.errors == 1
    assert a1.last_error.code == error_pb2.ERROR_CODES_INVALID

def prepare_order(client):
    # a1 writes an a few events
    iid1 = client.create_item('sneakers', 10)
    iid2 = client.create_item('caps', 5)
    client.change_stock([(iid1, 3), (iid2, 5)])
    assert client.errors == 0

    cid = client.create_order()
    assert client.errors == 0
    assert cid in client.orders
    assert len(client.orders[cid].items) == 0

    client.add_to_order(cid, iid1, 1)
    assert client.errors == 0

    client.add_to_order(cid, iid2, 2)
    assert client.errors == 0

    order = client.orders[cid]
    assert len(order.items) == 2
    assert order.items[iid1] == 1
    assert order.items[iid2] == 2

    return cid, iid2, iid2

def wait_for_finalization(client, order_id):
    for _ in range(5):
        client.handle_all()
        order = client.orders[order_id]
        assert order is not None
        if order.finalized:
            return order
        time.sleep(2)
    raise Exception(f"order not finalized in time")

def test_orders_happy_eth_byCall(make_client):
    alice = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_order(alice)

    alice.commit_order(cid)
    assert alice.errors == 0
    order = wait_for_finalization(alice, cid)
    total = order.total_in_crypto
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == alice.w3.to_wei(42, 'ether')

    # pay the order (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    beforePayed = alice.w3.eth.get_balance(alice.account.address)

    order_hash = keccak_256()
    order_hash.update(cid)
    pr = {
        "ttl": order.payment_ttl,
        "order": order_hash.digest(),
        "currency": "0x" + "00"*20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    tx = alice.payments.functions.pay(pr).transact({'value': total})
    alice.check_tx(tx)

    took = since(start_send)
    print(f"sending tx={tx.hex()} took {took}")

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.orders[cid].payed:
            break
        print("waiting for payment to be processed...")
        time.sleep(2)

    order = alice.orders[cid]
    assert order.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    assert afterPayed <= beforePayed

def test_orders_happy_eth_byAddress(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_order(alice)

    alice.commit_order(cid)
    assert alice.errors == 0
    order = wait_for_finalization(alice, cid)
    total = order.total_in_crypto
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == alice.w3.to_wei(42, 'ether')

    # check we got the same payment
    order_hash = keccak_256()
    order_hash.update(cid)

    pr = {
        "ttl": order.payment_ttl,
        "order": order_hash.digest(),
        "currency": "0x" + "00"*20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    # pay the order (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    purchase_address = alice.payments.functions.getPaymentAddress(pr, alice.account.address).call()
    print(f"sending tx to {purchase_address}")
    transaction = {
        'to': purchase_address,
        'value': total,
        'gas': 25000,
        'maxFeePerGas': alice.w3.to_wei(50, 'gwei'),
        'maxPriorityFeePerGas': alice.w3.to_wei(5, 'gwei'),
        'nonce': alice.w3.eth.get_transaction_count(alice.account.address),
        'chainId': alice.chain_id
    }
    tx_hash = alice.w3.eth.send_transaction(transaction)
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    # trigger new blocks so the watcher subscription is triggered again
    transaction["value"] = 1
    transaction["to"] = alice.account.address

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.orders[cid].payed:
            break

        transaction["nonce"] = alice.w3.eth.get_transaction_count(alice.account.address)
        tx_hash = alice.w3.eth.send_transaction(transaction)
        alice.check_tx(tx_hash)
        print("waiting for payment to be processed...")
        time.sleep(1)

    order = alice.orders[cid]
    assert order.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    afterSweep = alice.w3.eth.get_balance(alice.account.address)
    assert afterPayed < afterSweep

def test_orders_happy_erc20_byAddress(make_client):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(alice.account.address, 50000000000000000000).transact()
    alice.check_tx(tx)

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_order(alice)

    alice.commit_order(cid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, cid)
    total = order.total_in_crypto
    assert total == 2100

    # wait for next block so we dont pay before the the watcher is waiting
    # unless next-block time is less then a second this shouldnt be a problem in reality
    # ie. the client will not be able to pay before the relay has setup it's subscription for new events
    for _ in range(5):
        alice.handle_all()
        assert alice.errors == 0
        time.sleep(1)

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # construct PaymentRequest
    order_hash = keccak_256()
    order_hash.update(cid)

    pr = {
        "ttl": order.payment_ttl,
        "order": order_hash.digest(),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    purchase_address = alice.payments.functions.getPaymentAddress(pr, alice.account.address).call()

    # transfer erc20 tokens to the shop
    start_send = now()
    tx_hash = alice.erc20Token.functions.transfer(purchase_address, total).transact()
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.orders[cid].payed:
            break
        print("waiting for erc20 payment to be processed...")
        time.sleep(2)

    order = alice.orders[cid]
    assert order.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

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
    tx = alice.erc20Token.functions.mint(alice.account.address, 50000000000000000000).transact()
    alice.check_tx(tx)

    # register our erc20 token with the shop
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_order(alice)

    alice.commit_order(cid, currency=curr)
    assert alice.errors == 0
    order = wait_for_finalization(alice, cid)
    total = order.total_in_crypto
    assert total == 2100

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # pay the order
    tx = alice.erc20Token.functions.approve(alice.payments.address, total).transact()
    alice.check_tx(tx)

    order_hash = keccak_256()
    order_hash.update(cid)
    pr = {
        "ttl": order.payment_ttl,
        "order": order_hash.digest(),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.shop_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == order.payment_id

    tx =  alice.payments.functions.pay(pr).transact()
    alice.check_tx(tx)

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.orders[cid].payed:
            break
        print("waiting for erc20 payment to be noticed by the relay...")
        time.sleep(2)


    order = alice.orders[cid]
    assert order.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed == beforePayed

def test_orders_last_item(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in stock, let's create two orders with 2 each
    caps_id = alice.create_item('caps', 1)
    alice.change_stock([(caps_id, 3)])
    assert alice.errors == 0

    order1 = alice.create_order()
    assert alice.errors == 0
    assert order1 in alice.orders
    assert len(alice.orders[order1].items) == 0
    alice.add_to_order(order1, caps_id, 2)
    assert alice.errors == 0

    order2 = bob.create_order()
    assert bob.errors == 0
    assert order2 in bob.orders
    assert len(bob.orders[order2].items) == 0
    bob.add_to_order(order2, caps_id, 2)
    assert bob.errors == 0

    # see the others order
    alice.handle_all()
    bob.handle_all()
    assert len(alice.orders[order1].items) == 1
    assert len(alice.orders[order2].items) == 1
    assert len(bob.orders[order1].items) == 1
    assert len(bob.orders[order2].items) == 1

    # commit the first order
    alice.commit_order(order1)
    assert alice.errors == 0

    # commit the second order and expect an error
    bob.expect_error = True
    bob.commit_order(order2)
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
    bob.commit_order(order2)
    assert bob.errors == 0
