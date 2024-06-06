import time
import os
from pprint import pprint

from sha3 import keccak_256
from massmarket_hash_event import schema_pb2


def now():
    return time.time()

def since(start):
    return now() - start

# this is some helper code to create a bunch of unpayed carts for a relay refactor
def test_carts_unpayed(make_client):
    alice = make_client("alice")
    store_id = alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.create_store_manifest()
    assert alice.errors == 0

    iid = alice.create_item('sneakers', 10)
    alice.change_stock([(iid, 20)])
    assert alice.errors == 0

    for i in range(10):
        cid = alice.create_cart()
        alice.add_to_cart(cid, iid, 1)
        alice.commit_cart(cid)
        assert alice.errors == 0
        print(f'finalized eth cart {cid}')

    # register our erc20 token with the store
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    alice.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20, addr_value=erc20_addr)
    assert alice.errors == 0

    for i in range(10):
        cid = alice.create_cart()
        alice.add_to_cart(cid, iid, 1)
        alice.commit_cart(cid, erc20_addr)
        assert alice.errors == 0
        print(f'finalized erc20 cart {cid}')

def test_carts_invalid(make_two_clients, make_client):
    a1, a2 = make_two_clients

    # a1 writes an a few items
    iid1 = a1.create_item('sneakers', 1000)
    iid2 = a1.create_item('caps', 1000)
    a1.change_stock([(iid1, 3), (iid2, 5)])
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 starts a cart
    cid = a2.create_cart()
    assert a2.errors == 0
    assert cid in a2.carts
    a1.handle_all()
    assert a1.errors == 0
    assert cid in a1.carts

    # a2 tries to add non-existant item to cart
    a2.excpect_error = True
    a2.add_to_cart(cid, os.urandom(32), 1)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to use non-existant cart
    a2.excpect_error = True
    a2.add_to_cart(os.urandom(32), iid1, 1)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # add more items then in stock
    a2.excpect_error = True
    a2.add_to_cart(cid, iid1, 4)
    assert a2.errors == 1
    assert a2.last_error.code == "invalid"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # remove more items then in cart
    a2.excpect_error = True
    a2.remove_from_cart(cid, iid1, 2)
    assert a2.errors == 1
    assert a2.last_error.code == "invalid"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # create a 2nd store
    bob = make_client("bob")
    bob.register_store()
    bob.enroll_key_card()
    bob.login()
    bob.create_store_manifest()
    foreignItemId = bob.create_item('flute', 1000)
    assert bob.errors == 0

    # a2 tries to add item from other store to cart
    a2.errors = 0
    a2.excpect_error = True
    a2.add_to_cart(cid, foreignItemId, 1)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # cant commit empty carts
    cart = a1.carts[cid]
    assert len(cart.items) == 0
    a1.excpect_error = True
    a1.commit_cart(cid)
    assert a1.errors == 1
    assert a1.last_error.code == "invalid"

    # reset error state
    a1.excpect_error = False
    a1.errors = 0
    a1.last_error = None

    # a1 finalizes the cart and then tries to change it
    a1.handle_all()
    assert a1.errors == 0
    a1.add_to_cart(cid, iid1, 1)
    assert a1.errors == 0
    a1.commit_cart(cid)
    assert a1.errors == 0
    a1.excpect_error = True
    a1.add_to_cart(cid, iid1, 1)
    assert a1.errors == 1
    assert a1.last_error.code == "invalid"

def prepare_cart(client):
    # a1 writes an a few events
    iid1 = client.create_item('sneakers', 10)
    iid2 = client.create_item('caps', 5)
    client.change_stock([(iid1, 3), (iid2, 5)])
    assert client.errors == 0

    cid = client.create_cart()
    assert client.errors == 0
    assert cid in client.carts
    assert len(client.carts[cid].items) == 0

    client.add_to_cart(cid, iid1, 1)
    assert client.errors == 0

    client.add_to_cart(cid, iid2, 2)
    assert client.errors == 0

    cart = client.carts[cid]
    assert len(cart.items) == 2
    assert cart.items[iid1] == 1
    assert cart.items[iid2] == 2

    return cid, iid2, iid2

def test_carts_happy_eth_byCall(make_client):
    alice = make_client("alice")
    store_id = alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.create_store_manifest()
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_cart(alice)

    alice.commit_cart(cid)
    assert alice.errors == 0
    cart = alice.carts[cid]
    assert cart.finalized == True
    total = cart.total_in_crypto
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == alice.w3.to_wei(42, 'ether')

    # pay the cart (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    beforePayed = alice.w3.eth.get_balance(alice.account.address)

    order_hash = keccak_256()
    order_hash.update(cid)
    pr = {
        "ttl": cart.payment_ttl,
        "order": order_hash.digest(),
        "currency": "0x" + "00"*20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.store_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == cart.payment_id

    tx = alice.payments.functions.pay(pr).transact({'value': total})
    alice.check_tx(tx)

    took = since(start_send)
    print("sending tx={} took {}".format(tx.hex(), took))

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.carts[cid].payed:
            break
        print("waiting for payment to be processed...")
        time.sleep(5)

    cart = alice.carts[cid]
    assert cart.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    assert afterPayed <= beforePayed

def test_carts_happy_eth_byAddress(make_client):
    alice = make_client("alice")
    store_id = alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.create_store_manifest()
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_cart(alice)

    alice.commit_cart(cid)
    assert alice.errors == 0
    cart = alice.carts[cid]
    assert cart.finalized == True
    total = cart.total_in_crypto
    # testing ether is 2:1 => (20 in fiat + 5% fee => 21) * 2 => 42
    assert total == alice.w3.to_wei(42, 'ether')

    # check we got the same payment
    order_hash = keccak_256()
    order_hash.update(cid)

    pr = {
        "ttl": cart.payment_ttl,
        "order": order_hash.digest(),
        "currency": "0x" + "00"*20,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.store_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == cart.payment_id

    # pay the cart (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    start_send = now()
    purchase_address = alice.w3.to_checksum_address(alice.w3.to_hex(cart.purchase_address))
    print("sending tx to {}".format(purchase_address))
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

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.carts[cid].payed:
            break
        print("waiting for payment to be processed...")
        time.sleep(5)

    cart = alice.carts[cid]
    assert cart.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.w3.eth.get_balance(alice.account.address)

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    afterSweep = alice.w3.eth.get_balance(alice.account.address)
    assert afterPayed < afterSweep

def test_carts_happy_erc20_byAddress(make_client):
    alice = make_client("alice")
    alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.create_store_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(alice.account.address, 50000000000000000000).transact()
    alice.check_tx(tx)

    # register our erc20 token with the store
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    alice.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20, addr_value=erc20_addr)
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_cart(alice)

    alice.commit_cart(cid, erc20_addr=erc20_addr)
    assert alice.errors == 0
    cart = alice.carts[cid]
    assert cart.finalized == True
    total = cart.total_in_crypto
    assert total == 2100

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # pay the cart (usually this wouldnt be done by the clerk itself but let's not mess with another user now)
    purchase_address = alice.w3.to_checksum_address(alice.w3.to_hex(cart.purchase_address))

    # transfer erc20 tokens to the store
    start_send = now()
    tx_hash = alice.erc20Token.functions.transfer(purchase_address, total).transact()
    alice.check_tx(tx_hash)
    took = since(start_send)
    print("sending tx={} took {}".format(tx_hash.hex(), took))

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.carts[cid].payed:
            break
        print("waiting for erc20 payment to be processed...")
        time.sleep(5)

    cart = alice.carts[cid]
    assert cart.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed < beforePayed

    # check we can do the sweep
    order_hash = keccak_256()
    order_hash.update(cid)

    pr = {
        "ttl": cart.payment_ttl,
        "order": order_hash.digest(),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.store_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == cart.payment_id

    tx = alice.payments.functions.processPayment(pr, alice.account.address).transact()
    alice.check_tx(tx)
    print(f"processed payment tx: {tx.hex()}")

    afterSweep = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed <= afterSweep

def test_carts_happy_erc20_byCall(make_client):
    alice = make_client("alice")
    alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.create_store_manifest()
    assert alice.errors == 0

    # create some erc20 tokens for alice
    tx = alice.erc20Token.functions.mint(alice.account.address, 50000000000000000000).transact()
    alice.check_tx(tx)

    # register our erc20 token with the store
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    alice.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20, addr_value=erc20_addr)
    assert alice.errors == 0

    cid, iid1, iid2 = prepare_cart(alice)

    alice.commit_cart(cid, erc20_addr=erc20_addr)
    assert alice.errors == 0
    cart = alice.carts[cid]
    assert cart.finalized == True
    total = cart.total_in_crypto
    assert total == 2100

    beforePayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()

    # pay the cart
    tx = alice.erc20Token.functions.approve(alice.payments.address, total).transact()
    alice.check_tx(tx)

    order_hash = keccak_256()
    order_hash.update(cid)
    pr = {
        "ttl": cart.payment_ttl,
        "order": order_hash.digest(),
        "currency": alice.erc20Token.address,
        "amount": total,
        "payeeAddress": alice.account.address,
        "chainId": 31337,
        "isPaymentEndpoint": False,
        "shopId": alice.store_token_id,
        "shopSignature": "0x" + "00"*64
    }
    pprint(pr)

    gotPaymentId = alice.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId == cart.payment_id

    tx =  alice.payments.functions.pay(pr).transact()
    alice.check_tx(tx)

    # wait for payment to be processed
    for _ in range(15):
        alice.handle_all()
        assert alice.errors == 0
        if alice.carts[cid].payed:
            break
        print("waiting for erc20 payment to be noticed by the relay...")
        time.sleep(5)


    cart = alice.carts[cid]
    assert cart.payed == True
    assert alice.stock[iid1] == 3
    assert alice.stock[iid2] == 3

    afterPayed = alice.erc20Token.functions.balanceOf(alice.account.address).call()
    assert afterPayed == beforePayed

def test_carts_last_item(make_two_clients):
    alice, bob = make_two_clients

    # we only have three caps in stock, let's create two carts with 2 each
    caps_id = alice.create_item('caps', 1)
    alice.change_stock([(caps_id, 3)])
    assert alice.errors == 0

    cart1 = alice.create_cart()
    assert alice.errors == 0
    assert cart1 in alice.carts
    assert len(alice.carts[cart1].items) == 0
    alice.add_to_cart(cart1, caps_id, 2)
    assert alice.errors == 0

    cart2 = bob.create_cart()
    assert bob.errors == 0
    assert cart2 in bob.carts
    assert len(bob.carts[cart2].items) == 0
    bob.add_to_cart(cart2, caps_id, 2)
    assert bob.errors == 0

    # see the others cart
    alice.handle_all()
    bob.handle_all()
    assert len(alice.carts[cart1].items) == 1
    assert len(alice.carts[cart2].items) == 1
    assert len(bob.carts[cart1].items) == 1
    assert len(bob.carts[cart2].items) == 1

    # commit the first cart
    alice.commit_cart(cart1)
    assert alice.errors == 0

    # commit the second cart and expect an error
    bob.excpect_error = True
    bob.commit_cart(cart2)
    assert bob.errors == 1
    assert bob.last_error.code == "outOfStock"

    # reset error state
    bob.expect_error = False
    bob.errors = 0
    bob.last_error = None

    # alice's customer vanished
    alice.abandon_cart(cart1)
    assert alice.errors == 0
    bob.handle_all()
    assert bob.errors == 0

    # now bob can commit his cart
    bob.commit_cart(cart2)
    assert bob.errors == 0
