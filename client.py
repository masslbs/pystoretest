# stdlib
import requests
import json
import os
import base64
from urllib.parse import urlparse
from pprint import pprint
from time import sleep
import decimal

# pip
import google.protobuf.any_pb2 as anypb
from sha3 import keccak_256
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedError
from web3 import Web3, Account, HTTPProvider
from web3.middleware import construct_sign_and_send_raw_middleware
from web3.exceptions import TransactionNotFound
from eth_keys import keys
from eth_account.messages import encode_defunct, encode_typed_data

# our protobuf schema
from massmarket_hash_event import hash_event, error_pb2, transport_pb2, authentication_pb2, shop_pb2, shop_requests_pb2, shop_events_pb2

class RelayException(Exception):
    def __init__(self, err: error_pb2.Error):
        super().__init__(err.message)
        self.message = err.message
        self.code = err.code

def new_request_id():
    return os.urandom(16)

def new_event_id():
    return os.urandom(32)

class NamedTag():
    def __init__(self, name, items):
        self.name = name
        self.items = items

class PriceTotals():
    def __init__(self, subtotal, sales_tax, total):
        self.subtotal = subtotal
        self.sales_tax = sales_tax
        self.total = total

class Order():
    def __init__(self, id):
        self.id = id
        self.items = {}
        self.finalized = False
        self.purchase_address = None
        self.totals = None
        self.payed = False
        self.payment_id = None
        self.payment_ttl = None

eip712spec = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

class RelayClient():

    def __init__(self,
                 name="Alice",
                 wallet_private_key=None,
                 key_card_private_key=None,
                 guest=False,
                 relay_token_id=None,
                 chain_id=None):
        self.name = name

        self.relay_http_address = os.getenv("RELAY_HTTP_ADDRESS")
        assert self.relay_http_address is not None, "RELAY_HTTP_ADDRESS is not set"
        print(f"{name} is using relay: {self.relay_http_address}")
        relay_addr = urlparse(self.relay_http_address)

        self.relay_ping = float(os.getenv("RELAY_PING"))

        # construct and dial websocket endpoint
        relay_ws_endpoint = relay_addr._replace(path="/v2/sessions")
        if relay_addr.scheme == "http":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="ws")
        elif relay_addr.scheme == "https":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="wss")
        else:
            raise Exception("Unknown Relay HTTP scheme: {}".format(relay_addr.scheme))

        # connection setup
        self.relay_ws_endpoint_url = relay_ws_endpoint.geturl()
        self.connection = connect(self.relay_ws_endpoint_url, origin="localhost", close_timeout=0.5)
        self.connected = True
        print(f"{name} has ws endpoint: {self.relay_ws_endpoint_url}")
        self.logged_in = False
        self.pongs = 0
        self.outgoingRequests = {}
        self.errors = 0
        self.expect_error = False

        if relay_token_id == None:
            # request testing info from relay
            discovery_resp = requests.get(self.relay_http_address + "/testing/discovery", headers={'Origin': 'localhost'})
            if discovery_resp.status_code != 200:
                raise Exception(f"Discovery request failed with status code: {discovery_resp.status_code}")
            discovery_data = discovery_resp.json()

            # relay nft token id
            relay_token_str = discovery_data["relay_token_id"][2:]
            print(f"discovered relay_token_id: {relay_token_str}")
            relay_token_hex = bytes.fromhex(relay_token_str)
            self.relay_token_id = int.from_bytes(relay_token_hex, "big")
            self.chain_id = discovery_data["chain_id"]
        else:
            self.relay_token_id = relay_token_id
            assert chain_id is not None, "need to set both relay_token_id and chain_id"
            self.chain_id = chain_id


        # etherum setup
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_URL")))
        self.__load_contracts()
        if wallet_private_key is None:
            wallet_private_key = bytes.fromhex(os.getenv("ETH_PRIVATE_KEY"))
        account = Account.from_key(wallet_private_key)
        print("{} is using address: {}".format(name, account.address))
        self.account = account
        self.w3.eth.default_account = account.address
        sign_mw = construct_sign_and_send_raw_middleware(self.account)
        self.w3.middleware_onion.add(sign_mw)

        # mass state
        self.isGuest = guest
        if key_card_private_key is None:
            self.own_key_card = Account.create()
            print(f"new key card: {self.own_key_card}")
        else:
            Account.from_key(key_card_private_key)
        self.valid_addrs = []
        self.all_key_cards = {}
        self.shop_token_id = None
        self.manifest = None
        vanilla_eth = shop_pb2.ShopCurrency(token_addr=bytes(20), chain_id=self.chain_id)
        self.default_currency = vanilla_eth
        self.default_payee = shop_events_pb2.UpdateShopManifest.Payee(
            name="default",
            addr=bytes.fromhex(self.account.address[2:]),
            chain_id=self.chain_id)
        self.items = {}
        self.stock = {}
        self.tags = {}
        self.orders = {}
        self.currencies = []
        self.payees = {}
        self.base_currency = None

    def print_state(self):
        print("Shop State:")
        print("-----------")

        print("Currencies:")
        if len(self.currencies) == 0:
            print("  No currencies set up")
        else:
            for curr in self.currencies:
                print(f" ChainID: {curr.chain_id} Addr: {curr.token_addr.hex()}")

        if self.base_currency is None:
            print(" No base currency!")
        else:
            b = self.base_currency
            print(f"Base Currency:\n  ChainID: {b.chain_id} Addr: {b.token_addr.hex()}")

        if len(self.payees) == 0:
            print("  No Payees set up ")
        else:
            print("Payees:")
            for name, p in self.payees.items():
                print(f"  {name}: ChainID: {p.chain_id} Addr: {p.addr} (isEndpoint: {p.call_as_contract})")

        print("\nItems:")
        if not self.items:
            print("  No items available.")
        else:
            for item_id, item in self.items.items():
                print(f"  Item ID: {to_32byte_hex(item_id)}")
                print(f"    Price: {item.price}")
                print(f"    Metadata: {item.metadata}")
                if item_id in self.stock:
                    print(f"    Stock: {self.stock[item_id]}")
                else:
                    print("    Stock: Not available")

        print("\nOrders:")
        if not self.orders:
            print("  No orders available.")
        else:
            for order_id, order in self.orders.items():
                if order is None:
                    print(f"  Order ID: {to_32byte_hex(order_id)} (Canceled)")
                    continue
                print(f"  Order ID: {to_32byte_hex(order_id)}")
                print(f"    Payed: {order.payed}")
                print(f"    Finalized: {order.finalized}")
                if order.finalized:
                    print(f"    Totals:")
                    print(f"      Sub Total: {order.totals.subtotal}")
                    print(f"      Sales Tax: {order.totals.sales_tax}")
                    print(f"      Total: {order.totals.total}")
                    print(f"      Total in Crypto: {order.total_in_crypto}")
                    print(f"      Payment ID: {order.payment_id}")
                    print(f"      Payment TTL: {order.payment_ttl}")
                    print(f"    Items:")
                    for item_id, quantity in order.items.items():
                        print(f"      Item ID: {to_32byte_hex(item_id)} Quantity: {quantity}")

        print("\nTags:")
        if not self.tags:
            print("  No tags available.")
        else:
            for tag_id, tag in self.tags.items():
                print(f"  Tag ID: {to_32byte_hex(tag_id)}")
                print(f"    Name: {tag.name}")
                for item_id in tag.items:
                    print(f"    Item ID: {to_32byte_hex(item_id)}")

        # Print key cards
        print("\nKey Cards:")
        if not self.all_key_cards:
            print("  No key cards available.")
        else:
            for card_public_key, user_wallet_addr in self.all_key_cards.items():
                print(f"  Key Card: 0x{card_public_key.hex()}")
                print(f"    User Wallet Address: {user_wallet_addr}")

    def __load_contracts(self):
        addresses = json.loads(open(os.getenv("MASS_CONTRACTS")+"/deploymentAddresses.json", "r").read())
        print("using contracts:")
        pprint(addresses)

        relayRegABI = open(os.getenv("MASS_CONTRACTS")+"/abi/RelayReg.json", "r").read()
        self.relayReg = self.w3.eth.contract(address=addresses["RelayReg"], abi=relayRegABI)

        shopRegABI = open(os.getenv("MASS_CONTRACTS")+"/abi/ShopReg.json", "r").read()
        self.shopReg = self.w3.eth.contract(address=addresses["ShopReg"], abi=shopRegABI)

        erc20TestingTokenABI = open(os.getenv("MASS_CONTRACTS")+"/abi/Eddies.json", "r").read()
        self.erc20Token = self.w3.eth.contract(address=addresses["Eddies"], abi=erc20TestingTokenABI)

        paymentsABI = open(os.getenv("MASS_CONTRACTS")+"/abi/PaymentsByAddress.json", "r").read()
        self.payments =  self.w3.eth.contract(address=addresses["Payments"], abi=paymentsABI)

    def check_tx(self, tx):
        self.__check_transaction(tx)

    def __check_transaction(self, tx):
        status = None
        tries = 10
        while status is None:
            assert tries != 0, "Transaction not found"
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx)
                status = receipt["status"]
            except TransactionNotFound:
                print(f"ckeck_tx: retrying to find {tx.hex()}..")
                sleep(0.5)
                tries -= 1
                continue
        assert status == 1

    def register_shop(self):
        token_id = int.from_bytes(os.urandom(32), "big")
        tx = self.shopReg.functions.mint(token_id, self.account.address).transact()
        self.__check_transaction(tx)
        self.shop_token_id = token_id
        print("shopTokenID: {}".format(self.shop_token_id))
        # check admin access
        tx = self.shopReg.functions.updateRootHash(self.shop_token_id, os.urandom(32), 1).transact()
        self.__check_transaction(tx)
        self.add_relay_to_shop(self.relay_token_id)
        return token_id

    def add_relay_to_shop(self, relay_token):
        # get current relays and add them
        if self.shopReg.functions.getRelayCount(self.shop_token_id).call() > 0:
            current_relay_tokens = self.shopReg.functions.getAllRelays(self.shop_token_id).call()
            if relay_token in current_relay_tokens:
                return
        # update the relays assigned to this shop
        tx = self.shopReg.functions.addRelay(self.shop_token_id, relay_token).transact()
        self.__check_transaction(tx)

    def create_invite(self):
        reg_secret = os.urandom(32)
        acc = Account.from_key(reg_secret)
        print("addr of token: {}".format(acc.address))
        tx = self.shopReg.functions.publishInviteVerifier(self.shop_token_id, acc.address).transact()
        self.__check_transaction(tx)
        return reg_secret

    def redeem_invite(self, token):
        acc = Account.from_key(token)
        msg_text = "enrolling:{}".format(self.account.address)
        msg = encode_defunct(text=msg_text.lower())
        sig = acc.sign_message(msg)
        rhex = to_32byte_hex(sig.r)
        shex = to_32byte_hex(sig.s)
        tx = self.shopReg.functions.redeemInvite(self.shop_token_id,
                                                  sig.v, rhex, shex,
                                                  self.account.address).transact()
        self.__check_transaction(tx)

    def enroll_key_card(self):
        keyCardPK = keys.PrivateKey(self.own_key_card.key)
        typed_data = {
            "types": {
                "EIP712Domain": eip712spec,
                "Enrollment": [
                    {"name": "keyCard", "type": "string"},
                ],
            },
            "primaryType": "Enrollment",
            "domain": {
                "name": "MassMarket",
                "version": "1",
                "chainId": 0,
                "verifyingContract": "0x0000000000000000000000000000000000000000",
            },
            "message": {
                "keyCard": keyCardPK.public_key.to_hex()[2:],
            }
        }
        encoded_data = encode_typed_data(full_message=typed_data)
        signed_message = self.account.sign_message(encoded_data)
        signature = signed_message.signature

        json_data = json.dumps({
            "key_card": base64.b64encode(keyCardPK.public_key.to_bytes()).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "shop_token_id": base64.b64encode(self.shop_token_id.to_bytes(32, 'big')).decode('utf-8'),
        })

        # change path to register shop
        modified_url = urlparse(self.relay_http_address)._replace(path="/v2/enroll_key_card")
        if self.isGuest:
            modified_url = modified_url._replace(query="guest=1")
        enroll_url = modified_url.geturl()

        response = requests.post(enroll_url, data=json_data, headers={'Origin': 'localhost'})
        if response.status_code != 201:
            raise Exception(f"unexpected response http code: {response.status_code}")
        respData = response.json()
        if "error" in respData:
            raise Exception(respData["error"])
        assert respData["success"] == True
        print(f"{self.name} enrolled keyCard {keyCardPK.public_key.to_hex()}")
        self.all_key_cards[keyCardPK.public_key.to_bytes()] = self.account.address

    def close(self):
        self.connection.close()
        self.connected = False
        self.logged_in = False

    def _try_read(self):
        data = None
        try:
            data = self.connection.recv(timeout=self.relay_ping)
        except TimeoutError:
            pass
        except ConnectionClosedError as err:
            self.connected = False
            raise err
        return data

    def handle_all(self):
        try:
            data = self._try_read()
            while data is not None:
                self.handle(data)
                data = self._try_read()
        except Exception as err:
            self.connected = False
            raise err

    def handle(self, data):
        type, msg = _decode_message(data)
        print(f'{self.name} received messageType={type}')
        if type == 0x01:
            self.handle_ping_request(msg)
        elif type == 0x04:
            self.handle_event_write_response(msg)
        elif type == 0x05:
            self.handle_sync_status_request(msg)
        elif type == 0x07:
            self.handle_event_push_request(msg)
        elif type == 0x15:
            self.handle_authenticate_response(msg)
        elif type == 0x17:
            self.handle_challenge_solved_response(msg)
        elif type == 0x1f:
            self.handle_get_blob_upload_url_response(msg)
        elif type == 0x21:
            self.handle_commit_order_response(msg)
        else:
            err = f"Unknown message type: {type}"
            self.errors += 1
            self.last_error = error_pb2.Error(code="internal", message=err)
            if self.expect_error:
                print(f"Expected error: {msg}")
            else:
                raise Exception(err)

    def handle_ping_request(self, req: transport_pb2.PingRequest):
        resp = transport_pb2.PingResponse(request_id=req.request_id)
        data = b"\x02" + resp.SerializeToString()
        try:
            self.connection.send(data)
        except ConnectionClosedError as err:
            self.connected = False
            print(f"{self.name} failed to respond to ping")
        else:
            print(f"{self.name} sent a pong to request_id {req.request_id.hex()}")
            self.pongs += 1

    def handle_sync_status_request(self, req: transport_pb2.SyncStatusRequest):
        print("SyncStatusRequest: unpushedEvents={}".format(req.unpushed_events))
        resp = transport_pb2.SyncStatusResponse(request_id=req.request_id)
        data = b"\x06" + resp.SerializeToString()
        self.connection.send(data)

    def _check_expected_request(self, req_id, clean=False):
        if not req_id in self.outgoingRequests:
            raise Exception("Received reponse for unknown request. id={}".format(req_id))
        if clean:
            del self.outgoingRequests[req_id]

    def handle_authenticate_response(self, resp: authentication_pb2.AuthenticateResponse):
        if resp.HasField("error"):
            raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=True)
        encoded_data = encode_defunct(resp.challenge)
        signed_message = self.own_key_card.sign_message(encoded_data)
        signature = signed_message.signature
        req_id = new_request_id()
        csr = authentication_pb2.ChallengeSolvedRequest(request_id=req_id, signature=signature)
        data = b"\x16" + csr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {}

    def handle_challenge_solved_response(self, resp: authentication_pb2.ChallengeSolvedResponse):
        if resp.HasField("error"):
            raise Exception("Challenge failed: '{}'".format(resp.error))
        self._check_expected_request(resp.request_id, clean=True)
        self.logged_in = True

    def handle_get_blob_upload_url_response(self, resp: shop_requests_pb2.GetBlobUploadURLResponse):
        if resp.HasField("error"):
            raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=False)
        print("blobUrl: id={} url={}".format(resp.request_id, resp.url))
        if resp.request_id not in self.outgoingRequests:
            raise Exception("Unexpected response: {}".format(resp.request_id))
        self.outgoingRequests[resp.request_id] = { "url": resp.url }

    def handle_event_write_response(self, resp: transport_pb2.EventWriteResponse):
        print("EventWriteResponse: {}".format(resp))
        self._check_expected_request(resp.request_id, clean=True)
        if resp.HasField("error"):
            self.errors += 1
            if self.expect_error:
                print("Expected error: {}".format(resp.error))
                self.last_error = resp.error
                self.outgoingRequests[resp.request_id] = { 'err': resp.error }
            else:
                raise RelayException(resp.error)
        else:
            assert resp.event_sequence_no > 0, "event_sequence_no is 0"
            self.outgoingRequests[resp.request_id] = { 'new_shop_hash': resp.new_shop_hash }

    def handle_event_push_request(self, req: transport_pb2.EventPushRequest):
        print(f"{self.name} EventPushRequest reqID=0x{req.request_id.hex()} events={len(req.events)}")
        err = None
        for sig_evt in req.events:
            evt = shop_events_pb2.ShopEvent()
            #print(f"typeName: {sig_evt.event.TypeName()}")
            assert sig_evt.event.TypeName() == "market.mass.ShopEvent"
            sig_evt.event.Unpack(evt)
            # print(f"Event: {evt}")
            self._verify_event(sig_evt)
            which = evt.WhichOneof("union")
            if which == "shop_manifest":
                self.manifest = evt.shop_manifest
            elif which == "update_shop_manifest":
                um = evt.update_shop_manifest
                if um.HasField("domain"):
                    self.manifest.domain = um.domain
                if um.HasField("published_tag_id"):
                    self.manifest.published_tag_id = um.published_tag_id
                for add in um.add_accepted_currencies:
                    self.currencies.append(add)
                for rm in um.remove_accepted_currencies:
                    self.currencies.remove(rm)
                if um.HasField("add_payee"):
                    p = um.add_payee
                    self.payees[p.name] = p
                if um.HasField("set_base_currency"):
                    self.base_currency = um.set_base_currency
            elif which == "create_item":
                ci = evt.create_item
                self.items[ci.event_id] = ci
                #self.stock[ci.event_id] = 0
            elif which == "update_item":
                ui = evt.update_item
                if ui.item_id not in self.items:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown item: {ui.item_id}")
                else:
                    item = self.items[ui.item_id]
                    if ui.HasField("metadata"):
                        item.metadata = ui.metadata
                    if ui.HasField("price"):
                        dec_price = decimal.Decimal(ui.price)
                        item.price = format(dec_price, '.2f').encode('utf-8')
                    self.items[ui.item_id] = item
            elif which == "create_tag":
                ct = evt.create_tag
                if ct.event_id in self.tags:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_INVALID, message=f"tag already exists: {ct.event_id}")
                else:
                    self.tags[ct.event_id] = NamedTag(ct.name, [])
            elif which == "update_tag":
                ut = evt.update_tag
                if ut.tag_id not in self.tags:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown tag: {ut.tag_id}")
                else:
                    if ut.HasField("add_item_id"):
                        if ut.add_item_id not in self.items:
                            err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown item: {ut.add_item_id}")
                        else:
                            self.tags[ut.tag_id].items.append(ut.add_item_id)
                    if ut.HasField("remove_item_id"):
                        if ut.remove_item_id not in self.items:
                            err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown item: {ut.remove_item_id}")
                        else:
                            self.tags[ut.tag_id].items.remove(ut.remove_item_id)
                    if ut.HasField("rename"):
                        self.tags[ut.tag_id].name = ut.rename
                    if ut.HasField("delete"):
                        del self.tags[ut.tag_id]
            elif which == "change_stock":
                cs = evt.change_stock
                changes = list(zip(cs.item_ids, cs.diffs))
                for diff in changes:
                    if diff[0] not in self.items:
                        err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown item: {diff[0]}")
                    else:
                        self.stock[diff[0]] = self.stock.get(diff[0], 0) + diff[1]
                if len(cs.order_id) > 0:
                    if cs.order_id not in self.orders:
                        err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown order: {cs.order_id}")
                    else:
                        self.orders[cs.order_id].payed = True
            elif which == "create_order":
                cc = evt.create_order
                if cc.event_id in self.orders:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_INVALID, message=f"order already exists: {cc.event_id}")
                else:
                    self.orders[cc.event_id] = Order(cc.event_id)
            elif which == "update_order":
                uo = evt.update_order
                oid = uo.order_id
                if oid not in self.orders:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown order: {oid}")
                order = self.orders[oid]
                action = uo.WhichOneof("action")
                if action == "change_items":
                    cc = uo.change_items
                    if cc.item_id not in self.items:
                        err = error_pb2.Error(code=error_pb2.ERROR_CODES_NOT_FOUND, message=f"unknown item: {cc.item_id}")
                    else:
                        if cc.item_id not in order.items:
                            order.items[cc.item_id] = 0
                        order.items[cc.item_id] += cc.quantity
                        self.orders[oid] = order
                elif action == "items_finalized":
                    cf = uo.items_finalized
                    print(f"finalized: {cf}")
                    order.finalized = True
                    order.totals = PriceTotals(cf.sub_total, cf.sales_tax, cf.total)
                    order.total_in_crypto = int.from_bytes(cf.total_in_crypto, byteorder="big")
                    order.payment_id = int.from_bytes(cf.payment_id, byteorder="big")
                    order.payment_ttl = int(cf.ttl)
                    self.orders[oid] = order
                elif action == "order_canceled":
                    ca = uo.order_canceled
                    self.orders[oid] = None
            elif which == "new_key_card":
                nkc = evt.new_key_card
                if nkc.event_id in self.all_key_cards:
                    err = error_pb2.Error(code=error_pb2.ERROR_CODES_INVALID, message=f"key card already exists: {nkc.event_id}")
                else:
                    print(f"{self.name} adding keyCard=0x{nkc.card_public_key.hex()} for user={nkc.user_wallet_addr.hex()} isGuest={nkc.is_guest}")
                    self.all_key_cards[nkc.card_public_key] = nkc.user_wallet_addr
                    self.valid_addrs.append(public_key_to_address(nkc.card_public_key).lower())
            else:
                err = error_pb2.Error(code=error_pb2.ERROR_CODES_INVALID, message=f"unhandled event type: {which}")
        resp = transport_pb2.EventPushResponse(request_id=req.request_id, error=err)
        data = b"\x08" + resp.SerializeToString()
        self.connection.send(data)
        if err is not None:
            raise Exception(err.message)
        self.print_state()

    def handle_commit_order_response(self, resp: shop_requests_pb2.CommitItemsToOrderResponse):
        if resp.HasField("error"):
            self.errors += 1
            if self.expect_error:
                print("Expected error: {}".format(resp.error))
                self.last_error = resp.error
                return
            else:
                raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=False)
        print("CommitItemsToOrderResponse: {}".format(resp))

    def login(self):
        if not self.connected:
            self.connection = connect(self.relay_ws_endpoint_url, origin="localhost", close_timeout=0.5)
            self.connected = True
        kc = keys.PrivateKey(self.own_key_card.key)
        # print('public key: ' + kc.public_key.to_hex())
        req_id = new_request_id()
        ar = authentication_pb2.AuthenticateRequest(request_id=req_id, public_key=kc.public_key.to_bytes())
        data = b"\x14" + ar.SerializeToString()
        self.outgoingRequests[req_id] = {"waiting":True}
        self.connection.send(data)
        while not self.logged_in:
            print("waiting")
            self.handle_all()

    def get_blob_upload_url(self):
        req_id = new_request_id()
        ewr = shop_requests_pb2.GetBlobUploadURLRequest(request_id=req_id)
        data = b"\x1e" + ewr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {"waiting":True}
        return req_id

    def _assert_shop_against_response(self, req_id):
        got_hash = self.outgoingRequests[req_id]['new_shop_hash']
        has_hash = self._hash_shop()
        assert got_hash == has_hash, f"shop hash mismatch: {got_hash} != {has_hash}"
        return got_hash

    def _hash_shop(self):
        if self.manifest is None:
            return os.urandom(32) # TODO: all zeros
        manifest_hash = keccak_256()
        # pprint(self.manifest)
        manifest_hash.update(self.manifest.shop_token_id)
        manifest_hash.update(self.manifest.domain.encode('utf-8'))
        manifest_hash.update(self.manifest.published_tag_id)
        # print("manifest: {}".format(manifest_hash.hexdigest()))

        pub_tag_hash = keccak_256()
        pub_tag = self.tags[self.manifest.published_tag_id]
        # sort by itemId
        pub_tag_ids = []
        for item_id in pub_tag.items:
            pub_tag_ids.append(item_id)
        pub_tag_ids.sort()
        for item_id in pub_tag_ids:
            pub_tag_hash.update(item_id)
        # print("publish_tag: {}".format(pub_tag_hash.hexdigest()))

        stock_hash = keccak_256()
        stock_ids = []
        for id in self.stock:
            stock_ids.append(id)
        stock_ids.sort()
        for id in stock_ids:
            count = self.stock[id]
            if count is None:
                raise Exception("not in stock?!")
            stock_hash.update(id)
            stock_hash.update(str(count).encode('utf-8'))
        # print("stock: {}".format(stock_hash.hexdigest()))

        root_hash = keccak_256()
        root_hash.update(manifest_hash.digest())
        root_hash.update(pub_tag_hash.digest())
        root_hash.update(stock_hash.digest())
        return root_hash.digest()

    def _sign_event(self, evt: shop_events_pb2.ShopEvent):
        encoded_data = hash_event(evt)
        keyCardPK = Account.from_key(self.own_key_card.key)
        signed_message = keyCardPK.sign_message(encoded_data)
        print(f"hash: {signed_message.messageHash.hex()}")
        return signed_message

    # an actual implementation would probably cache the relays
    def _valid_event_signing_addresses(self):
        if len(self.valid_addrs) != 0:
            return self.valid_addrs
        else:
            all = []
            # retreive all relays nfts
            if self.shopReg.functions.getRelayCount(self.shop_token_id).call() > 0:
                all_relay_token_ids = self.shopReg.functions.getAllRelays(self.shop_token_id).call()
                for token_id in all_relay_token_ids:
                    # retreive the owner => it's address
                    relay_address = self.relayReg.functions.ownerOf(token_id).call()
                    all.append(relay_address.lower())

            # turn key cards into addresses
            key_card_addresses = [public_key_to_address(pk).lower() for pk in list(self.all_key_cards.keys())]
            all.extend(key_card_addresses)
            self.valid_addrs = all
            return all

    def _verify_event(self, evt: transport_pb2.SignedEvent):
        if len(evt.signature) != 65:
            raise Exception("Invalid signature length: {}".format(len(evt.signature)))
        encoded_data = encode_defunct(evt.event.value)
        pub_key = self.w3.eth.account.recover_message(encoded_data, signature=evt.signature)
        print(f"{self.name} received event from recovered pub_key: {pub_key}")
        their_addr = Web3.to_checksum_address(pub_key).lower()
        valid_addrs = self._valid_event_signing_addresses()
        if their_addr not in valid_addrs:
            print(f"valid addresses: {valid_addrs}")
            raise Exception("Event signed by unknown address: {}".format(their_addr))

    def _write_event(self, evt: shop_events_pb2.ShopEvent):
        msg = self._sign_event(evt)
        wrapped = anypb.Any()
        wrapped.Pack(evt)
        sig_evt = transport_pb2.SignedEvent(event=wrapped, signature=msg.signature)
        req_id = new_request_id()
        ewr = transport_pb2.EventWriteRequest(request_id=req_id, event=sig_evt)
        data = b"\x03" + ewr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {"waiting": True}
        while "waiting" in self.outgoingRequests[req_id]:
            print("write waiting")
            self.handle_all()
        print(f"event: {get_id_from_event(evt)} written")
        return req_id

    def create_shop_manifest(self):
        if not self.expect_error:
            assert self.manifest == None
        eid = new_event_id()
        tid = new_event_id()
        sm = shop_events_pb2.ShopManifest(event_id=eid,
                                shop_token_id=self.shop_token_id.to_bytes(32),
                                domain="socks.mass.market",
                                published_tag_id=tid)
        evt = shop_events_pb2.ShopEvent(shop_manifest=sm)
        self._write_event(evt)
        update = shop_events_pb2.UpdateShopManifest(
            event_id=new_event_id(),
            add_accepted_currencies=[self.default_currency],
            set_base_currency=self.default_currency,
            add_payee=self.default_payee)
        evt = shop_events_pb2.ShopEvent(update_shop_manifest=update)
        self._write_event(evt)
        self.create_tag("published", tag_id=tid)
        # update shop state
        self.manifest = sm

    def update_shop_manifest(self,
                             name=None,
                             description=None,
                             profile=None,
                             domain=None,
                             published_tag_id=None,
                             add_currencies=[],
                             remove_currencies=[],
                             set_base_currency=None,
                             remove_payee=None,
                             add_payee=None):
        eid = new_event_id()
        um = shop_events_pb2.UpdateShopManifest(event_id=eid)
        if name is not None:
            um.name = name
        if description is not None:
            um.description = description
        if profile is not None:
            um.profile_picture_url = profile
        if domain is not None:
            um.domain = domain
        if published_tag_id is not None:
            um.published_tag_id = published_tag_id
        for c in add_currencies:
            um.add_accepted_currencies.append(c)
        for c in remove_currencies:
            um.remove_accepted_currencies.append(c)
        if set_base_currency is not None:
            um.set_base_currency.CopyFrom(set_base_currency)
        if add_payee is not None:
            um.add_payee.CopyFrom(add_payee)
        if remove_payee is not None:
            um.remove_payee.CopyFrom(remove_payee)
        evt = shop_events_pb2.ShopEvent(update_shop_manifest=um)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            if domain is not None:
                self.manifest.domain = domain
            if published_tag_id is not None:
                self.manifest.published_tag_id = published_tag_id

    def create_item(self, name: str, price: str):
        decimal_price = decimal.Decimal(price)
        iid = new_event_id()
        if iid in self.items:
            raise Exception("Item already exists: {}".format(iid))
        meta = {
            'name': name,
            'description': 'This is a description of the item',
            'image': 'https://example.com/image.png',
        }
        metadata = json.dumps(meta).encode('utf-8')
        item = shop_events_pb2.CreateItem(event_id=iid, metadata=metadata, price=format(decimal_price, '.2f').encode('utf-8'))
        evt = shop_events_pb2.ShopEvent(create_item=item)
        self._write_event(evt)
        # update shop state
        self.items[iid] = item
        return iid

    def update_item(self, item_id, price=None, metadata:bytes=None):
        exisiting_item = shop_events_pb2.CreateItem()
        exists = False
        if item_id in self.items:
            exisiting_item = self.items[item_id]
            exists = True
        evtId = new_event_id()
        update = shop_events_pb2.UpdateItem(event_id=evtId, item_id=item_id)
        if metadata is not None:
            update.metadata = metadata
            exisiting_item.metadata = metadata
        if price is not None:
            decimal_price = decimal.Decimal(price)
            price_string = format(decimal_price, '.2f').encode('utf-8')
            update.price = price_string
            exisiting_item.price = price_string
        evt = shop_events_pb2.ShopEvent(update_item=update)
        req_id = self._write_event(evt)
        # update shop state
        if exists:
            self.items[item_id] = exisiting_item
        return req_id

    def create_tag(self, name, tag_id=None):
        tid = tag_id
        if tid is None:
            tid = new_event_id()
        if tid in self.tags:
            raise Exception("Tag already exists: {}".format(tid))
        tag = shop_events_pb2.CreateTag(event_id=tid, name=name)
        evt = shop_events_pb2.ShopEvent(create_tag=tag)
        self._write_event(evt)
        # update shop state
        self.tags[tid] = NamedTag(name, [])
        return tid

    def add_item_to_tag(self, tag_id, item_id):
        if not self.expect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.expect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        add = shop_events_pb2.UpdateTag(event_id=eid, tag_id=tag_id, add_item_id=item_id)
        evt = shop_events_pb2.ShopEvent(update_tag=add)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            self.tags[tag_id].items.append(item_id)

    def remove_from_tag(self, tag_id, item_id):
        if not self.expect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.expect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        remove = shop_events_pb2.UpdateTag(event_id=eid, tag_id=tag_id, remove_item_id=item_id)
        evt = shop_events_pb2.ShopEvent(update_tag=remove)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            self.tags[tag_id].items.remove(item_id)

    def rename_tag(self, tag_id, name):
        if not self.expect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        eid = new_event_id()
        rename = shop_events_pb2.UpdateTag(event_id=eid, tag_id=tag_id, rename=name)
        evt = shop_events_pb2.ShopEvent(update_tag=rename)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            self.tags[tag_id].name = name

    def delete_tag(self, tag_id):
        if not self.expect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        eid = new_event_id()
        delete = shop_events_pb2.UpdateTag(event_id=eid, tag_id=tag_id, delete=True)
        evt = shop_events_pb2.ShopEvent(update_tag=delete)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            del self.tags[tag_id]

    def create_order(self, oid=None):
        if oid is None:
            oid = new_event_id()
        if not self.expect_error and oid in self.orders:
            raise Exception("Order already exists: {}".format(oid))
        order = shop_events_pb2.CreateOrder(event_id=oid)
        evt = shop_events_pb2.ShopEvent(create_order=order)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            self.orders[oid] = Order(oid)
        return oid

    def add_to_order(self, order_id, item_id, quantity):
        if not self.expect_error and order_id not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if not self.expect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        add = shop_events_pb2.UpdateOrder.ChangeItems(item_id=item_id, quantity=quantity)
        update = shop_events_pb2.UpdateOrder(event_id=eid, order_id=order_id, change_items=add)
        evt = shop_events_pb2.ShopEvent(update_order=update)
        self._write_event(evt)
        # update shop state
        current = 0
        if not self.expect_error and item_id in self.orders[order_id].items:
            current = self.orders[order_id].items[item_id]
        if not self.expect_error:
            current += quantity
            self.orders[order_id].items[item_id] = current

    def remove_from_order(self, order_id, item_id, quantity):
        order = Order(None)
        if not self.expect_error and order_id not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if not self.expect_error:
            order = self.orders[order_id]
        if not self.expect_error and (item_id not in self.items or item_id not in order.items):
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        remove = shop_events_pb2.UpdateOrder.ChangeItems(item_id=item_id, quantity=-quantity)
        update = shop_events_pb2.UpdateOrder(event_id=eid, order_id=order_id, change_items=remove)
        evt = shop_events_pb2.ShopEvent(update_order=update)
        self._write_event(evt)
        # update shop state
        if not self.expect_error:
            order.items[item_id] += -quantity
            if order.items[item_id] <= 0:
                del order.items[item_id]
            self.orders[order_id] = order

    def abandon_order(self, order_id):
        eid = new_event_id()
        cancel = shop_events_pb2.UpdateOrder.OrderCanceled(timestamp=10)
        ca = shop_events_pb2.UpdateOrder(event_id=eid, order_id=order_id, order_canceled=cancel)
        evt = shop_events_pb2.ShopEvent(update_order=ca)
        self._write_event(evt)
        if not self.expect_error:
            self.orders[order_id] = None

    def update_shipping_address_for_order(self, order_id, address):
        eid = new_event_id()
        uo = shop_events_pb2.UpdateOrder(event_id=eid, order_id=order_id, update_shipping_details=address)
        evt = shop_events_pb2.ShopEvent(update_order=uo)
        self._write_event(evt)
        if not self.expect_error:
            self.orders[order_id].shipping = address


    def commit_order(self, order_id, currency=None, payee_name="default"):
        if not self.expect_error and order_id not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if currency is None:
            currency = self.default_currency
        ccr = shop_requests_pb2.CommitItemsToOrderRequest(
            request_id=new_request_id(),
            order_id=order_id,
            currency=currency,
            payee_name=payee_name)
        data = b"\x20" + ccr.SerializeToString()
        self.connection.send(data)
        # update shop state
        self.outgoingRequests[ccr.request_id] = order_id
        self.handle_all()


    def change_stock(self, changes):
        eid = new_event_id()
        checked_items = []
        checked_changes = []
        for item_id, change in changes:
            if not self.expect_error and item_id not in self.items:
                raise Exception("Unknown item: {}".format(item_id))
            checked_items.append(item_id)
            checked_changes.append(change)
        cs = shop_events_pb2.ChangeStock(event_id=eid, item_ids=checked_items, diffs=checked_changes)
        evt = shop_events_pb2.ShopEvent(change_stock=cs)
        self._write_event(evt)
        # update shop state
        for item_id, change in changes:
            if not self.expect_error:
                self.stock[item_id] = self.stock.get(item_id, 0) + change

def _decode_message(data):
    messageType = data[0]
    payload = data[1:]
    types = { # TODO: codegen these
        0x01: transport_pb2.PingRequest,
        0x04: transport_pb2.EventWriteResponse,
        0x05: transport_pb2.SyncStatusRequest,
        0x07: transport_pb2.EventPushRequest,
        0x15: authentication_pb2.AuthenticateResponse,
        0x17: authentication_pb2.ChallengeSolvedResponse,
        0x1f: shop_requests_pb2.GetBlobUploadURLResponse,
        0x21: shop_requests_pb2.CommitItemsToOrderResponse,
    }
    type = types[messageType]
    if type is None:
        raise Exception("Unknown message type: {}".format(messageType))
    msg = type()
    msg.ParseFromString(payload)
    return (messageType, msg)

def to_32byte_hex(val):
    return Web3.to_hex(Web3.to_bytes(val).rjust(32, b'\0'))

def get_id_from_event(evt: shop_events_pb2.ShopEvent):
    which = evt.WhichOneof("union")
    if which is None:
        raise Exception("No event type set")
    unwrapped = getattr(evt, which)
    return getattr(unwrapped, "event_id").hex()

def public_key_to_address(public_key: bytes) -> str:
    """
    Convert a public key to an Ethereum address.
    :param public_key: public key
    :return: Ethereum address
    """

    public_key_parsed = keys.PublicKey(public_key)
    # address_bytes = keccak()
    # return Web3.to_checksum_address(address_bytes.hex())
    return public_key_parsed.to_address()
