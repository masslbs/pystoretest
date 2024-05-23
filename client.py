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
from sha3 import keccak_256
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedError
from web3 import Web3, Account, HTTPProvider
from web3.middleware import construct_sign_and_send_raw_middleware
from web3.exceptions import TransactionNotFound
from eth_keys import keys
from eth_account.messages import encode_defunct, encode_structured_data

# our protobuf schema
from massmarket_hash_event import Hasher, schema_pb2

class RelayException(Exception):
    def __init__(self, err: schema_pb2.Error):
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

class Cart():
    def __init__(self, id):
        self.id = id
        self.items = {}
        self.finalized = False
        self.purchase_address = None
        self.totals = None
        self.payed = False

eip712spec = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

class RelayClient():

    def __init__(self, name="Alice", private_key=None):
        self.name = name

        self.relay_http_address = os.getenv("RELAY_HTTP_ADDRESS")
        assert self.relay_http_address is not None, "RELAY_HTTP_ADDRESS is not set"
        print(f"{name} is using relay: {self.relay_http_address}")
        relay_addr = urlparse(self.relay_http_address)

        self.relay_ping = float(os.getenv("RELAY_PING"))

        # construct and dial websocket endpoint
        relay_ws_endpoint = relay_addr._replace(path="/v1/sessions")
        if relay_addr.scheme == "http":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="ws")
        elif relay_addr.scheme == "https":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="wss")
        else:
            raise Exception("Unknown Relay HTTP scheme: {}".format(relay_addr.scheme))

        # connection setup
        self.relay_ws_endpoint_url = relay_ws_endpoint.geturl()
        self.connection = connect(self.relay_ws_endpoint_url)
        self.connected = True
        print(f"{name} has ws endpoint: {self.relay_ws_endpoint_url}")
        self.logged_in = False
        self.pongs = 0
        self.outgoingRequests = {}
        self.errors = 0
        self.excpect_error = False

        # request testing info from relay
        discovery_resp = requests.get(self.relay_http_address + "/testing/discovery")
        if discovery_resp.status_code != 200:
            raise Exception(f"Discovery request failed with status code: {discovery_resp.status_code}")
        discovery_data = discovery_resp.json()

        # relay nft token id
        relay_token_str = discovery_data["relay_token_id"][2:]
        print(f"relay_token_id: {relay_token_str}")
        relay_token_hex = bytes.fromhex(relay_token_str)
        self.relay_token_id = int.from_bytes(relay_token_hex, "big")

        # etherum setup
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_ENDPOINT")))
        self.__load_contracts()
        self.chain_id = discovery_data["chain_id"]
        if private_key is None:
            private_key = bytes.fromhex(os.getenv("ETH_PRIVATE_KEY"))
        account = Account.from_key(private_key)
        print("{} is using address: {}".format(name, account.address))
        self.account = account
        self.w3.eth.default_account = account.address
        sign_mw = construct_sign_and_send_raw_middleware(self.account)
        self.w3.middleware_onion.add(sign_mw)

        self.event_hasher = Hasher(self.chain_id, self.storeReg.address)

        # mass state
        self.own_key_card = Account.create()
        self.all_key_cards = {}
        self.store_token_id = None
        self.manifest = None
        self.items = {}
        self.stock = {}
        self.tags = {}
        self.carts = {}


    def __load_contracts(self):
        addresses = json.loads(open(os.getenv("MASS_CONTRACTS")+"/deploymentAddresses.json", "r").read())
        print("using contracts:")
        pprint(addresses)
        relayRegABI = open(os.getenv("MASS_CONTRACTS")+"/abi/RelayReg.json", "r").read()
        self.relayReg = self.w3.eth.contract(address=addresses["RelayReg"], abi=relayRegABI)
        storeRegABI = open(os.getenv("MASS_CONTRACTS")+"/abi/StoreReg.json", "r").read()
        self.storeReg = self.w3.eth.contract(address=addresses["StoreReg"], abi=storeRegABI)
        erc20TestingTokenABI = open(os.getenv("MASS_CONTRACTS")+"/abi/Eddies.json", "r").read()
        self.erc20Token = self.w3.eth.contract(address=addresses["Eddies"], abi=erc20TestingTokenABI)
        paymentFactoryABI = open(os.getenv("MASS_CONTRACTS")+"/abi/PaymentFactory.json", "r").read()
        self.paymentFactory =  self.w3.eth.contract(address=addresses["PaymentFactory"], abi=paymentFactoryABI)


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
                print(f"retrying to find {tx}..")
                sleep(0.5)
                tries -= 1
                continue
        assert status == 1

    def register_store(self):
        token_id = int.from_bytes(os.urandom(32), "big")
        tx = self.storeReg.functions.mint(token_id, self.account.address).transact()
        self.__check_transaction(tx)
        self.store_token_id = token_id
        print("storeTokenID: {}".format(self.store_token_id))
        # check admin access
        tx = self.storeReg.functions.updateRootHash(self.store_token_id, os.urandom(32)).transact()
        self.__check_transaction(tx)
        self.add_relay_to_store(self.relay_token_id)
        return token_id

    def add_relay_to_store(self, relay_token):
        # get current relays and add them
        if self.storeReg.functions.getRelayCount(self.store_token_id).call() > 0:
            current_relay_tokens = self.storeReg.functions.getAllRelays(self.store_token_id).call()
            if relay_token in current_relay_tokens:
                return
        # update the relays assigned to this store
        tx = self.storeReg.functions.addRelay(self.store_token_id, relay_token).transact()
        self.__check_transaction(tx)

    def create_invite(self):
        reg_secret = os.urandom(32)
        acc = Account.from_key(reg_secret)
        print("addr of token: {}".format(acc.address))
        tx = self.storeReg.functions.publishInviteVerifier(self.store_token_id, acc.address).transact()
        self.__check_transaction(tx)
        return reg_secret

    def redeem_invite(self, token):
        acc = Account.from_key(token)
        msg_text = "enrolling:{}".format(self.account.address)
        msg = encode_defunct(text=msg_text.lower())
        sig = acc.sign_message(msg)
        rhex = to_32byte_hex(sig.r)
        shex = to_32byte_hex(sig.s)
        tx = self.storeReg.functions.redeemInvite(self.store_token_id,
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
                "chainId": self.chain_id,
                "verifyingContract": self.storeReg.address,
            },
            "message": {
                "keyCard": keyCardPK.public_key.to_hex()[2:],
            }
        }
        encoded_data=encode_structured_data(typed_data)
        signed_message = self.account.sign_message(encoded_data)
        signature = signed_message.signature

        json_data = json.dumps({
            "key_card": base64.b64encode(keyCardPK.public_key.to_bytes()).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "store_token_id": base64.b64encode(self.store_token_id.to_bytes(32, 'big')).decode('utf-8'),
        })
        # mangel url to register store
        modified_url = urlparse(self.relay_http_address)._replace(path="/v1/enroll_key_card").geturl()

        response = requests.post(modified_url, data=json_data)
        respData = response.json()
        print("enroll response: {}".format(respData))
        if "error" in respData:
            raise Exception(respData["error"])
        assert respData["success"] == True
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
        print('Received messageType={} from server: {}'.format(type, self.w3.to_hex(data)))
        if type == 0x01:
            self.handle_ping_request(msg)
        elif type == 0x04:
            self.handle_authenticate_response(msg)
        elif type == 0x06:
            self.handle_challenge_solved_response(msg)
        elif type == 0x0a:
            self.handle_get_blob_upload_url_response(msg)
        elif type == 0x0e:
            self.handle_event_write_response(msg)
        elif type == 0x0f:
            self.handle_sync_status_request(msg)
        elif type == 0x11:
            self.handle_event_push_request(msg)
        elif type == 0x14:
            self.handle_commit_cart_response(msg)
        else:
            self.errors += 1
            self.last_error = "Unknown message type: {}".format(type)
            if self.excpect_error:
                print("Expected error: {}".format(msg))
            else:
                raise Exception("Unknown message type: {}".format(type))

    def handle_ping_request(self, req: schema_pb2.PingRequest):
        resp = schema_pb2.PingResponse(request_id=req.request_id)
        data = b"\x02" + resp.SerializeToString()
        self.connection.send(data)
        print("{} sent a pong to request_id {}".format(self.name, req.request_id))
        self.pongs += 1

    def handle_sync_status_request(self, req: schema_pb2.SyncStatusRequest):
        print("SyncStatusRequest: unpushedEvents={}".format(req.unpushed_events))
        resp = schema_pb2.SyncStatusResponse(request_id=req.request_id)
        data = b"\x10" + resp.SerializeToString()
        self.connection.send(data)

    def _check_expected_request(self, req_id, clean=False):
        if not req_id in self.outgoingRequests:
            raise Exception("Received reponse for unknown request. id={}".format(req_id))
        if clean:
            del self.outgoingRequests[req_id]

    def handle_authenticate_response(self, resp: schema_pb2.AuthenticateResponse):
        if resp.HasField("error"):
            raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=True)
        typed_data = {
            "types": {
                "EIP712Domain": eip712spec,
                "Challenge": [ {"name": "challenge", "type": "string"} ],
            },
            "primaryType": "Challenge",
            "domain": {
                "name": "MassMarket",
                "version": "1",
                "chainId": self.chain_id,
                "verifyingContract": self.storeReg.address,
            },
            "message": { "challenge": self.w3.to_hex(resp.challenge)[2:] }
        }
        encoded_data=encode_structured_data(typed_data)
        signed_message = self.own_key_card.sign_message(encoded_data)
        signature = signed_message.signature
        req_id = new_request_id()
        csr = schema_pb2.ChallengeSolvedRequest(request_id=req_id, signature=signature)
        data = b"\x05" + csr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {}

    def handle_challenge_solved_response(self, resp: schema_pb2.ChallengeSolvedResponse):
        if resp.HasField("error"):
            raise Exception("Challenge failed: '{}'".format(resp.error))
        self._check_expected_request(resp.request_id, clean=True)
        self.logged_in = True

    def handle_get_blob_upload_url_response(self, resp: schema_pb2.GetBlobUploadURLResponse):
        if resp.HasField("error"):
            raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=False)
        print("blobUrl: id={} url={}".format(resp.request_id, resp.url))
        if resp.request_id not in self.outgoingRequests:
            raise Exception("Unexpected response: {}".format(resp.request_id))
        self.outgoingRequests[resp.request_id] = { "url": resp.url }

    def handle_event_write_response(self, resp: schema_pb2.EventWriteResponse):
        print("EventWriteResponse: {}".format(resp))
        self._check_expected_request(resp.request_id, clean=True)
        if resp.HasField("error"):
            self.errors += 1
            if self.excpect_error:
                print("Expected error: {}".format(resp.error))
                self.last_error = resp.error
                self.outgoingRequests[resp.request_id] = { 'err': resp.error }
            else:
                raise RelayException(resp.error)
        else:
            assert resp.event_sequence_no > 0, "event_sequence_no is 0"
            self.outgoingRequests[resp.request_id] = { 'new_store_hash': resp.new_store_hash }

    def handle_event_push_request(self, req: schema_pb2.EventPushRequest):
        print("EventPushRequest: {}".format(req))
        err = None
        for evt in req.events:
            self._verify_event(evt)
            which = evt.WhichOneof("union")
            if which == "store_manifest":
                self.manifest = evt.store_manifest
            elif which == "update_manifest":
                if evt.update_manifest.field == schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN:
                    self.manifest.domain = evt.update_manifest.string
                elif evt.update_manifest.field == schema_pb2.UpdateManifest.MANIFEST_FIELD_PAYMENT_ADDR:
                    self.manifest.payment_addr = evt.update_manifest.hash
                elif evt.update_manifest.field == schema_pb2.UpdateManifest.MANIFEST_FIELD_PUBLISHED_TAG:
                    self.manifest.published_tag_id = evt.update_manifest.hash
            elif which == "create_item":
                ci = evt.create_item
                self.items[ci.event_id] = ci
                #self.stock[ci.event_id] = 0
            elif which == "update_item":
                ui = evt.update_item
                if ui.item_id not in self.items:
                    err = schema_pb2.Error(code="unknown_item", message="unknown item: {}".format(ui.item_id))
                else:
                    item = self.items[ui.item_id]
                    if ui.field == schema_pb2.UpdateItem.ITEM_FIELD_METADATA:
                        item.metadata = ui.metadata
                    elif ui.field == schema_pb2.UpdateItem.ITEM_FIELD_PRICE:
                        dec_price = decimal.Decimal(ui.price)
                        item.price = format(dec_price, '.2f').encode('utf-8')
                    else:
                        err = schema_pb2.Error(code="unknown_field", message="unknown field: {}".format(ui.field))
                    self.items[ui.item_id] = item
            elif which == "create_tag":
                ct = evt.create_tag
                if ct.event_id in self.tags:
                    err = schema_pb2.Error(code="tag_already_exists", message="tag already exists: {}".format(ct.event_id))
                else:
                    self.tags[ct.event_id] = NamedTag(ct.name, [])
            elif which == "add_to_tag":
                at = evt.add_to_tag
                # TODO: not a CRDT implementation yet
                if at.tag_id not in self.tags:
                    err = schema_pb2.Error(code="unknown_tag", message="unknown tag: {}".format(at.tag_id))
                elif at.item_id not in self.items:
                    err = schema_pb2.Error(code="unknown_item", message="unknown item: {}".format(at.item_id))
                else:
                    self.tags[at.tag_id].items.append(at.item_id)
            elif which == "remove_from_tag":
                rft = evt.remove_from_tag
                if rft.tag_id not in self.tags:
                    err = schema_pb2.Error(code="unknown_tag", message="unknown tag: {}".format(rft.tag_id))
                elif rft.item_id not in self.items:
                    err = schema_pb2.Error(code="unknown_item", message="unknown item: {}".format(rft.item_id))
                else:
                    self.tags[rft.tag_id].items.remove(rft.item_id)
            elif which == "rename_tag":
                rt = evt.rename_tag
                if rt.tag_id not in self.tags:
                    err = schema_pb2.Error(code="unknown_tag", message="unknown tag: {}".format(rt.tag_id))
                else:
                    self.tags[rt.tag_id].name = rt.name
            elif which == "delete_tag":
                dt = evt.delete_tag
                if dt.tag_id not in self.tags:
                    err = schema_pb2.Error(code="unknown_tag", message="unknown tag: {}".format(dt.tag_id))
                else:
                    del self.tags[dt.tag_id]
            elif which == "change_stock":
                cs = evt.change_stock
                changes = list(zip(cs.item_ids, cs.diffs))
                for diff in changes:
                    if diff[0] not in self.items:
                        err = schema_pb2.Error(code="unknown_item", message="unknown item: {}".format(diff[0]))
                    else:
                        self.stock[diff[0]] = self.stock.get(diff[0], 0) + diff[1]
                if len(cs.cart_id) > 0:
                    if cs.cart_id not in self.carts:
                        err = schema_pb2.Error(code="unknown_cart", message="unknown cart: {}".format(cs.cart_id))
                    else:
                        self.carts[cs.cart_id].payed = True
            elif which == "create_cart":
                cc = evt.create_cart
                if cc.event_id in self.carts:
                    err = schema_pb2.Error(code="cart_already_exists", message="cart already exists: {}".format(cc.event_id))
                else:
                    self.carts[cc.event_id] = Cart(cc.event_id)
            elif which == "change_cart":
                cc = evt.change_cart
                if cc.cart_id not in self.carts:
                    err = schema_pb2.Error(code="unknown_cart", message="unknown cart: {}".format(cc.cart_id))
                elif cc.item_id not in self.items:
                    err = schema_pb2.Error(code="unknown_item", message="unknown item: {}".format(cc.item_id))
                else:
                    cart = self.carts[cc.cart_id]
                    if cc.item_id not in cart.items:
                        cart.items[cc.item_id] = 0
                    cart.items[cc.item_id] += cc.quantity
                    self.carts[cc.cart_id] = cart
            elif which == "cart_finalized":
                cf = evt.cart_finalized
                print(f"finalized: {cf}")
                cart_id = cf.cart_id
                if cart_id not in self.carts:
                    raise Exception("Unknown cart: {}".format(cart_id))
                cart = self.carts[cart_id]
                cart.finalized = True
                cart.purchase_address = cf.purchase_addr
                cart.totals = PriceTotals(cf.sub_total, cf.sales_tax, cf.total)
                cart.total_in_crypto = int(cf.total_in_crypto)
                self.carts[cart_id] = cart
            elif which == "cart_abandoned":
                ca = evt.cart_abandoned
                self.carts[ca.cart_id] = None
            elif which == "new_key_card":
                nkc = evt.new_key_card
                if nkc.event_id in self.all_key_cards:
                    err = schema_pb2.Error(code="key_card_already_exists", message="key card already exists: {}".format(nkc.event_id))
                else:
                    self.all_key_cards[nkc.card_public_key] = nkc.user_wallet_addr
            else:
                err = schema_pb2.Error(code="unhandled_event_type", message="unhandled event type: {}".format(which))
        resp = schema_pb2.EventPushResponse(request_id=req.request_id, error=err)
        data = b"\x12" + resp.SerializeToString()
        self.connection.send(data)
        if err is not None:
            raise Exception(err.message)

    def handle_commit_cart_response(self, resp: schema_pb2.CommitCartResponse):
        if resp.HasField("error"):
            self.errors += 1
            if self.excpect_error:
                print("Expected error: {}".format(resp.error))
                self.last_error = resp.error
                return
            else:
                raise RelayException(resp.error)
        self._check_expected_request(resp.request_id, clean=False)
        print("CommitCartResponse: {}".format(resp))

    def login(self):
        if not self.connected:
            self.connection = connect(self.relay_ws_endpoint_url)
            self.connected = True
        kc = keys.PrivateKey(self.own_key_card.key)
        # print('public key: ' + kc.public_key.to_hex())
        req_id = new_request_id()
        ar = schema_pb2.AuthenticateRequest(request_id=req_id, public_key=kc.public_key.to_bytes())
        data = b"\x03" + ar.SerializeToString()
        self.outgoingRequests[req_id] = {"waiting":True}
        self.connection.send(data)
        while not self.logged_in:
            print("waiting")
            self.handle_all()

    def get_blob_upload_url(self):
        req_id = new_request_id()
        ewr = schema_pb2.GetBlobUploadURLRequest(request_id=req_id)
        data = b"\x09" + ewr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {"waiting":True}
        return req_id

    def _assert_store_against_response(self, req_id):
        got_hash = self.outgoingRequests[req_id]['new_store_hash']
        has_hash = self._hash_store()
        assert got_hash == has_hash, f"store hash mismatch: {got_hash} != {has_hash}"
        return got_hash

    def _hash_store(self):
        if self.manifest is None:
            return os.urandom(32) # TODO: all zeros
        manifest_hash = keccak_256()
        # pprint(self.manifest)
        manifest_hash.update(self.manifest.store_token_id)
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

    def _sign_event(self, evt: schema_pb2.Event):
        encoded_data = self.event_hasher.hash_event(evt)
        keyCardPK = Account.from_key(self.own_key_card.key)
        signed_message = keyCardPK.sign_message(encoded_data)
        print(f"hash: {signed_message.messageHash.hex()}")
        return signed_message

    # an actual implementation would probably cache the relays
    def _valid_event_signing_addresses(self):
        all = []
        # retreive all relays nfts
        if self.storeReg.functions.getRelayCount(self.store_token_id).call() > 0:
            all_relay_token_ids = self.storeReg.functions.getAllRelays(self.store_token_id).call()
            for token_id in all_relay_token_ids:
                # retreive the owner => it's address
                relay_address = self.relayReg.functions.ownerOf(token_id).call()
                all.append(relay_address.lower())
        # turn key cards into addresses
        key_card_addresses = [public_key_to_address(pk).lower() for pk in list(self.all_key_cards.keys())]
        all.extend(key_card_addresses)
        return all

    def _verify_event(self, evt: schema_pb2.Event):
        if len(evt.signature) != 65:
            raise Exception("Invalid signature length: {}".format(len(evt.signature)))
        encoded_data = self.event_hasher.hash_event(evt)
        pub_key = self.w3.eth.account.recover_message(encoded_data, signature=evt.signature)
        print(f"event:{get_id_from_event(evt)} recovered pub_key: {pub_key}")
        their_addr = Web3.to_checksum_address(pub_key).lower()
        valid_addrs = self._valid_event_signing_addresses()
        if their_addr not in valid_addrs:
            print(f"valid addresses: {valid_addrs}")
            raise Exception("Event signed by unknown address: {}".format(their_addr))

    def _write_event(self, evt: schema_pb2.Event):
        msg = self._sign_event(evt)
        evt.signature = msg.signature
        req_id = new_request_id()
        ewr = schema_pb2.EventWriteRequest(request_id=req_id, event=evt)
        data = b"\x0d" + ewr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id] = {"waiting": True}
        while "waiting" in self.outgoingRequests[req_id]:
            print("write waiting")
            self.handle_all()
        print(f"event: {get_id_from_event(evt)} written")
        return req_id

    def create_store_manifest(self):
        assert self.manifest == None
        eid = new_event_id()
        tid = new_event_id()
        sm = schema_pb2.StoreManifest(event_id=eid,
                                store_token_id=self.store_token_id.to_bytes(32),
                                domain="socks.mass.market",
                                published_tag_id=tid)
        evt = schema_pb2.Event(store_manifest=sm)
        self._write_event(evt)
        self.create_tag("published", tag_id=tid)
        # update store state
        self.manifest = sm

    def update_store_manifest(self, field: schema_pb2.UpdateManifest.ManifestField, string_value=None, id_value=None, addr_value:bytes=None):
        eid = new_event_id()
        um = schema_pb2.UpdateManifest(event_id=eid, field=field)
        if field == schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN:
            um.string = string_value
        elif field == schema_pb2.UpdateManifest.MANIFEST_FIELD_PUBLISHED_TAG:
            um.tag_id = id_value
        elif field == schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20:
            um.erc20_addr = addr_value
        elif field == schema_pb2.UpdateManifest.MANIFEST_FIELD_REMOVE_ERC20:
            um.erc20_addr = addr_value
        else:
            raise Exception("Unknown field: {}".format(field))
        evt = schema_pb2.Event(update_manifest=um)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            if field == schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN:
                self.manifest.domain = string_value
            elif field == schema_pb2.UpdateManifest.MANIFEST_FIELD_PUBLISHED_TAG:
                self.manifest.published_tag_id = id_value

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
        item = schema_pb2.CreateItem(event_id=iid, metadata=metadata, price=format(decimal_price, '.2f').encode('utf-8'))
        evt = schema_pb2.Event(create_item=item)
        self._write_event(evt)
        # update store state
        self.items[iid] = item
        return iid

    def update_item(self, item_id, field, value):
        exisiting_item = schema_pb2.CreateItem()
        exists = False
        if item_id in self.items:
            exisiting_item = self.items[item_id]
            exists = True
        evtId = new_event_id()
        update = schema_pb2.UpdateItem(event_id=evtId, item_id=item_id, field=field)
        if field == schema_pb2.UpdateItem.ITEM_FIELD_METADATA:
            update.metadata = value
            exisiting_item.metadata = value
        elif field == schema_pb2.UpdateItem.ITEM_FIELD_PRICE:
            decimal_price = decimal.Decimal(value)
            price_string = format(decimal_price, '.2f').encode('utf-8')
            update.price = price_string
            exisiting_item.price = price_string
        else:
            raise Exception("Unknown field: {}".format(field))
        evt = schema_pb2.Event(update_item=update)
        req_id = self._write_event(evt)
        # update store state
        if exists:
            self.items[item_id] = exisiting_item
        return req_id

    def create_tag(self, name, tag_id=None):
        tid = tag_id
        if tid is None:
            tid = new_event_id()
        if tid in self.tags:
            raise Exception("Tag already exists: {}".format(tid))
        tag = schema_pb2.CreateTag(event_id=tid, name=name)
        evt = schema_pb2.Event(create_tag=tag)
        self._write_event(evt)
        # update store state
        self.tags[tid] = NamedTag(name, [])
        return tid

    def add_item_to_tag(self, tag_id, item_id):
        if not self.excpect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.excpect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        add = schema_pb2.AddToTag(event_id=eid, tag_id=tag_id, item_id=item_id)
        evt = schema_pb2.Event(add_to_tag=add)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            self.tags[tag_id].items.append(item_id)

    def remove_from_tag(self, tag_id, item_id):
        if not self.excpect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.excpect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        remove = schema_pb2.RemoveFromTag(event_id=eid, tag_id=tag_id, item_id=item_id)
        evt = schema_pb2.Event(remove_from_tag=remove)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            self.tags[tag_id].items.remove(item_id)

    def rename_tag(self, tag_id, name):
        if not self.excpect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        eid = new_event_id()
        rename = schema_pb2.RenameTag(event_id=eid, tag_id=tag_id, name=name)
        evt = schema_pb2.Event(rename_tag=rename)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            self.tags[tag_id].name = name

    def delete_tag(self, tag_id):
        if not self.excpect_error and tag_id not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        eid = new_event_id()
        delete = schema_pb2.DeleteTag(event_id=eid, tag_id=tag_id)
        evt = schema_pb2.Event(delete_tag=delete)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            del self.tags[tag_id]

    def create_cart(self, cid=None):
        if cid is None:
            cid = new_event_id()
        if not self.excpect_error and cid in self.carts:
            raise Exception("Cart already exists: {}".format(cid))
        cart = schema_pb2.CreateCart(event_id=cid)
        evt = schema_pb2.Event(create_cart=cart)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            self.carts[cid] = Cart(cid)
        return cid

    def add_to_cart(self, cart_id, item_id, quantity):
        if not self.excpect_error and cart_id not in self.carts:
            raise Exception("Unknown cart: {}".format(cart_id))
        if not self.excpect_error and item_id not in self.items:
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        add = schema_pb2.ChangeCart(event_id=eid, cart_id=cart_id, item_id=item_id, quantity=quantity)
        evt = schema_pb2.Event(change_cart=add)
        self._write_event(evt)
        # update store state
        current = 0
        if not self.excpect_error and item_id in self.carts[cart_id].items:
            current = self.carts[cart_id].items[item_id]
        if not self.excpect_error:
            current += quantity
            self.carts[cart_id].items[item_id] = current

    def remove_from_cart(self, cart_id, item_id, quantity):
        cart = Cart(None)
        if not self.excpect_error and cart_id not in self.carts:
            raise Exception("Unknown cart: {}".format(cart_id))
        if not self.excpect_error:
            cart = self.carts[cart_id]
        if not self.excpect_error and (item_id not in self.items or item_id not in cart.items):
            raise Exception("Unknown item: {}".format(item_id))
        eid = new_event_id()
        remove = schema_pb2.ChangeCart(event_id=eid, cart_id=cart_id, item_id=item_id, quantity=-quantity)
        evt = schema_pb2.Event(change_cart=remove)
        self._write_event(evt)
        # update store state
        if not self.excpect_error:
            cart.items[item_id] += -quantity
            if cart.items[item_id] <= 0:
                del cart.items[item_id]
            self.carts[cart_id] = cart

    def commit_cart(self, cart_id, erc20_addr = None):
        if cart_id not in self.carts:
            raise Exception("Unknown cart: {}".format(cart_id))
        ccr = schema_pb2.CommitCartRequest(request_id=new_request_id(), cart_id=cart_id, erc20_addr=erc20_addr)
        data = b"\x13" + ccr.SerializeToString()
        self.connection.send(data)
        # update store state
        self.outgoingRequests[ccr.request_id] = cart_id
        self.handle_all()

    def abandon_cart(self, cart_id):
        eid = new_event_id()
        ca = schema_pb2.CartAbandoned(event_id=eid, cart_id=cart_id)
        evt = schema_pb2.Event(cart_abandoned=ca)
        self._write_event(evt)
        if not self.excpect_error:
            self.carts[cart_id] = None

    def change_stock(self, changes):
        eid = new_event_id()
        checked_items = []
        checked_changes = []
        for item_id, change in changes:
            if not self.excpect_error and item_id not in self.items:
                raise Exception("Unknown item: {}".format(item_id))
            checked_items.append(item_id)
            checked_changes.append(change)
        cs = schema_pb2.ChangeStock(event_id=eid, item_ids=checked_items, diffs=checked_changes)
        evt = schema_pb2.Event(change_stock=cs)
        self._write_event(evt)
        # update store state
        for item_id, change in changes:
            if not self.excpect_error:
                self.stock[item_id] = self.stock.get(item_id, 0) + change

def _decode_message(data):
    messageType = data[0]
    payload = data[1:]
    types = {
        0x01: schema_pb2.PingRequest,
        0x04: schema_pb2.AuthenticateResponse,
        0x06: schema_pb2.ChallengeSolvedResponse,
        0x0a: schema_pb2.GetBlobUploadURLResponse,
        0x0e: schema_pb2.EventWriteResponse,
        0x0f: schema_pb2.SyncStatusRequest,
        0x11: schema_pb2.EventPushRequest,
        0x14: schema_pb2.CommitCartResponse,
    }
    type = types[messageType]
    if type is None:
        raise Exception("Unknown message type: {}".format(type))
    msg = type()
    msg.ParseFromString(payload)
    return (messageType, msg)

def to_32byte_hex(val):
    return Web3.to_hex(Web3.to_bytes(val).rjust(32, b'\0'))

def get_id_from_event(evt: schema_pb2.Event):
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
