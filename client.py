# stdlib
import requests
import json
import os
import base64
from urllib.parse import urlparse
from pprint import pprint
import time
import datetime
from typing import Optional, List, Dict
import random

# pip
import google.protobuf.any_pb2 as anypb
from sha3 import keccak_256
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedError, InvalidStatus
from web3 import Web3, Account, HTTPProvider
from web3.middleware import construct_sign_and_send_raw_middleware
from web3.exceptions import TransactionNotFound
from eth_keys import keys
from eth_account.messages import encode_defunct
import siwe
from google.protobuf import timestamp_pb2

# our protobuf schema
from massmarket_hash_event import (
    hash_event,
    error_pb2,
    subscription_pb2,
    transport_pb2,
    authentication_pb2,
    shop_requests_pb2,
    shop_events_pb2 as mevents,
    base_types_pb2 as mtypes,
)
from massmarket_hash_event.envelope_pb2 import Envelope


class RelayException(Exception):
    def __init__(self, err: error_pb2.Error):
        super().__init__(err.message)
        self.message = err.message
        self.code = err.code


class EnrollException(Exception):
    def __init__(self, http_code, err: str):
        super().__init__(err)
        self.http_code = http_code
        self.message = err


class NamedTag:
    def __init__(self, name, listings):
        self.name = name
        self.listings = listings


class PriceTotals:
    def __init__(self, subtotal, sales_tax, total):
        self.subtotal = subtotal
        self.sales_tax = sales_tax
        self.total = total


class Order:
    def __init__(self, id):
        self.id = id
        self.items = {}
        self.state = "open"
        self.purchase_address = None
        self.total = None
        self.payment_id = None
        self.payment_ttl = None


# creates a compound id for inventory checks etc
def vid(listing_id: int, variations: Optional[List[int]] = None):
    id = str(listing_id) + ":"
    if variations:
        variations.sort()
        id = id + ":".join([str(v) for v in variations]) + ":"
    return id


def to_32byte_hex(val):
    return Web3.to_hex(Web3.to_bytes(val).rjust(32, b"\0"))


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


def uint256_to_int(u: mtypes.Uint256) -> int:
    assert len(u.raw) == 32
    return int.from_bytes(u.raw, "big")


def int_to_uint256(i):
    return mtypes.Uint256(raw=int(i).to_bytes(32, "big"))


def now_pbts() -> timestamp_pb2.Timestamp:
    now = datetime.datetime.utcnow()
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(now)
    return ts


def new_object_id(i=None):
    r = random.randbytes(8) if i is None else i.to_bytes(8, "big")
    return mtypes.ObjectId(raw=r)


def transact_with_retry(w3, account, contract_call, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
            max_priority_fee = w3.eth.max_priority_fee

            # Increase the safety margin with each attempt
            safety_margin = 1.2 + (0.1 * attempt)
            max_fee = int(base_fee * safety_margin) + max_priority_fee

            tx = contract_call.build_transaction(
                {
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": max_priority_fee,
                    "nonce": w3.eth.get_transaction_count(account.address),
                }
            )

            signed_tx = w3.eth.account.sign_transaction(tx, account.key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            return tx_hash
        except ValueError as e:
            assert (
                attempt < max_attempts
            ), f"Failed to transact contract call after {max_attempts} attempts"
            continue


def check_transaction(w3, tx, max_retries=10, initial_delay=0.5):
    for attempt in range(max_retries):
        try:
            receipt = w3.eth.get_transaction_receipt(tx)
            if receipt is None:
                continue  # retry
            if receipt["status"] == 1:
                return True
            elif receipt["status"] == 0:
                raise ValueError(f"Transaction {tx.hex()} failed")

        except TransactionNotFound:
            if attempt == max_retries - 1:
                raise TimeoutError(
                    f"Transaction {tx.hex()} not found after {max_retries} attempts"
                )

            backoff_time = initial_delay * (2**attempt)
            print(
                f"check_tx: retrying to find {tx.hex()} in {backoff_time:.2f} seconds..."
            )
            time.sleep(backoff_time)

    raise TransactionNotFound()


def notFoundError(msg):
    return error_pb2.Error(
        code=error_pb2.ERROR_CODES_NOT_FOUND,
        message=msg,
    )


def invalidError(msg):
    return error_pb2.Error(
        code=error_pb2.ERROR_CODES_INVALID,
        message=msg,
    )


class RelayClient:

    def __init__(
        self,
        name="Alice",
        wallet_account=None,
        wallet_private_key=None,
        key_card_private_key=None,
        guest=False,
        relay_token_id=None,
        chain_id=None,
        auto_connect=True,
        debug=False,
    ):
        self.name = name
        self.debug = debug

        self.relay_http_address = os.getenv("RELAY_HTTP_ADDRESS")
        assert self.relay_http_address is not None, "RELAY_HTTP_ADDRESS is not set"
        print(f"{name} is using relay: {self.relay_http_address}")
        relay_addr = urlparse(self.relay_http_address)
        self.relay_addr = relay_addr

        relay_ping = os.getenv("RELAY_PING")
        assert relay_ping is not None, "RELAY_PING is not set"
        self.relay_ping = float(relay_ping)

        # construct and dial websocket endpoint
        relay_ws_endpoint = relay_addr._replace(path="/v3/sessions")
        if relay_addr.scheme == "http":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="ws")
        elif relay_addr.scheme == "https":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="wss")
        else:
            raise Exception("Unknown Relay HTTP scheme: {}".format(relay_addr.scheme))
        self.relay_ws_endpoint_url = relay_ws_endpoint.geturl()
        print(f"{name} has ws endpoint: {self.relay_ws_endpoint_url}")

        # connection setup
        self.connected = False
        self.connection = None
        if auto_connect:
            health_resp = requests.get(
                self.relay_http_address + "/health",
                headers={"Origin": "localhost"},
            )
            if health_resp.status_code != 200:
                raise Exception(f"relay health check failed")
            self.connect()

        self.logged_in = False
        self.pongs = 0
        self.outgoingRequests = {}
        self.subscription = None
        self.errors = 0
        self.expect_error = False
        self.last_error = None

        if relay_token_id == None:
            # request testing info from relay
            discovery_resp = requests.get(
                self.relay_http_address + "/testing/discovery",
                headers={"Origin": "localhost"},
            )
            if discovery_resp.status_code != 200:
                raise Exception(
                    f"Discovery request failed with status code: {discovery_resp.status_code}"
                )
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
        self.w3.provider.cache_allowed_requests = True
        self.__load_contracts()
        self.account = None
        if not wallet_account and not wallet_private_key:
            raise Exception("need to define either private key or account")
        account = (
            wallet_account if wallet_account else Account.from_key(wallet_private_key)
        )
        print("{} is using address: {}".format(name, account.address))
        self.account = account
        self.w3.eth.default_account = account.address
        sign_mw = construct_sign_and_send_raw_middleware(self.account)
        self.w3.middleware_onion.add(sign_mw)

        # mass state
        self.last_request_id = 0
        self.is_guest = guest
        if key_card_private_key is None:
            self.own_key_card = Account.create()
            print(f"new key card: {self.own_key_card}")
        else:
            self.own_key_card = Account.from_key(key_card_private_key)
        self.last_event_nonce = 1  # TODO persist!
        self.valid_addrs = []
        self.all_key_cards = {}
        self.accounts = {}
        self.shop_token_id = 0
        self.last_shop_seq_no = 0
        self.manifest = None
        self.default_currency = mtypes.ShopCurrency(
            address=mtypes.EthereumAddress(raw=bytes(20)),
            chain_id=self.chain_id,
        )
        self.default_payee = mtypes.Payee(
            name="default",
            address=mtypes.EthereumAddress(raw=bytes.fromhex(self.account.address[2:])),
            chain_id=self.chain_id,
        )
        self.listings: Dict[bytes, mevents.Listing] = {}
        self.inventory: Dict[bytes, int] = {}
        self.tags: Dict[bytes, NamedTag] = {}
        self.orders: Dict[bytes, Order] = {}
        self.currencies: List[mtypes.ShopCurrency] = []
        self.payees: Dict[str, mtypes.Payee] = {}
        self.pricing_currency: Optional[mtypes.ShopCurrency] = None

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None
        self.connected = False
        self.logged_in = False
        self.last_request_id = 0
        self.errors = 0

    def next_request_id(self):
        next = self.last_request_id + 1
        req_id = mtypes.RequestId(raw=next)
        self.last_request_id = next
        return req_id

    def print_state(self):
        print("Shop State:")
        print("-----------")

        print("Currencies:")
        if len(self.currencies) == 0:
            print(" No currencies set up")
        else:
            for curr in self.currencies:
                print(f"  ChainID: {curr.chain_id} Addr: {curr.address.raw.hex()}")

        if self.pricing_currency is None:
            print(" No base currency!")
        else:
            b = self.pricing_currency
            print(
                f"Base Currency:\n  ChainID: {b.chain_id} Addr: {b.address.raw.hex()}"
            )

        if len(self.payees) == 0:
            print(" No Payees set up ")
        else:
            print("Payees:")
            for name, p in self.payees.items():
                print(
                    f"  {name}: ChainID: {p.chain_id} Addr: {p.address.raw.hex()} (isEndpoint: {p.call_as_contract})"
                )

        print("\nListings:")
        if not self.listings:
            print("  No listings available.")
        else:
            for listing_id, listing in self.listings.items():
                display_price = int.from_bytes(listing.price.raw, "big")
                print(f"  Listing ID: {listing_id}")
                print(f"    Price: {display_price}")
                # TODO: variations
                if listing_id in self.inventory:
                    print(f"    Stock: {self.inventory[listing_id]}")
                else:
                    print("    Stock: Not available")
                print(f"    Metadata: {listing.metadata}")

        print("\nOrders:")
        if not self.orders:
            print("  No orders available.")
        else:
            for order_id, order in self.orders.items():
                if order is None:
                    print(f"  Order ID: {order_id} (Canceled)")
                    continue
                # TODO: use new timestamps
                print(f"  Order ID: {order_id}")
                print(f"    Payed: {order.payed}")
                print(f"    Finalized: {order.finalized}")
                if order.finalized:
                    print(f"    Totals:")
                    print(f"      Total: {order.total}")
                    print(f"      Payment ID: {order.payment_id}")
                    print(f"      Payment TTL: {order.payment_ttl}")
                    print(f"    Items:")
                    for listing_id, quantity in order.items.items():
                        print(f"      Listing ID: {listing_id} Quantity: {quantity}")

        print("\nTags:")
        if not self.tags:
            print("  No tags available.")
        else:
            for tag_id, tag in self.tags.items():
                print(f"  Tag ID: {tag_id}")
                print(f"    Name: {tag.name}")
                for listing_id in tag.listings:
                    print(f"    Listing ID: {listing_id}")

        # Print key cards
        print("\nKey Cards:")
        if not self.all_key_cards:
            print("  No key cards available.")
        else:
            for card_public_key, user_wallet_addr in self.all_key_cards.items():
                print(f"  Key Card: 0x{card_public_key.hex()}")
                print(f"    User Wallet Address: {user_wallet_addr.raw.hex()}")

    def __load_contracts(self):
        contracts_path = os.getenv("MASS_CONTRACTS")
        assert contracts_path is not None, "MASS_CONTRACTS is not set"

        addresses = json.loads(
            open(contracts_path + "/deploymentAddresses.json", "r").read()
        )
        print("using contracts:")
        pprint(addresses)

        relayRegABI = open(contracts_path + "/abi/RelayReg.json", "r").read()
        self.relayReg = self.w3.eth.contract(
            address=addresses["RelayReg"], abi=relayRegABI
        )

        shopRegABI = open(contracts_path + "/abi/ShopReg.json", "r").read()
        self.shopReg = self.w3.eth.contract(
            address=addresses["ShopReg"], abi=shopRegABI
        )

        erc20TestingTokenABI = open(contracts_path + "/abi/Eddies.json", "r").read()
        self.erc20Token = self.w3.eth.contract(
            address=addresses["Eddies"], abi=erc20TestingTokenABI
        )

        paymentsABI = open(contracts_path + "/abi/PaymentsByAddress.json", "r").read()
        self.payments = self.w3.eth.contract(
            address=addresses["Payments"], abi=paymentsABI
        )

    def check_tx(self, tx):
        check_transaction(self.w3, tx)

    def transact_with_retry(self, func, max_attempts=10):
        return transact_with_retry(
            self.w3, self.account, func, max_attempts=max_attempts
        )

    def register_shop(self):
        token_id = int.from_bytes(os.urandom(32), "big")
        tx = self.transact_with_retry(
            self.shopReg.functions.mint(token_id, self.account.address)
        )
        self.check_tx(tx)
        self.shop_token_id = token_id
        print(f"shopTokenID: {self.shop_token_id}")
        # check admin access
        tx = self.transact_with_retry(
            self.shopReg.functions.updateRootHash(self.shop_token_id, os.urandom(32), 1)
        )
        self.check_tx(tx)
        self.add_relay_to_shop(self.relay_token_id)
        return token_id

    def add_relay_to_shop(self, relay_token):
        # get current relays and add them
        if self.shopReg.functions.getRelayCount(self.shop_token_id).call() > 0:
            current_relay_tokens = self.shopReg.functions.getAllRelays(
                self.shop_token_id
            ).call()
            if relay_token in current_relay_tokens:
                return
        # update the relays assigned to this shop
        tx = self.transact_with_retry(
            self.shopReg.functions.addRelay(self.shop_token_id, relay_token)
        )
        self.check_tx(tx)

    def create_invite(self):
        reg_secret = os.urandom(32)
        acc = Account.from_key(reg_secret)
        print("addr of token: {}".format(acc.address))
        tx = self.transact_with_retry(
            self.shopReg.functions.publishInviteVerifier(
                self.shop_token_id, acc.address
            )
        )
        self.check_tx(tx)
        return reg_secret

    def redeem_invite(self, token):
        acc = Account.from_key(token)
        msg_text = f"enrolling:{self.account.address}"
        msg = encode_defunct(text=msg_text.lower())
        sig = acc.sign_message(msg)
        rhex = to_32byte_hex(sig.r)
        shex = to_32byte_hex(sig.s)
        tx = self.transact_with_retry(
            self.shopReg.functions.redeemInvite(
                self.shop_token_id, sig.v, rhex, shex, self.account.address
            )
        )
        self.check_tx(tx)

    def enroll_key_card(self, siwe_msg=None):
        keyCard = keys.PrivateKey(self.own_key_card.key)

        modified_url = self.relay_addr._replace(path="/v3/enroll_key_card")
        if self.is_guest:
            modified_url = modified_url._replace(query="guest=1")
        enroll_url = modified_url.geturl()

        if self.shop_token_id is None:
            raise Exception("shop_token_id unset")

        if siwe_msg is None:
            kc_hex = keyCard.public_key.to_hex()

            now = datetime.datetime.utcnow().isoformat() + "Z"
            siwe_msg = siwe.SiweMessage(
                domain=self.relay_addr.netloc,
                address=self.account.address,
                uri=enroll_url,
                version="1",
                chain_id=self.chain_id,
                nonce="00000000",  # keyCards can only be enrolled once
                issued_at=now,
                statement=f"keyCard: {kc_hex}",
                resources=[
                    f"mass-relayid:{self.relay_token_id}",
                    f"mass-shopid:{self.shop_token_id}",
                    f"mass-keycard:{kc_hex}",
                ],
            )

        data = siwe_msg.prepare_message()
        encoded_data = encode_defunct(text=data)
        signed_message = self.account.sign_message(encoded_data)
        signature = signed_message.signature

        json_data = json.dumps(
            {
                "signature": base64.b64encode(signature).decode("utf-8"),
                "message": data,
            }
        )

        max_retries = 5
        retry_delay = 1  # Initial delay in seconds
        response = None
        for attempt in range(max_retries):
            response = requests.post(
                enroll_url, data=json_data, headers={"Origin": "localhost"}
            )

            if response.status_code != 429:
                break

            if attempt < max_retries - 1:
                sleep_time = retry_delay * (2**attempt)  # Exponential backoff
                print(f"Rate limited. Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)

        if response is None:
            raise Exception("Failed to enroll key card")

        respData = response.json()
        if response.status_code != 201 or "error" in respData:
            raise EnrollException(
                response.status_code, respData.get("error", "Unknown error")
            )
        assert respData["success"] == True
        print(f"{self.name} enrolled keyCard {keyCard.public_key.to_hex()}")

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
        msg = Envelope()
        msg.ParseFromString(data)
        type = msg.WhichOneof("message")
        req_id = msg.request_id.raw
        if self.debug:
            print(f"{self.name} received message_type={type} reqId={req_id}")
        if type == "ping_request":
            self.handle_ping_request(msg)
        elif type == "response":
            assert req_id in self.outgoingRequests
            req_data = self.outgoingRequests[req_id]
            assert req_data is not None
            req_data["handler"](msg)
        elif type == "sync_status_request":
            self.handle_sync_status_request(msg)
        elif type == "subscription_push_request":
            self.handle_event_push_request(msg)
        else:
            err = f"Unknown message type: {type}"
            self.errors += 1
            self.last_error = error_pb2.Error(
                code=error_pb2.ERROR_CODES_INVALID, message=err
            )
            if self.expect_error:
                print(f"Expected error: {msg}")
            else:
                raise Exception(err)

    def handle_ping_request(self, req: Envelope):
        resp = Envelope(
            request_id=req.request_id,
            response=Envelope.GenericResponse(),
        )
        data = resp.SerializeToString()
        try:
            self.connection.send(data)
        except ConnectionClosedError as err:
            self.connected = False
            # print(f"{self.name} failed to respond to ping")
        else:
            # print(f"{self.name} sent a pong to request_id {req.request_id.raw}")
            self.pongs += 1

    def handle_sync_status_request(self, env: Envelope):
        req = env.sync_status_request
        if self.debug:
            print("SyncStatusRequest: unpushedEvents={}".format(req.unpushed_events))
        resp = Envelope(
            request_id=env.request_id,
            response=Envelope.GenericResponse(),
        )
        data = resp.SerializeToString()
        self.connection.send(data)

    def _check_expected_request(self, req_id: mtypes.RequestId, clean=False):
        ours = req_id.raw
        if ours not in self.outgoingRequests:
            raise Exception(f"Received reponse for unknown request id={ours}")
        if clean:
            del self.outgoingRequests[ours]

    def handle_authenticate_response(self, msg: Envelope):
        resp = msg.response
        if resp.HasField("error"):
            raise RelayException(resp.error)
        self._check_expected_request(msg.request_id, clean=True)
        encoded_data = encode_defunct(resp.payload)
        signed_message = self.own_key_card.sign_message(encoded_data)
        signature = signed_message.signature
        req_id = self.next_request_id()
        csr = Envelope(
            request_id=req_id,
            challenge_solution_request=authentication_pb2.ChallengeSolvedRequest(
                signature=mtypes.Signature(raw=signature),
            ),
        )
        data = csr.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "handler": self.handle_challenge_solved_response,
        }

    def handle_challenge_solved_response(self, msg: Envelope):
        resp = msg.response
        if resp.HasField("error"):
            raise Exception(f"Challenge failed: '{resp.error}'")
        self._check_expected_request(msg.request_id, clean=True)
        self.logged_in = True

    def handle_get_blob_upload_url_response(self, msg: Envelope):
        resp = msg.response
        if resp.HasField("error"):
            raise RelayException(resp.error)
        req_id = msg.request_id
        self._check_expected_request(req_id, clean=False)
        url = resp.payload.decode("utf-8")
        if self.debug:
            print(f"blobUrl: id={req_id.raw} url={url}")
        self.outgoingRequests[req_id.raw] = {"url": url}

    def handle_event_write_response(self, msg: Envelope):
        resp = msg.response
        if self.debug:
            print(f"EventWriteResponse: {resp}")
        req_id = msg.request_id
        self._check_expected_request(req_id, clean=True)
        if resp.WhichOneof("response") == "error":
            self.errors += 1
            if self.expect_error:
                print(f"Expected error: {resp.error}")
                self.last_error = resp.error
                self.outgoingRequests[req_id.raw] = {"err": resp.error}
            else:
                raise RelayException(resp.error)
        else:
            self.outgoingRequests[req_id.raw] = {
                "new_state_hash": resp.payload,
            }

    def handle_subscription_response(self, msg: Envelope):
        resp = msg.response
        if self.debug:
            print(f"SubscriptionResponse: {resp}")
        req_id = msg.request_id
        self._check_expected_request(req_id, clean=True)
        if resp.WhichOneof("response") == "error":
            self.errors += 1
            if self.expect_error:
                print(f"Expected error: {resp.error}")
                self.last_error = resp.error
                self.outgoingRequests[req_id.raw] = {"err": resp.error}
            else:
                raise RelayException(resp.error)
        else:
            assert len(resp.payload) == 2
            id = int.from_bytes(resp.payload, "big")
            self.outgoingRequests[req_id.raw] = {
                "subscription_id": id,
            }
            self.subscription = id
            # TODO: update subscription details

    def handle_subscription_cancel_response(self, msg: Envelope):
        resp = msg.response
        if self.debug:
            print(f"SubscriptionCancelResponse: {resp}")
        req_id = msg.request_id
        self._check_expected_request(req_id, clean=False)
        if resp.WhichOneof("response") == "error":
            self.errors += 1
            if self.expect_error:
                print(f"Expected error: {resp.error}")
                self.last_error = resp.error
                self.outgoingRequests[req_id.raw] = {"err": resp.error}
            else:
                raise RelayException(resp.error)
        else:
            del self.outgoingRequests[req_id.raw]["waiting"]
            subscription_id = self.outgoingRequests[req_id.raw]["subscription_id"]
            assert subscription_id == self.subscription
            self.subscription = None

    def handle_event_push_request(self, msg: Envelope):
        req = msg.subscription_push_request
        if self.debug:
            print(
                f"{self.name} EventPushRequest reqID={msg.request_id.raw} events={len(req.events)}"
            )
        err = None
        last_seq_no = None
        for sig_evt in req.events:
            evt = mevents.ShopEvent()
            assert sig_evt.event.event.TypeName() == "market.mass.ShopEvent"
            sig_evt.event.event.Unpack(evt)
            signed_by = self._verify_event(sig_evt.event)
            which = evt.WhichOneof("union")
            if self.debug:
                print(
                    f"{self.name}/newEvent shopSeq:{sig_evt.seq_no} nonce:{evt.nonce} kc:{signed_by} type:{which}"
                )
                pprint(evt)
            last_seq_no = sig_evt.seq_no
            if which == "manifest":
                self.manifest = evt.manifest
                for p in evt.manifest.payees:
                    self.payees[p.name] = p
                for add in evt.manifest.accepted_currencies:
                    self.currencies.append(add)
                if evt.manifest.pricing_currency:
                    self.pricing_currency = evt.manifest.pricing_currency
            elif which == "update_manifest":
                um = evt.update_manifest
                for add in um.add_accepted_currencies:
                    self.currencies.append(add)
                for rm in um.remove_accepted_currencies:
                    self.currencies.remove(rm)
                if um.HasField("add_payee"):
                    p = um.add_payee
                    self.payees[p.name] = p
                if um.HasField("set_pricing_currency"):
                    self.pricing_currency = um.set_pricing_currency
            elif which == "listing":
                ci = evt.listing
                self.listings[ci.id.raw] = ci
            elif which == "update_listing":
                ui = evt.update_listing
                if ui.id.raw not in self.listings:
                    err = notFoundError(f"unknown listing: {ui.id}")
                else:
                    listing = self.listings[ui.id.raw]
                    if ui.HasField("price"):
                        listing.price.CopyFrom(ui.price)
                    if ui.HasField("view_state"):
                        listing.view_state = ui.view_state
                    if ui.HasField("metadata"):
                        # more partial updates :S
                        if ui.metadata.title:
                            listing.metadata.title = ui.metadata.title
                        if ui.metadata.images:
                            listing.metadata.ClearField("images")
                            listing.metadata.images.MergeFrom(ui.metadata.images)
                    for opt in ui.add_options:
                        # check if option id already exists
                        for existing in listing.options:
                            if existing.id == opt.id:
                                err = invalidError(f"option already exists: {opt.id}")
                        listing.options.append(opt)
                    for id in ui.remove_option_ids:
                        found = False
                        for opt in listing.options:
                            if opt.id == id:
                                listing.options.remove(opt)
                                found = True
                                break
                        if not found:
                            err = notFoundError(f"unknown option to remove: {id}")
                    for av in ui.add_variations:
                        found = False
                        for opt in listing.options:
                            if opt.id == av.option_id:
                                opt.variations.append(av.variation)
                                found = True
                                break
                        if not found:
                            err = notFoundError(
                                f"unknown option to add variation to: {av.option_id}"
                            )
                    for id in ui.remove_variation_ids:
                        found = False
                        for opt in listing.options:
                            for v in opt.variations:
                                if v.id == id:
                                    opt.variations.remove(v)
                                    found = True
                                    break
                        if not found:
                            err = notFoundError(f"unknown variation to remove: {id}")
                    self.listings[ui.id.raw] = listing
            elif which == "tag":
                ct = evt.tag
                if ct.id.raw in self.tags:
                    err = invalidError(f"tag already exists: {ct.id}")
                else:
                    self.tags[ct.id.raw] = NamedTag(ct.name, [])
            elif which == "update_tag":
                ut = evt.update_tag
                tid = ut.id.raw
                if tid not in self.tags:
                    err = notFoundError(f"unknown tag: {tid}")
                else:
                    for id in ut.add_listing_ids:
                        aid = id.raw
                        if aid not in self.listings:
                            err = notFoundError(f"unknown listing: {aid}")
                        else:
                            self.tags[tid].listings.append(aid)

                    for id in ut.remove_listing_ids:
                        rid = id.raw
                        if rid not in self.listings:
                            err = notFoundError(f"unknown listing: {rid}")
                        else:
                            self.tags[tid].listings.remove(rid)
                    if ut.HasField("rename"):
                        self.tags[tid].name = ut.rename
                    if ut.HasField("delete"):
                        del self.tags[tid]
            elif which == "change_inventory":
                cs = evt.change_inventory
                if cs.id.raw not in self.listings:
                    err = notFoundError(f"unknown listing: {cs.id}")
                else:
                    lookup_id = vid(cs.id, cs.variation_ids)
                    self.inventory[lookup_id] = (
                        self.inventory.get(lookup_id, 0) + cs.diff
                    )
            elif which == "create_order":
                cc = evt.create_order
                if cc.id.raw in self.orders:
                    err = invalidError(f"order already exists: {cc.id}")
                else:
                    self.orders[cc.id.raw] = Order(cc.id)
            elif which == "update_order":
                uo = evt.update_order
                oid = uo.id.raw
                if oid not in self.orders:
                    err = notFoundError(f"unknown order: {oid}")
                order = self.orders[oid]

                action = uo.WhichOneof("action")
                if self.debug:
                    print(f"{self.name} updating order {oid} with action {action}")
                if action == "change_items":
                    ci = uo.change_items
                    # TODO: variations
                    for ai in ci.adds:
                        aid = ai.listing_id.raw
                        if aid not in self.listings:
                            err = notFoundError(f"unknown listing: {aid}")
                        else:
                            if aid not in order.items:
                                order.items[aid] = 0
                                order.items[aid] += ai.quantity
                                self.orders[oid] = order
                    for ri in ci.removes:
                        rid = ri.listing_id.raw
                        if rid not in self.listings:
                            err = notFoundError(f"unknown listing: {rid}")
                        else:
                            if rid not in order.items:
                                order.items[rid] = 0
                                order.items[rid] -= ri.quantity
                                self.orders[oid] = order
                elif action == "commit_items":
                    order.state = "committed"
                    self.orders[oid] = order
                elif action == "set_payment_details":
                    cf = uo.set_payment_details
                    if self.debug:
                        print(f"Order payment details:\n{cf}")
                    order.finalized = True
                    order.listing_hashes = cf.listing_hashes
                    order.total = int.from_bytes(cf.total.raw, byteorder="big")
                    order.payment_id = int.from_bytes(
                        cf.payment_id.raw, byteorder="big"
                    )
                    order.payment_ttl = int(cf.ttl)
                    order.chosen_region = cf.shipping_region
                    order.state = "unpayed"
                    self.orders[oid] = order
                elif action == "cancel":
                    ca = uo.cancel
                    self.orders[oid].state = "canceled"
                elif action == "add_payment_tx":
                    order.state = "payed"
                    # TODO: track block hash etc?
                    self.orders[oid] = order

            elif which == "account":
                acc = evt.account
                action = acc.WhichOneof("action")
                if action == "add":
                    addr = acc.add.account_address.raw.hex()
                    self.accounts[addr] = acc.add
                    if self.debug:
                        print(f"{self.name} onchain add of {addr}")
                elif action == "remove":
                    addr = acc.remove.account_address.raw.hex()
                    del self.accounts[addr]
                    if self.debug:
                        print(f"{self.name} onchain remove of {addr}")
                elif action == "enroll_keycard":
                    nkc = acc.enroll_keycard
                    if nkc.keycard_pubkey.raw in self.all_key_cards:
                        err = invalidError(
                            f"key card already exists: {nkc.keycard_pubkey.raw.hex()}"
                        )
                    else:
                        if self.debug:
                            print(
                                f"{self.name} adding keyCard=0x{nkc.keycard_pubkey.raw.hex()} for user={nkc.user_wallet.raw.hex()}"
                            )
                        self.all_key_cards[nkc.keycard_pubkey.raw] = nkc.user_wallet
                        self.valid_addrs.append(
                            public_key_to_address(nkc.keycard_pubkey.raw).lower()
                        )
                else:
                    err = invalidError(f"unhandled acount.action type: {action}")

            else:
                err = invalidError(f"unhandled event type: {which}")
        resp = Envelope(
            request_id=msg.request_id,
            response=Envelope.GenericResponse(error=err),
        )
        data = resp.SerializeToString()
        assert self.connection is not None, "not connected"
        self.connection.send(data)
        if err is not None:
            raise Exception(f"{err.code}: {err.message}")
        if self.debug:
            self.print_state()
        # Update the last processed seq_no
        if last_seq_no is not None:
            self.last_shop_seq_no = max(self.last_shop_seq_no, last_seq_no)

    def connect(self):
        if not self.connected:
            max_retries = 10
            retry_delay = 2  # Initial delay in seconds

            for attempt in range(max_retries):
                try:
                    self.connection = connect(
                        self.relay_ws_endpoint_url,
                        origin="localhost",
                        close_timeout=0.5,
                    )
                    self.connected = True
                    break
                except InvalidStatus as e:
                    if e.response.status_code == 429:
                        assert (
                            attempt < max_retries - 1
                        ), "Max retries reached. Unable to connect."
                        sleep_time = retry_delay * (2**attempt)  # Exponential backoff
                        print(f"Rate limited. Retrying in {sleep_time} seconds...")
                        time.sleep(sleep_time)
                    else:
                        raise e

    def authenticate(self):
        kc = keys.PrivateKey(self.own_key_card.key)
        # print('public key: ' + kc.public_key.to_hex())
        req_id = self.next_request_id()
        ar = authentication_pb2.AuthenticateRequest(
            public_key=mtypes.PublicKey(raw=kc.public_key.to_bytes()),
        )
        msg = Envelope(
            request_id=req_id,
            auth_request=ar,
        )
        data = msg.SerializeToString()
        self.outgoingRequests[req_id.raw] = {
            "waiting": True,
            "handler": self.handle_authenticate_response,
        }
        self.connection.send(data)
        timeout = 10
        while req_id.raw in self.outgoingRequests:
            print(f"waiting for authenticate response")
            self.handle_all()
            timeout -= 1
            assert timeout > 0, "no authenticate response in time"
        timeout = 10
        while not self.logged_in:  # wait for challenge resp
            print(f"waiting for challenge response")
            self.handle_all()
            assert self.last_error is None, f"Error: {self.last_error}"
            timeout -= 1
            assert timeout > 0, "no challenge response in time"
        assert self.logged_in, "login failed"

    def login(self, subscribe=True):
        if not self.connected:
            self.connect()
        self.authenticate()
        if subscribe:
            self.subscribe_all()

    def get_blob_upload_url(self):
        req_id = self.next_request_id()
        ewr = shop_requests_pb2.GetBlobUploadURLRequest()
        msg = Envelope(
            request_id=req_id,
            get_blob_upload_url_request=ewr,
        )
        data = msg.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "handler": self.handle_get_blob_upload_url_response,
            "waiting": True,
        }
        return req_id.raw

    def _assert_shop_against_response(self, req_id: mtypes.RequestId):
        got_hash = self.outgoingRequests[req_id.raw]["new_state_hash"]
        has_hash = self._hash_shop()
        assert got_hash == has_hash, f"shop hash mismatch: {got_hash} != {has_hash}"
        return got_hash

    def _hash_shop(self):
        return b"todo" * 8  # TODO: merklization spec
        if self.manifest is None:
            return os.urandom(32)
        manifest_hash = keccak_256()
        # pprint(self.manifest)
        manifest_hash.update(self.manifest.shop_token_id)
        manifest_hash.update(self.manifest.domain.encode("utf-8"))
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
        for id in self.inventory:
            stock_ids.append(id)
        stock_ids.sort()
        for id in stock_ids:
            count = self.inventory[id]
            if count is None:
                raise Exception("not in stock?!")
            stock_hash.update(id)
            stock_hash.update(str(count).encode("utf-8"))
        # print("stock: {}".format(stock_hash.hexdigest()))

        root_hash = keccak_256()
        root_hash.update(manifest_hash.digest())
        root_hash.update(pub_tag_hash.digest())
        root_hash.update(stock_hash.digest())
        return root_hash.digest()

    def subscribe_all(self):
        all = [
            subscription_pb2.SubscriptionRequest.Filter(object_type=t)
            for t in subscription_pb2.ObjectType.keys()[1:]
        ]
        return self.subscribe(all)

    def subscribe_visitor(self):
        types = [
            "OBJECT_TYPE_LISTING",
            "OBJECT_TYPE_TAG",
            "OBJECT_TYPE_ACCOUNT",
            "OBJECT_TYPE_MANIFEST",
        ]
        f = [subscription_pb2.SubscriptionRequest.Filter(object_type=t) for t in types]
        return self.subscribe(f)

    def subscribe_customer(self):
        types = [
            "OBJECT_TYPE_LISTING",
            "OBJECT_TYPE_TAG",
            "OBJECT_TYPE_ACCOUNT",
            "OBJECT_TYPE_ORDER",
            "OBJECT_TYPE_MANIFEST",
        ]
        f = [subscription_pb2.SubscriptionRequest.Filter(object_type=t) for t in types]
        return self.subscribe(f)

    def subscribe_order(self, id=None):
        f = [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_ORDER",
                object_id=id,
            )
        ]
        self.subscribe(f)

    def subscribe(self, filters):
        req_id = self.next_request_id()
        req = subscription_pb2.SubscriptionRequest(
            start_shop_seq_no=self.last_shop_seq_no,
            shop_id=mtypes.Uint256(raw=self.shop_token_id.to_bytes(32, "big")),
            filters=filters,
        )
        msg = Envelope(
            request_id=req_id,
            subscription_request=req,
        )
        data = msg.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "waiting": True,
            "handler": self.handle_subscription_response,
        }
        # TODO: timeout
        timeout = 100
        while "waiting" in self.outgoingRequests[req_id.raw]:
            print(f"{self.name} subscription waiting")
            self.handle_all()
            assert timeout > 0, "timeout"
            timeout -= 1
        resp = self.outgoingRequests[req_id.raw]
        if not self.expect_error:
            id = resp["subscription_id"]
            print(f"{self.name} subscription: {id} open")
            return id
        else:
            return resp

    def cancel_subscription(self, id):
        req_id = self.next_request_id()
        req = subscription_pb2.SubscriptionCancelRequest(
            subscription_id=id.to_bytes(2, "big"),
        )
        msg = Envelope(
            request_id=req_id,
            subscription_cancel_request=req,
        )
        data = msg.SerializeToString()
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "waiting": True,
            "subscription_id": id,
            "handler": self.handle_subscription_cancel_response,
        }
        # TODO: timeout
        while "waiting" in self.outgoingRequests[req_id.raw]:
            print(f"{self.name} subscription cancel waiting")
            self.handle_all()

    def _sign_event(self, evt: mevents.ShopEvent):
        encoded_data = hash_event(evt)
        keyCardPK = Account.from_key(self.own_key_card.key)
        signed_message = keyCardPK.sign_message(encoded_data)
        # print(f"hash: {signed_message.messageHash.hex()}")
        return signed_message

    # an actual implementation would probably cache the relays
    def _valid_event_signing_addresses(self):
        if len(self.valid_addrs) != 0:
            return self.valid_addrs
        else:
            all = []
            # retreive all relays nfts
            if self.shopReg.functions.getRelayCount(self.shop_token_id).call() > 0:
                all_relay_token_ids = self.shopReg.functions.getAllRelays(
                    self.shop_token_id
                ).call()
                for token_id in all_relay_token_ids:
                    # retreive the owner => it's address
                    relay_address = self.relayReg.functions.ownerOf(token_id).call()
                    all.append(relay_address.lower())

            # turn key cards into addresses
            key_card_addresses = [
                public_key_to_address(pk).lower()
                for pk in list(self.all_key_cards.keys())
            ]
            all.extend(key_card_addresses)
            self.valid_addrs = all
            return all

    def _verify_event(self, evt: transport_pb2.SignedEvent):
        sig = evt.signature.raw
        if len(sig) != 65:
            raise Exception(f"Invalid signature length: {len(sig)}")
        encoded_data = encode_defunct(evt.event.value)
        pub_key = self.w3.eth.account.recover_message(encoded_data, signature=sig)
        # print(f"{self.name} received event from recovered pub_key: {pub_key}")
        their_addr = Web3.to_checksum_address(pub_key).lower()
        valid_addrs = self._valid_event_signing_addresses()
        if their_addr not in valid_addrs:
            print(f"valid addresses: {valid_addrs}")
            raise Exception("Event signed by unknown address: {}".format(their_addr))
        return their_addr

    def _write_event(self, **kwargs):
        sig_evt = self._create_event(**kwargs)
        # default wait to yes
        wait = kwargs.get("wait")
        wait = True if wait is None else wait
        return self._send_event(sig_evt, wait)

    def _create_event(
        self,
        manifest: Optional[mevents.Manifest] = None,
        update_manifest: Optional[mevents.UpdateManifest] = None,
        listing: Optional[mevents.Listing] = None,
        update_listing: Optional[mevents.UpdateListing] = None,
        change_inventory: Optional[mevents.ChangeInventory] = None,
        tag: Optional[mevents.Tag] = None,
        update_tag: Optional[mevents.UpdateTag] = None,
        create_order: Optional[mevents.CreateOrder] = None,
        update_order: Optional[mevents.UpdateOrder] = None,
        wait: bool = True,
    ):
        shop_evt = mevents.ShopEvent(
            nonce=self.last_event_nonce,
            shop_id=mtypes.Uint256(raw=self.shop_token_id.to_bytes(32, "big")),
            timestamp=now_pbts(),
        )
        self.last_event_nonce += 1
        # TODO: kwargs?
        if manifest:
            shop_evt.manifest.CopyFrom(manifest)
        elif update_manifest:
            shop_evt.update_manifest.CopyFrom(update_manifest)
        elif listing:
            shop_evt.listing.CopyFrom(listing)
        elif update_listing:
            shop_evt.update_listing.CopyFrom(update_listing)
        elif change_inventory:
            shop_evt.change_inventory.CopyFrom(change_inventory)
        elif tag:
            shop_evt.tag.CopyFrom(tag)
        elif update_tag:
            shop_evt.update_tag.CopyFrom(update_tag)
        elif create_order:
            shop_evt.create_order.CopyFrom(create_order)
        elif update_order:
            shop_evt.update_order.CopyFrom(update_order)
        else:
            raise Exception("unhandled event type")
        # TODO: deubg flag
        # print(f"{self.name} writes:")
        # pprint(shop_evt)
        msg = self._sign_event(shop_evt)
        wrapped = anypb.Any()
        wrapped.Pack(shop_evt)
        sig_evt = transport_pb2.SignedEvent(
            event=wrapped,
            signature=mtypes.Signature(raw=msg.signature),
        )
        return sig_evt

    # wait controls whether to wait for a response to the request
    def _send_event(self, sig_evt: transport_pb2.SignedEvent, wait: bool = True):
        req_id = self.next_request_id()
        ewr = transport_pb2.EventWriteRequest(events=[sig_evt])
        msg = Envelope(
            request_id=req_id,
            event_write_request=ewr,
        )
        data = msg.SerializeToString()
        assert self.connection is not None
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "waiting": True,
            "handler": self.handle_event_write_response,
        }
        if wait:
            while "waiting" in self.outgoingRequests[req_id.raw]:
                print(f"{self.name} write waiting")
                self.handle_all()
            print(f"{self.name} event written")
        return req_id

    def create_shop_manifest(self):
        if not self.expect_error:
            assert self.manifest == None
        sm = mevents.Manifest(
            token_id=mtypes.Uint256(raw=self.shop_token_id.to_bytes(32, "big")),
            accepted_currencies=[self.default_currency],
            pricing_currency=self.default_currency,
            payees=[self.default_payee],
            shipping_regions=[
                mtypes.ShippingRegion(
                    name="all",
                    country="",
                ),
            ],
        )
        self._write_event(manifest=sm)

    def update_shop_manifest(
        self,
        add_currencies=[],
        remove_currencies=[],
        set_pricing_currency=None,
        remove_payee=None,
        add_payee=None,
        add_regions=[],
        remove_regions=[],
    ):
        um = mevents.UpdateManifest()
        for c in add_currencies:
            um.add_accepted_currencies.append(c)
        for c in remove_currencies:
            um.remove_accepted_currencies.append(c)
        if set_pricing_currency:
            um.set_pricing_currency.CopyFrom(set_pricing_currency)
        if add_payee:
            um.add_payee.CopyFrom(add_payee)
        if remove_payee:
            um.remove_payee.CopyFrom(remove_payee)
        for r in add_regions:
            um.add_shipping_regions.append(r)
        for r in remove_regions:
            um.remove_shipping_regions.append(r)
        self._write_event(update_manifest=um)

    def create_listing(self, name: str, price: int, iid=None, wait=True):
        if iid is None:
            iid = new_object_id()
        if iid.raw in self.listings:
            raise Exception(f"Listing already exists: {iid}")
        meta = mtypes.ListingMetadata(
            title=name,
            description="This is a description of the listing",
            images=["https://example.com/image.png"],
        )
        listing = mevents.Listing(
            id=iid,
            metadata=meta,
            price=int_to_uint256(price),
        )
        self._write_event(listing=listing)
        if wait and not self.expect_error:
            i = 10
            while iid.raw not in self.listings:
                self.handle_all()
                i -= 1
                assert i > 0, "create listing timeout"
        return iid

    def update_listing(
        self,
        listing_id,
        price: Optional[mtypes.Uint256] = None,
        title: Optional[str] = None,
        descr: Optional[str] = None,
        add_image: Optional[str] = None,
        state: Optional[mtypes.ListingViewState] = None,
        add_option: Optional[mtypes.ListingOption] = None,
        add_variation: Optional[mevents.UpdateListing.AddVariation] = None,
        remove_variation: Optional[mtypes.ObjectId] = None,
        remove_option: Optional[mtypes.ObjectId] = None,
    ):
        if not self.expect_error:
            assert listing_id.raw in self.listings, f"unknown listing: {listing_id}"
        update = mevents.UpdateListing(id=listing_id)
        if title:
            update.metadata.title = title
        if descr:
            update.metadata.description = descr
        if add_image:
            existing = self.listings[listing_id.raw]
            existing = existing.metadata.images if existing.metadata.images else []
            existing.append(add_image)
            update.metadata.images.extend(existing)
        if price:
            update.price.CopyFrom(price)
        if state:
            update.view_state = state
        if add_option:
            update.add_options.append(add_option)
        if add_variation:
            update.add_variations.append(add_variation)
        if remove_variation:
            update.remove_variation_ids.append(remove_variation)
        if remove_option:
            update.remove_option_ids.append(remove_option)
        req_id = self._write_event(update_listing=update)
        return req_id

    def create_tag(self, name, tag_id=None):
        tid = tag_id
        if tid is None:
            tid = new_object_id()
        if tid.raw in self.tags:
            raise Exception("Tag already exists: {}".format(tid))
        tag = mevents.Tag(id=tid, name=name)
        self._write_event(tag=tag)
        return tid

    def add_to_tag(self, tag_id, listing_id):
        if not self.expect_error and tag_id.raw not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.expect_error and listing_id.raw not in self.listings:
            raise Exception("Unknown listing: {}".format(listing_id))
        add = mevents.UpdateTag(id=tag_id, add_listing_ids=[listing_id])
        self._write_event(update_tag=add)

    def remove_from_tag(self, tag_id, listing_id):
        if not self.expect_error and tag_id.raw not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        if not self.expect_error and listing_id.raw not in self.listings:
            raise Exception("Unknown listing: {}".format(listing_id))
        remove = mevents.UpdateTag(id=tag_id, remove_listing_ids=[listing_id])
        self._write_event(update_tag=remove)

    def rename_tag(self, tag_id, name):
        if not self.expect_error and tag_id.raw not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        rename = mevents.UpdateTag(id=tag_id, rename=name)
        self._write_event(update_tag=rename)

    def delete_tag(self, tag_id):
        if not self.expect_error and tag_id.raw not in self.tags:
            raise Exception("Unknown tag: {}".format(tag_id))
        delete = mevents.UpdateTag(id=tag_id, delete=True)
        self._write_event(update_tag=delete)

    def create_order(self, oid=None):
        if oid is None:
            oid = new_object_id()
        if not self.expect_error and oid.raw in self.orders:
            raise Exception("Order already exists: {}".format(oid))
        order = mevents.CreateOrder(id=oid)
        self._write_event(create_order=order)
        return oid

    def add_to_order(self, order_id, listing_id, quantity, variations=None):
        if not self.expect_error and order_id.raw not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if not self.expect_error and listing_id.raw not in self.listings:
            raise Exception("Unknown listing: {}".format(listing_id))
        update = mevents.UpdateOrder(
            id=order_id,
            change_items=mevents.UpdateOrder.ChangeItems(
                adds=[
                    mtypes.OrderedItem(
                        listing_id=listing_id,
                        quantity=quantity,
                        variation_ids=variations,
                    )
                ],
            ),
        )
        self._write_event(update_order=update)

    def remove_from_order(self, order_id, listing_id, quantity):
        order = Order(None)
        if not self.expect_error and order_id.raw not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if not self.expect_error:
            order = self.orders[order_id.raw]
        if not self.expect_error and (
            listing_id.raw not in self.listings or listing_id.raw not in order.items
        ):
            raise Exception("Unknown listing: {}".format(listing_id))
        update = mevents.UpdateOrder(
            id=order_id,
            change_items=mevents.UpdateOrder.ChangeItems(
                removes=[
                    mtypes.OrderedItem(
                        listing_id=listing_id,
                        quantity=quantity,
                    )
                ],
            ),
        )
        self._write_event(update_order=update)

    def abandon_order(self, order_id):
        utcnow = datetime.datetime.utcnow()
        now = timestamp_pb2.Timestamp()
        now.FromDatetime(utcnow)
        ca = mevents.UpdateOrder(
            id=order_id,
            cancel=mevents.UpdateOrder.Cancel(),
        )
        self._write_event(update_order=ca)

    def update_address_for_order(self, order_id, invoice=None, shipping=None):
        uo = mevents.UpdateOrder(id=order_id)
        if invoice:
            uo.set_invoice_address.CopyFrom(invoice)
        elif shipping:
            uo.set_shipping_address.CopyFrom(shipping)
        else:
            raise Exception("Need to set invoice or shipping address")
        self._write_event(update_order=uo)

    def commit_items(self, order_id):
        if not self.expect_error and order_id.raw not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        commit = mevents.UpdateOrder(
            id=order_id,
            commit_items=mevents.UpdateOrder.CommitItems(),
        )
        self._write_event(update_order=commit)

    def choose_payment(self, order_id, currency=None, payee_name="default"):
        if not self.expect_error and order_id.raw not in self.orders:
            raise Exception("Unknown order: {}".format(order_id))
        if currency is None:
            currency = self.default_currency
        payee = self.default_payee
        if payee_name in self.payees:
            payee = self.payees[payee_name]
        method = mevents.UpdateOrder(
            id=order_id,
            choose_payment=mevents.UpdateOrder.ChoosePaymentMethod(
                currency=currency,
                payee=payee,
            ),
        )
        self._write_event(update_order=method)

    def change_inventory(self, listing_id: int, change: int, variations=None):
        if not self.expect_error and listing_id.raw not in self.listings:
            raise Exception(f"Unknown listing: {listing_id}")
        evt = mevents.ChangeInventory(
            id=listing_id, diff=change, variation_ids=variations
        )
        self._write_event(change_inventory=evt)

    def check_inventory(self, listing_id: int, variations=[]):
        lookup_id = vid(listing_id, variations)
        return self.inventory.get(lookup_id, 0)
