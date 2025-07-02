# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

# stdlib
import requests
import json
import os
import base64
from urllib.parse import urlparse
from pprint import pprint
import time
import datetime
from typing import Optional, List, Tuple

# pip
import cbor2
from hashlib import sha256
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedError, InvalidStatus
from web3 import Web3, Account, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from eth_keys.datatypes import PrivateKey
from eth_account.messages import encode_defunct
import siwe

# our schema
from massmarket import (
    cbor_encode,
    verify_proof,
    get_root_hash_of_patches,
    error_pb2,
    subscription_pb2,
    transport_pb2,
    authentication_pb2,
    shop_requests_pb2,
    base_types_pb2 as pb_base,
)
from massmarket.envelope_pb2 import Envelope

import massmarket.hamt as hamt
from massmarket.cbor import Shop
import massmarket.cbor.patch as mass_patch
import massmarket.cbor.base_types as mass_base
import massmarket.cbor.manifest as mass_manifest
import massmarket.cbor.listing as mass_listing
import massmarket.cbor.order as mass_order

# Local utilities
from .utils import (
    to_32byte_hex,
    public_key_to_address,
    cbor_now,
    new_object_id,
    vid,
    transact_with_retry,
    check_transaction,
    notFoundError,
    invalidError,
    RelayException,
    EnrollException,
)


class PriceTotals:
    def __init__(self, subtotal, sales_tax, total):
        self.subtotal = subtotal
        self.sales_tax = sales_tax
        self.total = total


class Order:
    def __init__(self, id):
        self.id = id
        self.items = {}
        self.payment_state = mass_order.OrderPaymentState.OPEN
        self.purchase_address = None
        self.total = None
        self.payment_id = None
        self.payment_ttl = None


class RelayClient:
    shop: None | Shop = None

    def __init__(
        self,
        name="Alice",
        wallet_account=None,
        wallet_private_key=None,
        key_card_private_key=None,
        key_card_nonce=1,
        guest=False,
        relay_http_address=None,
        relay_token_id=None,
        chain_id=None,
        auto_connect=True,
        debug=False,
        log_file=None,
        validate_patches=True,
    ):
        self.name = name
        self.debug = debug
        self.validate_patches = validate_patches
        self.log_patches = os.getenv("LOG_PATCHES") in ["true", "1", "yes", "on"]
        current_time = datetime.datetime.now(datetime.UTC)
        self.start_time = current_time
        timestamp = current_time.strftime("%H%M%S")
        self.log_file = log_file or f"{name}_{timestamp}_patches.cbor"

        # Initialize patch log entries list
        self.patch_log_entries = []

        if self.log_patches:
            # Create header but store in memory
            header = {
                "type": "header",
                "client_name": self.name,
                "start_time": self.start_time.isoformat(),
                "version": 1,
            }
            self.patch_log_entries.append(header)

        self.relay_http_address = (
            os.getenv("RELAY_HTTP_ADDRESS")
            if relay_http_address is None
            else relay_http_address
        )
        assert self.relay_http_address is not None, "RELAY_HTTP_ADDRESS is not set"
        print(f"{name} is using relay: {self.relay_http_address}")
        relay_addr = urlparse(self.relay_http_address)
        self.relay_addr = relay_addr

        relay_ping = os.getenv("RELAY_PING")
        assert relay_ping is not None, "RELAY_PING is not set"
        self.relay_ping = float(relay_ping)

        # construct and dial websocket endpoint
        relay_ws_endpoint = relay_addr._replace(path="/v5/sessions")
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
        self.batching_enabled = False
        self.patch_buffer = []
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
        sign_mw = SignAndSendRawMiddlewareBuilder.build(self.account)
        self.w3.middleware_onion.inject(sign_mw, layer=0)

        # mass state
        self.last_request_id = 0
        self.is_guest = guest
        if key_card_private_key is None:
            self.own_key_card = Account.create()
            print(f"new key card: {self.own_key_card}")
        else:
            self.own_key_card = Account.from_key(key_card_private_key)
        self.last_event_nonce = key_card_nonce
        self.valid_addrs = []
        self.all_key_cards = {}
        self.accounts = {}
        self.shop_token_id = 0
        self.last_shop_seq_no = 0
        self.default_currency = mass_base.ChainAddress(
            chain_id=self.chain_id,
            address=bytes(20),
        )
        self.default_payee = mass_base.Payee(
            address=mass_base.ChainAddress(
                chain_id=self.chain_id,
                address=self.account.address,
            ),
            call_as_contract=False,
        )
        self.default_shipping_address = mass_order.AddressDetails(
            name="Valentin Mustermann",
            address1="Musterstraße 1",
            city="Musterstadt",
            country="DE",
            postal_code="12345",
            email_address="valentin@mustermann.de",
            phone_number="+491234567890",
        )
        self.shop = None

    def close(self):
        if self.log_patches and hasattr(self, "start_time") and self.patch_log_entries:
            # Add a footer entry
            end_time = datetime.datetime.now(datetime.UTC)
            duration_ms = int((end_time - self.start_time).total_seconds() * 1000)
            footer = {
                "type": "footer",
                "end_time": end_time.isoformat(),
                "duration_ms": duration_ms,
                "patches_count": self.last_shop_seq_no,
                "errors": self.errors,
            }
            self.patch_log_entries.append(footer)

            # Write all entries at once
            with open(self.log_file, "wb") as f:
                f.write(cbor_encode(self.patch_log_entries))

            print(f"Wrote {len(self.patch_log_entries)} log entries to {self.log_file}")
            self.patch_log_entries = []

        if self.connection:
            self.connection.close()
            self.connection = None
        self.connected = False
        self.logged_in = False
        self.last_request_id = 0
        self.errors = 0
        print(f"closed {self.name}")

    def next_request_id(self):
        next = self.last_request_id + 1
        req_id = pb_base.RequestId(raw=next)
        self.last_request_id = next
        return req_id

    # TODO: update to shop object
    def print_state(self):
        print("Shop State:")
        print("-----------")

        if self.shop is None:
            print("No shop data available.")
            return

        print("Currencies:")
        if (
            self.shop.manifest.accepted_currencies is None
            or len(self.shop.manifest.accepted_currencies) == 0
        ):
            print(" No currencies set up")
        else:
            for chain_id, addresses in self.shop.manifest.accepted_currencies.items():
                for addr in addresses:
                    print(f"  ChainID: {chain_id} Addr: {addr}")

        if self.shop.manifest.pricing_currency is None:
            print(" No base currency!")
        else:
            b = self.shop.manifest.pricing_currency
            print(f"Base Currency:\n  ChainID: {b.chain_id} Addr: {b.address}")

        if self.shop.manifest.payees is None or len(self.shop.manifest.payees) == 0:
            print(" No Payees set up ")
        else:
            print("Payees:")
            for chain_id, addresses in self.shop.manifest.payees.items():
                for addr, metadata in addresses.items():
                    print(
                        f"  ChainID: {chain_id} Addr: {addr} (isEndpoint: {metadata.call_as_contract})"
                    )

        print("\nListings:")
        if not self.shop.listings or self.shop.listings.size == 0:
            print("  No listings available.")
        else:

            def print_listing(listing_id, listing: mass_listing.Listing):
                print(f"  Listing ID: {listing_id}")
                print(f"    Price: {listing.price}")
                if listing.options is not None:
                    for option_name, option in listing.options.items():
                        print(f"    Option: {option_name}")
                        for variation_name, variation in option.variations.items():
                            print(f"      Variation: {variation_name}")
                            print(f"       Modifier: {variation.price_modifier}")
                if self.shop.inventory and self.shop.inventory.has(listing_id):
                    quantity = self.shop.inventory.get(listing_id)
                    if quantity is not None:
                        print(f"    Stock: {quantity}")
                else:
                    print("    Stock: Not available")
                print(f"    Metadata: {listing.metadata}")
                return True

            self.shop.listings.all(print_listing)

        print("\nOrders:")
        if not self.shop.orders or self.shop.orders.size == 0:
            print("  No orders available.")
        else:

            def print_order(order_id, order: mass_order.Order):
                # TODO: use new timestamps
                print(f"  Order ID: {order_id}")
                print(f"    State: {order.state}")
                print(f"    Items:")
                for item in order.items:
                    print(
                        f"    Listing ID: {item.listing_id} Quantity: {item.quantity}"
                    )
                if order.payment_details:
                    print(f"  Totals:")
                    print(f"    Total: {order.payment_details.total}")
                    print(f"    Payment ID: {order.payment_details.payment_id}")
                    print(f"    Payment TTL: {order.payment_details.ttl}")
                if order.chosen_payee:
                    print(f"  Chosen Payee:")
                    print(
                        f"    Address: {order.chosen_payee.address.address.to_bytes().hex()}"
                    )
                    print(f"    Chain ID: {order.chosen_payee.address.chain_id}")
                    print(f"    Is Endpoint: {order.chosen_payee.call_as_contract}")
                if order.shipping_address:
                    print(f"  Shipping Details:")
                    print(f"    Name: {order.shipping_address.name}")
                    print(f"    Address: {order.shipping_address.address1}")
                    print(f"    City: {order.shipping_address.city}")
                    print(f"    Country: {order.shipping_address.country}")
                    print(f"    Postal Code: {order.shipping_address.postal_code}")
                    print(f"    Email: {order.shipping_address.email_address}")
                    print(f"    Phone: {order.shipping_address.phone_number}")
                return True

            self.shop.orders.all(print_order)

        print("\nTags:")
        if not self.shop.tags or self.shop.tags.size == 0:
            print("  No tags available.")
        else:

            def print_tag(tag_id, tag):
                if tag is None:
                    return True
                print(f"  Tag ID: {tag_id}")
                print(f"    Name: {tag.name}")
                for listing_id in tag.listings:
                    print(f"    Listing ID: {listing_id}")
                return True

            self.shop.tags.all(print_tag)

        # Print key cards
        print("\nKey Cards:")
        if not self.shop or not self.shop.accounts or self.shop.accounts.size == 0:
            print("  No key cards available.")
        else:

            def print_account(user_wallet, account: mass_base.Account):
                print(f"  User Wallet: {user_wallet.hex()}:")
                for keycard in account.keycards:
                    print(f"     KeyCard: 0x{keycard.key.hex()}")
                return True

            self.shop.accounts.all(print_account)

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

    def register_shop(self, token_id=None):
        if token_id is None:
            token_id = int.from_bytes(os.urandom(32), "big")
        else:
            assert isinstance(token_id, int)
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
        keyCard = PrivateKey(self.own_key_card.key)

        modified_url = self.relay_addr._replace(path="/v5/enroll_key_card")
        if self.is_guest:
            modified_url = modified_url._replace(query="guest=1")
        enroll_url = modified_url.geturl()

        if self.shop_token_id is None:
            raise Exception("shop_token_id unset")

        if siwe_msg is None:
            kc_hex = "0x" + keyCard.public_key.to_compressed_bytes().hex()

            now = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
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
        try:
            respData = response.json()
        except json.JSONDecodeError:
            print(f"Failed to decode response: {response.text}")
            raise
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
            self.connection = None
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
            self.handle_subscription_push_request(msg)
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
            assert self.connection is not None
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
            print(f"SyncStatusRequest: unpushedPatches={req.unpushed_patches}")
        resp = Envelope(
            request_id=env.request_id,
            response=Envelope.GenericResponse(),
        )
        data = resp.SerializeToString()
        assert self.connection is not None
        self.connection.send(data)

    def _check_expected_request(self, req_id: pb_base.RequestId, clean=False):
        ours = req_id.raw
        if ours not in self.outgoingRequests:
            raise Exception(f"Received response for unknown request id={ours}")
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
                signature=pb_base.Signature(raw=signature),
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
            if self.expect_error:
                print(f"{self.name} expected error: {resp}")
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

    def handle_subscription_push_request(self, msg: Envelope):
        req = msg.subscription_push_request
        if self.debug:
            print(
                f"{self.name} SubscriptionPushRequest reqID={msg.request_id.raw} sets={len(req.sets)}"
            )
        err = None
        last_seq_no = None
        # pprint(req)

        # Log received patch sets if enabled
        if self.log_patches:
            now = datetime.datetime.now(datetime.UTC)
            delta_ms = int((now - self.start_time).total_seconds() * 1000)

            for set_idx, set in enumerate(req.sets):
                # Create a wrapper with metadata
                patch_log_entry = {
                    "type": "patch_set",
                    "timestamp_delta_ms": delta_ms,
                    "shop_seq_no": set.shop_seq_no,
                    "header": set.header,
                    "signature": set.signature,
                    "patch": [patch for patch in set.patches],
                    "proofs": [proof for proof in set.proofs],
                    "set_index": set_idx,
                    "total_sets": len(req.sets),
                }

                # Store entry in memory
                self.patch_log_entries.append(patch_log_entry)

        for set in req.sets:
            (npatches, nproofs) = len(set.patches), len(set.proofs)
            if npatches == 0:
                raise Exception("empty partial set?")
            if npatches != nproofs:
                raise Exception(
                    f"unequal number of patches({npatches}) and proofs({nproofs})"
                )

            header = mass_patch.PatchSetHeader.from_cbor(set.header)

            signed_by = None
            if self.validate_patches:
                signed_by = self._verify_signature(set.header, set.signature)

            for i, patch_data in enumerate(set.patches):

                # TODO: move to verify_proof helper
                [leaf_index, size, proof_path] = cbor2.loads(set.proofs[i])
                if proof_path is None:
                    proof_path = []

                # TODO: move hashing into verify_proof helper
                hashed_patch = sha256(patch_data).digest()
                verify_proof(leaf_index, hashed_patch, proof_path, header.root_hash)
                # print("proof & signature verified.")

                # apply patch to local state
                patch = mass_patch.Patch.from_cbor(patch_data)

                obj_type = patch.path.type
                if self.debug:
                    print(
                        f"{self.name}/newEvent shopSeq:{set.shop_seq_no} nonce:{header.key_card_nonce} kc:{signed_by} type:{obj_type}"
                    )
                    pprint(patch)
                last_seq_no = set.shop_seq_no
                if obj_type == mass_patch.ObjectType.MANIFEST:
                    err = self._patch_manifest(patch)
                elif obj_type == mass_patch.ObjectType.ACCOUNT:
                    err = self._patch_account(patch)
                elif obj_type == mass_patch.ObjectType.LISTING:
                    err = self._patch_listing(patch)
                elif obj_type == mass_patch.ObjectType.TAG:
                    err = self._patch_tag(patch)
                elif obj_type == mass_patch.ObjectType.INVENTORY:
                    print(f"{self.name}: inventory patch: {patch}")
                    err = self._patch_inventory(patch)
                elif obj_type == mass_patch.ObjectType.ORDER:
                    err = self._patch_order(patch)
                else:
                    err = invalidError(f"unhandled object type: {obj_type}")
                if err is not None:
                    break
                if self.debug:
                    print(
                        f"{self.name} patched {patch.path.type}: {patch.op} {patch.path.fields}"
                    )
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

    def _patch_manifest(self, patch: mass_patch.Patch):
        if patch.op == mass_patch.OpString.REPLACE:
            if len(patch.path.fields) == 0:
                manifest = mass_manifest.Manifest.from_cbor_dict(patch.value)
                if self.shop is None:
                    self.shop = Shop(
                        schema_version=4,
                        manifest=manifest,
                        accounts=(
                            self.accountsHamt
                            if hasattr(self, "accountsHamt")
                            else hamt.Trie.new()
                        ),
                        listings=hamt.Trie.new(),
                        tags=hamt.Trie.new(),
                        orders=hamt.Trie.new(),
                        inventory=hamt.Trie.new(),
                    )
                else:
                    self.shop.manifest = manifest
                if self.debug:
                    print(f"{self.name} manifest replaced: {self.shop.manifest}")
            elif patch.path.fields[0] == "PricingCurrency":
                if self.shop is None:
                    return invalidError("shop not initialized")
                self.shop.manifest.pricing_currency = patch.value
            elif patch.path.fields[0] == "AcceptedCurrencies":
                if self.shop is None:
                    return invalidError("shop not initialized")
                chain_id = int(patch.path.fields[1])
                addr = mass_base.EthereumAddress(patch.path.fields[2])
                assert isinstance(chain_id, int)
                assert isinstance(addr, mass_base.EthereumAddress)
                if (
                    chain_id in self.shop.manifest.accepted_currencies
                    and addr in self.shop.manifest.accepted_currencies[chain_id]
                ):
                    return invalidError(
                        f"currency already exists: {chain_id}/{addr.hex()}"
                    )
                self.shop.manifest.accepted_currencies[chain_id].add(addr)
            else:
                return invalidError(
                    f"unhandled manifest patch fields: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.ADD:
            assert self.shop is not None
            if len(patch.path.fields) == 0:
                return invalidError("wont handle empty add patch")
            elif patch.path.fields[0] == "Payees":
                chain_id = int(patch.path.fields[1])
                addr = mass_base.EthereumAddress(patch.path.fields[2])
                assert isinstance(chain_id, int)
                assert isinstance(addr, mass_base.EthereumAddress)
                meta = mass_base.PayeeMetadata.from_cbor_dict(patch.value)
                self.shop.manifest.payees[chain_id][addr] = meta
            elif patch.path.fields[0] == "AcceptedCurrencies":
                chain_id = int(patch.path.fields[1])
                addr = mass_base.EthereumAddress(patch.path.fields[2])
                assert isinstance(chain_id, int)
                assert isinstance(addr, mass_base.EthereumAddress)
                if chain_id in self.shop.manifest.accepted_currencies:
                    if addr in self.shop.manifest.accepted_currencies[chain_id]:
                        return invalidError(
                            f"currency already exists: {chain_id}/{addr.hex()}"
                        )
                if chain_id not in self.shop.manifest.accepted_currencies:
                    self.shop.manifest.accepted_currencies[chain_id] = set()
                self.shop.manifest.accepted_currencies[chain_id].add(addr)
            elif patch.path.fields[0] == "ShippingRegions":
                if self.shop.manifest.shipping_regions is None:
                    self.shop.manifest.shipping_regions = {}
                name = patch.path.fields[1]
                if not isinstance(name, str):
                    return invalidError(f"invalid shipping region: {name}")
                region = mass_manifest.ShippingRegion.from_cbor_dict(patch.value)
                self.shop.manifest.shipping_regions[name] = region
            else:
                return invalidError(f"unhandled manifest field: {patch.path.fields}")
        elif patch.op == mass_patch.OpString.REMOVE:
            assert self.shop is not None
            if len(patch.path.fields) == 0:
                return invalidError("wont handle empty remove patch")
            elif patch.path.fields[0] == "Payees":
                chain_id = int(patch.path.fields[1])
                addr = mass_base.EthereumAddress(patch.path.fields[2])
                assert isinstance(chain_id, int)
                assert isinstance(addr, mass_base.EthereumAddress)
                if chain_id not in self.shop.manifest.payees:
                    return notFoundError(f"unknown payee: {chain_id}")
                if addr not in self.shop.manifest.payees[chain_id]:
                    return notFoundError(f"unknown payee: {addr}")
                del self.shop.manifest.payees[chain_id][addr]
            elif patch.path.fields[0] == "AcceptedCurrencies":
                chain_id = int(patch.path.fields[1])
                addr = mass_base.EthereumAddress(patch.path.fields[2])
                assert isinstance(chain_id, int)
                assert isinstance(addr, mass_base.EthereumAddress)
                if chain_id not in self.shop.manifest.accepted_currencies:
                    return notFoundError(f"unknown currency: {chain_id}")
                self.shop.manifest.accepted_currencies[chain_id].remove(addr)
            elif patch.path.fields[0] == "ShippingRegions":
                name = patch.path.fields[1]
                if self.shop.manifest.shipping_regions is None:
                    return notFoundError(f"no shipping regions defined")
                if not isinstance(name, str):
                    return invalidError(f"invalid name: {name}")
                if name not in self.shop.manifest.shipping_regions:
                    return notFoundError(f"unknown shipping region: {name}")
                del self.shop.manifest.shipping_regions[name]
            else:
                return invalidError(f"unhandled manifest field: {patch.path.fields}")
        else:
            return invalidError(f"unhandled manifest patch op: {patch.op}")

    def _patch_account(self, patch: mass_patch.Patch):
        if self.shop is None:
            self.accountsHamt = hamt.Trie.new()
            self.shop = Shop(
                schema_version=5,
                manifest=mass_manifest.Manifest(
                    shop_id=self.shop_token_id,
                    payees={},
                    accepted_currencies=[self.default_currency],
                    pricing_currency=self.default_currency,
                    order_payment_timeout=60000000,
                ),
                accounts=self.accountsHamt,
            )
        if isinstance(patch.path.account_addr, mass_base.EthereumAddress):
            user_wallet = patch.path.account_addr.to_bytes()
        elif isinstance(patch.path.account_addr, bytes):
            user_wallet = patch.path.account_addr
        else:
            return invalidError(
                f"account address is required: {type(patch.path.account_addr)}"
            )
        if patch.op == mass_patch.OpString.ADD:
            # pprint(patch)
            if len(patch.path.fields) == 0:
                account = mass_base.Account.from_cbor_dict(patch.value)
                self.accounts[user_wallet] = account
                self.shop.accounts.insert(user_wallet, account)
                if self.debug:
                    print(f"{self.name} account add of {user_wallet.hex()}")
                for kc in account.keycards:
                    if kc in self.all_key_cards:
                        return invalidError(f"key card already exists: {kc.key.hex()}")
                    else:
                        if self.debug:
                            print(
                                f"{self.name} adding keyCard=0x{kc.key.hex()} for user={user_wallet.hex()}"
                            )
                        self.all_key_cards[kc] = user_wallet
                        self.valid_addrs.append(public_key_to_address(kc).lower())
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "KeyCards":
                if not self.shop.accounts.has(user_wallet):
                    return notFoundError(f"unknown account: {user_wallet.hex()}")
                account = self.shop.accounts.get(user_wallet)
                keycard = mass_base.PublicKey.from_cbor_dict(patch.value)

                if keycard in self.all_key_cards:
                    return invalidError(f"key card already exists: {keycard.key.hex()}")

                try:
                    index = patch.path.fields[1]
                    if index < 0 or index > len(account.keycards):
                        return invalidError(f"index out of bounds: {index}")
                    account.keycards.insert(index, keycard)
                except ValueError:
                    return invalidError(
                        f"invalid KeyCards index: {patch.path.fields[1]}"
                    )

                self.accounts[user_wallet] = account
                self.shop.accounts.insert(user_wallet, account)

                if self.debug:
                    print(
                        f"{self.name} adding keyCard=0x{keycard.key.hex()} for user={user_wallet.hex()}"
                    )
                self.all_key_cards[keycard] = user_wallet
                self.valid_addrs.append(public_key_to_address(keycard).lower())
            else:
                return invalidError(
                    f"unhandled accounts patch path: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.APPEND:
            if len(patch.path.fields) == 1 and patch.path.fields[0] == "KeyCards":
                if not self.shop.accounts.has(user_wallet):
                    return notFoundError(f"unknown account: {user_wallet.hex()}")
                account = self.shop.accounts.get(user_wallet)
                keycard = mass_base.PublicKey.from_cbor_dict(patch.value)

                if keycard in self.all_key_cards:
                    return invalidError(f"key card already exists: {keycard.key.hex()}")

                account.keycards.append(keycard)
                self.accounts[user_wallet] = account
                self.shop.accounts.insert(user_wallet, account)

                if self.debug:
                    print(
                        f"{self.name} adding keyCard=0x{keycard.key.hex()} for user={user_wallet.hex()}"
                    )
                self.all_key_cards[keycard] = user_wallet
                self.valid_addrs.append(public_key_to_address(keycard).lower())
            else:
                return invalidError(
                    f"unhandled accounts append patch path: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if not self.shop.accounts.has(user_wallet):
                return notFoundError(f"unknown account: {user_wallet.hex()}")
            # Remove all keycards for this user first
            for kc, addr in list(self.all_key_cards.items()):
                if addr == user_wallet:
                    del self.all_key_cards[kc]
                    self.valid_addrs.remove(public_key_to_address(kc).lower())
            # Then remove the account
            del self.accounts[user_wallet]
            self.shop.accounts.delete(user_wallet)
            if self.debug:
                print(f"{self.name} onchain remove of {user_wallet.hex()}")
        else:
            return invalidError(f"unhandled patch.op type: {patch.op}")

    def _patch_listing(self, patch: mass_patch.Patch):
        listing_id = patch.path.object_id
        assert isinstance(listing_id, int)
        assert self.shop is not None
        if patch.op == mass_patch.OpString.ADD:
            l = self.shop.listings.get(listing_id)
            if patch.path.fields == []:
                if l is not None:
                    return invalidError(f"listing already exists: {listing_id}")
                else:
                    listing = mass_listing.Listing.from_cbor_dict(patch.value)
                    self.shop.listings.insert(listing.id, listing)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "Options":
                opt_name = patch.path.fields[1]
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                if l.options is None:
                    l.options = {}
                if opt_name in l.options:
                    return invalidError(f"option already exists: {opt_name}")
                l.options[opt_name] = mass_listing.ListingOption.from_cbor_dict(
                    patch.value
                )
                self.shop.listings.insert(listing_id, l)
            elif (
                len(patch.path.fields) == 4
                and patch.path.fields[0] == "Options"
                and patch.path.fields[2] == "Variations"
            ):
                opt_name = patch.path.fields[1]
                var_name = patch.path.fields[3]
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                if l.options is None or opt_name not in l.options:
                    return notFoundError(f"unknown option: {opt_name}")
                curr_vars = l.options[opt_name].variations
                if curr_vars is not None and var_name in curr_vars:
                    return invalidError(f"variation already exists: {var_name}")
                l.options[opt_name].variations[var_name] = (
                    mass_listing.ListingVariation.from_cbor_dict(patch.value)
                )
                self.shop.listings.insert(listing_id, l)
            else:
                return invalidError(
                    f"unhandled add patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.APPEND:
            if patch.path.fields == ["Metadata", "Images"]:
                l = self.shop.listings.get(listing_id)
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert l.metadata.images is not None
                l.metadata.images.append(patch.value)
                self.shop.listings.insert(listing_id, l)
            else:
                return invalidError(
                    f"unhandled append patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REPLACE:
            l = self.shop.listings.get(listing_id)
            if l is None:
                return notFoundError(f"unknown listing: {listing_id}")
            if patch.path.fields == ["Price"]:
                if not isinstance(patch.value, int):
                    return invalidError(f"invalid price: {patch.value}")
                l.price = mass_base.Uint256(patch.value)
            elif patch.path.fields == ["ViewState"]:
                if not isinstance(patch.value, int):
                    return invalidError(f"invalid viewState: {patch.value}")
                l.view_state = mass_listing.ListingViewState(patch.value)
            elif patch.path.fields == ["Metadata"]:
                if not isinstance(patch.value, dict):
                    return invalidError(f"invalid metadata: {patch.value}")
                l.metadata = mass_listing.ListingMetadata.from_cbor_dict(patch.value)
            elif patch.path.fields == ["Metadata", "Title"]:
                if not isinstance(patch.value, str):
                    return invalidError(f"invalid title: {patch.value}")
                l.metadata.title = patch.value
            elif patch.path.fields == ["Metadata", "Description"]:
                if not isinstance(patch.value, str):
                    return invalidError(f"invalid description: {patch.value}")
                l.metadata.description = patch.value
            # TODO: replace image by index
            else:
                return invalidError(
                    f"unhandled replace patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if patch.path.fields == []:
                l = self.shop.listings.get(listing_id)
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                self.shop.listings.delete(listing_id)
            elif len(patch.path.fields) == 3 and patch.path.fields[0] == "Metadata":
                if patch.path.fields[1] == "Images":
                    index = int(patch.path.fields[2])
                    if not isinstance(index, int):
                        return invalidError(f"invalid image index: {index}")
                    l = self.shop.listings.get(listing_id)
                    if l is None:
                        return notFoundError(f"unknown listing: {listing_id}")
                    assert l.metadata.images is not None
                    if index < 0 or index >= len(l.metadata.images):
                        return invalidError(f"invalid image index: {index}")
                    del l.metadata.images[index]
                    self.shop.listings.insert(listing_id, l)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "Options":
                opt_name = patch.path.fields[1]
                l = self.shop.listings.get(listing_id)
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert l.options is not None
                if opt_name in l.options:
                    del l.options[opt_name]
                self.shop.listings.insert(listing_id, l)
            elif (
                len(patch.path.fields) == 4
                and patch.path.fields[0] == "Options"
                and patch.path.fields[2] == "Variations"
            ):
                opt_name = patch.path.fields[1]
                var_name = patch.path.fields[3]
                l = self.shop.listings.get(listing_id)
                if l is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert l.options is not None
                assert opt_name in l.options
                if l.options[opt_name] is None:
                    return notFoundError(f"unknown option: {opt_name}")
                curr_vars = l.options[opt_name].variations
                if curr_vars is None or var_name not in curr_vars:
                    return notFoundError(f"unknown variation: {var_name}")
                del curr_vars[var_name]
                self.shop.listings.insert(listing_id, l)
            else:
                return invalidError(
                    f"unhandled remove patch.path.fields for listing: {patch.path.fields}"
                )
        else:
            return invalidError(f"unhandled patch.op for listing: {patch.op}")

    def _patch_tag(self, patch: mass_patch.Patch):
        assert self.shop is not None, "shop not initialized"
        tag_name = patch.path.tag_name
        assert tag_name is not None, "tag name is required"
        if patch.op == mass_patch.OpString.ADD:
            if patch.path.fields == []:
                tag = mass_base.Tag.from_cbor_dict(patch.value)
                if self.shop.tags.has(tag_name):
                    return invalidError(f"tag already exists: {tag_name}")
                else:
                    self.shop.tags.insert(tag_name, tag)
            else:
                return invalidError(
                    f"unhandled add patch.path.fields for tag: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.APPEND:
            if patch.path.fields == ["ListingIDs"]:
                tag = self.shop.tags.get(tag_name)
                if tag is None:
                    return notFoundError(f"unknown tag: {tag_name}")
                else:
                    tag.listings.append(patch.value)
                    self.shop.tags.insert(tag_name, tag)
            else:
                return invalidError(
                    f"unhandled append patch.path.fields for tag: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if patch.path.fields == []:
                if not self.shop.tags.has(tag_name):
                    return notFoundError(f"unknown tag: {tag_name}")
                else:
                    self.shop.tags.delete(tag_name)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "ListingIDs":
                index = int(patch.path.fields[1])
                if not isinstance(index, int):
                    return invalidError(f"invalid index: {index}")
                else:
                    tag = self.shop.tags.get(tag_name)
                    if tag is None:
                        return notFoundError(f"unknown tag: {tag_name}")
                    else:
                        tag.listings.pop(index)
                        self.shop.tags.insert(tag_name, tag)
            else:
                return invalidError(
                    f"unhandled remove patch.path.fields for tag: {patch.path.fields}"
                )
        else:
            return invalidError(f"unhandled patch.op for tag: {patch.op}")

    def _patch_inventory(self, patch: mass_patch.Patch):
        assert self.shop is not None, "shop not initialized"
        assert isinstance(patch.value, int)
        listing_id = patch.path.object_id
        assert isinstance(listing_id, int)
        lookup_id = vid(listing_id, patch.path.fields)
        if patch.op == mass_patch.OpString.ADD:
            if not self.shop.listings.has(listing_id):
                return notFoundError(f"unknown listing: {listing_id}")
            current = self.shop.inventory.get(lookup_id)
            if current is None:
                current = 0
            self.shop.inventory.insert(lookup_id, current + patch.value)
        elif patch.op == mass_patch.OpString.REMOVE:
            if not self.shop.inventory.has(lookup_id):
                return notFoundError(f"unknown inventory: {lookup_id}")
            self.shop.inventory.delete(lookup_id)
        elif patch.op == mass_patch.OpString.REPLACE:
            if not self.shop.inventory.has(lookup_id):
                return notFoundError(f"unknown inventory: {lookup_id}")
            self.shop.inventory.insert(lookup_id, patch.value)
        elif patch.op == mass_patch.OpString.INCREMENT:
            current = self.shop.inventory.get(lookup_id)
            if current is None:
                current = 0
            new_value = current + patch.value
            print(f"{self.name}/inventory/incr: {lookup_id} to {new_value}")
            self.shop.inventory.insert(lookup_id, new_value)
        elif patch.op == mass_patch.OpString.DECREMENT:
            if not self.shop.inventory.has(lookup_id):
                return notFoundError(f"unknown inventory: {lookup_id}")
            current = self.shop.inventory.get(lookup_id)
            if current is None or current < patch.value:
                return invalidError(f"inventory underflow: {lookup_id}")
            self.shop.inventory.insert(lookup_id, current - patch.value)
        else:
            return invalidError(f"unhandled patch.op for inventory: {patch.op}")

    def _patch_order(self, patch: mass_patch.Patch):
        assert self.shop is not None, "shop not initialized"
        order_id = patch.path.object_id
        assert isinstance(order_id, int)
        if patch.op == mass_patch.OpString.ADD:
            if len(patch.path.fields) == 0:
                # Check if order already exists before insertion
                if self.shop.orders.has(order_id):
                    return invalidError(f"order already exists: {order_id}")
                # Create a new order
                order = mass_order.Order.from_cbor_dict(patch.value)
                self.shop.orders.insert(order_id, order)
                return None

            order = self.shop.orders.get(order_id)
            if order is None:
                return notFoundError(f"unknown order: {order_id}")

            if patch.path.fields[0] == "InvoiceAddress":
                assert order.invoice_address is None
                order.invoice_address = mass_order.AddressDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "ShippingAddress":
                assert order.shipping_address is None
                order.shipping_address = mass_order.AddressDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "PaymentDetails":
                assert order.payment_details is None
                order.payment_details = mass_order.PaymentDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "TxDetails":
                assert order.tx_details is None
                order.tx_details = mass_order.OrderPaid.from_cbor_dict(patch.value)
            elif patch.path.fields[0] == "ChosenPayee":
                assert order.chosen_payee is None
                order.chosen_payee = mass_order.Payee.from_cbor_dict(patch.value)
            elif patch.path.fields[0] == "CanceledAt":
                assert order.canceled_at is None
                order.canceled_at = patch.value
            else:
                return invalidError(
                    f"unhandled add patch.path.fields for order: {patch.path.fields}"
                )
            self.shop.orders.insert(order_id, order)
        elif patch.op == mass_patch.OpString.APPEND:
            order = self.shop.orders.get(order_id)
            if order is None:
                return notFoundError(f"unknown order: {order_id}")

            if patch.path.fields[0] == "Items":
                # Add item to order
                item = mass_order.OrderedItem.from_cbor_dict(patch.value)
                order.items.append(item)
                self.shop.orders.insert(order_id, order)
            else:
                return invalidError(
                    f"unhandled append patch.path.fields for order: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REPLACE:
            if not self.shop.orders.has(order_id):
                return notFoundError(f"unknown order: {order_id}")
            order = self.shop.orders.get(order_id)
            assert len(patch.path.fields) > 0
            if order is None:
                return notFoundError(f"unknown order: {order_id}")
            if patch.path.fields[0] == "PaymentState":
                order.payment_state = patch.value
            elif patch.path.fields[0] == "Items":
                if not isinstance(patch.value, list):
                    return invalidError(f"invalid items: {patch.value}")
                print(patch.value)
                order.items = [
                    mass_order.OrderedItem.from_cbor_dict(item) for item in patch.value
                ]
            elif patch.path.fields[0] == "InvoiceAddress":
                order.invoice_address = patch.value
            elif patch.path.fields[0] == "ShippingAddress":
                order.shipping_address = patch.value
            elif patch.path.fields[0] == "ChosenCurrency":
                order.chosen_currency = patch.value
            elif patch.path.fields[0] == "ChosenPayee":
                order.chosen_payee = patch.value
            elif patch.path.fields[0] == "CanceledAt":
                order.canceled_at = patch.value
            elif patch.path.fields[0] == "PaymentDetails":
                order.payment_details = mass_order.PaymentDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "TxDetails":
                order.tx_details = mass_order.OrderPaid.from_cbor_dict(patch.value)
            else:
                return invalidError(
                    f"unhandled replace patch.path.fields for order: {patch.path.fields}"
                )
            self.shop.orders.insert(order_id, order)
        elif patch.op == mass_patch.OpString.DECREMENT:
            if not self.shop.orders.has(order_id):
                return notFoundError(f"unknown order: {order_id}")
            order = self.shop.orders.get(order_id)
            if order is None:
                return notFoundError(f"unknown order: {order_id}")
            if (
                len(patch.path.fields) == 3
                and patch.path.fields[0] == "Items"
                and patch.path.fields[2] == "Quantity"
            ):
                # Decrement item quantity
                try:
                    index = int(patch.path.fields[1])
                    if index >= len(order.items):
                        return notFoundError(f"item index out of range: {index}")

                    item = order.items[index]
                    if item.quantity < patch.value:
                        return invalidError(
                            f"item quantity underflow: {item.quantity} < {patch.value}"
                        )

                    item.quantity -= patch.value
                    if item.quantity == 0:
                        order.items.pop(index)
                    self.shop.orders.insert(order_id, order)
                except ValueError:
                    return invalidError(f"invalid item index: {patch.path.fields[1]}")
            else:
                return invalidError(
                    f"unhandled decrement patch.path.fields for order: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if not self.shop.orders.has(order_id):
                return notFoundError(f"unknown order: {order_id}")
            self.shop.orders.delete(order_id)
        else:
            return invalidError(f"unhandled patch.op for order: {patch.op}")

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
        kc = PrivateKey(self.own_key_card.key)
        # print('public key: ' + kc.public_key.to_hex())
        req_id = self.next_request_id()
        ar = authentication_pb2.AuthenticateRequest(
            public_key=pb_base.PublicKey(raw=kc.public_key.to_compressed_bytes()),
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
        assert self.connection is not None, "connection not initialized"
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
        assert self.connection is not None, "connection not initialized"
        self.connection.send(data)
        self.outgoingRequests[req_id.raw] = {
            "handler": self.handle_get_blob_upload_url_response,
            "waiting": True,
        }
        return req_id.raw

    def _assert_shop_against_response(self, req_id: pb_base.RequestId):
        assert self.shop is not None, "shop not initialized"
        assert req_id is not None, "no request id"
        got_hash = self.outgoingRequests[req_id.raw]["new_state_hash"]
        has_hash = self.shop.hash()
        assert (
            got_hash == has_hash
        ), f"shop hash mismatch: {got_hash.hex()} != {has_hash.hex()}"
        return got_hash

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
            "OBJECT_TYPE_INVENTORY",
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
            "OBJECT_TYPE_INVENTORY",
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
        return self.subscribe(f)

    def subscribe(self, filters):
        req_id = self.next_request_id()
        req = subscription_pb2.SubscriptionRequest(
            start_shop_seq_no=self.last_shop_seq_no,
            shop_id=pb_base.Uint256(raw=self.shop_token_id.to_bytes(32, "big")),
            filters=filters,
        )
        msg = Envelope(
            request_id=req_id,
            subscription_request=req,
        )
        data = msg.SerializeToString()
        assert self.connection is not None
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
        assert self.connection is not None
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

    def _sign_header(self, header: mass_patch.PatchSetHeader):
        keyCardPK = Account.from_key(self.own_key_card.key)
        encoded_header = cbor_encode(header.to_cbor_dict())
        # print(f"DEBUG encoded_header: {encoded_header.hex()}")
        eip191_data = encode_defunct(encoded_header)
        signed_message = keyCardPK.sign_message(eip191_data)
        # print(f"hash: {signed_message.messageHash.hex()}")
        return signed_message.signature

    # an actual implementation would probably cache the relays
    def _valid_event_signing_addresses(self):
        if len(self.valid_addrs) != 0:
            return self.valid_addrs
        else:
            all = []
            # retrieve all relays nfts
            if self.shopReg.functions.getRelayCount(self.shop_token_id).call() > 0:
                all_relay_token_ids = self.shopReg.functions.getAllRelays(
                    self.shop_token_id
                ).call()
                for token_id in all_relay_token_ids:
                    # retrieve the owner => it's address
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

    def _verify_signature(self, header_data: bytes, signature: bytes):
        if len(signature) != 65:
            raise Exception(f"Invalid signature length: {len(signature)}")
        encoded_data = encode_defunct(header_data)
        pub_key = self.w3.eth.account.recover_message(encoded_data, signature=signature)
        # print(f"{self.name} received event from recovered pub_key: {pub_key}")
        their_addr = Web3.to_checksum_address(pub_key).lower()
        valid_addrs = self._valid_event_signing_addresses()
        if their_addr not in valid_addrs:
            print(f"valid addresses: {valid_addrs}")
            raise Exception(f"Event signed by unknown address: {their_addr}")
        return their_addr

    def _write_patch(self, **kwargs):
        assert len(kwargs) >= 3
        assert "type" in kwargs
        assert "op" in kwargs
        patch = self._create_patch(**kwargs)

        # If batching is enabled, buffer the patch
        if self.batching_enabled:
            print(f"{self.name} buffering patch no: {len(self.patch_buffer)}")
            self.patch_buffer.append(patch)
            return None

        # Otherwise, create a patch set with a single patch and send it
        sig_pset = self._create_patch_set([patch])

        # default wait to yes
        wait = kwargs.get("wait")
        wait = True if wait is None else wait
        return self._send_signed_patch(sig_pset, wait)

    def _create_patch(self, **kwargs):
        # convert object to cbor dict if possible
        obj = kwargs.get("obj", None)
        if obj is not None and hasattr(obj, "to_cbor_dict"):
            obj = obj.to_cbor_dict()

        # construct path from kwargs
        path = mass_patch.PatchPath(
            type=mass_patch.ObjectType(kwargs["type"]),
            object_id=kwargs.get("object_id", None),
            tag_name=kwargs.get("tag_name", None),
            account_addr=kwargs.get("account_addr", None),
            fields=kwargs.get("fields", None),
        )

        # create patch for object
        return mass_patch.Patch(
            path=path,
            op=kwargs["op"],
            value=obj,
        )

    def _create_patch_set(self, patches):
        # create header
        header = mass_patch.PatchSetHeader(
            key_card_nonce=self.last_event_nonce,
            shop_id=mass_base.Uint256(self.shop_token_id),
            timestamp=cbor_now(),
            root_hash=get_root_hash_of_patches(patches),
        )
        self.last_event_nonce += 1

        # TODO: debug flag
        # print(f"{self.name} writes:")
        # pprint(shop_evt)

        signature = self._sign_header(header)

        return mass_patch.SignedPatchSet(
            header=header,
            signature=signature,
            patches=patches,
        )

    def toggle_batching(self):
        self.batching_enabled = not self.batching_enabled

    # Start buffering patches instead of sending them immediately
    def start_batch(self):
        assert not self.batching_enabled
        self.batching_enabled = True
        self.patch_buffer.clear()

    # Send all buffered patches as a single patch set
    def flush_batch(self, wait=True):
        if len(self.patch_buffer) == 0:
            print(f"{self.name} no patches to flush")
            return None

        patches = self.patch_buffer.copy()
        self.patch_buffer.clear()
        self.batching_enabled = False

        sig_pset = self._create_patch_set(patches)
        return self._send_signed_patch(sig_pset, wait)

    # wait controls whether to wait for a response to the request
    def _send_signed_patch(
        self, sig_pset: mass_patch.SignedPatchSet, wait: bool = True
    ):
        req_id = self.next_request_id()
        cbor_bytes = cbor_encode(sig_pset.to_cbor_dict())
        wr = transport_pb2.PatchSetWriteRequest(patch_set=cbor_bytes)
        msg = Envelope(
            request_id=req_id,
            patch_set_write_request=wr,
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
        # TODO: batching cleanup
        # if not self.expect_error:
        #     assert self.shop is None
        sm = mass_manifest.Manifest(
            shop_id=mass_base.Uint256(self.shop_token_id),
            accepted_currencies={
                self.default_currency.chain_id: {
                    self.default_currency.address,
                },
            },
            pricing_currency=self.default_currency,
            payees={
                self.default_payee.address.chain_id: {
                    self.default_payee.address.address: mass_base.PayeeMetadata(
                        call_as_contract=False
                    )
                },
            },
            shipping_regions={
                "default": mass_base.ShippingRegion(
                    country="",
                    postal_code="",
                    city="",
                )
            },
            order_payment_timeout=600000000,
        )
        self._write_patch(
            obj=sm,
            type=mass_patch.ObjectType.MANIFEST,
            op="replace",
        )

    def update_shop_manifest(
        self,
        add_currency: Optional[mass_base.ChainAddress] = None,
        remove_currency: Optional[mass_base.ChainAddress] = None,
        set_pricing_currency: Optional[mass_base.ChainAddress] = None,
        add_payee: Optional[mass_base.Payee] = None,
        remove_payee: Optional[mass_base.Payee] = None,
        add_region: Optional[Tuple[str, mass_base.ShippingRegion]] = None,
        remove_region: Optional[str] = None,
        wait: bool = True,
    ):
        obj = None
        fields = None
        op = None
        assert self.shop is not None, "shop not initialized"
        if add_currency:
            op = mass_patch.OpString.ADD
            fields = [
                "AcceptedCurrencies",
                add_currency.chain_id,
                add_currency.address.to_bytes(),
            ]
            obj = {}
        elif remove_currency is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_currency, mass_base.ChainAddress)
            fields = [
                "AcceptedCurrencies",
                remove_currency.chain_id,
                remove_currency.address.to_bytes(),
            ]
            obj = None
        elif set_pricing_currency:
            op = mass_patch.OpString.REPLACE
            fields = ["PricingCurrency"]
            obj = set_pricing_currency
            assert isinstance(obj, mass_base.ChainAddress)
        elif add_payee:
            op = mass_patch.OpString.ADD
            assert isinstance(add_payee, mass_base.Payee)
            fields = [
                "Payees",
                add_payee.address.chain_id,
                add_payee.address.address.to_bytes(),
            ]
            obj = mass_base.PayeeMetadata(call_as_contract=add_payee.call_as_contract)
        elif remove_payee is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_payee, mass_base.Payee)
            fields = [
                "Payees",
                remove_payee.address.chain_id,
                remove_payee.address.address.to_bytes(),
            ]
            obj = None
        elif add_region:
            op = mass_patch.OpString.ADD
            name = add_region[0]
            fields = ["ShippingRegions", name]
            obj = add_region[1]
            assert isinstance(obj, mass_base.ShippingRegion)
        elif remove_region is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_region, str)
            fields = ["ShippingRegions", remove_region]
            obj = None
        else:
            raise Exception("no fields to update")
        self._write_patch(
            type=mass_patch.ObjectType.MANIFEST,
            obj=obj,
            op=op,
            fields=fields,
            wait=wait,
        )

    def create_listing(
        self,
        name: str,
        price: int,
        iid=None,
        wait=True,
        state=mass_listing.ListingViewState.PUBLISHED,
    ):
        if iid is None:
            iid = new_object_id()
        if self.shop is None and not self.expect_error:
            raise Exception("shop not initialized")
        if self.shop is not None and self.shop.listings.has(iid):
            raise Exception(f"Listing already exists: {iid}")
        meta = mass_listing.ListingMetadata(
            title=name,
            description="This is a description of the listing",
            images=["https://example.com/image.png"],
        )
        listing = mass_listing.Listing(
            id=iid,
            metadata=meta,
            price=mass_base.Uint256(price),
            view_state=state,
        )
        self._write_patch(
            obj=listing,
            object_id=iid,
            type=mass_patch.ObjectType.LISTING,
            op=mass_patch.OpString.ADD,
            wait=wait,
        )
        if wait and not self.expect_error:
            i = 10
            while not self.shop.listings.has(iid):
                self.handle_all()
                i -= 1
                assert i > 0, f"create listing {iid} timeout"
        return iid

    def update_listing(
        self,
        listing_id: int,
        price: Optional[int | mass_base.Uint256] = None,
        title: Optional[str] = None,
        descr: Optional[str] = None,
        add_image: Optional[str] = None,
        remove_image: Optional[int] = None,
        state: Optional[mass_listing.ListingViewState] = None,
        add_option: Optional[Tuple[str, mass_listing.ListingOption]] = None,
        remove_option: Optional[str] = None,
        add_variation: Optional[
            Tuple[str, Tuple[str, mass_listing.ListingVariation]]
        ] = None,
        remove_variation: Optional[Tuple[str, str]] = None,
    ):
        op = None
        obj = None
        fields = None
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error:
            assert self.shop.listings.has(listing_id), f"unknown listing: {listing_id}"
        if price:
            op = mass_patch.OpString.REPLACE
            fields = ["Price"]
            assert isinstance(price, int) or isinstance(price, mass_base.Uint256)
            obj = price
        elif title:
            op = mass_patch.OpString.REPLACE
            fields = ["Metadata", "Title"]
            assert isinstance(title, str)
            obj = title
        elif descr:
            op = mass_patch.OpString.REPLACE
            fields = ["Metadata", "Description"]
            assert isinstance(descr, str)
            obj = descr
        elif add_image:
            op = mass_patch.OpString.APPEND
            fields = ["Metadata", "Images"]
            assert isinstance(add_image, str)
            obj = add_image
        elif remove_image is not None:
            op = mass_patch.OpString.REMOVE
            fields = ["Metadata", "Images", remove_image]
            assert isinstance(remove_image, int)
            obj = None
        elif state:
            op = mass_patch.OpString.REPLACE
            fields = ["ViewState"]
            assert isinstance(state, mass_listing.ListingViewState)
            obj = state
        elif add_option:
            op = mass_patch.OpString.ADD
            assert isinstance(add_option, tuple) and len(add_option) == 2
            opt_name = add_option[0]
            assert isinstance(opt_name, str)
            obj = add_option[1]
            assert isinstance(obj, mass_listing.ListingOption)
            fields = ["Options", opt_name]
        elif remove_option:
            op = mass_patch.OpString.REMOVE
            fields = ["Options", remove_option]
            assert isinstance(remove_option, str)
            obj = None
        elif add_variation:
            op = mass_patch.OpString.ADD
            assert isinstance(add_variation, tuple) and len(add_variation) == 2
            opt_name = add_variation[0]
            assert isinstance(opt_name, str)
            new_var = add_variation[1]
            assert isinstance(new_var, tuple) and len(new_var) == 2
            var_name = new_var[0]
            assert isinstance(var_name, str)
            obj = new_var[1]
            assert isinstance(obj, mass_listing.ListingVariation)
            fields = ["Options", opt_name, "Variations", var_name]
        elif remove_variation:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_variation, tuple) and len(remove_variation) == 2
            opt_name = remove_variation[0]
            assert isinstance(opt_name, str)
            var_name = remove_variation[1]
            assert isinstance(var_name, str)
            fields = ["Options", opt_name, "Variations", var_name]
            obj = None
        else:
            raise Exception("no fields to update")
        assert fields is not None, "no fields to update"
        assert op is not None, "no op to update"
        return self._write_patch(
            type=mass_patch.ObjectType.LISTING,
            object_id=listing_id,
            obj=obj,
            op=op,
            fields=fields,
        )

    def create_tag(self, name):
        if not self.expect_error:
            assert self.shop is not None, "shop not initialized"
        if self.shop is not None and self.shop.tags.has(name):
            raise Exception(f"Tag already exists: {name}")
        tag = mass_base.Tag(name=name, listings=[])
        self._write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=name,
            obj=tag,
            op=mass_patch.OpString.ADD,
        )

    def add_to_tag(self, tag_name, listing_id):
        assert self.shop is not None, "shop not initialized"
        # Skip tag existence check when batching is enabled since the tag might
        # be created earlier in the same batch but not yet applied to local state
        if (
            not self.expect_error
            and not self.batching_enabled
            and not self.shop.tags.has(tag_name)
        ):
            raise Exception(f"Unknown tag: {tag_name}")
        if not self.expect_error and not self.shop.listings.has(listing_id):
            raise Exception(f"Unknown listing: {listing_id}")
        if not isinstance(listing_id, int):
            raise Exception("Listing ID must be an integer")
        self._write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=tag_name,
            fields=["ListingIDs"],
            op=mass_patch.OpString.APPEND,
            obj=listing_id,
        )

    def remove_from_tag(self, tag_name, listing_id):
        assert self.shop is not None, "shop not initialized"
        tag = self.shop.tags.get(tag_name)
        if not self.expect_error and tag is None:
            raise Exception(f"Unknown tag: {tag_name}")
        if not self.expect_error and not self.shop.listings.has(listing_id):
            raise Exception(f"Unknown listing: {listing_id}")
        assert tag is not None, f"Unknown tag: {tag_name}"
        # Find the index of the listing ID in the tag's listings array
        try:
            index = tag.listings.index(listing_id)
        except ValueError:
            raise Exception(f"Listing {listing_id} not found in tag {tag_name}")
        except AttributeError:
            if self.expect_error:
                index = 0
            else:
                raise Exception(f"Tag {tag_name} has no listings")

        self._write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=tag_name,
            fields=["ListingIDs", index],
            op=mass_patch.OpString.REMOVE,
        )

    # TODO: figure out semantics
    # def rename_tag(self, tag_name, new_name):
    #     if not self.expect_error and not self.tags.has(tag_name):
    #         raise Exception(f"Unknown tag: {tag_name}")
    #     self._write_patch(
    #         type=mass_patch.ObjectType.TAG,
    #         tag_name=tag_name,
    #         fields=["Name"],
    #         op=mass_patch.OpString.REPLACE,
    #         obj=new_name,
    #   )

    def delete_tag(self, tag_name):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.tags.has(tag_name):
            raise Exception(f"Unknown tag: {tag_name}")
        self._write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=tag_name,
            op=mass_patch.OpString.REMOVE,
        )

    def change_inventory(
        self, listing_id: int, change: int, variations: Optional[List[str]] = None
    ):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.listings.has(listing_id):
            raise Exception(f"Unknown listing: {listing_id}")

        op = mass_patch.OpString.ADD
        lookup_id = vid(listing_id, variations)
        current = self.shop.inventory.get(lookup_id)
        if current is None:
            current = 0
            op = mass_patch.OpString.ADD
        if not self.expect_error and current + change < 0:
            raise Exception(
                f"Inventory underflow: {lookup_id} {current} + {change} < 0"
            )
        if change == 0:
            op = mass_patch.OpString.REPLACE
        elif change > 0:
            op = mass_patch.OpString.INCREMENT
        else:
            change = -change
            op = mass_patch.OpString.DECREMENT
        self._write_patch(
            type=mass_patch.ObjectType.INVENTORY,
            object_id=listing_id,
            op=op,
            obj=change,
            fields=variations,
        )

    def check_inventory(self, listing_id: int, variations: Optional[List[str]] = None):
        assert self.shop is not None, "shop not initialized"
        lookup_id = vid(listing_id, variations)
        current = self.shop.inventory.get(lookup_id)
        if current is None:
            return 0
        else:
            return current

    def create_order(self, oid=None, wait=True):
        if not self.expect_error:
            assert self.shop is not None, "shop not initialized"
        if oid is None:
            oid = new_object_id()
        if not self.expect_error and self.shop.orders.has(oid):
            raise Exception(f"Order already exists: {oid}")
        order = mass_order.Order(id=oid, items=[], payment_state=mass_order.OrderPaymentState.OPEN)
        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=oid,
            obj=order,
            op=mass_patch.OpString.ADD,
            wait=wait,
        )

        if wait and not self.expect_error:
            i = 10
            while not self.shop.orders.has(oid):
                self.handle_all()
                i -= 1
                assert i > 0, "create order timeout"
        return oid

    def add_to_order(self, order_id, listing_id, quantity, variations=None):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")
        if not self.expect_error and not self.shop.listings.has(listing_id):
            raise Exception(f"Unknown listing: {listing_id}")
        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.APPEND,
            obj=mass_order.OrderedItem(
                listing_id=listing_id,
                quantity=quantity,
                variation_ids=variations,
            ),
            fields=["Items"],
        )

    def remove_from_order(self, order_id, listing_id, quantity, variations=None):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")
        if not self.expect_error and not self.shop.listings.has(listing_id):
            raise Exception(f"Unknown listing: {listing_id}")

        order = self.shop.orders.get(order_id)
        if order is None:
            raise Exception(f"Unknown order: {order_id}")

        index = None
        for i, item in enumerate(order.items):
            if item.listing_id == listing_id and item.variation_ids == variations:
                index = i
                break

        if index is None:
            raise Exception(f"Listing {listing_id} not found in order {order_id}")

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.DECREMENT,
            obj=quantity,
            fields=["Items", index, "Quantity"],
        )

    def abandon_order(self, order_id):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")

        # Start batch to combine these operations
        was_batching = self.batching_enabled
        if not was_batching:
            self.start_batch()

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.ADD,
            fields=["CanceledAt"],
            obj=cbor_now(),
        )
        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["PaymentState"],
            obj=mass_order.OrderPaymentState.CANCELED,
        )

        if not was_batching:
            self.flush_batch()

    def update_address_for_order(self, order_id, invoice=None, shipping=None):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")
        if invoice is None and shipping is None:
            raise Exception("invoice and shipping cannot both be None")
        field_name = "InvoiceAddress" if invoice else "ShippingAddress"
        address_obj = invoice if invoice else shipping

        # check if order already has an address
        order = self.shop.orders.get(order_id)
        if order is not None:
            if order.invoice_address is not None and field_name == "InvoiceAddress":
                op = mass_patch.OpString.REPLACE
            elif order.shipping_address is not None and field_name == "ShippingAddress":
                op = mass_patch.OpString.REPLACE
            else:
                op = mass_patch.OpString.ADD
        else:
            op = mass_patch.OpString.ADD

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=op,
            fields=[field_name],
            obj=address_obj,
        )

    def commit_items(self, order_id):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")
        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["PaymentState"],
            obj=mass_order.OrderPaymentState.COMMITTED,
            wait=self.expect_error,
        )

    def choose_payment(self, order_id, currency=None, payee=None):
        assert self.shop is not None, "shop not initialized"
        if not self.expect_error and not self.shop.orders.has(order_id):
            raise Exception(f"Unknown order: {order_id}")

        # Set chosen currency
        if currency is None:
            currency = self.default_currency

        # Set chosen payee
        if payee is None:
            payee = self.default_payee

        was_batching_before = self.batching_enabled
        if not was_batching_before:
            self.start_batch()

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["ChosenCurrency"],
            obj=currency,
        )

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["ChosenPayee"],
            obj=payee,
        )

        self._write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["PaymentState"],
            obj=mass_order.OrderPaymentState.PAYMENT_CHOSEN,
        )

        if not was_batching_before:
            self.flush_batch()
