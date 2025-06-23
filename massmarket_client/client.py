# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import os
import requests
import json
import datetime
from typing import Optional, List, Tuple
from hashlib import sha256
import cbor2

from web3 import Web3, Account, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from eth_account.messages import encode_defunct

from massmarket import (
    cbor_encode,
    verify_proof,
    get_root_hash_of_patches,
    error_pb2,
    subscription_pb2,
    transport_pb2,
    shop_requests_pb2,
    base_types_pb2 as pb_base,
)
from massmarket.envelope_pb2 import Envelope
import massmarket.cbor.patch as mass_patch
import massmarket.cbor.base_types as mass_base
import massmarket.cbor.manifest as mass_manifest
import massmarket.cbor.listing as mass_listing
import massmarket.cbor.order as mass_order

from .persistence import ShopPersistence, PatchLogger, StateManager
from .connection_manager import ConnectionManager, AuthenticationManager
from .patch_manager import PatchManager
from .subscription_manager import SubscriptionManager
from .blockchain_manager import BlockchainManager
from .shop_operations import ShopOperations
from .utils import (
    cbor_now,
    new_object_id,
    vid,
    transact_with_retry,
    check_transaction,
    RelayException,
    public_key_to_address,
)


class RefactoredRelayClient:
    """Refactored relay client with separated concerns and persistence."""

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
        data_dir="shop_data",
        log_dir="patch_logs",
    ):
        self.name = name
        self.debug = debug
        self.validate_patches = validate_patches
        self.is_guest = guest
        self.start_time = datetime.datetime.now(datetime.UTC)

        # Setup relay connection
        self.relay_http_address = (
            os.getenv("RELAY_HTTP_ADDRESS")
            if relay_http_address is None
            else relay_http_address
        )
        assert self.relay_http_address is not None, "RELAY_HTTP_ADDRESS is not set"
        print(f"{name} is using relay: {self.relay_http_address}")

        relay_ping = os.getenv("RELAY_PING")
        assert relay_ping is not None, "RELAY_PING is not set"
        self.relay_ping = float(relay_ping)

        # Initialize connection manager
        self.connection_manager = ConnectionManager(
            self.relay_http_address, self.relay_ping, debug=debug
        )

        # Register subscription push handler
        self.connection_manager.register_handler(
            "subscription_push_request", self._handle_subscription_push_request
        )

        # Setup relay token and chain ID
        if relay_token_id == None:
            # Request testing info from relay
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

        # Setup account
        self.account = None
        if not wallet_account and not wallet_private_key:
            raise Exception("need to define either private key or account")
        account = (
            wallet_account if wallet_account else Account.from_key(wallet_private_key)
        )
        print("{} is using address: {}".format(name, account.address))
        self.account = account

        # Initialize blockchain manager
        self.blockchain_manager = BlockchainManager(self.account, debug=debug)

        # Key card setup
        if key_card_private_key is None:
            self.own_key_card = Account.create()
            print(f"new key card: {self.own_key_card}")
        else:
            self.own_key_card = Account.from_key(key_card_private_key)

        # Shop state initialization
        self._shop_token_id = 0
        self.valid_addrs = []  # Initialize valid addresses cache
        self._all_key_cards = {}  # Initialize key cards cache
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

        # Initialize persistence and state management
        self.persistence = ShopPersistence(data_dir)
        self.patch_logger = PatchLogger(log_dir)
        self.state_manager = None  # Will be initialized when shop_token_id is set

        # Initialize managers (will be set up when shop is initialized)
        self.patch_manager = None
        self.subscription_manager = None
        self.shop_operations = None
        self.auth_manager = None

        # Auto-connect if requested
        if auto_connect:
            health_resp = requests.get(
                self.relay_http_address + "/health",
                headers={"Origin": "localhost"},
            )
            if health_resp.status_code != 200:
                raise Exception(f"relay health check failed")
            self.connect()

    # ============================================================================
    # PRIVATE/INTERNAL METHODS
    # ============================================================================

    @property
    def shop_token_id(self):
        """Get the shop token ID."""
        return self._shop_token_id

    @shop_token_id.setter
    def shop_token_id(self, value):
        """Set the shop token ID and initialize managers if needed."""
        self._shop_token_id = value
        if value != 0:
            self._initialize_state_manager()

    def _rebuild_key_cards_from_state(self):
        """Rebuild _all_key_cards from current shop state (for initialization)."""
        if not self.state_manager:
            return

        # Load the shop state first
        shop = self.state_manager.load_shop()
        if not shop or not shop.accounts:
            return

        # Rebuild _all_key_cards from current shop state
        self._all_key_cards = {}

        def collect_keycards(user_wallet, account):
            if account and account.keycards:
                for keycard in account.keycards:
                    self._all_key_cards[keycard] = user_wallet
            return True

        shop.accounts.all(collect_keycards)

        # Clear address cache so it gets recomputed with loaded keycards
        self._clear_valid_addresses_cache()

    def _initialize_state_manager(self):
        """Initialize the state manager for the current shop."""
        if self._shop_token_id == 0:
            return

        self.state_manager = StateManager(
            self._shop_token_id, self.persistence, self.patch_logger
        )

        # Rebuild keycard tracking from any existing shop state
        # This is critical for reconnecting clients to validate signatures
        # from keycards that were enrolled while they were offline
        self._rebuild_key_cards_from_state()

        # Start patch logging session
        self.patch_logger.start_session(self.name, self._shop_token_id)

        # Initialize patch manager
        self.patch_manager = PatchManager(
            self.connection_manager,
            self.own_key_card,
            self._shop_token_id,
            debug=self.debug,
        )
        self.patch_manager.set_last_event_nonce(1)  # Reset nonce for new shop

        # Initialize subscription manager
        self.subscription_manager = SubscriptionManager(
            self.connection_manager, debug=self.debug
        )

        # Initialize shop operations
        self.shop_operations = ShopOperations(
            self.patch_manager,
            self.state_manager,
            self.default_currency,
            self.default_payee,
            self.default_shipping_address,
            self,  # Pass reference to self for expect_error access
            debug=self.debug,
        )

        # Initialize authentication manager
        self.auth_manager = AuthenticationManager(
            self.connection_manager,
            self,  # Pass reference to self so it can get current keycard and account
            self.chain_id,
            self.relay_token_id,
            self._shop_token_id,
            self.is_guest,
        )

    # ============================================================================
    # CONNECTION AND AUTHENTICATION METHODS
    # ============================================================================

    def connect(self):
        """Connect to the relay."""
        self.connection_manager.connect()

    def handle_all(self):
        """Handle all pending messages."""
        self.connection_manager.handle_all()

    def enroll_key_card(self, siwe_msg=None):
        """Enroll a key card with the relay."""
        if self.auth_manager:
            self.auth_manager.enroll_key_card(siwe_msg, self.account)

            # Add own keycard to _all_key_cards to match original client behavior
            from eth_keys.datatypes import PrivateKey

            keyCard = PrivateKey(self.own_key_card.key)
            # Store as mass_base.PublicKey to match original client
            mass_public_key = mass_base.PublicKey(
                key=keyCard.public_key.to_compressed_bytes()
            )
            self._all_key_cards[mass_public_key] = self.account.address
            # Clear address cache so it gets recomputed with new keycard
            self._clear_valid_addresses_cache()
        else:
            raise Exception("No auth manager initialized")

    def close(self):
        """Close the connection and save state."""
        if self.state_manager and self.state_manager.is_dirty():
            self.state_manager.save_shop()

        if self.patch_logger:
            self.patch_logger.end_session(self.connection_manager.errors)

        self.connection_manager.close()
        print(f"closed {self.name}")

    # ============================================================================
    # SHOP REGISTRATION AND SETUP METHODS
    # ============================================================================

    def register_shop(self, token_id=None):
        """Register a new shop."""
        token_id = self.blockchain_manager.register_shop(token_id)
        self.shop_token_id = (
            token_id  # This will automatically call _initialize_state_manager
        )
        print(f"shopTokenID: {self.shop_token_id}")

        # Add relay to shop
        self.blockchain_manager.add_relay_to_shop(
            self.shop_token_id, self.relay_token_id
        )

        return token_id

    def add_relay_to_shop(self, relay_token):
        """Add a relay to the shop."""
        self.blockchain_manager.add_relay_to_shop(self.shop_token_id, relay_token)

    # ============================================================================
    # UTILITY METHODS
    # ============================================================================

    def check_tx(self, tx):
        """Check a transaction."""
        return self.blockchain_manager.check_tx(tx)

    def transact_with_retry(self, func, max_attempts=10):
        """Execute a transaction with retry logic."""
        return self.blockchain_manager.transact_with_retry(func, max_attempts)

    def authenticate(self):
        """Authenticate with the relay."""
        if self.auth_manager:
            self.auth_manager.authenticate()
        else:
            raise Exception("No auth manager initialized")

    def _write_patch(self, **kwargs):
        """Write a patch to the relay (delegates to patch manager)."""
        return self.patch_manager.write_patch(**kwargs)

    def _sign_header(self, header):
        """Sign a patch set header (delegates to patch manager)."""
        return self.patch_manager._sign_header(header)

    def _send_signed_patch(self, sig_pset, wait=True):
        """Send a signed patch set (delegates to patch manager)."""
        return self.patch_manager._send_signed_patch(sig_pset, wait)

    def _create_patch(self, **kwargs):
        """Create a patch (delegates to patch manager)."""
        return self.patch_manager._create_patch(**kwargs)

    def _create_patch_set(self, patches):
        """Create a patch set (delegates to patch manager)."""
        return self.patch_manager._create_patch_set(patches)

    def login(self, subscribe=True):
        """Login to the relay."""
        if not self.connection_manager.connected:
            self.connect()

        if self.auth_manager:
            self.auth_manager.authenticate()

        if subscribe:
            self.subscribe_all()

    # ============================================================================
    # SUBSCRIPTION METHODS
    # ============================================================================

    def subscribe_all(self):
        """Subscribe to all object types."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.subscribe_all(
            self.shop_token_id,
            self.state_manager.get_last_seq_no() if self.state_manager else 0,
        )

    def subscribe(self, filters):
        """Subscribe to specific filters."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.subscribe(
            filters,
            self.shop_token_id,
            self.state_manager.get_last_seq_no() if self.state_manager else 0,
        )

    def subscribe_visitor(self):
        """Subscribe as a visitor."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.subscribe_visitor(
            self.shop_token_id,
            self.state_manager.get_last_seq_no() if self.state_manager else 0,
        )

    def subscribe_customer(self):
        """Subscribe as a customer."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.subscribe_customer(
            self.shop_token_id,
            self.state_manager.get_last_seq_no() if self.state_manager else 0,
        )

    def subscribe_order(self, id=None):
        """Subscribe to a specific order."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.subscribe_order(
            self.shop_token_id,
            self.state_manager.get_last_seq_no() if self.state_manager else 0,
            id,
        )

    def cancel_subscription(self, id):
        """Cancel a subscription."""
        if not self.subscription_manager:
            raise Exception("No subscription manager initialized")
        return self.subscription_manager.cancel_subscription(id)

    def _handle_subscription_push_request(self, msg: Envelope):
        """Handle subscription push request."""
        req = msg.subscription_push_request
        if self.debug:
            print(
                f"{self.name} SubscriptionPushRequest reqID={msg.request_id.raw} sets={len(req.sets)}"
            )

        err = None
        last_seq_no = None

        # Patch logging is now handled by StateManager.apply_patch()

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
                # Verify proof
                [leaf_index, size, proof_path] = cbor2.loads(set.proofs[i])
                if proof_path is None:
                    proof_path = []

                hashed_patch = sha256(patch_data).digest()
                verify_proof(leaf_index, hashed_patch, proof_path, header.root_hash)

                # Apply patch to local state
                patch = mass_patch.Patch.from_cbor(patch_data)

                obj_type = patch.path.type
                if self.debug:
                    print(
                        f"{self.name}/newEvent shopSeq:{set.shop_seq_no} nonce:{header.key_card_nonce} kc:{signed_by} type:{obj_type}"
                    )

                last_seq_no = set.shop_seq_no

                # Apply patch using state manager
                if self.state_manager:
                    try:
                        self.state_manager.apply_patch(patch, set.shop_seq_no)

                        # Clear address cache if accounts were modified (keycards changed)
                        if patch.path.type == mass_patch.ObjectType.ACCOUNT:
                            self._clear_valid_addresses_cache()
                            # Update _all_key_cards to match original client behavior
                            self._update_key_cards_from_patch(patch)

                    except Exception as e:
                        print(f"Patch application failed: {e}")
                        err = error_pb2.Error(
                            code=error_pb2.ERROR_CODES_INVALID,
                            message=str(e),
                        )
                        break

                if self.debug:
                    print(
                        f"{self.name} patched {patch.path.type}: {patch.op} {patch.path.fields}"
                    )

        # Send response
        resp = Envelope(
            request_id=msg.request_id,
            response=Envelope.GenericResponse(error=err),
        )

        self.connection_manager.send_message(resp)

        if err is not None:
            raise Exception(f"{err.code}: {err.message}")

        if self.debug:
            self.print_state()

        # Note: Sequence number tracking is now handled by StateManager

    # ============================================================================
    # SIGNATURE VERIFICATION
    # ============================================================================

    def _verify_signature(self, header_data: bytes, signature: bytes):
        """Verify a signature against valid signing addresses."""
        if len(signature) != 65:
            raise Exception(f"Invalid signature length: {len(signature)}")
        encoded_data = encode_defunct(header_data)
        pub_key = self.blockchain_manager.w3.eth.account.recover_message(
            encoded_data, signature=signature
        )
        # print(f"{self.name} received event from recovered pub_key: {pub_key}")
        their_addr = Web3.to_checksum_address(pub_key).lower()
        valid_addrs = self._valid_event_signing_addresses()
        if their_addr not in valid_addrs:
            print(f"valid addresses: {valid_addrs}")
            raise Exception(f"Event signed by unknown address: {their_addr}")
        return their_addr

    def _valid_event_signing_addresses(self):
        """Get all valid signing addresses (relays + key cards)."""
        # Match original client implementation exactly
        if len(self.valid_addrs) != 0:
            return self.valid_addrs
        else:
            all_addrs = []
            # retrieve all relays nfts
            if self.shop_token_id and self.blockchain_manager:
                try:
                    relay_count = (
                        self.blockchain_manager.shopReg.functions.getRelayCount(
                            self.shop_token_id
                        ).call()
                    )
                    if relay_count > 0:
                        all_relay_token_ids = (
                            self.blockchain_manager.shopReg.functions.getAllRelays(
                                self.shop_token_id
                            ).call()
                        )
                        for token_id in all_relay_token_ids:
                            # retrieve the owner => it's address
                            relay_address = (
                                self.blockchain_manager.relayReg.functions.ownerOf(
                                    token_id
                                ).call()
                            )
                            all_addrs.append(relay_address.lower())
                except Exception as e:
                    print(f"Warning: Could not fetch relay addresses: {e}")

            # turn key cards into addresses using shop state
            all_key_cards = self.all_key_cards  # This gets from shop state
            key_card_addresses = [
                public_key_to_address(pk).lower() for pk in list(all_key_cards.keys())
            ]
            all_addrs.extend(key_card_addresses)
            self.valid_addrs = all_addrs
            return all_addrs

    def _clear_valid_addresses_cache(self):
        """Clear the cached valid addresses (call when accounts/keycards change)."""
        self.valid_addrs = []

    def _update_key_cards_from_patch(self, patch):
        """Update _all_key_cards when account patches are applied (matches original client)."""
        if not self.state_manager or not self.state_manager.shop:
            return

        shop = self.state_manager.shop
        if not shop.accounts:
            return

        # Rebuild _all_key_cards from current shop state
        self._all_key_cards = {}

        def collect_keycards(user_wallet, account):
            if account and account.keycards:
                for keycard in account.keycards:
                    self._all_key_cards[keycard] = user_wallet
            return True

        shop.accounts.all(collect_keycards)

    def _assert_shop_against_response(self, req_id):
        """Assert that local shop state matches server response hash."""
        if not self.state_manager:
            raise Exception("No state manager initialized")

        shop = self.state_manager.get_shop()
        if not shop:
            raise Exception("No shop state available")

        # Get the hash from the response
        if req_id.raw not in self.connection_manager.outgoing_requests:
            raise Exception(f"No response found for request {req_id.raw}")

        response_data = self.connection_manager.outgoing_requests[req_id.raw]
        if "new_state_hash" not in response_data:
            raise Exception(f"No state hash in response for request {req_id.raw}")

        got_hash = response_data["new_state_hash"]
        has_hash = shop.hash()

        if got_hash != has_hash:
            raise Exception(
                f"Shop hash mismatch: server={got_hash.hex()} != local={has_hash.hex()}"
            )

        return got_hash

    # ============================================================================
    # BATCHING METHODS (DELEGATED TO PATCH MANAGER)
    # ============================================================================

    def toggle_batching(self):
        """Toggle batching mode."""
        if self.patch_manager:
            self.patch_manager.toggle_batching()

    def start_batch(self):
        """Start buffering patches instead of sending them immediately."""
        if self.patch_manager:
            self.patch_manager.start_batch()

    def flush_batch(self, wait=True):
        """Send all buffered patches as a single patch set."""
        if self.patch_manager:
            return self.patch_manager.flush_batch(wait)

    # ============================================================================
    # SHOP MANAGEMENT METHODS (DELEGATED TO SHOP OPERATIONS)
    # ============================================================================

    # Shop manifest

    def create_shop_manifest(self):
        """Create a shop manifest."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.create_shop_manifest(self.shop_token_id)

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
        """Update shop manifest."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.update_shop_manifest(
            add_currency,
            remove_currency,
            set_pricing_currency,
            add_payee,
            remove_payee,
            add_region,
            remove_region,
            wait,
        )

    # Listings

    def create_listing(
        self,
        name: str,
        price: int,
        iid=None,
        wait=True,
        state=mass_listing.ListingViewState.PUBLISHED,
    ):
        """Create a new listing."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        return self.shop_operations.create_listing(name, price, iid, wait, state)

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
        """Update a listing."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        return self.shop_operations.update_listing(
            listing_id,
            price,
            title,
            descr,
            add_image,
            remove_image,
            state,
            add_option,
            remove_option,
            add_variation,
            remove_variation,
        )

    # Tags

    def create_tag(self, name):
        """Create a new tag."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.create_tag(name)

    def add_to_tag(self, tag_name, listing_id):
        """Add a listing to a tag."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.add_to_tag(tag_name, listing_id)

    def remove_from_tag(self, tag_name, listing_id):
        """Remove a listing from a tag."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.remove_from_tag(tag_name, listing_id)

    def delete_tag(self, tag_name):
        """Delete a tag."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.delete_tag(tag_name)

    # Inventory

    def check_inventory(self, listing_id: int, variations: Optional[List[str]] = None):
        """Check inventory for a listing."""
        if not self.shop_operations:
            return 0
        return self.shop_operations.check_inventory(listing_id, variations)

    def change_inventory(
        self, listing_id: int, change: int, variations: Optional[List[str]] = None
    ):
        """Change inventory for a listing."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.change_inventory(listing_id, change, variations)

    # Orders

    def create_order(self, oid=None, wait=True):
        """Create a new order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        return self.shop_operations.create_order(oid, wait)

    def add_to_order(self, order_id, listing_id, quantity, variations=None):
        """Add an item to an order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.add_to_order(order_id, listing_id, quantity, variations)

    def remove_from_order(self, order_id, listing_id, quantity, variations=None):
        """Remove an item from an order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.remove_from_order(
            order_id, listing_id, quantity, variations
        )

    def abandon_order(self, order_id):
        """Abandon an order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.abandon_order(order_id)

    def update_address_for_order(self, order_id, invoice=None, shipping=None):
        """Update address for an order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.update_address_for_order(order_id, invoice, shipping)

    def commit_items(self, order_id):
        """Commit order items."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.commit_items(order_id)

    def choose_payment(self, order_id, currency=None, payee=None):
        """Choose payment for an order."""
        if not self.shop_operations:
            raise Exception("No shop operations initialized")
        self.shop_operations.choose_payment(order_id, currency, payee)

    # ============================================================================
    # BLOB UPLOAD METHODS
    # ============================================================================

    def get_blob_upload_url(self):
        """Get a blob upload URL."""
        req_id = self.connection_manager.next_request_id()
        ewr = shop_requests_pb2.GetBlobUploadURLRequest()
        msg = Envelope(
            request_id=req_id,
            get_blob_upload_url_request=ewr,
        )
        self.connection_manager.outgoing_requests[req_id.raw] = {
            "handler": self._handle_get_blob_upload_url_response,
            "waiting": True,
        }
        self.connection_manager.send_message(msg)
        return req_id.raw

    def _handle_get_blob_upload_url_response(self, msg: Envelope):
        """Handle blob upload URL response."""
        resp = msg.response
        if resp.HasField("error"):
            raise RelayException(resp.error)
        req_id = msg.request_id
        self.connection_manager._check_expected_request(req_id, clean=False)
        url = resp.payload.decode("utf-8")
        if self.debug:
            print(f"blobUrl: id={req_id.raw} url={url}")
        self.connection_manager.outgoing_requests[req_id.raw] = {"url": url}

    # ============================================================================
    # STATE MANAGEMENT METHODS
    # ============================================================================

    def save_state(self):
        """Save the current shop state to disk."""
        if self.state_manager:
            self.state_manager.save_shop()

    def load_state(self):
        """Load the shop state from disk."""
        if self.state_manager:
            return self.state_manager.get_shop()
        return None

    # ============================================================================
    # BLOCKCHAIN COMPATIBILITY PROPERTIES
    # ============================================================================

    @property
    def w3(self):
        """Get Web3 instance from blockchain manager."""
        return self.blockchain_manager.w3

    @property
    def erc20Token(self):
        """Get ERC20 token contract from blockchain manager."""
        return self.blockchain_manager.erc20Token

    @property
    def shopReg(self):
        """Get shop registry contract from blockchain manager."""
        return self.blockchain_manager.shopReg

    @property
    def relayReg(self):
        """Get relay registry contract from blockchain manager."""
        return self.blockchain_manager.relayReg

    @property
    def payments(self):
        """Get payments contract from blockchain manager."""
        return self.blockchain_manager.payments

    @property
    def all_key_cards(self):
        """Get all enrolled key cards (matches original client behavior)."""
        return self._all_key_cards

    @property
    def accounts(self):
        """Get accounts from shop state as a dictionary for compatibility."""
        if (
            self.state_manager
            and self.state_manager.shop
            and self.state_manager.shop.accounts
        ):
            accounts_dict = {}

            def collect_accounts(user_wallet, account):
                accounts_dict[user_wallet] = account
                return True

            self.state_manager.shop.accounts.all(collect_accounts)
            return accounts_dict
        return {}

    def print_state(self):
        """Print the current shop state."""
        if not self.state_manager:
            print("No shop state available.")
            return

        shop = self.state_manager.get_shop()
        print("Shop State:")
        print("-----------")
        print(f"Shop ID: {self.shop_token_id}")
        print(f"Schema Version: {shop.schema_version}")
        print(f"Last Seq No: {self.state_manager.get_last_seq_no()}")
        print(f"Dirty: {self.state_manager.is_dirty()}")

        # Print more detailed state information here...
        if shop is None:
            print("No shop data available.")
            return

        print("Currencies:")
        if (
            shop.manifest.accepted_currencies is None
            or len(shop.manifest.accepted_currencies) == 0
        ):
            print(" No currencies set up")
        else:
            for chain_id, addresses in shop.manifest.accepted_currencies.items():
                for addr in addresses:
                    print(f"  ChainID: {chain_id} Addr: {addr}")

        if shop.manifest.pricing_currency is None:
            print(" No base currency!")
        else:
            b = shop.manifest.pricing_currency
            print(f"Base Currency:\n  ChainID: {b.chain_id} Addr: {b.address}")

        if shop.manifest.payees is None or len(shop.manifest.payees) == 0:
            print(" No Payees set up ")
        else:
            print("Payees:")
            for chain_id, addresses in shop.manifest.payees.items():
                for addr, metadata in addresses.items():
                    print(
                        f"  ChainID: {chain_id} Addr: {addr} (isEndpoint: {metadata.call_as_contract})"
                    )

        print("\nListings:")
        if not shop.listings or shop.listings.size == 0:
            print("  No listings available.")
        else:

            def print_listing(listing_id, listing):
                print(f"  Listing ID: {listing_id}")
                print(f"    Price: {listing.price}")
                if listing.options is not None:
                    for option_name, option in listing.options.items():
                        print(f"    Option: {option_name}")
                        for variation_name, variation in option.variations.items():
                            print(f"      Variation: {variation_name}")
                            print(f"       Modifier: {variation.price_modifier}")
                if shop.inventory and shop.inventory.has(listing_id):
                    quantity = shop.inventory.get(listing_id)
                    if quantity is not None:
                        print(f"    Stock: {quantity}")
                else:
                    print("    Stock: Not available")
                print(f"    Metadata: {listing.metadata}")
                return True

            shop.listings.all(print_listing)

        print("\nTags:")
        if not shop.tags or shop.tags.size == 0:
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

            shop.tags.all(print_tag)

    # ============================================================================
    # COMPATIBILITY PROPERTIES
    # ============================================================================

    @property
    def connected(self) -> bool:
        """Get connection status."""
        return self.connection_manager.connected if self.connection_manager else False

    @property
    def logged_in(self) -> bool:
        """Get login status."""
        return self.auth_manager.logged_in if self.auth_manager else False

    @property
    def errors(self) -> int:
        """Get error count."""
        return self.connection_manager.errors if self.connection_manager else 0

    @errors.setter
    def errors(self, value: int):
        """Set error count."""
        if self.connection_manager:
            self.connection_manager.errors = value

    @property
    def last_error(self):
        """Get last error."""
        return self.connection_manager.last_error if self.connection_manager else None

    @last_error.setter
    def last_error(self, value):
        """Set last error."""
        if self.connection_manager:
            self.connection_manager.last_error = value

    @property
    def pongs(self) -> int:
        """Get pong count."""
        return self.connection_manager.pongs if self.connection_manager else 0

    @property
    def outgoingRequests(self) -> dict:
        """Get outgoing requests for compatibility."""
        return (
            self.connection_manager.outgoing_requests if self.connection_manager else {}
        )

    @property
    def shop(self):
        """Get shop state."""
        return self.state_manager.get_shop() if self.state_manager else None

    @property
    def expect_error(self) -> bool:
        """Get expect error flag."""
        return (
            self.connection_manager.expect_error if self.connection_manager else False
        )

    @expect_error.setter
    def expect_error(self, value: bool):
        """Set expect error flag."""
        if self.connection_manager:
            self.connection_manager.expect_error = value

    @property
    def subscription(self):
        """Get current subscription ID."""
        return (
            self.subscription_manager.subscription
            if self.subscription_manager
            else None
        )

    @subscription.setter
    def subscription(self, value):
        """Set current subscription ID."""
        if self.subscription_manager:
            self.subscription_manager.subscription = value

    @property
    def connection(self):
        """Get the raw connection for compatibility."""
        return self.connection_manager.connection if self.connection_manager else None

    @property
    def batching_enabled(self) -> bool:
        """Get batching status."""
        return self.patch_manager.batching_enabled if self.patch_manager else False

    @property
    def patch_buffer(self) -> list:
        """Get patch buffer for compatibility."""
        return self.patch_manager.patch_buffer if self.patch_manager else []

    @property
    def last_event_nonce(self) -> int:
        """Get last event nonce."""
        return self.patch_manager.last_event_nonce if self.patch_manager else 1

    @last_event_nonce.setter
    def last_event_nonce(self, value: int):
        """Set last event nonce."""
        if self.patch_manager:
            self.patch_manager.last_event_nonce = value
