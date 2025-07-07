# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import os
from web3 import Web3, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from .utils import transact_with_retry, check_transaction
from .contracts import DEPLOYMENT_ADDRESSES, ABIS


class BlockchainManager:
    """Manages Ethereum blockchain interactions and contract operations."""

    def __init__(self, account, debug=False):
        self.account = account
        self.debug = debug

        # Ethereum setup
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_URL")))
        self.w3.provider.cache_allowed_requests = True
        self.w3.eth.default_account = account.address

        # Add signing middleware
        sign_mw = SignAndSendRawMiddlewareBuilder.build(self.account)
        self.w3.middleware_onion.inject(sign_mw, layer=0)

        # Load contracts
        self._load_contracts()

    def _load_contracts(self):
        """Load Ethereum contracts."""
        addresses = DEPLOYMENT_ADDRESSES
        if self.debug:
            print("Using contracts:")
            import pprint

            pprint.pprint(addresses)

        # Load RelayReg contract
        self.relayReg = self.w3.eth.contract(
            address=addresses["RelayReg"], abi=ABIS["RelayReg"]
        )

        # Load ShopReg contract
        self.shopReg = self.w3.eth.contract(
            address=addresses["ShopReg"], abi=ABIS["ShopReg"]
        )

        # Load ERC20 testing token contract
        self.erc20Token = self.w3.eth.contract(
            address=addresses["Eddies"], abi=ABIS["Eddies"]
        )

        # Load Payments contract
        self.payments = self.w3.eth.contract(
            address=addresses["Payments"], abi=ABIS["PaymentsByAddress"]
        )

    def check_tx(self, tx):
        """Check a transaction."""
        check_transaction(self.w3, tx)

    def transact_with_retry(self, func, max_attempts=10):
        """Execute a transaction with retry logic."""
        return transact_with_retry(
            self.w3, self.account, func, max_attempts=max_attempts
        )

    def register_shop(self, token_id=None):
        """Register a new shop."""
        if token_id is None:
            token_id = int.from_bytes(os.urandom(32), "big")
        else:
            assert isinstance(token_id, int)

        # Mint shop NFT
        tx = self.transact_with_retry(
            self.shopReg.functions.mint(token_id, self.account.address)
        )
        self.check_tx(tx)

        if self.debug:
            print(f"Registered shop with token ID: {token_id}")

        # Check admin access by updating root hash
        tx = self.transact_with_retry(
            self.shopReg.functions.updateRootHash(token_id, os.urandom(32), 1)
        )
        self.check_tx(tx)

        return token_id

    def add_relay_to_shop(self, shop_token_id, relay_token_id):
        """Add a relay to the shop."""
        # Check if relay is already added
        if self.shopReg.functions.getRelayCount(shop_token_id).call() > 0:
            current_relay_tokens = self.shopReg.functions.getAllRelays(
                shop_token_id
            ).call()
            if relay_token_id in current_relay_tokens:
                return

        # Update the relays assigned to this shop
        tx = self.transact_with_retry(
            self.shopReg.functions.addRelay(shop_token_id, relay_token_id)
        )
        self.check_tx(tx)

    def create_invite(self, shop_token_id):
        """Create an invite for the shop."""
        reg_secret = os.urandom(32)
        from web3 import Account

        acc = Account.from_key(reg_secret)

        if self.debug:
            print("Invite token address: {}".format(acc.address))

        tx = self.transact_with_retry(
            self.shopReg.functions.publishInviteVerifier(shop_token_id, acc.address)
        )
        self.check_tx(tx)
        return reg_secret

    def redeem_invite(self, shop_token_id, invite_token):
        """Redeem an invite token."""
        from web3 import Account
        from eth_account.messages import encode_defunct
        from utils import to_32byte_hex

        acc = Account.from_key(invite_token)
        msg_text = f"enrolling:{self.account.address}"
        msg = encode_defunct(text=msg_text.lower())
        sig = acc.sign_message(msg)
        rhex = to_32byte_hex(sig.r)
        shex = to_32byte_hex(sig.s)

        tx = self.transact_with_retry(
            self.shopReg.functions.redeemInvite(
                shop_token_id, sig.v, rhex, shex, self.account.address
            )
        )
        self.check_tx(tx)

    def get_shop_relays(self, shop_token_id):
        """Get all relays for a shop."""
        if self.shopReg.functions.getRelayCount(shop_token_id).call() > 0:
            return self.shopReg.functions.getAllRelays(shop_token_id).call()
        return []

    def get_relay_owner(self, relay_token_id):
        """Get the owner of a relay token."""
        return self.relayReg.functions.ownerOf(relay_token_id).call()
