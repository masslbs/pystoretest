# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

"""Shared utility functions for the relay client."""

import os
import random
import datetime
import json
import filelock
import time
from typing import Optional, List

from web3 import Web3, Account, HTTPProvider
from web3.exceptions import TransactionNotFound
from web3.middleware import SignAndSendRawMiddlewareBuilder
from eth_keys.datatypes import PublicKey
from google.protobuf import timestamp_pb2

from massmarket import error_pb2
import massmarket.cbor.base_types as mass_base


def to_32byte_hex(val):
    """Convert a value to 32-byte hex representation."""
    return Web3.to_hex(Web3.to_bytes(val).rjust(32, b"\0"))


def public_key_to_address(pk: bytes | mass_base.PublicKey) -> str:
    """
    Convert a public key to an Ethereum address.
    :param pk: public key
    :return: Ethereum address
    """
    if isinstance(pk, bytes):
        parsed = PublicKey(pk)
    elif isinstance(pk, mass_base.PublicKey):
        parsed = PublicKey.from_compressed_bytes(pk.key)
    else:
        raise ValueError("Invalid public key type")
    return parsed.to_address()


def now_pbts() -> timestamp_pb2.Timestamp:
    """Create a protobuf timestamp for the current time."""
    now = datetime.datetime.now(datetime.UTC)
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(now)
    return ts


def cbor_now():
    """Create a CBOR-compatible datetime for the current time."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


# Ensure value fits in 53 bits for JavaScript compatibility
# https://github.com/masslbs/Tennessine/issues/342
js_safe = False
if os.getenv("JS_SAFE") in ["true", "1", "yes", "on"]:
    js_safe = True
seed_data_width = 4 if js_safe else 8


def new_object_id(i=None):
    """Generate a new object ID."""
    if i is None:
        r = random.randbytes(seed_data_width)
    else:
        r = i.to_bytes(seed_data_width, "big")
    return int.from_bytes(r, "big")


def vid(listing_id: int, variations: Optional[List[str]] = None):
    """Create a compound id for inventory checks etc."""
    id = str(listing_id) + ":"
    if variations:
        variations.sort()
        id = id + ":".join(variations) + ":"
    return id


def transact_with_retry(w3, account, contract_call, max_attempts=3):
    """Execute a transaction with retry logic for gas price adjustments."""
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
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            return tx_hash
        except ValueError:
            assert attempt < max_attempts, (
                f"Failed to transact contract call after {max_attempts} attempts"
            )
            continue


def check_transaction(w3, tx, max_retries=5, initial_delay=0.5):
    """Check transaction status with retries."""
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

    raise TransactionNotFound(
        f"Transaction {tx.hex()} not found after {max_retries} attempts"
    )


def notFoundError(msg):
    """Create a NOT_FOUND error."""
    return error_pb2.Error(
        code=error_pb2.ERROR_CODES_NOT_FOUND,
        message=msg,
    )


def invalidError(msg):
    """Create an INVALID error."""
    return error_pb2.Error(
        code=error_pb2.ERROR_CODES_INVALID,
        message=msg,
    )


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


# Testing


class AccountFaucet:
    def __init__(
        self,
        funded_account: Account,
        initial_balance: int = Web3.to_wei(0.05, "ether"),
        nonce_folder: str = "/tmp/pystoretest",
    ):
        self.funded_account = funded_account
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_URL")))
        sign_mw = SignAndSendRawMiddlewareBuilder.build(self.funded_account)
        self.w3.middleware_onion.inject(sign_mw, layer=0)  # type: ignore

        self.initial_balance = initial_balance

        # Create a file-based lock in a temp directory
        temp_dir = (
            os.getcwd() if os.getcwd().startswith(f"{nonce_folder}.") else nonce_folder
        )
        os.makedirs(temp_dir, exist_ok=True)
        self.lock_file = os.path.join(temp_dir, "eth_test_nonce.lock")
        self.nonce_file = os.path.join(temp_dir, "eth_test_nonce.json")
        self.file_lock = filelock.FileLock(self.lock_file)

        # Initialize nonce file properly
        self._initialize_nonce_file()

    def _initialize_nonce_file(self):
        """Initialize the nonce file with the current network nonce if it doesn't exist or is behind"""
        with self.file_lock:
            network_nonce = self.w3.eth.get_transaction_count(
                self.funded_account.address  # type: ignore
            )

            if not os.path.exists(self.nonce_file):
                # File doesn't exist, create it with network nonce
                with open(self.nonce_file, "w") as f:
                    json.dump(network_nonce, f)
            else:
                # File exists, but check if it's behind the network
                with open(self.nonce_file, "r") as f:
                    file_nonce = json.load(f)

                if file_nonce < network_nonce:
                    # Our file is behind, update it to match network
                    with open(self.nonce_file, "w") as f:
                        json.dump(network_nonce, f)

    def get_test_account(self) -> Account:
        new_account = Account.create()

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Move transaction sending inside the file lock to prevent race conditions
                with self.file_lock:
                    # Get nonce from file
                    with open(self.nonce_file, "r") as f:
                        current_nonce = json.load(f)

                    # Double-check our nonce isn't behind the network
                    network_nonce = self.w3.eth.get_transaction_count(
                        self.funded_account.address  # type: ignore
                    )
                    if current_nonce < network_nonce:
                        # We're behind, sync up
                        current_nonce = network_nonce
                        with open(self.nonce_file, "w") as f:
                            json.dump(current_nonce, f)

                    # Build and send transaction atomically with nonce allocation
                    transaction = {
                        "to": new_account.address,
                        "value": self.initial_balance,
                        "nonce": current_nonce,
                        "gas": 21000,
                        "maxFeePerGas": self.w3.to_wei(50, "gwei"),
                        "maxPriorityFeePerGas": self.w3.to_wei(5, "gwei"),
                        "chainId": 31337,
                    }
                    recpt = self.w3.eth.send_transaction(transaction)  # type: ignore
                    check_transaction(self.w3, recpt)

                    # Only increment nonce after successful transaction send
                    with open(self.nonce_file, "w") as f:
                        json.dump(current_nonce + 1, f)

                    return new_account

            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                continue

        raise Exception("max_retries exceeded")
