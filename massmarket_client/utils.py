# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

"""Shared utility functions for the relay client."""

import os
import random
import datetime
import time
from typing import Optional, List
from web3 import Web3
from web3.exceptions import TransactionNotFound
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
