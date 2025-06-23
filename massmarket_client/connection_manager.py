# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import Optional, Dict, Any, Callable
import time
import datetime
import base64
import json

import requests
from urllib.parse import urlparse
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedError, InvalidStatus
from eth_account.messages import encode_defunct
from eth_keys.datatypes import PrivateKey
import siwe

from massmarket import (
    error_pb2,
    authentication_pb2,
    base_types_pb2 as pb_base,
)
from massmarket.envelope_pb2 import Envelope

from .utils import RelayException, EnrollException


class ConnectionManager:
    """Manages WebSocket connection to the relay."""

    def __init__(self, relay_http_address: str, relay_ping: float, debug: bool = False):
        self.relay_http_address = relay_http_address
        self.relay_ping = relay_ping
        self.debug = debug

        # Parse relay address
        relay_addr = urlparse(relay_http_address)
        self.relay_addr = relay_addr

        # Construct WebSocket endpoint
        relay_ws_endpoint = relay_addr._replace(path="/v4/sessions")
        if relay_addr.scheme == "http":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="ws")
        elif relay_addr.scheme == "https":
            relay_ws_endpoint = relay_ws_endpoint._replace(scheme="wss")
        else:
            raise Exception("Unknown Relay HTTP scheme: {}".format(relay_addr.scheme))
        self.relay_ws_endpoint_url = relay_ws_endpoint.geturl()

        # Connection state
        self.connected = False
        self.connection = None
        self.logged_in = False
        self.pongs = 0
        self.outgoing_requests: Dict[int, Dict[str, Any]] = {}
        self.last_request_id = 0
        self.errors = 0
        self.expect_error = False
        self.last_error = None

        # Message handlers
        self.message_handlers: Dict[str, Callable] = {}
        self._setup_default_handlers()

    def _setup_default_handlers(self):
        """Setup default message handlers."""
        self.message_handlers = {
            "ping_request": self._handle_ping_request,
            "sync_status_request": self._handle_sync_status_request,
            "subscription_push_request": self._handle_subscription_push_request,
        }

    def connect(self, max_retries: int = 10, retry_delay: float = 2):
        """Connect to the relay WebSocket endpoint."""
        if self.connected:
            return

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

    def close(self):
        """Close the WebSocket connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
        self.connected = False
        self.logged_in = False
        self.last_request_id = 0
        self.errors = 0
        self.outgoing_requests.clear()

    def next_request_id(self) -> pb_base.RequestId:
        """Generate the next request ID."""
        next_id = self.last_request_id + 1
        req_id = pb_base.RequestId(raw=next_id)
        self.last_request_id = next_id
        return req_id

    def send_message(self, envelope: Envelope) -> None:
        """Send a message to the relay."""
        if not self.connected:
            raise Exception("Not connected to relay")

        data = envelope.SerializeToString()
        self.connection.send(data)

    def _try_read(self) -> Optional[bytes]:
        """Try to read data from the connection."""
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

    def handle_all(self) -> None:
        """Handle all pending messages."""
        try:
            data = self._try_read()
            while data is not None:
                self.handle_message(data)
                data = self._try_read()
        except Exception as err:
            self.connected = False
            raise err

    def handle_message(self, data: bytes) -> None:
        """Handle a single message."""
        msg = Envelope()
        msg.ParseFromString(data)
        msg_type = msg.WhichOneof("message")
        req_id = msg.request_id.raw

        if self.debug:
            print(f"Received message_type={msg_type} reqId={req_id}")

        if msg_type == "response":
            self._handle_response(msg)
        elif msg_type in self.message_handlers:
            self.message_handlers[msg_type](msg)
        else:
            err = f"Unknown message type: {msg_type}"
            self.errors += 1
            self.last_error = error_pb2.Error(
                code=error_pb2.ERROR_CODES_INVALID, message=err
            )
            if self.expect_error:
                print(f"Expected error: {msg}")
            else:
                raise Exception(err)

    def _handle_response(self, msg: Envelope) -> None:
        """Handle a response message."""
        req_id = msg.request_id.raw
        if req_id not in self.outgoing_requests:
            raise Exception(f"Received response for unknown request id={req_id}")

        req_data = self.outgoing_requests[req_id]
        if "handler" in req_data:
            req_data["handler"](msg)

    def _handle_ping_request(self, req: Envelope) -> None:
        """Handle a ping request."""
        resp = Envelope(
            request_id=req.request_id,
            response=Envelope.GenericResponse(),
        )
        data = resp.SerializeToString()
        try:
            self.connection.send(data)
        except ConnectionClosedError as err:
            self.connected = False
        else:
            self.pongs += 1

    def _handle_sync_status_request(self, env: Envelope) -> None:
        """Handle a sync status request."""
        req = env.sync_status_request
        if self.debug:
            print(f"SyncStatusRequest: unpushedPatches={req.unpushed_patches}")
        resp = Envelope(
            request_id=env.request_id,
            response=Envelope.GenericResponse(),
        )
        data = resp.SerializeToString()
        self.connection.send(data)

    def _handle_subscription_push_request(self, msg: Envelope) -> None:
        """Handle a subscription push request."""
        # This will be handled by the main client
        pass

    def register_handler(self, msg_type: str, handler: Callable) -> None:
        """Register a custom message handler."""
        self.message_handlers[msg_type] = handler

    def wait_for_response(self, req_id: int, timeout: int = 10) -> Dict[str, Any]:
        """Wait for a response to a specific request."""
        while req_id in self.outgoing_requests:
            self.handle_all()
            timeout -= 1
            assert timeout > 0, f"Timeout waiting for response to request {req_id}"

        return self.outgoing_requests.get(req_id, {})

    def _check_expected_request(
        self, req_id: pb_base.RequestId, clean: bool = False
    ) -> None:
        """Check if a request ID is expected and optionally clean it up."""
        ours = req_id.raw
        if ours not in self.outgoing_requests:
            raise Exception(f"Received response for unknown request id={ours}")
        if clean:
            del self.outgoing_requests[ours]


class AuthenticationManager:
    """Handles authentication with the relay."""

    def __init__(
        self,
        connection_manager: ConnectionManager,
        client,  # Reference to the client to get current keycard and account
        chain_id: int,
        relay_token_id: int,
        shop_token_id: int,
        is_guest: bool = False,
    ):
        self.connection_manager = connection_manager
        self.client = client  # Store reference to client
        self.chain_id = chain_id
        self.relay_token_id = relay_token_id
        self.shop_token_id = shop_token_id
        self.is_guest = is_guest
        self.logged_in = False
        self.relay_addr = connection_manager.relay_addr

    @property
    def key_card_private_key(self) -> bytes:
        """Get the current keycard private key from the client."""
        return self.client.own_key_card.key

    @property
    def account_address(self) -> str:
        """Get the current account address from the client."""
        return self.client.account.address

    def authenticate(self) -> None:
        """Authenticate with the relay."""
        from web3 import Account

        key_card_account = Account.from_key(self.key_card_private_key)
        key_card = PrivateKey(self.key_card_private_key)

        # Send authentication request
        req_id = self.connection_manager.next_request_id()
        ar = authentication_pb2.AuthenticateRequest(
            public_key=pb_base.PublicKey(raw=key_card.public_key.to_compressed_bytes()),
        )
        msg = Envelope(
            request_id=req_id,
            auth_request=ar,
        )

        self.connection_manager.outgoing_requests[req_id.raw] = {
            "waiting": True,
            "handler": self._handle_authenticate_response,
        }

        self.connection_manager.send_message(msg)

        # Wait for authentication response
        timeout = 10
        while req_id.raw in self.connection_manager.outgoing_requests:
            print(f"waiting for authenticate response")
            self.connection_manager.handle_all()
            timeout -= 1
            assert timeout > 0, "no authenticate response in time"

        # Wait for challenge response
        timeout = 10
        while not self.logged_in:
            print(f"waiting for challenge response")
            self.connection_manager.handle_all()
            assert (
                self.connection_manager.last_error is None
            ), f"Error: {self.connection_manager.last_error}"
            timeout -= 1
            assert timeout > 0, "no challenge response in time"

        assert self.logged_in, "login failed"

    def _handle_authenticate_response(self, msg: Envelope) -> None:
        """Handle authentication response."""
        resp = msg.response
        if resp.HasField("error"):
            raise RelayException(resp.error)

        self.connection_manager._check_expected_request(msg.request_id, clean=True)

        # Sign the challenge using Account (like the original client)
        from web3 import Account

        encoded_data = encode_defunct(resp.payload)
        key_card_account = Account.from_key(self.key_card_private_key)
        signed_message = key_card_account.sign_message(encoded_data)
        signature = signed_message.signature

        # Send challenge solution
        req_id = self.connection_manager.next_request_id()
        csr = Envelope(
            request_id=req_id,
            challenge_solution_request=authentication_pb2.ChallengeSolvedRequest(
                signature=pb_base.Signature(raw=signature),
            ),
        )
        data = csr.SerializeToString()
        self.connection_manager.connection.send(data)
        self.connection_manager.outgoing_requests[req_id.raw] = {
            "handler": self._handle_challenge_solved_response,
        }

    def _handle_challenge_solved_response(self, msg: Envelope) -> None:
        """Handle challenge solved response."""
        resp = msg.response
        if resp.HasField("error"):
            raise Exception(f"Challenge failed: '{resp.error}'")

        self.connection_manager._check_expected_request(msg.request_id, clean=True)
        self.logged_in = True

    def enroll_key_card(self, siwe_msg=None, wallet_account=None) -> None:
        """Enroll a key card with the relay."""
        if wallet_account is None:
            raise ValueError("wallet_account is required for key card enrollment")

        key_card = PrivateKey(self.key_card_private_key)

        modified_url = self.relay_addr._replace(path="/v4/enroll_key_card")
        if self.is_guest:
            modified_url = modified_url._replace(query="guest=1")
        enroll_url = modified_url.geturl()

        if siwe_msg is None:
            kc_hex = "0x" + key_card.public_key.to_compressed_bytes().hex()

            now = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
            siwe_msg = siwe.SiweMessage(
                domain=self.relay_addr.netloc,
                address=self.account_address,
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
        signed_message = wallet_account.sign_message(encoded_data)
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
        print(f"enrolled keyCard {key_card.public_key.to_hex()}")
