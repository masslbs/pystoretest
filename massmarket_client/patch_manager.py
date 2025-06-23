# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from web3 import Account
from eth_account.messages import encode_defunct

from massmarket import (
    cbor_encode,
    get_root_hash_of_patches,
    transport_pb2,
)
from massmarket.envelope_pb2 import Envelope
import massmarket.cbor.patch as mass_patch
import massmarket.cbor.base_types as mass_base

from .utils import cbor_now, RelayException


class PatchManager:
    """Manages patch creation, signing, and batching."""

    def __init__(self, connection_manager, own_key_card, shop_token_id, debug=False):
        self.connection_manager = connection_manager
        self.own_key_card = own_key_card
        self.shop_token_id = shop_token_id
        self.debug = debug

        # Batching state
        self.batching_enabled = False
        self.patch_buffer = []

        # Event nonce tracking
        self.last_event_nonce = 1

    def set_last_event_nonce(self, nonce: int):
        """Set the last event nonce."""
        self.last_event_nonce = nonce

    def toggle_batching(self):
        """Toggle batching mode."""
        self.batching_enabled = not self.batching_enabled

    def start_batch(self):
        """Start buffering patches instead of sending them immediately."""
        assert not self.batching_enabled, "Batching already enabled"
        self.batching_enabled = True
        self.patch_buffer.clear()

    def flush_batch(self, wait=True):
        """Send all buffered patches as a single patch set."""
        if len(self.patch_buffer) == 0:
            print("No patches to flush")
            return None

        patches = self.patch_buffer.copy()
        self.patch_buffer.clear()
        self.batching_enabled = False

        sig_pset = self._create_patch_set(patches)
        return self._send_signed_patch(sig_pset, wait)

    def write_patch(self, **kwargs):
        """Write a patch to the relay."""
        assert len(kwargs) >= 3
        assert "type" in kwargs
        assert "op" in kwargs

        patch = self._create_patch(**kwargs)

        # If batching is enabled, buffer the patch
        if self.batching_enabled:
            print(f"Buffering patch no: {len(self.patch_buffer)}")
            self.patch_buffer.append(patch)
            return None

        # Otherwise, create a patch set with a single patch and send it
        sig_pset = self._create_patch_set([patch])

        # default wait to yes
        wait = kwargs.get("wait")
        wait = True if wait is None else wait
        return self._send_signed_patch(sig_pset, wait)

    def _create_patch(self, **kwargs):
        """Create a patch from kwargs."""
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
        """Create a signed patch set."""
        # create header
        header = mass_patch.PatchSetHeader(
            key_card_nonce=self.last_event_nonce,
            shop_id=mass_base.Uint256(self.shop_token_id),
            timestamp=cbor_now(),
            root_hash=get_root_hash_of_patches(patches),
        )
        self.last_event_nonce += 1

        signature = self._sign_header(header)

        return mass_patch.SignedPatchSet(
            header=header,
            signature=signature,
            patches=patches,
        )

    def _sign_header(self, header: mass_patch.PatchSetHeader):
        """Sign a patch set header."""
        keyCardPK = Account.from_key(self.own_key_card.key)
        encoded_header = cbor_encode(header.to_cbor_dict())
        eip191_data = encode_defunct(encoded_header)
        signed_message = keyCardPK.sign_message(eip191_data)
        return signed_message.signature

    def _send_signed_patch(
        self, sig_pset: mass_patch.SignedPatchSet, wait: bool = True
    ):
        """Send a signed patch set."""
        req_id = self.connection_manager.next_request_id()
        cbor_bytes = cbor_encode(sig_pset.to_cbor_dict())
        wr = transport_pb2.PatchSetWriteRequest(patch_set=cbor_bytes)
        msg = Envelope(
            request_id=req_id,
            patch_set_write_request=wr,
        )

        self.connection_manager.outgoing_requests[req_id.raw] = {
            "waiting": True,
            "handler": self._handle_event_write_response,
        }

        self.connection_manager.send_message(msg)

        if wait:
            while "waiting" in self.connection_manager.outgoing_requests[req_id.raw]:
                print("Write waiting")
                self.connection_manager.handle_all()
            print("Event written")

        return req_id

    def _handle_event_write_response(self, msg: Envelope):
        """Handle event write response."""

        resp = msg.response
        if self.debug:
            print(f"EventWriteResponse: {resp}")

        req_id = msg.request_id
        self.connection_manager._check_expected_request(req_id, clean=True)

        if resp.WhichOneof("response") == "error":
            self.connection_manager.errors += 1
            if self.connection_manager.expect_error:
                print(f"Expected error: {resp.error}")
                self.connection_manager.last_error = resp.error
                self.connection_manager.outgoing_requests[req_id.raw] = {
                    "err": resp.error
                }
            else:
                raise RelayException(resp.error)
        else:
            if self.connection_manager.expect_error:
                print(f"Expected error: {resp}")
            self.connection_manager.outgoing_requests[req_id.raw] = {
                "new_state_hash": resp.payload,
            }
