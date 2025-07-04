# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import json
import datetime
from typing import Optional, Dict, Any
from pathlib import Path
import cbor2
from massmarket.cbor import Shop
from massmarket.cbor_encoder import cbor_encode
from massmarket.cbor.manifest import Manifest
from massmarket.cbor.listing import Listing
from massmarket.cbor.base_types import Tag, Account
from massmarket.cbor.order import Order
from massmarket.hamt import Trie
from massmarket_client.patch_handler import PatchHandler


class ShopPersistence:
    """Handles persistence of shop data to local storage."""

    def __init__(self, data_dir: str = "shop_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def save_shop(self, shop_id: int, shop: Shop, last_seq_no: int = 0) -> None:
        """Save shop data to disk."""
        shop_file = self.data_dir / f"shop_{shop_id}.cbor"
        with open(shop_file, "wb") as f:
            f.write(cbor_encode(shop.serialize()))

        # Also save metadata
        meta_file = self.data_dir / f"shop_{shop_id}_meta.json"
        metadata = {
            "shop_id": shop_id,
            "schema_version": shop.schema_version,
            "last_seq_no": last_seq_no,
            "last_updated": (
                shop.manifest.timestamp.isoformat()
                if hasattr(shop.manifest, "timestamp")
                else None
            ),
            "accounts_count": shop.accounts.size if shop.accounts else 0,
            "listings_count": shop.listings.size if shop.listings else 0,
            "orders_count": shop.orders.size if shop.orders else 0,
            "tags_count": shop.tags.size if shop.tags else 0,
            "inventory_count": shop.inventory.size if shop.inventory else 0,
        }
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)

    def load_shop(self, shop_id: int) -> Optional[Shop]:
        """Load shop data from disk."""
        shop, _ = self.load_shop_with_seq_no(shop_id)
        return shop

    def load_shop_with_seq_no(self, shop_id: int) -> tuple[Optional[Shop], int]:
        """Load shop data and sequence number from disk."""
        shop_file = self.data_dir / f"shop_{shop_id}.cbor"
        if not shop_file.exists():
            return None, 0

        try:
            with open(shop_file, "rb") as f:
                cbor_data = f.read()
                shop_dict = cbor2.loads(cbor_data)
                shop = self._deserialize_shop_with_typed_objects(shop_dict)

            # Load sequence number from metadata
            metadata = self.get_shop_metadata(shop_id)
            last_seq_no = metadata.get("last_seq_no", 0) if metadata else 0

            return shop, last_seq_no
        except Exception as e:
            print(f"Error loading shop {shop_id}: {e}")
            return None, 0

    def _deserialize_shop_with_typed_objects(self, shop_dict: dict) -> Shop:
        """Deserialize shop with properly typed objects in HAMTs."""

        # Deserialize basic shop structure
        shop = Shop(
            schema_version=shop_dict["SchemaVersion"],
            manifest=Manifest.from_cbor_dict(shop_dict["Manifest"]),
        )

        # Deserialize HAMTs with properly typed objects
        shop.accounts = self._deserialize_typed_hamt(
            shop_dict["Accounts"], Account.from_cbor_dict
        )
        shop.listings = self._deserialize_typed_hamt(
            shop_dict["Listings"], Listing.from_cbor_dict
        )
        shop.tags = self._deserialize_typed_hamt(shop_dict["Tags"], Tag.from_cbor_dict)
        shop.orders = self._deserialize_typed_hamt(
            shop_dict["Orders"], Order.from_cbor_dict
        )
        shop.inventory = Trie.from_cbor_array(
            shop_dict["Inventory"]
        )  # int values, no conversion needed

        return shop

    def _deserialize_typed_hamt(self, hamt_data, deserializer_func):
        """Deserialize a HAMT with typed objects."""
        if not hamt_data:
            return Trie.new()

        # First get the raw HAMT structure
        raw_trie = Trie.from_cbor_array(hamt_data)
        typed_trie = Trie.new()

        # Convert each value to the proper type
        def convert_value(key, value):
            if isinstance(value, dict):
                typed_value = deserializer_func(value)
                typed_trie.insert(key, typed_value)
            else:
                # Already a typed object, just insert it
                typed_trie.insert(key, value)
            return True

        raw_trie.all(convert_value)
        return typed_trie

    def shop_exists(self, shop_id: int) -> bool:
        """Check if shop data exists on disk."""
        shop_file = self.data_dir / f"shop_{shop_id}.cbor"
        return shop_file.exists()

    def delete_shop(self, shop_id: int) -> bool:
        """Delete shop data from disk."""
        shop_file = self.data_dir / f"shop_{shop_id}.cbor"
        meta_file = self.data_dir / f"shop_{shop_id}_meta.json"

        deleted = False
        if shop_file.exists():
            shop_file.unlink()
            deleted = True
        if meta_file.exists():
            meta_file.unlink()

        return deleted

    def list_shops(self) -> list[int]:
        """List all shop IDs that have data on disk."""
        shops = []
        for file in self.data_dir.glob("shop_*.cbor"):
            try:
                shop_id = int(file.stem.split("_")[1])
                shops.append(shop_id)
            except (ValueError, IndexError):
                continue
        return sorted(shops)

    def get_shop_metadata(self, shop_id: int) -> Optional[Dict[str, Any]]:
        """Get shop metadata without loading the full shop."""
        meta_file = self.data_dir / f"shop_{shop_id}_meta.json"
        if not meta_file.exists():
            return None

        try:
            with open(meta_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading metadata for shop {shop_id}: {e}")
            return None


class PatchLogger:
    """Handles logging of patch operations for debugging and replay."""

    def __init__(self, log_dir: str = "patch_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.current_session = None
        self.session_file = None

    def start_session(self, client_name: str, shop_id: int) -> None:
        """Start a new patch logging session."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_name = f"{client_name}_{shop_id}_{timestamp}"
        self.current_session = session_name
        self.session_file = self.log_dir / f"{session_name}.cbor"

        # Write session header
        header = {
            "type": "session_header",
            "client_name": client_name,
            "shop_id": shop_id,
            "start_time": datetime.datetime.now().isoformat(),
            "version": 1,
        }
        with open(self.session_file, "wb") as f:
            f.write(cbor_encode([header]))

    def log_patch(
        self,
        patch_data: dict,
        shop_seq_no: int,
        timestamp: Optional[datetime.datetime] = None,
    ) -> None:
        """Log a patch operation."""
        if not self.session_file:
            return

        if timestamp is None:
            timestamp = datetime.datetime.now()

        log_entry = {
            "type": "patch",
            "timestamp": timestamp.isoformat(),
            "shop_seq_no": shop_seq_no,
            "patch": patch_data,
        }

        # Append to existing log
        try:
            with open(self.session_file, "rb") as f:
                existing_data = cbor2.loads(f.read())
        except (FileNotFoundError, cbor2.CBORDecodeError):
            existing_data = []

        existing_data.append(log_entry)

        with open(self.session_file, "wb") as f:
            f.write(cbor_encode(existing_data))

    def end_session(self, error_count: int = 0) -> None:
        """End the current patch logging session."""
        if not self.session_file:
            return

        # Read existing data and add footer
        try:
            with open(self.session_file, "rb") as f:
                existing_data = cbor2.loads(f.read())
        except (FileNotFoundError, cbor2.CBORDecodeError):
            existing_data = []

        footer = {
            "type": "session_footer",
            "end_time": datetime.datetime.now().isoformat(),
            "error_count": error_count,
            "total_patches": len(
                [e for e in existing_data if e.get("type") == "patch"]
            ),
        }

        existing_data.append(footer)

        with open(self.session_file, "wb") as f:
            f.write(cbor_encode(existing_data))

        self.current_session = None
        self.session_file = None


class StateManager:
    """Manages shop state with persistence and caching."""

    def __init__(
        self,
        shop_id: int,
        persistence: ShopPersistence,
        patch_logger: Optional[PatchLogger] = None,
        patch_handler_factory=None,
    ):
        self.shop_id = shop_id
        self.persistence = persistence
        self.patch_logger = patch_logger
        self.patch_handler_factory = patch_handler_factory
        self.shop: Optional[Shop] = None
        self.last_seq_no = 0
        self.dirty = False

    def load_shop(self) -> Shop:
        """Load shop from persistence or create new one."""
        if self.shop is None:
            self.shop, loaded_seq_no = self.persistence.load_shop_with_seq_no(
                self.shop_id
            )
            if self.shop is None:
                # Create new shop
                # Import Uint256 for proper typing
                from massmarket.cbor.base_types import Uint256

                manifest = Manifest(
                    shop_id=Uint256(self.shop_id),
                    accepted_currencies={},
                    pricing_currency=None,
                    payees={},
                    shipping_regions={},
                    order_payment_timeout=100000000000,
                )

                self.shop = Shop(
                    schema_version=5,
                    manifest=manifest,
                    accounts=Trie.new(),
                    listings=Trie.new(),
                    tags=Trie.new(),
                    orders=Trie.new(),
                    inventory=Trie.new(),
                )
                self.dirty = True
            else:
                # Shop was loaded from persistence, set the sequence number
                self.last_seq_no = loaded_seq_no

        return self.shop

    def save_shop(self) -> None:
        """Save shop to persistence if dirty."""
        if self.shop and self.dirty:
            self.persistence.save_shop(self.shop_id, self.shop, self.last_seq_no)
            self.dirty = False

    def apply_patch(self, patch, shop_seq_no: int) -> None:
        """Apply a patch to the shop state."""

        shop = self.load_shop()

        # Apply patch using PatchHandler
        if self.patch_handler_factory:
            patch_handler = self.patch_handler_factory(shop)
        else:
            patch_handler = PatchHandler(shop)
        error = patch_handler.apply_patch(patch)

        if error is not None:
            raise Exception(f"Patch application failed: {error.code} - {error.message}")

        # Mark as dirty and update sequence number
        self.dirty = True
        self.last_seq_no = max(self.last_seq_no, shop_seq_no)

        # Log patch if logger is available
        if self.patch_logger:
            # Convert patch to dict for logging if it's not already
            if hasattr(patch, "to_cbor_dict"):
                patch_data = patch.to_cbor_dict()
            else:
                patch_data = patch
            self.patch_logger.log_patch(patch_data, shop_seq_no)

    def get_shop(self) -> Shop:
        """Get the current shop state."""
        return self.load_shop()

    def is_dirty(self) -> bool:
        """Check if shop state has unsaved changes."""
        return self.dirty

    def get_last_seq_no(self) -> int:
        """Get the last processed sequence number."""
        # Ensure shop is loaded first to get the correct sequence number
        self.load_shop()
        return self.last_seq_no

    def set_last_seq_no(self, seq_no: int) -> None:
        """Set the last processed sequence number."""
        self.last_seq_no = seq_no
