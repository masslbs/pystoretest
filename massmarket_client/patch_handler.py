# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import Optional
import massmarket.cbor.patch as mass_patch
import massmarket.cbor.base_types as mass_base
import massmarket.cbor.manifest as mass_manifest
import massmarket.cbor.listing as mass_listing
import massmarket.cbor.order as mass_order
from massmarket import error_pb2
from massmarket.cbor import Shop


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


class PatchHandler:
    """Handles application of patches to shop state."""

    def __init__(self, shop: Shop):
        self.shop = shop

    def apply_patch(self, patch: mass_patch.Patch) -> Optional[error_pb2.Error]:
        """Apply a patch to the shop state."""
        obj_type = patch.path.type

        if obj_type == mass_patch.ObjectType.MANIFEST:
            return self._patch_manifest(patch)
        elif obj_type == mass_patch.ObjectType.ACCOUNT:
            return self._patch_account(patch)
        elif obj_type == mass_patch.ObjectType.LISTING:
            return self._patch_listing(patch)
        elif obj_type == mass_patch.ObjectType.TAG:
            return self._patch_tag(patch)
        elif obj_type == mass_patch.ObjectType.INVENTORY:
            return self._patch_inventory(patch)
        elif obj_type == mass_patch.ObjectType.ORDER:
            return self._patch_order(patch)
        else:
            return invalidError(f"unhandled object type: {obj_type}")

    def _patch_manifest(self, patch: mass_patch.Patch):
        if patch.op == mass_patch.OpString.REPLACE:
            if len(patch.path.fields) == 0:
                manifest = mass_manifest.Manifest.from_cbor_dict(patch.value)
                self.shop.manifest = manifest
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
                    return notFoundError("no shipping regions defined")
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
            import massmarket.hamt as hamt

            self.shop.accounts = hamt.Trie.new()
            self.shop = Shop(
                schema_version=4,
                manifest=mass_manifest.Manifest(
                    shop_id=self.shop_token_id,
                    payees={},
                    accepted_currencies=[],
                    pricing_currency=None,
                ),
                accounts=self.shop.accounts,
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
            if len(patch.path.fields) == 0:
                account = mass_base.Account.from_cbor_dict(patch.value)
                self.shop.accounts.insert(user_wallet, account)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "KeyCards":
                if not self.shop.accounts.has(user_wallet):
                    return notFoundError(f"unknown account: {user_wallet.hex()}")
                account = self.shop.accounts.get(user_wallet)
                keycard = mass_base.PublicKey.from_cbor_dict(patch.value)

                try:
                    index = patch.path.fields[1]
                    if index < 0 or index > len(account.keycards):
                        return invalidError(f"index out of bounds: {index}")
                    account.keycards.insert(index, keycard)
                except ValueError:
                    return invalidError(
                        f"invalid KeyCards index: {patch.path.fields[1]}"
                    )

                self.shop.accounts.insert(user_wallet, account)
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

                account.keycards.append(keycard)
                self.shop.accounts.insert(user_wallet, account)
            else:
                return invalidError(
                    f"unhandled accounts append patch path: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if not self.shop.accounts.has(user_wallet):
                return notFoundError(f"unknown account: {user_wallet.hex()}")
            self.shop.accounts.delete(user_wallet)
        else:
            return invalidError(f"unhandled patch.op type: {patch.op}")

    def _patch_listing(self, patch: mass_patch.Patch):
        listing_id = patch.path.object_id
        assert isinstance(listing_id, int)
        assert self.shop is not None

        if patch.op == mass_patch.OpString.ADD:
            listing = self.shop.listings.get(listing_id)
            if patch.path.fields == []:
                if listing is not None:
                    return invalidError(f"listing already exists: {listing_id}")
                else:
                    listing = mass_listing.Listing.from_cbor_dict(patch.value)
                    self.shop.listings.insert(listing.id, listing)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "Options":
                opt_name = patch.path.fields[1]
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                if listing.options is None:
                    listing.options = {}
                if opt_name in listing.options:
                    return invalidError(f"option already exists: {opt_name}")
                listing.options[opt_name] = mass_listing.ListingOption.from_cbor_dict(
                    patch.value
                )
                self.shop.listings.insert(listing_id, listing)
            elif (
                len(patch.path.fields) == 4
                and patch.path.fields[0] == "Options"
                and patch.path.fields[2] == "Variations"
            ):
                opt_name = patch.path.fields[1]
                var_name = patch.path.fields[3]
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                if listing.options is None or opt_name not in listing.options:
                    return notFoundError(f"unknown option: {opt_name}")
                curr_vars = listing.options[opt_name].variations
                if curr_vars is not None and var_name in curr_vars:
                    return invalidError(f"variation already exists: {var_name}")
                listing.options[opt_name].variations[var_name] = (
                    mass_listing.ListingVariation.from_cbor_dict(patch.value)
                )
                self.shop.listings.insert(listing_id, listing)
            else:
                return invalidError(
                    f"unhandled add patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.APPEND:
            if patch.path.fields == ["Metadata", "Images"]:
                listing = self.shop.listings.get(listing_id)
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert listing.metadata.images is not None
                listing.metadata.images.append(patch.value)
                self.shop.listings.insert(listing_id, listing)
            else:
                return invalidError(
                    f"unhandled append patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REPLACE:
            listing = self.shop.listings.get(listing_id)
            if listing is None:
                return notFoundError(f"unknown listing: {listing_id}")
            if patch.path.fields == ["Price"]:
                if not isinstance(patch.value, int):
                    return invalidError(f"invalid price: {patch.value}")
                listing.price = mass_base.Uint256(patch.value)
            elif patch.path.fields == ["ViewState"]:
                if not isinstance(patch.value, int):
                    return invalidError(f"invalid viewState: {patch.value}")
                listing.view_state = mass_listing.ListingViewState(patch.value)
            elif patch.path.fields == ["Metadata"]:
                if not isinstance(patch.value, dict):
                    return invalidError(f"invalid metadata: {patch.value}")
                listing.metadata = mass_listing.ListingMetadata.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields == ["Metadata", "Title"]:
                if not isinstance(patch.value, str):
                    return invalidError(f"invalid title: {patch.value}")
                listing.metadata.title = patch.value
            elif patch.path.fields == ["Metadata", "Description"]:
                if not isinstance(patch.value, str):
                    return invalidError(f"invalid description: {patch.value}")
                listing.metadata.description = patch.value
            else:
                return invalidError(
                    f"unhandled replace patch.path.fields for listing: {patch.path.fields}"
                )
        elif patch.op == mass_patch.OpString.REMOVE:
            if patch.path.fields == []:
                listing = self.shop.listings.get(listing_id)
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                self.shop.listings.delete(listing_id)
            elif len(patch.path.fields) == 3 and patch.path.fields[0] == "Metadata":
                if patch.path.fields[1] == "Images":
                    index = int(patch.path.fields[2])
                    if not isinstance(index, int):
                        return invalidError(f"invalid image index: {index}")
                    listing = self.shop.listings.get(listing_id)
                    if listing is None:
                        return notFoundError(f"unknown listing: {listing_id}")
                    assert listing.metadata.images is not None
                    if index < 0 or index >= len(listing.metadata.images):
                        return invalidError(f"invalid image index: {index}")
                    del listing.metadata.images[index]
                    self.shop.listings.insert(listing_id, listing)
            elif len(patch.path.fields) == 2 and patch.path.fields[0] == "Options":
                opt_name = patch.path.fields[1]
                listing = self.shop.listings.get(listing_id)
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert listing.options is not None
                if opt_name in listing.options:
                    del listing.options[opt_name]
                self.shop.listings.insert(listing_id, listing)
            elif (
                len(patch.path.fields) == 4
                and patch.path.fields[0] == "Options"
                and patch.path.fields[2] == "Variations"
            ):
                opt_name = patch.path.fields[1]
                var_name = patch.path.fields[3]
                listing = self.shop.listings.get(listing_id)
                if listing is None:
                    return notFoundError(f"unknown listing: {listing_id}")
                assert listing.options is not None
                assert opt_name in listing.options
                if listing.options[opt_name] is None:
                    return notFoundError(f"unknown option: {opt_name}")
                curr_vars = listing.options[opt_name].variations
                if curr_vars is None or var_name not in curr_vars:
                    return notFoundError(f"unknown variation: {var_name}")
                del curr_vars[var_name]
                self.shop.listings.insert(listing_id, listing)
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

        # Create compound ID for inventory
        lookup_id = str(listing_id) + ":"
        if patch.path.fields:
            patch.path.fields.sort()
            lookup_id = lookup_id + ":".join(patch.path.fields) + ":"

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
            self.shop.inventory.insert(lookup_id, current + patch.value)
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
                order.items = [
                    mass_order.OrderedItem.from_cbor_dict(item) for item in patch.value
                ]
            elif patch.path.fields[0] == "InvoiceAddress":
                order.invoice_address = mass_order.AddressDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "ShippingAddress":
                order.shipping_address = mass_order.AddressDetails.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "ChosenCurrency":
                order.chosen_currency = mass_base.ChainAddress.from_cbor_dict(
                    patch.value
                )
            elif patch.path.fields[0] == "ChosenPayee":
                order.chosen_payee = mass_order.Payee.from_cbor_dict(patch.value)
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
