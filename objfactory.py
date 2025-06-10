# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import factory
import random
from typing import List

from massmarket.cbor import (
    base_types as mass_base,
    listing as mass_listing,
)


class Uint256Factory(factory.Factory):
    class Meta:
        model = mass_base.Uint256

    value = factory.LazyFunction(lambda: random.randint(1, 1000) * 100)


# Helper function to generate product-like names
def generate_product_name():
    adjectives = ["Premium", "Deluxe", "Classic", "Modern", "Eco-friendly"]
    categories = ["Shirt", "Pants", "Jacket", "Shoes", "Bag", "Hat"]
    return f"{random.choice(adjectives)} {random.choice(categories)}"


dataset = "QmRzcQUvnJDiNJoi5KdnHAdHaErAwmJvss154Enp3Ssjsw"

images = [
    "pexels-bearmax-1077093-3960037.jpg",
    "pexels-catscoming-2942325.jpg",
    "pexels-cottonbro-6865166.jpg",
    "pexels-d-ng-nhan-324384-2817412.jpg",
    "pexels-fotios-photos-1852914.jpg",
    "pexels-fox-58267-1265624.jpg",
    "pexels-milivigerova-5989344.jpg",
    "pexels-minan1398-693651.jpg",
    "pexels-mtyutina-3206572.jpg",
    "pexels-myca-1311572.jpg",
    "pexels-natalie-bond-320378-3257811.jpg",
    "pexels-tamba09-979248.jpg",
    "pexels-yuliya-kota-2099022-3791591.jpg"
]

class ListingMetadataFactory(factory.Factory):
    class Meta:
        model = mass_listing.ListingMetadata

    title = factory.LazyFunction(generate_product_name)
    description = factory.Faker("text", max_nb_chars=300)
    images = factory.LazyFunction(
        # TODO: assuming localhost:8080 is the ipfs gateway
        lambda: [f"http://localhost:8080/ipfs/{dataset}/{random.choice(images)}" for _ in range(random.randint(1, 5))]
    )


class ListingVariationMetadataFactory(factory.Factory):
    class Meta:
        model = mass_listing.ListingMetadata

    title = factory.LazyFunction(generate_product_name)
    description = factory.Faker("text", max_nb_chars=100)
    images = factory.LazyFunction(
        lambda: [f"variation_{i}.jpg" for i in range(random.randint(0, 1))]
    )


class ListingVariationFactory(factory.Factory):
    class Meta:
        model = mass_listing.ListingVariation

    variation_info = factory.SubFactory(ListingVariationMetadataFactory)
    price_modifier = factory.LazyFunction(
        lambda: mass_base.PriceModifier(
            modification_absolute=mass_base.ModificationAbsolute(
                amount=mass_base.Uint256(random.randint(1, 1000)),
                plus=random.choice([True, False]),
            )
        )
    )


class ListingOptionFactory(factory.Factory):
    class Meta:
        model = mass_listing.ListingOption

    title = factory.Iterator(["Color", "Size", "Material", "Style"])
    variations = factory.LazyFunction(
        lambda: {
            f"var_{i}": ListingVariationFactory() for i in range(random.randint(2, 5))
        }
    )


# Global counter to ensure unique IDs
_next_id = 100


def get_next_id():
    global _next_id
    _next_id += 1
    return _next_id


class ListingFactory(factory.Factory):
    class Meta:
        model = mass_listing.Listing

    id = factory.LazyFunction(lambda: get_next_id())
    price = factory.SubFactory(Uint256Factory)
    metadata = factory.SubFactory(ListingMetadataFactory)
    # options = factory.LazyFunction(
    #     lambda: {
    #         f"opt_{i}": ListingOptionFactory() for i in range(random.randint(1, 3))
    #     }
    # )
    view_state = factory.LazyFunction(lambda: mass_listing.ListingViewState.PUBLISHED)


def create_test_listings(count: int = 10) -> List[mass_listing.Listing]:
    return [ListingFactory() for _ in range(count)]


if __name__ == "__main__":
    # Example usage
    listings = create_test_listings(100)
    total = 0
    for listing in listings:
        print(f"Listing: {listing.metadata.title}")
        print(f"  Images: {listing.metadata.images}")
        print(f"  Price: {listing.price}")
        if listing.options is None:
            continue
        opts = [
            f"{title}: {[v.variation_info.title for v in opt.variations.values()]}"
            for title, opt in listing.options.items()
            if opt.variations is not None
        ]
        print(f"  Options: {opts}")
        print()
