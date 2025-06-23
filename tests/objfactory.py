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

    value = factory.LazyFunction(lambda: random.randint(1, 1000) * 100000)


# Helper function to generate product-like names
def generate_product_name():
    adjectives = ["Playful", "Sleepy", "Curious", "Fluffy", "Mischievous"]
    categories = ["Kitten", "Tabby", "Persian", "Siamese", "Calico", "Maine Coon"]
    return f"{random.choice(adjectives)} {random.choice(categories)}"


# for fetching https://http.cat/images/[status_code].jpg
http_status_codes = [
    100,
    101,
    102,
    103,
    200,
    201,
    202,
    203,
    204,
    205,
    206,
    207,
    208,
    214,
    226,
    300,
    301,
    302,
    303,
    304,
    305,
    307,
    308,
    400,
    401,
    402,
    403,
    404,
    405,
    406,
    407,
    408,
    409,
    410,
    411,
    412,
    413,
    414,
    415,
    416,
    417,
    418,
    419,
    420,
    421,
    422,
    423,
    424,
    425,
    426,
    428,
    429,
    431,
    444,
    450,
    451,
    495,
    496,
    497,
    498,
    499,
    500,
    501,
    502,
    503,
    504,
    505,
    506,
    507,
    508,
    509,
    510,
    511,
    522,
    523,
    525,
    530,
    599,
]


class ListingMetadataFactory(factory.Factory):
    class Meta:
        model = mass_listing.ListingMetadata

    title = factory.LazyFunction(generate_product_name)
    description = factory.Faker("text", max_nb_chars=300)
    images = factory.LazyFunction(
        # TODO: assuming localhost:8080 is the ipfs gateway
        lambda: [
            f"https://http.cat/images/{random.choice(http_status_codes)}.jpg"
            for _ in range(random.randint(1, 5))
        ]
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
