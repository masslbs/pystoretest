# from requests_cache import CachedSession
import requests
import decimal

# session = CachedSession('cg_cache', cache_control=True)


class CoinGecko:
    def __init__(self, demo_key=None, base_currency="usd"):
        self.demo_key = demo_key
        self.base_currency = base_currency
        self.decimal_context = decimal.getcontext()
        self.decimal_context.prec = 2
        self.decimal_context.rounding = decimal.ROUND_HALF_UP
        self.erc20_token_addresses = {
            "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
            "FDUSD": "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409",
            "ZKERA": "0x5A7d6b2F92C77FAD6CCaBd7EE0624E64907Eaf3E",
        }

    def get_platforms(self):
        url = "https://api.coingecko.com/api/v3/asset_platforms"
        if self.demo_key:
            url += f"?x_cg_demo_api_key={self.demo_key}"
        headers = {
            "accept": "application/json",
        }
        response = requests.get(url, headers=headers).json()
        platforms = {}
        for p in response:
            platforms[p["id"]] = p
        return platforms

    def get_coin_price(self, coin):
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin}&vs_currencies={self.base_currency}&precision=full"
        if self.demo_key:
            url += f"&x_cg_demo_api_key={self.demo_key}"
        headers = {
            "accept": "application/json",
        }
        response = requests.get(url, headers=headers).json()
        if coin not in response:
            print(response)
            raise ValueError(f"Coin {coin} not found")
        coin_price = response[coin][self.base_currency]
        return decimal.Decimal(coin_price)

    def get_erc20_price(self, token, platform="ethereum"):
        if token not in self.erc20_token_addresses:
            raise ValueError(f"Token {token} not found")
        token_address = self.erc20_token_addresses[token].lower()
        url = f"https://api.coingecko.com/api/v3/simple/token_price/{platform}?contract_addresses={token_address}&vs_currencies={self.base_currency}&precision=full"
        if self.demo_key:
            url += f"&x_cg_demo_api_key={self.demo_key}"
        headers = {
            "accept": "application/json",
        }
        response = requests.get(url, headers=headers).json()
        if token_address not in response:
            print(response)
            raise ValueError(f"Token {token} not in response!")
        token_price = response[token_address][self.base_currency]
        return decimal.Decimal(token_price)

    def convert_to_base_from_coin(self, coin, amount):
        coin_price = self.get_coin_price(coin)
        return decimal.Decimal(amount) * coin_price

    def convert_from_base_to_coin(self, coin, amount):
        coin_price = self.get_coin_price(coin)
        return decimal.Decimal(amount) / coin_price

    def convert_from_base_to_erc20(self, token, amount):
        token_price = self.get_erc20_price(token)
        return decimal.Decimal(amount) / token_price

    def convert_to_base_from_erc20(self, token, amount):
        token_price = self.get_erc20_price(token)
        return decimal.Decimal(amount) * token_price
