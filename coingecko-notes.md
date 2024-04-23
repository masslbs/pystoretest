
# get ID of your coin
curl -X 'GET' \ 
  'https://api.coingecko.com/api/v3/coins/list?include_platform=true' \
  -H 'accept: application/json' \
  | jq '.[] | select(.symbol == "eth")' | less
...
{
  "id": "ethereum",
  "symbol": "eth",
  "name": "Ethereum",
  "platforms": {}
}


# supported currencis for `vs_currencies`

curl -X 'GET'   'https://api.coingecko.com/api/v3/simple/supported_vs_currencies'   -H 'accept: application/json'

# get a the conversion

curl -X 'GET' \
  'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd,eur&precision=2' \
  -H 'accept: application/json'

{
  "ethereum": {
    "usd": 2803.53,
    "eur": 2611.74
  }
}

## erc20 contract addresses:



* 0xdac17f958d2ee523a2206206994597c13d831ec7 -  Tether / USDT
* 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 - USDC
* 0x6b175474e89094c44da98b954eedeac495271d0f - DAI
* 0xc5f0f7b66764f6ec8c8dff7ba683102295e16409 - FDUSD


# token prices

curl -X 'GET' \
  'https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses=0xdac17f958d2ee523a2206206994597c13d831ec7%2C0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48%2C0xc5f0f7b66764f6ec8c8dff7ba683102295e16409&vs_currencies=eth,usd,eur&precision=full' \
  -H 'accept: application/json'

{
  "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": {
    "eth": 0.000357101738479457,
    "usd": 1.0007365650514997,
    "eur": 0.932218133915554
  },
  "0xdac17f958d2ee523a2206206994597c13d831ec7": {
    "eth": 0.00035714729301936245,
    "usd": 1.0010821989969478,
    "eur": 0.9327222999562427
  },
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
    "eth": 0.0003566534509563415,
    "usd": 0.9994802908089035,
    "eur": 0.9310478742578
  }
}