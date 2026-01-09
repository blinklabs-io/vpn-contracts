# vpn-contracts

## Use cases

* General
  - assets/datums stay in contract
  - client datum contains owner credential, region, and expiration
  - on-chain refdata containing valid regions and plan price/duration combinations
  - validation of plan selection and region against refdata
  - validation that amount sent to "provider" wallet matches price of plan selection
  - validation that expiration matches duration of plan selection

* Signup
  - mint unique asset

* Renew/transfer
  - spend existing asset from contract
  - possible to perform renew and transfer in single TX
  - Renew
    - update expiration in datum
    - anybody can renew for anybody else
    - expiration adds to current expiration when not yet expired
    - expiration adds to current time when already expired
  - Transfer
    - update owner credential in datum
    - must be signed by current owner

## Preview
Data can be found in `preview/`.

- reference nft policy id: `400d048d3548bde36426a6b7d8d576eb6689ec156d3e7203fe41e0b0`
- vpn access token policy id: `a8f482df4a1963648fc3f248beb14f8916a5ba3c2bb943c67dbed5c2`
- vpn validator address: `addr_test1zz50fqklfgvkxey0c0ey3043f7y3dfd68s4mjs7x0kldts4tza0gsjhr8s8v5f6axuprv6utq3h7ctm7xm3zd9fscd6sn2xm2z`
- vpn reference script tx hash: `a4ba98190a4dedd6dfc88121f15ff9284bfc44d7d83ed9e1e470fd9b836c80fe#1`

## Preprod
Data can be found in `preprod/`.

- reference nft policy id: `446dd7d5f53db5232b3d925ab5e883c90a685099d75ae69854fa62a1`
- vpn access token policy id: `aa5d7253d7c94e0d0e4f46959a0a4be905620abcad9cb7d1e9c12c32`
- vpn validator address: `addr_test1zz496ujn6ly5urgwfarftxs2f05s2cs2hjkeed73a8qjcvjjduk3c6ecrpkrk8qqlr4ep37cx03ytlcn70n93zyemj6suh7mks`
- vpn reference script tx hash: `ea7e4f0147eeba9a17c519e1652ed933262d30fe462bf418ece18dc27a2c13ba#1`

## Mainnet
Data can be found in `mainnet/`

- reference nft policy id: `949dfe5cf4691b821a09e4017f1894a5dfbf12c02271cbcaa6136c8d`
- vpn access token policy id: `9b0a098ebc40e81ee6493806079ad0139222e42b6067631bbd851602`
- vpn validator address: `addr1zxds5zvwh3qws8hxfyuqvpu66qfeyghy9dsxwccmhkz3vqkgx8yp9m2ssx9v9vv60a3xudznxtw68vr8l0rpw26u2gfqhx5tkz`
- vpn reference script tx hash: `ef40fa428ae3485fa089896f577139f3212bff7f7908329d677d387c240103f2#1`

## Datums

### VPN Provider

**VPNReferenceData** provides all data required for purchasing VPN access. 
Initialized once and attached to an NFT but may be updated over time.

```aiken
pub type Pricing {
  duration: Int,
  price: Int,
}

VPNReferenceData { 
    pricing: List<Pricing>, 
    regions: List<ByteArray> 
    }
```

- pricing = list of tuples representing time (seconds) and price (lovelace)
- regions = Available VPN server regions

Example:
```json
{
    "constructor": 0,
    "fields": [
        {
            "list": [
                {
                    "constructor": 0,
                    "fields": [
                        {
                            "int": 259200
                        },
                        {
                            "int": 5000000
                        }
                    ]
                },
                {
                    "constructor": 0,
                    "fields": [
                        {
                            "int": 604800
                        },
                        {
                            "int": 9000000
                        }
                    ]
                }
            ]
        },
        {
            "list": [
                {
                    "bytes": "757320656173742d31"
                },
                {
                    "bytes": "757320656173742d32"
                }
            ]
        }
    ]
}
```

### User

**VPNData** initialized for every user and attached to a token. Each token has a unique name and identifies a VPN access. Token names are the output UTXO hash of the minting transaction.

```aiken
  VPNData {
    owner: VerificationKeyHash,
    region: ByteArray,
    expiration_time: Int,
  }
```

- owner = Public Key Hash of the owner
- region = Desired VPN server region
- expiration_time = Absolute expiration timestamp (unix timestamp) for VPN access

Example:
```json
{
    "constructor": 1,
    "fields": [
        {
            "bytes": "52123aab84dd509386585bab55185de2ff5305cc72b89f07c132c326"
        },
        {
            "bytes": "757320656173742d31"
        },
        {
            "int": 1750834153200
        }
    ]
}
```
