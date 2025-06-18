# vpn-contracts

## Datums

### VPN Provider

**VPNReferenceData** provides all data required for purchasing VPN access. 
Initialized once and attached to an NFT but may be updated over time.

```aiken
VPNReferenceData { 
    pricing: Pairs<Int, Int>, 
    regions: List<ByteArray> 
    }
```

- pricing = list of pairs representing time (slots) and price (lovelace)
- regions = Available VPN server regions

Example:
```json
{
    "constructor": 0,
    "fields": [
      {
        "list": [
          [
            {"int": 2592000},
            {"int": 5000000}
          ],
          [
            {"int": 5184000},
            {"int": 9000000}
          ],
          [
            {"int": 7776000},
            {"int": 12000000}
          ]
        ]
      },
      {
        "list": [
          {"bytes": "757320656173742d31"},
          {"bytes": "757320776573742d32"},
          {"bytes": "65752d776573742d31"},
          {"bytes": "61702d736f757468656173742d31"}
        ]
      }
    ]
}
```

### User

**VPNData** initialized for every user and attached to a token. Each token has a unique name and identifies a VPN access. Token names are the output UTXO hash of the minting transaction.

```aiken
VPNData { 
    owner: Address,
    region: ByteArray,
    expiration_time: Int 
    }
```

- owner = Cardano address used for payment
- region = Desired VPN server region
- expiration_time = Absolute expiration timestamp (in slots) for VPN access

Example:
```json
{
    "constructor": 1,
    "fields": [
      {
        "constructor": 0,
        "fields": [
          {
            "constructor": 0,
            "fields": [
              {"bytes": "a1b2c3d4e5f6789012345678901234567890123456789012abcd"}
            ]
          },
          {
            "constructor": 1,
            "fields": []
          }
        ]
      },
      {"bytes": "757320656173742d31"},
      {"int": 125000000}
    ]
}
```