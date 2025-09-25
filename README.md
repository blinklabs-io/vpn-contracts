# vpn-contracts

## Preprod
Data can be found in `preprod/`.

- reference nft policy id: `eddc8f734e487da2204993bd3fb2a6228307c52df2ce0384506d2038`
- vpn access token policy id: `b165a24ac3d306f413fdd996626584b6e864645afc87fcea09b0c1cd`
- vpn validator address: `addr_test1zzcktgj2c0fsdaqnlhvevcn9sjmwserytt7g0l82pxcvrn2jduk3c6ecrpkrk8qqlr4ep37cx03ytlcn70n93zyemj6sfgz2vs`
- vpn reference script tx hash: `bbbe818c99e248c305a0d0ebad7508974f37e342833c55bc0242dcdfbaa2848c#1`

## Mainnet
Data can be found in `mainnet/`

- reference nft policy id: `a9ffba368834780fcbac8214bcc953b23e41cef206167064771bfc79`
- vpn access token policy id: `69dfadbe53a463af0f0d5d1a04b7736669a9c579b4c9cb2d269a745c`
- vpn validator address: `addr1z95altd72wjx8tc0p4w35p9hwdnxn2w90x6vnjedy6d8ghxgx8yp9m2ssx9v9vv60a3xudznxtw68vr8l0rpw26u2gfq4lxj45`
- vpn reference script tx hash: `c6860c0ea1295776fa7bb1b7b198f9c71751fef2c404f02f183b08b888fa991e#1`

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