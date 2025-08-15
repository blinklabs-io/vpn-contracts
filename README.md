# vpn-contracts

## Preprod
Data can be found in `preprod/`.

- reference nft policy id: `85b95fee1b7cf6f2a7dca818e77b901ff3c1b6aae4473219cf56902b`
- vpn access token policy id: `f6653983683830202a722ac3b0a85785c41b2222fd4ec0a2b13046f5`
- vpn validator address: `addr_test1zrmx2wvrdqurqgp2wg4v8v9g27zugxezyt75as9zkycyda2jduk3c6ecrpkrk8qqlr4ep37cx03ytlcn70n93zyemj6s4mgt63`
- vpn reference script tx hash: `3588c6f7d5fbd80b6bfc2ad2d6ad595a7fc750361909f89cf2e911519d1fbdea#0`

## Mainnet
Data can be found in `mainnet/`

- reference nft policy id: `a7933ba55ab251ae2537027d678779d7c13ed8f86d1075c86b615c6d`
- vpn access token policy id: `8e1b1737ebaa0fd821393b6065a10ea522dd861b324a5344fe0db7b0`
- vpn validator address: `addr1zx8pk9ehaw4qlkpp8yakqedpp6jj9hvxrvey556ylcxm0vxgx8yp9m2ssx9v9vv60a3xudznxtw68vr8l0rpw26u2gfqqv5eww`
- vpn reference script tx hash: `df6922b3581c819888f28844a195b16201edff60e66422e0add11cf1851edf13#1`

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