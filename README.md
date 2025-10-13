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

## Preprod
Data can be found in `preprod/`.

- reference nft policy id: `f043e77d22674a36edfbda3200a6ba9eb966c045ed72eb427cf45c92`
- vpn access token policy id: `da9d3ac097f9ae0c0bd933d4e04848fe5bde15bbbdc86cb0fb10222b`
- vpn validator address: `addr_test1zrdf6wkqjlu6urqtmyeafczgfrl9hhs4hw7usm9slvgzy26jduk3c6ecrpkrk8qqlr4ep37cx03ytlcn70n93zyemj6svnkmku`
- vpn reference script tx hash: `363fb149456226998f537df63cdfbab015ae4a10cb45bf427b89ffbc53f484c3#1`

## Mainnet
Data can be found in `mainnet/`

- reference nft policy id: `1497d1a199633ac5908aa872c9771f9f736f0dc08337b071df2508b7`
- vpn access token policy id: `926344085bfd2e62f3e74d50beff2e48274e1193ed719662d783db0b`
- vpn validator address: `addr1zxfxx3qgt07juchnuax4p0hl9eyzwns3j0khr9nz67pakz7gx8yp9m2ssx9v9vv60a3xudznxtw68vr8l0rpw26u2gfq8cpcxm`
- vpn reference script tx hash: `df1b318e4c45a162ef6b4ba00774018b54d4c873d5414b6d35b4858ec866512a#1`

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
