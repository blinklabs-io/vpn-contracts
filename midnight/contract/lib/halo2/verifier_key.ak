use aiken/builtin.{bls12_381_g1_neg}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/scalar.{Scalar, from_int}
use aiken/crypto/bls12_381/g1.{generator, decompress}
use aiken/crypto/bls12_381/g2.{decompress as decompress_g2}


pub const p1_commitment: ByteArray = #"a43dd666c07189a6f95a7b43eafbd3f47f439e7b0009c6757fbb9f6a16e56dfc91a854bd4a3097d833d54a15beb68e35"
pub const p2_commitment: ByteArray = #"b9b8c093e6b4efbcbca3b6876143ca681f06ae11ad5acc06a35ae8497051add514541593cc0b55abbb99e751f118395f"
pub const p3_commitment: ByteArray = #"876271babe6dc0f340c1d915137e63d28ed084715a24d5db7f0ec5832e83fdb27b8d56479310dade4beb8182cefd036d"
pub const p4_commitment: ByteArray = #"aa8ba187020269855801cc6bda320ddc824c9e3f4de7ff8743a40d5f5a848a67ddf62d8d5fed24d330db841d0c507daa"
pub const p5_commitment: ByteArray = #"983a5d4bb6951ed7d551809bdb5ced58af067c6174a03244f992cf0627e187b2ad7d605f9c63f6771daa6ed092e90794"
pub const p6_commitment: ByteArray = #"a02360514557df66cd43cf6e02dee789f76ff3cd0fb276989ec3e8d2cd29354482a2c136ce8925d14db36943e6b1172c"


pub const f1_commitment: ByteArray = #"aafafb58379f4c91f6db074651a3050c462e597f3e4f264e307441db48966b601f40a83210a6a233c15307136e89a599"
pub const f2_commitment: ByteArray = #"90dd71ed5cd9e61d15d5aa5188cad05ae7ce2b4b775f7309d6f39e1045cf2ad5279650a55185ea5c036ec38e6f874197"
pub const f3_commitment: ByteArray = #"ab3db715f527a6c9694600afe4128ad5d01f3bf7eaf800fdf3590d607d36264e123e4c37e81866137cf469684584d8ec"
pub const f4_commitment: ByteArray = #"b58a6b00fb30f1eae0f5de96f6511b691e7923c7a7ebc61de749b38962da1b542ab9ac300cf24f1029f7177f1132f9ee"


pub const g2_const: G2Element = decompress_g2( #"92ff41673671512047d062b24263fa56c318bdd836231669239cc76fe2193a741faf178b2147b647209868e2edd0ae5b16b838a496b7d8bf4ba10f02703c88923fbc40abf2c3c72e48f6b65bb4a0c05d2ab498925722ce13c85512efa42e8240" )
pub const neg_g1_generator: ByteArray = #"B7F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB"

pub const omega: State<Scalar> = from_int( 0x20b1ce9140267af9dd1c0af834cec32c17beb312f20b6f7653ea61d87742bcce )
pub const omega_inv: State<Scalar> = from_int( 0x3b25b475ab91194b687a73c92f188612fc010d53ccb225425e544cdf4c887948 )

pub const barycentric_weight: State<Scalar> = from_int( 0x6caeccddf703a573b0063a878907ba84fe81c9c2cffe763f0fffffff10000001 )

pub const transcript_rep: State<Scalar> = from_int( 0x3fd0305e614cdf7588f777bc68c83d5403851353f0d3628ef8763a5ea98e6b1b )

pub const blinding_factors: Int = 5

// this test is for checking how much budget is used when G1 constants are used in script, assertions are only to force use of the constant
test cpu_mem_budget_check() {
	let f1_commitment = decompress(f1_commitment)
	expect f1_commitment == f1_commitment
	let f2_commitment = decompress(f2_commitment)
	expect f2_commitment == f2_commitment
	let f3_commitment = decompress(f3_commitment)
	expect f3_commitment == f3_commitment
	let f4_commitment = decompress(f4_commitment)
	expect f4_commitment == f4_commitment
	let p1_commitment = decompress(p1_commitment)
	expect p1_commitment == p1_commitment
	let p2_commitment = decompress(p2_commitment)
	expect p2_commitment == p2_commitment
	let p3_commitment = decompress(p3_commitment)
	expect p3_commitment == p3_commitment
	let p4_commitment = decompress(p4_commitment)
	expect p4_commitment == p4_commitment
	let p5_commitment = decompress(p5_commitment)
	expect p5_commitment == p5_commitment
	let p6_commitment = decompress(p6_commitment)
	expect p6_commitment == p6_commitment
    expect g2_const == g2_const
}

test neg_g2_generator() {
    let neg_g1 = bls12_381_g1_neg(generator)
    expect decompress(neg_g1_generator) == neg_g1
}