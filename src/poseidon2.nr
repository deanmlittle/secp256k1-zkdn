/// Secp256k1 Deterministic Nonce
///
/// Our circuit takes in 3 parameters
/// 
/// - secret_key: the signer for whom we are proving the deterministic nonce.
/// - message_hash to be signed
/// - public aggregate_point_x: X-coordinate of Point of mulG(key+nonce)
/// 
/// It then performs the following functions:
/// 
/// 1. Use hashing to create a new, deterministic nonce from our message hash and private key. This enables us to have deterministic randomness, preventing nonce-reuse attacks, whilst also allowing our prover system to convince other signers in an adversarial environment that the nonce was generated with good pRNG without revealing the relationship between the nonce and the private key or the message.
/// 2. Add the private key to the nonce, leveraging the fact that add(priv a, priv b) == ecadd(pub A, pub B ) to create a single scalar for both points, saving us many constraints, as we only need a single ECMul
/// 3. Calculate the aggregated point via ECMul from the aggregated scalar
/// 4. Ensure recovered point matches the witness value of the aggregate point 
///
/// To make this efficient and secure in a real-world scenario, we should consider:
/// - Adding some kind of domain separation
/// - Using a more performant hashing function designed for ZK prover systems
///

use std::bigint::Secpk1Fq;
use std::hash::poseidon2;
use std::cmp::Eq;

struct Point { x: Secpk1Fq, y: Secpk1Fq }

global ZERO = Secpk1Fq::from_le_bytes(&[0]);
global TWO = Secpk1Fq::from_le_bytes(&[2]);
global THREE = Secpk1Fq::from_le_bytes(&[3]);
global G = Point {
    x: Secpk1Fq::from_le_bytes(&[0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02, 0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79]),
    y: Secpk1Fq::from_le_bytes(&[0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd, 0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48]),
};

// Optional - only used for debugging
fn check_hash(nonce_hash: [u8;32]) {
    let expected_hash: [u8;32] = [
        0x22, 0x35, 0xff, 0x4b, 0xf3, 0x9e, 0xfa, 0xc1, 
        0x47, 0x9a, 0x34, 0x96, 0xfc, 0x68, 0x5b, 0x77, 
        0x6e, 0xad, 0xcb, 0x17, 0x49, 0xb8, 0x40, 0x2c, 
        0x94, 0xf8, 0x48, 0x87, 0xd6, 0x25, 0x52, 0xd7,
    ];
    assert(nonce_hash == expected_hash);
}

// Optional - used for debugging
fn check_aggregate_scalar(scalar: Secpk1Fq) {
    let aggregate_le = scalar.to_le_bytes();
    let aggregate_scalar: [u8;32] = [
        aggregate_le[31], aggregate_le[30], aggregate_le[29], aggregate_le[28], aggregate_le[27], aggregate_le[26], aggregate_le[25], aggregate_le[24], 
        aggregate_le[23], aggregate_le[22], aggregate_le[21], aggregate_le[20], aggregate_le[19], aggregate_le[18], aggregate_le[17], aggregate_le[16], 
        aggregate_le[15], aggregate_le[14], aggregate_le[13], aggregate_le[12], aggregate_le[11], aggregate_le[10], aggregate_le[9], aggregate_le[8], 
        aggregate_le[7], aggregate_le[6], aggregate_le[5], aggregate_le[4], aggregate_le[3], aggregate_le[2], aggregate_le[1], aggregate_le[0]
    ];
    let expected_scalar: [u8;32] = [
        0x7a, 0x6f, 0x5a, 0xc4, 0x8e, 0x35, 0x19, 0xa4, 
        0xb0, 0xd9, 0x20, 0x1c, 0x02, 0xc8, 0x34, 0x97, 
        0xa0, 0x35, 0xe3, 0x98, 0x92, 0xad, 0x8a, 0x4b, 
        0x95, 0x13, 0x01, 0x28, 0xe2, 0x63, 0x6b, 0xec,
    ];
    assert(aggregate_scalar == expected_scalar);
}

fn check_aggregate_point(p: Point, x: [u8;32], y: [u8;32]) {
    let x_scalar = Secpk1Fq::from_le_bytes_32(x);
    let y_scalar = Secpk1Fq::from_le_bytes_32(y);
    assert_eq(p.x, x_scalar);
    assert_eq(p.y, y_scalar);
}

/* Convenience functions */
fn hash_to_nonce(secret_key: [Field;2], message_hash: [Field;2]) -> [u8;32] {
    let input: [Field;4] = [
        secret_key[0], secret_key[1],
        message_hash[0], message_hash[1],
    ];
    let hash = poseidon2::Poseidon2::hash(input, 4);
    let x: [u8;32] = hash.to_be_bytes(32).as_array();
    x
}

fn calculate_aggregate_scalar(secret: [u8;32], nonce_hash: [u8;32]) -> Secpk1Fq {
    let nonce_scalar = Secpk1Fq::from_le_bytes_32(reverse_endianness_32(nonce_hash));
    let secret_scalar = Secpk1Fq::from_le_bytes_32(reverse_endianness_32(secret));
    nonce_scalar + secret_scalar
}

fn mul_g(scalar: Secpk1Fq) -> Point {
    let mut res = (ZERO, ZERO);
    let mut p = (G.x, G.y);

    let scalar_bytes = scalar.to_le_bytes();

    for i in 0..32 {
        let byte = (scalar_bytes[i] as Field).to_le_bits(8);

        for j in 0..8 {
            if byte[j] == 1 {
                if res == (ZERO, ZERO) {
                    res = p;
                } else {
                    res = add_point(res.0, res.1, p.0, p.1);
                }
            }
            p = double_point(p.0, p.1);
        }
    }
    Point { x: res.0, y: res.1 }
}

fn double_point(x: Secpk1Fq, y: Secpk1Fq) -> (Secpk1Fq, Secpk1Fq) {
    let s = (THREE * x * x) / (TWO * y);
    let x3 = s * s - TWO * x;
    let y3 = s * (x - x3) - y;
    (x3, y3)
}

fn add_point(x0: Secpk1Fq, y0: Secpk1Fq, x1: Secpk1Fq, y1: Secpk1Fq) -> (Secpk1Fq, Secpk1Fq) {
    let s = (y0 - y1) / (x0 - x1);
    let x2 = (s * s - x0 - x1);
    let y2 = (s * (x0 - x2) - y0);
    (x2, y2)
}

fn to_u8_array<N>(n: [u8; 32]) -> [u8] {
    n
}

fn reverse_endianness_32(x: [u8;32]) -> [u8;32] {
    [
        x[31], x[30], x[29], x[28], x[27], x[26], x[25], x[24], 
        x[23], x[22], x[21], x[20], x[19], x[18], x[17], x[16], 
        x[15], x[14], x[13], x[12], x[11], x[10], x[9], x[8], 
        x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]
    ]
}

fn to_u8_32(smth: [u8]) -> [u8; 32] {
    let mut res = [0 as u8; 32];
    for i in 0..smth.len() {
        res[i] = smth[i];
    }
    res
}

fn fields_to_scalar(fields: [Field;2]) -> [u8;32] {
    let a: [u8;16] = fields[0].to_be_bytes(16).as_array();
    let b: [u8;16] = fields[1].to_be_bytes(16).as_array();
    let x: [u8;32] = [
        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
        a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    ];
    x
}

fn main(
    secret: [Field;2], 
    message: pub [Field;2],
    aggregate_point_x: pub [u8;32], 
    aggregate_point_y: pub [u8;32]
) {
    // Step 1: Create a new nonce from our private key and message hash without revealing the private key or the nonce
    let nonce_hash = hash_to_nonce(secret, message);
    // Debug: We can use this to check our hash is correct: 2235ff4bf39efac1479a3496fc685b776eadcb1749b8402c94f84887d62552d7
    // check_hash(nonce_hash);
    // Step 2. Add our private key to this scalar via modular bignum addition
    let aggregate_scalar = calculate_aggregate_scalar(fields_to_scalar(secret), nonce_hash);
    // DEBUG: We can use this to check our resulting aggregate scalar is correct
    // check_aggregate_scalar(aggregate_scalar);
    /// 3. Calculate the aggregated point via ECMul from the aggregated scalar
    let aggregate_point = mul_g(aggregate_scalar);
    // DEBUG: Print out the aggregate point
    println(aggregate_point);
    // / 4. Ensure recovered point matches the witness value of the aggregate point
    check_aggregate_point(aggregate_point, aggregate_point_x, aggregate_point_y);
}

#[test]
fn test_poseidon() {
    main(
        // Privkey (BE) 58395b789a961ee3693eeb85065fd9203188188148f54a1f001ab8a10c3e1915
        [
            0x58395b789a961ee3693eeb85065fd920,
            0x3188188148f54a1f001ab8a10c3e1915,
        ],
        // Message hash "test"
        [
            0x9f86d081884c7d659a2feaa0c55ad015,
            0xa3bf4f1b2b0b822cd15d6c15b0f00a08,
        ],
        // This creates scalar (BE): 
        // 2235ff4bf39efac1479a3496fc685b776eadcb1749b8402c94f84887d62552d7
        //
        // When we add private key to it, we get the tweaked scalar (BE):
        // 7a6f5ac48e3519a4b0d9201c02c83497a035e39892ad8a4b95130128e2636bec
        //
        // This creates the following point:
        // X Coordinate (LE): 4c17631a428d85da2baa8ed9a7b9a2f8a69b5be36c0e4deb22bff1d25ec839e9
        [
            0x4c, 0x17, 0x63, 0x1a, 0x42, 0x8d, 0x85, 0xda, 
            0x2b, 0xaa, 0x8e, 0xd9, 0xa7, 0xb9, 0xa2, 0xf8, 
            0xa6, 0x9b, 0x5b, 0xe3, 0x6c, 0x0e, 0x4d, 0xeb, 
            0x22, 0xbf, 0xf1, 0xd2, 0x5e, 0xc8, 0x39, 0xe9, 
        ],
        // Y Coordinate (LE): 923616b2b7d23b07966652619904f0f3984e0d01f75f49b2af32566859f9c4c0
        [
            0x92, 0x36, 0x16, 0xb2, 0xb7, 0xd2, 0x3b, 0x07, 
            0x96, 0x66, 0x52, 0x61, 0x99, 0x04, 0xf0, 0xf3, 
            0x98, 0x4e, 0x0d, 0x01, 0xf7, 0x5f, 0x49, 0xb2, 
            0xaf, 0x32, 0x56, 0x68, 0x59, 0xf9, 0xc4, 0xc0
        ]
    );
}
