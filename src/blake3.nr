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
use std::hash::blake3;
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
        0xb8, 0xc2, 0x14, 0xee, 0xad, 0xdb, 0xa4, 0x04, 
        0x23, 0x0f, 0x77, 0x02, 0xa7, 0xdd, 0x6c, 0x79, 
        0x60, 0xe4, 0x23, 0xfe, 0x78, 0x8f, 0x63, 0xe0, 
        0x4d, 0x60, 0x39, 0xf2, 0x84, 0x7f, 0xf4, 0x18,
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
        0x10, 0xfb, 0x70, 0x67, 0x48, 0x71, 0xc2, 0xe7, 
        0x8c, 0x4e, 0x62, 0x87, 0xae, 0x3d, 0x45, 0x99, 
        0x92, 0x6c, 0x3c, 0x7f, 0xc1, 0x84, 0xad, 0xff, 
        0x4d, 0x7a, 0xf2, 0x94, 0x90, 0xbe, 0x10, 0xfe,
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
fn hash_to_nonce(secret_key: [u8;32], message_hash: [u8;32]) -> [u8;32] {
    let input: [u8;64] = [
        secret_key[0], secret_key[1], secret_key[2], secret_key[3], secret_key[4], secret_key[5], secret_key[6], secret_key[7],
        secret_key[8], secret_key[9], secret_key[10], secret_key[11], secret_key[12], secret_key[13], secret_key[14], secret_key[15],
        secret_key[16], secret_key[17], secret_key[18], secret_key[19], secret_key[20], secret_key[21], secret_key[22], secret_key[23],
        secret_key[24], secret_key[25], secret_key[26], secret_key[27], secret_key[28], secret_key[29], secret_key[30], secret_key[31],
        message_hash[0], message_hash[1], message_hash[2], message_hash[3], message_hash[4], message_hash[5], message_hash[6], message_hash[7],
        message_hash[8], message_hash[9], message_hash[10], message_hash[11], message_hash[12], message_hash[13], message_hash[14], message_hash[15],
        message_hash[16], message_hash[17], message_hash[18], message_hash[19], message_hash[20], message_hash[21], message_hash[22], message_hash[23],
        message_hash[24], message_hash[25], message_hash[26], message_hash[27], message_hash[28], message_hash[29], message_hash[30], message_hash[31]
    ];
    blake3(input)
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

fn get_gx() -> [u8; 32] {
    [
        152, 23, 248, 22, 91, 129, 242, 89,
        217, 40, 206, 45, 219, 252, 155, 2,
        7, 11, 135, 206, 149, 98, 160, 85,
        172, 187, 220, 249, 126, 102, 190, 121
    ]
}

fn get_gy() -> [u8; 32] {
    [
        184, 212, 16, 251, 143, 208, 71, 156,
        25, 84, 133, 166, 72, 180, 23, 253,
        168, 8, 17, 14, 252, 251, 164, 93,
        101, 196, 163, 38, 119, 218, 58, 72
    ]
}

fn main(
    secret: [u8;32], 
    message: pub [u8;32],
    aggregate_point_x: pub [u8;32], 
    aggregate_point_y: pub [u8;32]
) {
    // Step 1: Create a new nonce from our private key and message hash without revealing the private key or the nonce
    let nonce_hash = hash_to_nonce(secret, message);
    // Debug: We can use this to check our hash is correct: e032e27aabc7173d4658cc3625a91abe10de84161267a1783afe1536b68ec3ab
    // check_hash(nonce_hash);
    // Step 2. Add our private key to this scalar via modular bignum addition
    let aggregate_scalar = calculate_aggregate_scalar(secret, nonce_hash);
    // DEBUG: We can use this to check our resulting aggregate scalar is correct
    // check_aggregate_scalar(aggregate_scalar);
    /// 3. Calculate the aggregated point via ECMul from the aggregated scalar
    let aggregate_point = mul_g(aggregate_scalar);
    // DEBUG: Print out the aggregate point
    // println(aggregate_point);
    /// 4. Ensure recovered point matches the witness value of the aggregate point
    check_aggregate_point(aggregate_point, aggregate_point_x, aggregate_point_y);
}

#[test]
fn test_blake3() {
    main(
        // Privkey (BE) 58395b789a961ee3693eeb85065fd9203188188148f54a1f001ab8a10c3e1915
        [
            0x58, 0x39, 0x5b, 0x78, 0x9a, 0x96, 0x1e, 0xe3, 
            0x69, 0x3e, 0xeb, 0x85, 0x06, 0x5f, 0xd9, 0x20, 
            0x31, 0x88, 0x18, 0x81, 0x48, 0xf5, 0x4a, 0x1f, 
            0x00, 0x1a, 0xb8, 0xa1, 0x0c, 0x3e, 0x19, 0x15,
        ],
        // Sha256 message hash "test"
        [
            0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 
            0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 
            0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 
            0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
        ],
        // This creates scalar (BE): 
        // b8c214eeaddba404230f7702a7dd6c7960e423fe788f63e04d6039f2847ff418
        //
        // When we add private key to it, we get the tweaked scalar (BE):
        // 10fb70674871c2e78c4e6287ae3d4599926c3c7fc184adff4d7af29490be10fe
        //
        // This creates the following point:
        // X Coordinate (LE): 50e327fcb5c08eee68944291d2f5af8e5a9206e0c2b7d87a8037b40cf657a6ca
        [
            0x50, 0xe3, 0x27, 0xfc, 0xb5, 0xc0, 0x8e, 0xee, 
            0x68, 0x94, 0x42, 0x91, 0xd2, 0xf5, 0xaf, 0x8e, 
            0x5a, 0x92, 0x06, 0xe0, 0xc2, 0xb7, 0xd8, 0x7a, 
            0x80, 0x37, 0xb4, 0x0c, 0xf6, 0x57, 0xa6, 0xca, 
        ],
        // Y Coordinate (LE): fd0c59982a42920b8d8a3b2c2452e42448594732c5fb8780432dab371877161c
        [
            0xfd, 0x0c, 0x59, 0x98, 0x2a, 0x42, 0x92, 0x0b, 
            0x8d, 0x8a, 0x3b, 0x2c, 0x24, 0x52, 0xe4, 0x24, 
            0x48, 0x59, 0x47, 0x32, 0xc5, 0xfb, 0x87, 0x80, 
            0x43, 0x2d, 0xab, 0x37, 0x18, 0x77, 0x16, 0x1c, 
        ]
    );
}
