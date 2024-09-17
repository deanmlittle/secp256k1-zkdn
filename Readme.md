# secp256k1-zkdn

An implementation of zero-knowledge deterministic nonces written in Noir—used to prevent nonce-based attacks in adversarial multi-party signing environments.

## Nonces in Single-Party Schnorr

In Schnorr (and other Schnorr-like signature schemes like EdDSA), each signature requires a unique and unpredictable nonce $k$ to ensure cryptographic security. If a nonce is reused or suffers from weak randomness, it becomes trivial to reverse the signature and recover the private key. As such, nonces are typically generated deterministically by computing some variant of $k = H(x, m)$, where $H$ is a cryptographic hash function, $x$ is the private key, and $m$ is the message being signed.

This method of deterministic nonce generation ensures that each nonce:

- **Derives unpredictability from the private key and message via a cryptographic hash function**
- **Is consistent for any given message each time**
- **Is unique to each message and never reused for different messages**

This approach allows us to be confident that our signature's security is at least as strong as the secrecy of our private key. However, in aggregated Schnorr signatures, deterministic nonces can introduce new challenges.

## Nonces in Aggregate Schnorr

One of the best features of Schnorr signatures is their ability to be aggregated. A simplified understanding is:

- **Public Keys**:  
  $P_{\text{agg}} = \sum_{i} P_i$

- **Nonce Points**:  
  $R_{\text{agg}} = \sum_{i} R_i$

- **Signature Scalars**:  
  $S_{\text{agg}} = \sum_{i} S_i$

However, an issue arises when aggregating signatures. Each signature $(R_i, S_i)$ is derived from the signer's private nonce $k_i$, private key $x_i$, and challenge $e$:

- $e = H(R_{\text{agg}}, P_{\text{agg}}, m)$
- $S_i = k_i + e \cdot x_i \mod n$
- $R_i = k_i G$

Because the challenge $e$ depends on the aggregated nonce $R_{\text{agg}}$, aggregated public key $P_{\text{agg}}$, and the message $m$, we cannot arbitrarily aggregate $S_i$ values created with unrelated nonces and challenges. All signers must agree ahead of time on a common aggregate nonce $R_{\text{agg}}$ and compute the same challenge $e$. While each party signs with their own $k_i$, this coordination is essential for the validity of the aggregated signature.

This requirement introduces a vulnerability similar to that in single-signer Schnorr. If just one party uses a weak or predictable nonce, the security of the entire signature scheme could be compromised. This leads to a conundrum:

- **If nonces are purely random, signers could be manipulated into signing the same message with different nonces.**
- **We have no way of proving that a signer derived their nonce securely and deterministically.**

## Zero-Knowledge Proofs for Deterministic Nonces

The solution is to utilize a zero-knowledge proof system. By doing so, signing parties can prove that their nonce was derived deterministically from their private key and the message hash, without revealing any secret information. This approach ensures that all parties are using nonces securely, mitigating the risks associated with weak or malicious nonce generation.

### The Circuit Design

The circuit takes in three inputs:

- **$p$**: (private) private key scalar
- **$H(m)$**: hash of the message to sign
- **$A = P + R$**: the aggregated point of the public key and nonce point

By aggregating the nonce point $R$ with the public key $P$, we leverage the property that scalar addition corresponds to point addition:

$$
A = (p + k)G = pG + kG = P + R
$$

This allows us to perform a single scalar multiplication inside our circuit instead of two, optimizing efficiency. When the signer eventually signs, their public key $P$ is already known, and they provide their nonce point $R$, enabling others to compute $A = P + R$ and verify the proof.

The circuit performs the following steps:

1. **Nonce Derivation**: Compute $k = H(p, H(m))$, deriving the nonce deterministically from the private key $p$ and the message hash $H(m)$.

2. **Aggregate Scalar Calculation**: Compute $a = p + k \mod n$, combining the private key and nonce scalar modulo the curve order $n$.

3. **Aggregate Point Computation**: Calculate $A' = aG$, where $G$ is the generator point of the curve.

4. **Verification**: Verify that $A' = A$, confirming that the computed point matches the provided aggregate point.

By implementing this zero-knowledge proof, we can be highly confident that all parties in an adversarial environment are generating their nonces securely and deterministically. This not only prevents nonce reuse and related attacks but also ensures that the entire signature scheme remains robust against malleability and key extraction attacks. The proof establishes that each signer adheres to the protocol without compromising their private keys, thus maintaining the cryptographic soundness of the aggregate signature.
