using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Generates the RSA key pair a simulated <c>TPM2_CreatePrimary()</c> returns: the private key the TPM
/// retains and the public modulus it exports in <c>outPublic</c> (TPM 2.0 Library Part 3, clause 24.1).
/// </summary>
/// <remarks>
/// The simulator models a TPM's key generation, not a real entropy source, so the actual key creation is
/// supplied through this seam — exactly as the ECC backend and the RNG backend are — keeping
/// <see cref="Verifiable.Tpm"/> backend-agnostic.
/// </remarks>
/// <param name="keyBits">The RSA modulus size in bits.</param>
/// <param name="pool">The memory pool backing the returned key material.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The generated key. The caller owns and disposes it.</returns>
public delegate ValueTask<TpmGeneratedRsaKey> TpmRsaKeyGenerationDelegate(
    ushort keyBits,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// Signs a pre-computed digest with an RSA private key, modelling <c>TPM2_Sign()</c> over an
/// externally-computed digest with a NULL validation ticket (TPM 2.0 Library Part 3, clause 20.5).
/// </summary>
/// <remarks>
/// The digest is signed <strong>directly</strong> under the requested padding scheme — the backend must not
/// hash it again. The result is the raw RSA signature octets, which the simulator frames as the
/// <c>TPMS_SIGNATURE_RSA</c> signature value.
/// </remarks>
/// <param name="privateKey">The signing key's retained private key, in the backend's own encoding.</param>
/// <param name="digest">The pre-computed digest to sign.</param>
/// <param name="scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="hashAlg">The scheme's hash algorithm.</param>
/// <param name="pool">The memory pool backing the returned signature.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The raw RSA signature. The caller owns and disposes it.</returns>
public delegate ValueTask<Signature> TpmRsaDigestSignDelegate(
    ReadOnlyMemory<byte> privateKey,
    ReadOnlyMemory<byte> digest,
    TpmAlgIdConstants scheme,
    TpmAlgIdConstants hashAlg,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// OAEP-encrypts a plaintext value to an RSA public key, modelling the RSA arm of credential-protection seed
/// transport for <c>TPM2_MakeCredential()</c> (TPM 2.0 Library Part 1, clauses 43.4 "RSAES_OAEP", 20.3.2.3, 21.3;
/// RFC 8017 §7.1.1 EME-OAEP encoding, which clause 43.4 references normatively for the encoding mechanics).
/// </summary>
/// <remarks>
/// A public-key-only operation — unlike <see cref="TpmEccSharedSecretDelegate"/>, which needs a local private
/// scalar, OAEP-encrypting to a peer needs only their modulus and exponent, mirroring how
/// <c>TPM2_MakeCredential()</c> resolves only the credential key's public area. <paramref name="lhashAlg"/> and
/// <paramref name="mgfHashAlg"/> are kept as separate parameters even though the L-1 template's NULL scheme
/// makes them coincide (clause 43.4: <c>lhash</c> uses the key's scheme hash, or the key's Name algorithm when
/// the scheme is <c>TPM_ALG_NULL</c>; MGF1 always uses the key's Name algorithm, independent of that choice).
/// </remarks>
/// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
/// <param name="exponent">The RSA public exponent.</param>
/// <param name="plaintext">The plaintext value to encrypt (the credential-protection seed).</param>
/// <param name="label">The OAEP label octets (<c>L</c>), including any terminator the caller intends — fed to the <c>lhash</c> digest verbatim.</param>
/// <param name="lhashAlg">The hash algorithm computing <c>lhash = H(L)</c>.</param>
/// <param name="mgfHashAlg">The hash algorithm driving MGF1 for <c>dbMask</c>/<c>seedMask</c>.</param>
/// <param name="pool">The memory pool backing the returned ciphertext.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The OAEP ciphertext, the same octet width as the modulus. The caller owns and disposes it.</returns>
public delegate ValueTask<IMemoryOwner<byte>> TpmRsaOaepEncryptDelegate(
    ReadOnlyMemory<byte> modulus,
    uint exponent,
    ReadOnlyMemory<byte> plaintext,
    ReadOnlyMemory<byte> label,
    TpmAlgIdConstants lhashAlg,
    TpmAlgIdConstants mgfHashAlg,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// OAEP-decrypts a ciphertext with an RSA private key, modelling the RSA arm of credential-protection seed
/// recovery for <c>TPM2_ActivateCredential()</c> (TPM 2.0 Library Part 1, clauses 43.3 "RSADP", 43.4,
/// 20.3.2.3, 21.3; RFC 8017 §7.1.2 EME-OAEP decoding).
/// </summary>
/// <remarks>
/// Any OAEP decode failure (a non-zero leading octet, an <c>lhash</c> mismatch, malformed padding, or
/// <c>c &gt;= n</c>) must not surface as a distinct outcome the caller can branch on early: the v184 clause
/// A.10.3 note, imported by A.10.4 for the credential case, requires the failure to stay silent until the outer
/// integrity HMAC rejects it, so decryption cannot become a padding oracle; v185 keeps that rationale as
/// Part 3, clause 13.3.1's integrity-before-use rule. This delegate signals a decode
/// failure by returning <see langword="null"/> rather than throwing or returning a shaped error — the shape
/// that lets the caller substitute an unpredictable seed and proceed without an exception in the failure path.
/// </remarks>
/// <param name="privateKey">The decrypting key's retained private key, in the backend's own encoding.</param>
/// <param name="ciphertext">The OAEP ciphertext, the same octet width as the modulus.</param>
/// <param name="label">The OAEP label octets (<c>L</c>), matching the value the encrypt side used.</param>
/// <param name="lhashAlg">The hash algorithm computing <c>lhash = H(L)</c>.</param>
/// <param name="mgfHashAlg">The hash algorithm driving MGF1 for <c>dbMask</c>/<c>seedMask</c>.</param>
/// <param name="pool">The memory pool backing the returned plaintext.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The recovered plaintext (the credential-protection seed) on success; <see langword="null"/> when OAEP
/// decoding failed. The caller owns and disposes a non-null result.
/// </returns>
public delegate ValueTask<IMemoryOwner<byte>?> TpmRsaOaepDecryptDelegate(
    ReadOnlyMemory<byte> privateKey,
    ReadOnlyMemory<byte> ciphertext,
    ReadOnlyMemory<byte> label,
    TpmAlgIdConstants lhashAlg,
    TpmAlgIdConstants mgfHashAlg,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// RSAES (PKCS#1 v1.5) encrypts a message to an RSA public key, modelling the RSAES padding scheme
/// <c>TPM2_RSA_Encrypt()</c> selects (TPM 2.0 Library Part 1, clause 43.5 "This encryption scheme is defined in
/// RFC 8017 [13]. It has no parameters. The algorithm identifier for this scheme is TPM_ALG_RSAES."; RFC 8017
/// §7.2.1 EME-PKCS1-v1_5 encoding).
/// </summary>
/// <remarks>
/// A public-key-only operation, the same shape as <see cref="TpmRsaOaepEncryptDelegate"/>. The message-size
/// limit (Table 43: <c>mLen ≤ k − 11</c>) and the modulus-width padding octet count are the simulator's own
/// judgment ahead of the call; this delegate always returns exactly <c>k</c> octets, the modulus width.
/// </remarks>
/// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
/// <param name="exponent">The RSA public exponent.</param>
/// <param name="message">The message to encrypt.</param>
/// <param name="pool">The memory pool backing the returned ciphertext.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The RSAES ciphertext, exactly <c>k</c> octets (the modulus width). The caller owns and disposes it.</returns>
public delegate ValueTask<IMemoryOwner<byte>> TpmRsaEsEncryptDelegate(
    ReadOnlyMemory<byte> modulus,
    uint exponent,
    ReadOnlyMemory<byte> message,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// RSAES (PKCS#1 v1.5) decrypts a ciphertext with an RSA private key, modelling the RSAES padding scheme
/// <c>TPM2_RSA_Decrypt()</c> selects (RFC 8017 §7.2.2 EME-PKCS1-v1_5 decoding, referenced normatively by TPM
/// 2.0 Library Part 1, clause 43.5).
/// </summary>
/// <remarks>
/// TPM 2.0 Library Part 3, clause 14.3.1's own sentence — "If the padding checks fail, TPM_RC_VALUE is
/// returned" — makes an RSAES padding failure an immediate, distinguishable outcome, unlike
/// <see cref="TpmRsaOaepDecryptDelegate"/>'s credential-path deferral: this delegate still signals the failure
/// by returning <see langword="null"/>, and the simulator's own effect maps that directly to
/// <c>TPM_RC_VALUE</c> rather than deferring it.
/// </remarks>
/// <param name="privateKey">The decrypting key's retained private key, in the backend's own encoding.</param>
/// <param name="ciphertext">The RSAES ciphertext, exactly <c>k</c> octets (the modulus width).</param>
/// <param name="pool">The memory pool backing the returned message.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The recovered message on success, at most <c>k − 11</c> octets (Table 43's own <c>mLen ≤ k − 11</c>) — the
/// effect refuses a wider answer with <c>TPM_RC_VALUE</c>; <see langword="null"/> when PKCS#1 v1.5 decoding
/// failed. The caller owns and disposes a non-null result.
/// </returns>
public delegate ValueTask<IMemoryOwner<byte>?> TpmRsaEsDecryptDelegate(
    ReadOnlyMemory<byte> privateKey,
    ReadOnlyMemory<byte> ciphertext,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// RSAEP, the raw RSA public-key primitive, modelling the <c>TPM_ALG_NULL</c> scheme selection of
/// <c>TPM2_RSA_Encrypt()</c> (TPM 2.0 Library Part 1, clause 43.2: "This is the RSA public key primitive
/// defined in RFC 8017 [13], clause 5.1.1. It is a modular exponentiation of a message (m) with the public
/// exponent (e), modulo the public modulus (n) to produce the cipher text (c)." — <c>c = m^e mod n</c>).
/// </summary>
/// <remarks>
/// The caller has already judged <c>value &lt; n</c> (a fixed-time big-endian octet compare of two
/// <c>k</c>-wide values) before invoking this delegate, so it never sees an out-of-range value; it need not
/// re-check the bound. The delegate itself must answer exactly <c>k</c> octets, left-padding a bare modular
/// exponentiation's minimal encoding to the modulus width before returning; the effect refuses any other width
/// with <c>TPM_RC_VALUE</c>.
/// </remarks>
/// <param name="modulus">The RSA public modulus, unsigned big-endian.</param>
/// <param name="exponent">The RSA public exponent.</param>
/// <param name="value">The value to exponentiate, exactly <c>k</c> octets (the modulus width).</param>
/// <param name="pool">The memory pool backing the returned result.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The exponentiation result <c>m^e mod n</c>, exactly <c>k</c> octets (left-padded by the delegate). The caller owns and disposes it.</returns>
public delegate ValueTask<IMemoryOwner<byte>> TpmRsaPublicOperationDelegate(
    ReadOnlyMemory<byte> modulus,
    uint exponent,
    ReadOnlyMemory<byte> value,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// RSADP, the raw RSA private-key primitive, modelling the <c>TPM_ALG_NULL</c> scheme selection of
/// <c>TPM2_RSA_Decrypt()</c> (TPM 2.0 Library Part 1, clause 43.3: "This is the RSA private key primitive
/// defined in PSCS#1v2.1, clause 5.1.2. … the RSADP operation recovers a message from a cipher text by: m = c^d
/// (mod n)" — PSCS#1v2.1 is the spec's own spelling of PKCS#1 v2.1, RFC 3447).
/// </summary>
/// <remarks>
/// The caller has already judged <c>value &lt; n</c> before invoking this delegate, exactly as
/// <see cref="TpmRsaPublicOperationDelegate"/>'s remarks describe; the delegate itself must answer exactly
/// <c>k</c> octets, RSADP's output left-padded to the modulus width by the delegate before returning — the
/// effect refuses any other width with <c>TPM_RC_VALUE</c>.
/// </remarks>
/// <param name="privateKey">The decrypting key's retained private key, in the backend's own encoding.</param>
/// <param name="value">The value to exponentiate, exactly <c>k</c> octets (the modulus width).</param>
/// <param name="pool">The memory pool backing the returned result.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The exponentiation result <c>c^d mod n</c>, exactly <c>k</c> octets (RSADP's output, left-padded by the delegate). The caller owns and disposes it.</returns>
public delegate ValueTask<IMemoryOwner<byte>> TpmRsaPrivateOperationDelegate(
    ReadOnlyMemory<byte> privateKey,
    ReadOnlyMemory<byte> value,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// Verifies that a signature over a pre-computed digest is valid for an RSA key, modelling the public-key
/// operation <c>TPM2_VerifySignature()</c> performs (TPM 2.0 Library Part 3, clause 20.2).
/// </summary>
/// <remarks>
/// The digest is verified <strong>directly</strong> under the requested padding scheme — the backend must not
/// hash it again, mirroring <see cref="TpmRsaDigestSignDelegate"/>. Takes the public modulus and exponent
/// directly, the same public-input shape <see cref="TpmEccDigestVerifyDelegate"/> already took: every loaded
/// RSA object retains its full public area (<c>TransientKeyState.PublicArea</c>), so verification needs no
/// private-key material and works unchanged against a public-only object <c>TPM2_LoadExternal()</c> loads
/// (TPM 2.0 Library Part 3, clause 12.3.1).
/// </remarks>
/// <param name="modulus">The verifying key's public modulus, unsigned big-endian.</param>
/// <param name="exponent">The verifying key's public exponent.</param>
/// <param name="digest">The digest the signature is claimed to be over.</param>
/// <param name="signature">The signature to verify.</param>
/// <param name="scheme">The RSA signing scheme (<c>TPM_ALG_RSASSA</c> or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="hashAlg">The scheme's hash algorithm.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns><see langword="true"/> when the signature verifies against the public key; otherwise <see langword="false"/>.</returns>
public delegate ValueTask<bool> TpmRsaDigestVerifyDelegate(
    ReadOnlyMemory<byte> modulus,
    uint exponent,
    ReadOnlyMemory<byte> digest,
    ReadOnlyMemory<byte> signature,
    TpmAlgIdConstants scheme,
    TpmAlgIdConstants hashAlg,
    CancellationToken cancellationToken);

/// <summary>
/// Imports an RSA private key from its public modulus, public exponent, and one prime factor, modelling the
/// public/private key pair consistency check <c>TPM2_LoadExternal()</c> runs over an RSA sensitive area (TPM
/// 2.0 Library Part 3, clause 12.3.1: "For an RSA key, the private exponent is computed using the two prime
/// factors of the public modulus. One of the primes is P, and the second prime (Q) is found by dividing the
/// public modulus by P").
/// </summary>
/// <remarks>
/// Returns <see langword="null"/> rather than throwing when the supplied prime does not divide the modulus,
/// or when the two resulting prime factors have different bit sizes (Part 2, clause 11.2.4.8: "All primes are
/// required to have exactly half the number of significant bits as the public modulus"; clause 12.3.1's own
/// "may" for the size-mismatch case) — so the caller can answer <c>TPM_RC_BINDING</c> without an
/// exception-driven control path.
/// </remarks>
/// <param name="modulus">The public modulus, unsigned big-endian.</param>
/// <param name="exponent">The public exponent (zero meaning the default 65537, TPM 2.0 Library Part 2, Table 228's wire convention).</param>
/// <param name="prime">The supplied prime factor <c>P</c>, unsigned big-endian.</param>
/// <param name="pool">The memory pool backing the returned key.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The imported private key, in the backend's own encoding; <see langword="null"/> when <paramref name="prime"/>
/// does not divide <paramref name="modulus"/> or the two prime factors' bit sizes differ. The caller owns and
/// disposes a non-null result.
/// </returns>
public delegate ValueTask<PrivateKeyMemory?> TpmRsaPrivateKeyImportDelegate(
    ReadOnlyMemory<byte> modulus,
    uint exponent,
    ReadOnlyMemory<byte> prime,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);

/// <summary>
/// The RSA backend the simulator drives for <c>TPM2_CreatePrimary()</c>, <c>TPM2_Sign()</c>,
/// <c>TPM2_VerifySignature()</c>, <c>TPM2_RSA_Encrypt()</c>, and <c>TPM2_RSA_Decrypt()</c>: a key generator
/// paired with a digest signer/verifier and the RSAES/OAEP/raw encrypt-decrypt primitives. The RSA counterpart
/// of <see cref="TpmEccSigningBackend"/>.
/// </summary>
/// <remarks>
/// A seam-bundle the constructor of <see cref="TpmSimulator"/> takes as one optional dependency, alongside
/// the ECC backend. When neither asymmetric backend is supplied, the simulator answers the object/signing
/// commands with <c>TPM_RC_COMMAND_CODE</c>.
/// </remarks>
/// <param name="GenerateKey">Generates the primary RSA key a <c>TPM2_CreatePrimary()</c> returns.</param>
/// <param name="SignDigest">Signs a digest with a retained RSA key for <c>TPM2_Sign()</c>.</param>
/// <param name="EncryptOaep">
/// OAEP-encrypts the credential-protection seed to a credential key's public modulus for the RSA arm of
/// <c>TPM2_MakeCredential()</c> (TPM 2.0 Library Part 1, clauses 43.4, 20.3.2.3, 21.3).
/// </param>
/// <param name="DecryptOaep">
/// OAEP-decrypts the credential-protection seed with a credential key's retained private key for the RSA arm
/// of <c>TPM2_ActivateCredential()</c> (TPM 2.0 Library Part 1, clauses 43.3, 43.4, 20.3.2.3, 21.3).
/// </param>
/// <param name="VerifyDigest">Verifies a digest/signature pair against a key's public modulus and exponent for <c>TPM2_VerifySignature()</c>.</param>
/// <param name="ImportPrivateKey">
/// Imports a private key from its public modulus, public exponent, and one prime factor, for
/// <c>TPM2_LoadExternal()</c>'s public/private key pair consistency check over a loaded RSA sensitive area
/// (TPM 2.0 Library Part 3, clause 12.3.1).
/// </param>
/// <param name="EncryptRsaes">RSAES (PKCS#1 v1.5) encrypts a message to an RSA public key for <c>TPM2_RSA_Encrypt()</c>.</param>
/// <param name="DecryptRsaes">RSAES (PKCS#1 v1.5) decrypts a ciphertext with an RSA private key for <c>TPM2_RSA_Decrypt()</c>.</param>
/// <param name="EncryptRaw">RSAEP, the raw RSA public-key primitive, for the <c>TPM_ALG_NULL</c> scheme of <c>TPM2_RSA_Encrypt()</c>.</param>
/// <param name="DecryptRaw">RSADP, the raw RSA private-key primitive, for the <c>TPM_ALG_NULL</c> scheme of <c>TPM2_RSA_Decrypt()</c>.</param>
public sealed record TpmRsaSigningBackend(
    TpmRsaKeyGenerationDelegate GenerateKey,
    TpmRsaDigestSignDelegate SignDigest,
    TpmRsaOaepEncryptDelegate EncryptOaep,
    TpmRsaOaepDecryptDelegate DecryptOaep,
    TpmRsaDigestVerifyDelegate VerifyDigest,
    TpmRsaPrivateKeyImportDelegate ImportPrivateKey,
    TpmRsaEsEncryptDelegate EncryptRsaes,
    TpmRsaEsDecryptDelegate DecryptRsaes,
    TpmRsaPublicOperationDelegate EncryptRaw,
    TpmRsaPrivateOperationDelegate DecryptRaw);

/// <summary>
/// The key material a <see cref="TpmRsaKeyGenerationDelegate"/> produces: the private key the TPM retains
/// and the public modulus it exports. The simulator copies what it needs into its durable model state and
/// then disposes this carrier.
/// </summary>
/// <param name="PrivateKey">The generated private key, in the backend's own encoding.</param>
/// <param name="Modulus">The generated public modulus (big-endian).</param>
public sealed record TpmGeneratedRsaKey(PrivateKeyMemory PrivateKey, PublicKeyMemory Modulus): IDisposable
{
    /// <summary>
    /// Releases the key material backing the private key and the public modulus.
    /// </summary>
    public void Dispose()
    {
        PrivateKey.Dispose();
        Modulus.Dispose();
    }
}
