using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Signs the message a WebAuthn authentication assertion or packed self-attestation covers, with a
/// credential's own private key — the primitive that turns a credential (passkey) into a first-class
/// signing key.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication Level 3
/// section 7.2: Verifying an Authentication Assertion</see> step 21, and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">section 8.2: Packed Attestation
/// Statement Format</see>'s self attestation branch, both sign the same message: <c>authenticatorData ‖
/// clientDataHash</c> (step 20). This type assembles that message into a pooled buffer — mirroring
/// <see cref="PackedAttestation"/>'s <c>RentToBeSigned</c> and <see cref="Fido2AssertionVerifier"/>'s
/// own copy of it — and signs it with <paramref name="credentialKey"/>'s bound
/// <see cref="SigningDelegate"/>.
/// </para>
/// <para>
/// <see cref="PrivateKey"/> abstracts key custody: <paramref name="credentialKey"/> may wrap a software
/// key, or a hardware-held key such as a TPM-resident or smart-card/APDU-held credential whose private
/// scalar never leaves the device. <see cref="SignAssertionAsync"/> signs identically either way, without
/// knowing or caring which — the same seam <c>Verifiable.Apdu.Eac.TerminalAuthenticationSignature</c>
/// uses for a Terminal Authentication key. This is what lets a wallet application hold a passkey as a
/// signing key transparently, regardless of where the credential's key material actually lives.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section 6.5.5,
/// Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures</see>
/// requires an ECDSA <c>sig</c> value (<c>COSEAlgorithmIdentifier</c> -7/-35/-36/-47,
/// ES256/ES384/ES512/ES256K) to be encoded as an ASN.1 DER <c>Ecdsa-Sig-Value</c>
/// (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3</see>),
/// while this library's registered ECDSA signing seam returns the fixed-width IEEE P1363 <c>r ‖ s</c>
/// encoding (the same encoding <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.1">RFC 9053
/// section 2.1</see> defines for a COSE signature). <see cref="SignAssertionAsync"/> re-encodes an EC
/// signature from P1363 to DER after signing, via <see cref="EcdsaSignatureEncoding.ConvertP1363ToDer"/>,
/// so the returned <see cref="Signature"/> is the spec-conformant WebAuthn wire value. RSA
/// (<c>RS256</c>/<c>PS256</c>/...) and EdDSA signatures carry no such re-encoding — section 6.5.5
/// leaves them "not ASN.1 wrapped" — so they pass through unchanged.
/// </para>
/// </remarks>
public static class Fido2CredentialSigner
{
    /// <summary>
    /// Signs the WebAuthn assertion/self-attestation message <c>authenticatorData ‖ clientDataHash</c>
    /// with <paramref name="credentialKey"/>, re-encoding an EC signature to ASN.1 DER when
    /// <paramref name="coseAlgorithm"/> is ES256, ES384, ES512, or ES256K.
    /// </summary>
    /// <param name="credentialKey">
    /// The credential's private key, with its signing function already bound (for example via
    /// <see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, Tag, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>).
    /// May be backed by software or hardware (TPM/APDU-held) custody; this method signs identically
    /// either way.
    /// </param>
    /// <param name="authenticatorData">The raw <c>authData</c> wire bytes.</param>
    /// <param name="clientDataHash">The SHA-256 hash of <c>clientDataJSON</c> (WebAuthn L3 section 7.2 step 20).</param>
    /// <param name="coseAlgorithm">
    /// The credential's <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE
    /// algorithm identifier</see>, used only to decide whether the resulting signature needs the DER
    /// re-encoding; it is not cross-checked against <paramref name="credentialKey"/> here.
    /// </param>
    /// <param name="pool">The memory pool the message and signature buffers rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The spec-conformant assertion/self-attestation signature. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="credentialKey"/>, <paramref name="clientDataHash"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature (re-encoded or passed through) transfers to the caller, which disposes it via a using declaration.")]
    public static async ValueTask<Signature> SignAssertionAsync(
        PrivateKey credentialKey,
        ReadOnlyMemory<byte> authenticatorData,
        DigestValue clientDataHash,
        int coseAlgorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialKey);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        using IMemoryOwner<byte> messageOwner = RentToBeSigned(authenticatorData, clientDataHash, pool, out int messageLength);
        Signature rawSignature = await credentialKey.SignAsync(messageOwner.Memory[..messageLength], pool).ConfigureAwait(false);

        return IsEcAlgorithm(coseAlgorithm) ? ReencodeToDer(rawSignature, pool) : rawSignature;
    }


    /// <summary>
    /// Rents a buffer sized to <paramref name="authenticatorData"/> plus <paramref name="clientDataHash"/>
    /// and fills it with their concatenation — the bytes every WebAuthn assertion (section 7.2 step 21)
    /// and packed self-attestation (section 8.2) signature covers.
    /// </summary>
    /// <param name="length">The exact number of meaningful bytes in the returned owner's memory.</param>
    private static IMemoryOwner<byte> RentToBeSigned(ReadOnlyMemory<byte> authenticatorData, DigestValue clientDataHash, MemoryPool<byte> pool, out int length)
    {
        length = authenticatorData.Length + clientDataHash.Length;
        IMemoryOwner<byte> owner = pool.Rent(length);
        authenticatorData.Span.CopyTo(owner.Memory.Span);
        clientDataHash.AsReadOnlySpan().CopyTo(owner.Memory.Span[authenticatorData.Length..]);

        return owner;
    }


    /// <summary>
    /// Determines whether <paramref name="coseAlgorithm"/> is one of the ECDSA algorithms section
    /// 6.5.5 requires ASN.1 DER re-encoding for.
    /// </summary>
    /// <remarks>
    /// Mirrors <see cref="Fido2EcdsaWireSignature.TryGetEcFieldWidth"/>'s field-width table, which
    /// already includes ES256K (secp256k1, RFC 8812 §3): the wire-side verifier converts an ES256K
    /// signature from DER to P1363, so the signer must produce DER for the same algorithm, or a
    /// legitimately-signed ES256K assertion/self-attestation would leave the wire signature in raw
    /// P1363 and fail verification.
    /// </remarks>
    private static bool IsEcAlgorithm(int coseAlgorithm) =>
        WellKnownCoseAlgorithms.IsEs256(coseAlgorithm)
        || WellKnownCoseAlgorithms.IsEs384(coseAlgorithm)
        || WellKnownCoseAlgorithms.IsEs512(coseAlgorithm)
        || WellKnownCoseAlgorithms.IsEs256K(coseAlgorithm);


    /// <summary>
    /// Re-encodes <paramref name="rawSignature"/> from the registered signing seam's fixed-width IEEE
    /// P1363 <c>r ‖ s</c> encoding to the ASN.1 DER <c>Ecdsa-Sig-Value</c> encoding section 6.5.5
    /// requires, disposing the intermediate P1363 signature.
    /// </summary>
    private static Signature ReencodeToDer(Signature rawSignature, MemoryPool<byte> pool)
    {
        using(rawSignature)
        {
            IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(rawSignature.AsReadOnlySpan(), pool, out _);

            return new Signature(derOwner, CryptoTags.AlgorithmAgnosticSignature);
        }
    }
}
