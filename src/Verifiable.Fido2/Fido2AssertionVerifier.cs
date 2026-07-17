using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Orchestrates the WebAuthn L3 §7.2 authentication ceremony verification: the assertion
/// signature check this library performs directly, composed with the surface-field ceremony
/// rules in <see cref="Fido2ValidationProfiles.AssertionRules"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>. This type performs the two
/// steps the rule list deliberately excludes — computing <c>clientDataHash</c> (step 20) and
/// verifying the assertion signature against the stored credential public key (step 21) — then
/// runs the remaining steps (10-19, 22, 24) via the supplied <see cref="ClaimIssuer{TInput}"/>.
/// </para>
/// <para>
/// The signature check mirrors <see cref="PackedAttestation"/>'s self-attestation branch: the
/// bytes covered by the signature are <c>authenticatorData</c> concatenated with
/// <c>clientDataHash</c>, verified against the credential's own <see cref="CoseKey"/> converted
/// to a <see cref="PublicKeyMemory"/>. Unlike attestation, an assertion carries no attestation
/// statement or <c>alg</c> member to cross-check — the credential public key was already
/// established at registration time and is supplied here as the stored record.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section 6.5.5,
/// Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures</see>
/// requires an ECDSA <c>sig</c> value (<c>COSEAlgorithmIdentifier</c> -7 ES256, -35 ES384, -36 ES512) to
/// be encoded as an ASN.1 DER <c>Ecdsa-Sig-Value</c>
/// (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC 3279 section 2.2.3</see>),
/// while the registered EC verification seam this type calls into expects the fixed-width IEEE P1363
/// <c>r ‖ s</c> encoding. <see cref="TryVerifySignatureAsync"/> converts an EC credential's wire
/// signature from DER to P1363, via <see cref="EcdsaSignatureEncoding.ConvertDerToP1363"/>, before
/// calling the registered verifier, so a spec-conformant DER-encoded assertion signature verifies
/// correctly. RSA and EdDSA signatures carry no such conversion — section 6.5.5 leaves them "not
/// ASN.1 wrapped" — so they pass through unchanged. A malformed DER value fails the surrounding
/// fail-closed catch in <see cref="TryVerifySignatureAsync"/> the same way any other invalid signature does.
/// </para>
/// </remarks>
public static class Fido2AssertionVerifier
{
    /// <summary>
    /// The issuer identifier stamped on <see cref="ClaimIssueResult.ClaimIssuerId"/> when the
    /// convenience overload builds its own <see cref="ClaimIssuer{TInput}"/> from
    /// <see cref="Fido2ValidationProfiles.AssertionRules"/>.
    /// </summary>
    private const string DefaultIssuerId = "fido2-assertion-verifier";

    /// <summary>
    /// The key identifier passed to <see cref="CryptographicKeyFactory"/> for the stored
    /// credential public key. Not a DID or credential id — this seam has no such identity to
    /// carry, only the key material and its algorithm tag.
    /// </summary>
    private const string CredentialPublicKeyIdentifier = "fido2-assertion:credential-public-key";


    /// <summary>
    /// Verifies an authentication assertion using a caller-supplied, already-configured
    /// <see cref="ClaimIssuer{TInput}"/> for the WebAuthn L3 §7.2 surface-field rules.
    /// </summary>
    /// <param name="credentialPublicKey">The relying party's stored credential public key, established at registration time.</param>
    /// <param name="signature">The raw assertion signature bytes (<c>response.signature</c>).</param>
    /// <param name="authenticatorData">The raw <c>authData</c> wire bytes (<c>response.authenticatorData</c>).</param>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> wire bytes (<c>response.clientDataJSON</c>).</param>
    /// <param name="ceremonyInput">The surface-field ceremony input the WebAuthn L3 §7.2 rules evaluate.</param>
    /// <param name="claimIssuer">The configured claim issuer to run <paramref name="ceremonyInput"/> through.</param>
    /// <param name="correlationId">Identifier correlating this verification with other operations.</param>
    /// <param name="pool">The memory pool the verification's working buffers rent from.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The combined signature and ceremony-rule outcome.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="credentialPublicKey"/>, <paramref name="ceremonyInput"/>,
    /// <paramref name="claimIssuer"/> or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="correlationId"/> is <see langword="null"/> or empty.</exception>
    public static async ValueTask<Fido2AssertionOutcome> VerifyAsync(
        CoseKey credentialPublicKey,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> authenticatorData,
        ReadOnlyMemory<byte> clientDataJson,
        AssertionCeremonyInput ceremonyInput,
        ClaimIssuer<AssertionCeremonyInput> claimIssuer,
        string correlationId,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialPublicKey);
        ArgumentNullException.ThrowIfNull(ceremonyInput);
        ArgumentNullException.ThrowIfNull(claimIssuer);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);
        ArgumentNullException.ThrowIfNull(pool);

        bool signatureValid = await TryVerifySignatureAsync(
            credentialPublicKey, signature, authenticatorData, clientDataJson, pool, cancellationToken).ConfigureAwait(false);

        ClaimIssueResult claims = await claimIssuer.GenerateClaimsAsync(ceremonyInput, correlationId, cancellationToken).ConfigureAwait(false);

        bool isAcceptable = signatureValid && !HasFailure(claims);

        return new Fido2AssertionOutcome(signatureValid, claims, isAcceptable);
    }


    /// <summary>
    /// Convenience overload that builds its own <see cref="ClaimIssuer{TInput}"/> from
    /// <see cref="Fido2ValidationProfiles.AssertionRules"/> and the supplied
    /// <paramref name="timeProvider"/>, for callers with no need for a custom rule list.
    /// </summary>
    /// <param name="credentialPublicKey">The relying party's stored credential public key, established at registration time.</param>
    /// <param name="signature">The raw assertion signature bytes (<c>response.signature</c>).</param>
    /// <param name="authenticatorData">The raw <c>authData</c> wire bytes (<c>response.authenticatorData</c>).</param>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> wire bytes (<c>response.clientDataJSON</c>).</param>
    /// <param name="ceremonyInput">The surface-field ceremony input the WebAuthn L3 §7.2 rules evaluate.</param>
    /// <param name="correlationId">Identifier correlating this verification with other operations.</param>
    /// <param name="pool">The memory pool the verification's working buffers rent from.</param>
    /// <param name="timeProvider">
    /// Time provider for <see cref="ClaimIssueResult.CreationTimestampInUtc"/> stamping. When
    /// <see langword="null"/>, <see cref="TimeProvider.System"/> is used.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The combined signature and ceremony-rule outcome.</returns>
    public static ValueTask<Fido2AssertionOutcome> VerifyAsync(
        CoseKey credentialPublicKey,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> authenticatorData,
        ReadOnlyMemory<byte> clientDataJson,
        AssertionCeremonyInput ceremonyInput,
        string correlationId,
        MemoryPool<byte> pool,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        var claimIssuer = new ClaimIssuer<AssertionCeremonyInput>(
            DefaultIssuerId, Fido2ValidationProfiles.AssertionRules(), timeProvider);

        return VerifyAsync(
            credentialPublicKey, signature, authenticatorData, clientDataJson, ceremonyInput,
            claimIssuer, correlationId, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies the assertion signature (step 21) over <c>authenticatorData || clientDataHash</c>
    /// (step 20), fail-closed: any thrown crypto or format error yields <see langword="false"/>
    /// rather than escaping as an exception.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Signature verification is fail-closed: any crypto/format error, expected or not, must resolve to an invalid signature rather than crash the caller.")]
    private static async ValueTask<bool> TryVerifySignatureAsync(
        CoseKey credentialPublicKey,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> authenticatorData,
        ReadOnlyMemory<byte> clientDataJson,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson.Span, pool);
            using IMemoryOwner<byte> toBeSignedOwner = RentToBeSigned(authenticatorData, clientDataHash, pool, out int toBeSignedLength);
            ReadOnlyMemory<byte> toBeSigned = toBeSignedOwner.Memory[..toBeSignedLength];

            //ToPublicKeyMemory rents from the pool; CreatePublicKey takes ownership of the result,
            //released when credentialKey is disposed below.
            PublicKeyMemory credentialKeyMemory = credentialPublicKey.ToPublicKeyMemory(pool);
            using PublicKey credentialKey = CryptographicKeyFactory.CreatePublicKey(credentialKeyMemory, CredentialPublicKeyIdentifier, credentialKeyMemory.Tag);

            using Signature sig = Fido2EcdsaWireSignature.WrapWireSignatureForVerification(
                signature.Span, credentialKeyMemory.Tag.Get<CryptoAlgorithm>(), pool);

            return await credentialKey.VerifyAsync(toBeSigned, sig).ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch(Exception)
        {
            return false;
        }
    }


    /// <summary>
    /// Rents a buffer sized to <paramref name="authenticatorData"/> plus
    /// <paramref name="clientDataHash"/> and fills it with their concatenation — the bytes the
    /// assertion signature covers.
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
    /// Determines whether <paramref name="claims"/> contains at least one
    /// <see cref="ClaimOutcome.Failure"/> claim.
    /// </summary>
    private static bool HasFailure(ClaimIssueResult claims)
    {
        foreach(Claim claim in claims.Claims)
        {
            if(claim.Outcome == ClaimOutcome.Failure)
            {
                return true;
            }
        }

        return false;
    }
}
