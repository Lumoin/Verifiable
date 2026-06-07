using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// SD-CWT issuance convenience method for <c>Verifiable.Cbor</c>.
/// </summary>
/// <remarks>
/// <para>
/// Wraps <see cref="SdIssuance.IssueAsync"/> with the internal <see cref="SdCwtPipeline"/>
/// implementation so callers never handle delegates directly:
/// </para>
/// <code>
/// var result = await SdCwtIssuance.IssueAsync(
///     cborBytes, disclosablePaths,
///     SaltGenerator.Create,
///     privateKey, "did:example:issuer#key-1", pool);
/// </code>
/// <para>
/// For custom serialization backends, use <see cref="SdIssuance.IssueAsync"/> in
/// <c>Verifiable.Core</c> directly with your own <see cref="RedactPayloadDelegate"/>
/// and <see cref="SignPayloadDelegate"/> implementations.
/// </para>
/// </remarks>
public static class SdCwtIssuance
{
    /// <summary>
    /// Issues an SD-CWT by redacting claims from a CBOR payload and signing the result.
    /// </summary>
    /// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
    /// <param name="disclosablePaths">
    /// Paths identifying claims that should be selectively disclosable.
    /// For CWT integer keys, use the integer string representation (e.g., <c>/501</c>).
    /// </param>
    /// <param name="generateSalt">Factory for generating 128-bit cryptographic salt.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
    /// </param>
    /// <param name="mediaType">
    /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
    /// to <see cref="WellKnownMediaTypes.Application.SdCwt"/> (<c>"application/sd-cwt"</c>).
    /// </param>
    /// <param name="decoyOptions">
    /// Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location.
    /// Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
    public static ValueTask<SdTokenResult> IssueAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return IssueAsync(
            payload, disclosablePaths, generateSalt,
            privateKey, keyId, memoryPool, signingDelegate,
            hashAlgorithm, mediaType, decoyOptions, cancellationToken);
    }


    /// <summary>
    /// Issues an SD-CWT using an explicit <see cref="SigningDelegate"/>. Forwards to
    /// <c>IssueVerboseAsync</c> and discards the redacted payload.
    /// </summary>
    /// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
    /// <param name="disclosablePaths">
    /// Paths identifying claims that should be selectively disclosable.
    /// </param>
    /// <param name="generateSalt">Factory for generating 128-bit cryptographic salt.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
    /// </param>
    /// <param name="mediaType">
    /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
    /// to <see cref="WellKnownMediaTypes.Application.SdCwt"/> (<c>"application/sd-cwt"</c>).
    /// </param>
    /// <param name="decoyOptions">
    /// Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location.
    /// Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
    public static async ValueTask<SdTokenResult> IssueAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        SigningDelegate signingDelegate,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        (SdTokenResult result, _) = await IssueVerboseAsync(
            payload, disclosablePaths, generateSalt,
            privateKey, keyId, memoryPool, signingDelegate,
            hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

        return result;
    }


    /// <summary>
    /// Issues an SD-CWT using an explicit <see cref="SigningDelegate"/> and additionally
    /// returns the redacted CBOR payload (the signed COSE_Sign1 payload) — the parameter-taking
    /// canonical body. The registry-resolving overload below derives the signing function from
    /// the key's tag and forwards here.
    /// </summary>
    /// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
    /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
    /// <param name="generateSalt">Factory for generating 128-bit cryptographic salt.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="signingDelegate">The signing function to use.</param>
    /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
    /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <see cref="WellKnownMediaTypes.Application.SdCwt"/>.</param>
    /// <param name="decoyOptions">
    /// Decoy-digest policy (RFC 9901 §4.2.5; the SD-CWT draft inherits the concept), invoked once per
    /// <c>redacted_claim_keys</c> location. When <see langword="null"/>, defaults to
    /// <see cref="DecoyDigestOptions.None"/> — no decoys, so the issued token is the minimal, deterministic
    /// form. Opt in (e.g. <see cref="DecoyDigestPolicy.Random(int, int)"/>) to obscure the
    /// selectively-disclosable claim count from an adversarial verifier.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuance result and the redacted CBOR payload that was signed.</returns>
    public static ValueTask<(SdTokenResult Result, ReadOnlyMemory<byte> RedactedPayload)> IssueVerboseAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        SigningDelegate signingDelegate,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingDelegate);

        //The pipeline functions are passed as method groups; the signing delegate and decoy options
        //thread through SdIssuance explicitly, so nothing here is captured by a closure.
        return SdIssuance.IssueVerboseAsync(
            payload, disclosablePaths,
            SdCwtPipeline.Redact,
            SdCwtPipeline.Sign,
            generateSalt, privateKey, keyId, memoryPool,
            signingDelegate, hashAlgorithm, mediaType, decoyOptions, cancellationToken);
    }


    /// <summary>
    /// Issues an SD-CWT and additionally returns the redacted CBOR payload, resolving the
    /// signing function from <paramref name="privateKey"/>'s tag and forwarding to the
    /// <see cref="SigningDelegate"/>-taking overload.
    /// </summary>
    /// <param name="payload">The CBOR-encoded CWT claims set bytes.</param>
    /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
    /// <param name="generateSalt">Factory for generating 128-bit cryptographic salt.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
    /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
    /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
    /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <see cref="WellKnownMediaTypes.Application.SdCwt"/>.</param>
    /// <param name="decoyOptions">
    /// Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location.
    /// Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issuance result and the redacted CBOR payload that was signed.</returns>
    public static ValueTask<(SdTokenResult Result, ReadOnlyMemory<byte> RedactedPayload)> IssueVerboseAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        GenerateDisclosureSaltDelegate generateSalt,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        string? hashAlgorithm = null,
        string? mediaType = null,
        DecoyDigestOptions decoyOptions = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return IssueVerboseAsync(
            payload, disclosablePaths, generateSalt,
            privateKey, keyId, memoryPool, signingDelegate,
            hashAlgorithm, mediaType, decoyOptions, cancellationToken);
    }
}
