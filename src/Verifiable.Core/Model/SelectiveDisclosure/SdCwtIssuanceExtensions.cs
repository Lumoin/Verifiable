using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extension members for issuing SD-CWT tokens from arbitrary types and
/// <see cref="VerifiableCredential"/> POCOs.
/// </summary>
/// <remarks>
/// <para>
/// These extensions serialize the claims object to CBOR using a caller-provided serializer,
/// then hand the bytes to the CBOR issue-pipeline seam, eliminating the need for callers to
/// pre-serialize to <c>byte[]</c>. The issuance is crypto orchestration — claim redaction
/// plus COSE_Sign1 signing — not serialization, so it lives beside the credential model and
/// the verification code (<c>SdCwtVerificationExtensions</c>) rather than in
/// <c>Verifiable.Cbor</c>. The CBOR the orchestration touches — redacting the CWT claims set
/// and serializing the signed COSE_Sign1 — crosses a delegate seam the application wires to
/// the <c>Verifiable.Cbor</c> implementation: <see cref="IssueSdCwtVerboseDelegate"/> (wired
/// to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>).
/// </para>
/// <para>
/// Unlike the JSON side where <see cref="System.Text.Json.JsonSerializer"/> provides
/// universal type-to-bytes conversion, CBOR has no universal serializer for arbitrary
/// types. The caller provides a named CBOR-bytes delegate that performs the encoding:
/// <see cref="ToCborBytesDelegate{T}"/> for the generic claims overload and
/// <see cref="CredentialToCborBytesDelegate"/> for the <see cref="VerifiableCredential"/> overload.
/// </para>
/// <para>
/// Mirrors the registry/delegate split that <c>SdCwtVerificationExtensions</c> exposes: the
/// explicit-<see cref="SigningDelegate"/> overload carries the entire issuance body; the
/// registry overload resolves the signing function via
/// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> and then forwards.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension hosts are clearly distinct.")]
public static class SdCwtIssuanceExtensions
{
    private const string CredentialSubjectPrefix = "/credentialSubject";


    /// <summary>
    /// Generic extension for any claims type. Requires a serializer delegate that
    /// converts the claims object to CBOR bytes.
    /// </summary>
    extension<T>(T claims)
    {
        /// <summary>
        /// Issues an SD-CWT by serializing the claims object to CBOR using the provided
        /// serializer, redacting the specified paths, and signing the result.
        /// </summary>
        /// <param name="serializer">
        /// Delegate that serializes the claims object to CBOR bytes. The output must be a
        /// CBOR map with integer keys suitable for CWT processing.
        /// </param>
        /// <param name="issuePipeline">
        /// The CBOR issue-pipeline seam that redacts and signs the serialized claims.
        /// Wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.
        /// </param>
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable. For CWT integer
        /// keys, use the string representation (e.g., <c>/501</c>).
        /// </param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">
        /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
        /// </param>
        /// <param name="mediaType">
        /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
        /// to <c>"application/sd-cwt"</c>.
        /// </param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        public ValueTask<SdTokenResult> IssueSdCwtAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdCwtAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-CWT using an explicit <see cref="SigningDelegate"/> — the
        /// parameter-taking canonical body. The registry-resolving overload above
        /// derives the signing function from the key's tag and forwards here.
        /// </summary>
        /// <param name="serializer">
        /// Delegate that serializes the claims object to CBOR bytes. The output must be a
        /// CBOR map with integer keys suitable for CWT processing.
        /// </param>
        /// <param name="issuePipeline">
        /// The CBOR issue-pipeline seam that redacts and signs the serialized claims.
        /// Wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.
        /// </param>
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable. For CWT integer
        /// keys, use the string representation (e.g., <c>/501</c>).
        /// </param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">
        /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
        /// </param>
        /// <param name="mediaType">
        /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
        /// to <c>"application/sd-cwt"</c>.
        /// </param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        public async ValueTask<SdTokenResult> IssueSdCwtAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            ArgumentNullException.ThrowIfNull(claims);
            ArgumentNullException.ThrowIfNull(serializer);
            ArgumentNullException.ThrowIfNull(issuePipeline);

            //The serializer yields a ReadOnlySpan<byte> per the CBOR-bytes delegate
            //contract; the async issuance pipeline takes ReadOnlyMemory<byte>, so the
            //span is materialized here. The payload is plain serialized claims, not
            //SensitiveMemory, so the copy carries no disposal contract.
            byte[] cborBytes = serializer(claims).ToArray();

            (SdTokenResult result, _) = await issuePipeline(
                cborBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return result;
        }


        /// <summary>
        /// Issues an SD-CWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// (envelope <see cref="ReadOnlyMemory{T}"/> of <see cref="byte"/>) directly — owning
        /// its disclosures — rather than the issuance-pipeline <see cref="SdTokenResult"/>.
        /// Resolves the signing function from the key's tag and forwards to the
        /// <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures.</returns>
        public ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdCwtTokenAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-CWT using an explicit <see cref="SigningDelegate"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> directly. Forwards to
        /// <c>IssueSdCwtTokenVerboseAsync</c> and discards the redacted payload.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures.</returns>
        public async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            (SdToken<ReadOnlyMemory<byte>> token, _) = await claims.IssueSdCwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return token;
        }


        /// <summary>
        /// Issues an SD-CWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// together with the redacted CBOR payload — the parameter-taking canonical body. The
        /// registry-resolving overload below derives the signing function and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures, and the redacted CBOR payload that was signed.</returns>
        public async ValueTask<(SdToken<ReadOnlyMemory<byte>> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdCwtTokenVerboseAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            ArgumentNullException.ThrowIfNull(claims);
            ArgumentNullException.ThrowIfNull(serializer);
            ArgumentNullException.ThrowIfNull(issuePipeline);

            //Materialize the serializer's span (CBOR-bytes delegate contract) for the async
            //issuance pipeline; plain serialized claims, not SensitiveMemory (rule 8 n/a).
            byte[] cborBytes = serializer(claims).ToArray();

            (SdTokenResult result, ReadOnlyMemory<byte> redactedPayload) = await issuePipeline(
                cborBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return (new SdToken<ReadOnlyMemory<byte>>(result.SignedToken, result.Disclosures), redactedPayload);
        }


        /// <summary>
        /// Issues an SD-CWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// together with the redacted CBOR payload, resolving the signing function from the
        /// key's tag and forwarding to the <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> and the redacted CBOR payload that was signed.</returns>
        public ValueTask<(SdToken<ReadOnlyMemory<byte>> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdCwtTokenVerboseAsync(
            ToCborBytesDelegate<T> serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdCwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }
    }


    /// <summary>
    /// Extension for <see cref="VerifiableCredential"/> that validates all disclosable
    /// paths are under <c>/credentialSubject</c> before issuing.
    /// </summary>
    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/>, validating that all
        /// disclosable paths are under <c>/credentialSubject</c>.
        /// </summary>
        /// <param name="serializer">
        /// Delegate that serializes the credential to CBOR bytes. The output must be a
        /// CBOR map with integer keys suitable for CWT processing.
        /// </param>
        /// <param name="issuePipeline">
        /// The CBOR issue-pipeline seam that redacts and signs the serialized credential.
        /// Wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.
        /// </param>
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable.
        /// All paths must begin with <c>/credentialSubject</c>.
        /// </param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">
        /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
        /// </param>
        /// <param name="mediaType">
        /// The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults
        /// to <c>"application/sd-cwt"</c>.
        /// </param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when any disclosable path does not start with <c>/credentialSubject</c>.
        /// </exception>
        public ValueTask<SdTokenResult> IssueSdCwtAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdCwtAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/> using an explicit
        /// <see cref="SigningDelegate"/> — the parameter-taking canonical body. Validates
        /// that all disclosable paths are under <c>/credentialSubject</c>. The
        /// registry-resolving overload above derives the signing function from the key's
        /// tag and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<SdTokenResult> IssueSdCwtAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentNullException.ThrowIfNull(serializer);
            ArgumentNullException.ThrowIfNull(issuePipeline);
            ArgumentNullException.ThrowIfNull(disclosablePaths);

            ValidateCredentialPaths(disclosablePaths);

            //See the generic overload: the span returned by the delegate is copied to a
            //ReadOnlyMemory<byte>-compatible array for the async issuance pipeline.
            byte[] cborBytes = serializer(credential).ToArray();

            (SdTokenResult result, _) = await issuePipeline(
                cborBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return result;
        }


        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> directly. Resolves the signing
        /// function from the key's tag and forwards to the <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdCwtTokenAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/> using an explicit
        /// <see cref="SigningDelegate"/> and returns the consumer-facing
        /// <see cref="SdToken{TEnvelope}"/> directly. Forwards to
        /// <c>IssueSdCwtTokenVerboseAsync</c> and discards the redacted payload.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            (SdToken<ReadOnlyMemory<byte>> token, _) = await credential.IssueSdCwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return token;
        }


        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> together with the redacted CBOR
        /// payload — the parameter-taking canonical body. Validates that all disclosable paths
        /// are under <c>/credentialSubject</c>; the registry-resolving overload below derives the
        /// signing function and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the issued token bytes and disclosures, and the redacted CBOR payload that was signed.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<(SdToken<ReadOnlyMemory<byte>> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdCwtTokenVerboseAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentNullException.ThrowIfNull(serializer);
            ArgumentNullException.ThrowIfNull(issuePipeline);
            ArgumentNullException.ThrowIfNull(disclosablePaths);

            ValidateCredentialPaths(disclosablePaths);

            //See the generic overload: the span returned by the delegate is copied to a
            //ReadOnlyMemory<byte>-compatible array for the async issuance pipeline.
            byte[] cborBytes = serializer(credential).ToArray();

            (SdTokenResult result, ReadOnlyMemory<byte> redactedPayload) = await issuePipeline(
                cborBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return (new SdToken<ReadOnlyMemory<byte>>(result.SignedToken, result.Disclosures), redactedPayload);
        }


        /// <summary>
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> together with the redacted CBOR
        /// payload, resolving the signing function from the key's tag and forwarding to the
        /// <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to CBOR bytes.</param>
        /// <param name="issuePipeline">The CBOR issue-pipeline seam wired to <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the COSE <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the COSE <c>typ</c> header. When <see langword="null"/>, defaults to <c>"application/sd-cwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>redacted_claim_keys</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> and the redacted CBOR payload that was signed.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public ValueTask<(SdToken<ReadOnlyMemory<byte>> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdCwtTokenVerboseAsync(
            CredentialToCborBytesDelegate serializer,
            IssueSdCwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdCwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }
    }


    /// <summary>
    /// Validates that all disclosable paths are under <c>/credentialSubject</c>.
    /// </summary>
    internal static void ValidateCredentialPaths(IReadOnlySet<CredentialPath> disclosablePaths)
    {
        foreach(CredentialPath path in disclosablePaths)
        {
            string pathString = path.ToString();
            if(!pathString.StartsWith(CredentialSubjectPrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"All disclosable paths for a VerifiableCredential must be under '{CredentialSubjectPrefix}'. " +
                    $"Path '{pathString}' is outside the credential subject.",
                    nameof(disclosablePaths));
            }
        }
    }
}
