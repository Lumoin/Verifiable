using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extension members for issuing SD-JWT tokens from arbitrary types and
/// <see cref="VerifiableCredential"/> POCOs.
/// </summary>
/// <remarks>
/// <para>
/// These extensions serialize the claims object to UTF-8 JSON using a caller-provided serializer,
/// then hand the bytes to the JSON issue-pipeline seam, eliminating the need for callers to
/// pre-serialize to <c>byte[]</c>. The issuance is crypto orchestration — claim redaction plus JWS
/// signing — not serialization, so it lives beside the credential model and the verification code
/// (<see cref="SdJwtVerificationExtensions"/>) rather than in <c>Verifiable.Json</c>. The JSON the
/// orchestration touches — redacting the claims set and serializing the signed compact JWS —
/// crosses a delegate seam the application wires to the <c>Verifiable.Json</c> implementation:
/// <see cref="IssueSdJwtVerboseDelegate"/> (wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>).
/// </para>
/// <para>
/// Although <see cref="System.Text.Json.JsonSerializer"/> provides universal type-to-bytes
/// conversion, <c>Verifiable.Core</c> cannot reference a serialization library, so the caller
/// provides a named JSON-bytes delegate that performs the encoding:
/// <see cref="ToJsonBytesDelegate{T}"/> for the generic claims overload and
/// <see cref="CredentialToJsonBytesDelegate"/> for the <see cref="VerifiableCredential"/> overload.
/// This mirrors the CBOR side (<see cref="SdCwtIssuanceExtensions"/>).
/// </para>
/// <para>
/// Mirrors the registry/delegate split that <see cref="SdJwtVerificationExtensions"/> exposes: the
/// explicit-<see cref="SigningDelegate"/> overload carries the entire issuance body; the registry
/// overload resolves the signing function via
/// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> and then forwards.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension hosts are clearly distinct.")]
public static class SdJwtIssuanceExtensions
{
    private const string CredentialSubjectPrefix = "/credentialSubject";


    /// <summary>
    /// Generic extension for any claims type. Requires a serializer delegate that
    /// converts the claims object to UTF-8 JSON bytes.
    /// </summary>
    extension<T>(T claims)
    {
        /// <summary>
        /// Issues an SD-JWT by serializing the claims object to JSON using the provided
        /// serializer, redacting the specified paths, and signing the result.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        public ValueTask<SdTokenResult> IssueSdJwtAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdJwtAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-JWT using an explicit <see cref="SigningDelegate"/> — the
        /// parameter-taking canonical body. The registry-resolving overload above
        /// derives the signing function from the key's tag and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        public async ValueTask<SdTokenResult> IssueSdJwtAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            //Materialize the serializer's span (JSON-bytes delegate contract) for the async
            //issuance pipeline; plain serialized claims, not SensitiveMemory (rule 8 n/a).
            byte[] jsonBytes = serializer(claims).ToArray();

            (SdTokenResult result, _) = await issuePipeline(
                jsonBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return result;
        }


        /// <summary>
        /// Issues an SD-JWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// (envelope <see cref="string"/>, the compact JWS) directly — owning its disclosures —
        /// rather than the issuance-pipeline <see cref="SdTokenResult"/>. Resolves the signing
        /// function from the key's tag and forwards to the <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures.</returns>
        public ValueTask<SdToken<string>> IssueSdJwtTokenAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdJwtTokenAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-JWT using an explicit <see cref="SigningDelegate"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> directly. Forwards to
        /// <c>IssueSdJwtTokenVerboseAsync</c> and discards the redacted payload.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures.</returns>
        public async ValueTask<SdToken<string>> IssueSdJwtTokenAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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
            (SdToken<string> token, _) = await claims.IssueSdJwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return token;
        }


        /// <summary>
        /// Issues an SD-JWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// together with the redacted JSON payload — the parameter-taking canonical body. The
        /// registry-resolving overload below derives the signing function and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures, and the redacted JSON payload that was signed.</returns>
        public async ValueTask<(SdToken<string> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdJwtTokenVerboseAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            //Materialize the serializer's span (JSON-bytes delegate contract) for the async
            //issuance pipeline; plain serialized claims, not SensitiveMemory (rule 8 n/a).
            byte[] jsonBytes = serializer(claims).ToArray();

            (SdTokenResult result, ReadOnlyMemory<byte> redactedPayload) = await issuePipeline(
                jsonBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
            return (new SdToken<string>(compactJws, result.Disclosures), redactedPayload);
        }


        /// <summary>
        /// Issues an SD-JWT and returns the consumer-facing <see cref="SdToken{TEnvelope}"/>
        /// together with the redacted JSON payload, resolving the signing function from the
        /// key's tag and forwarding to the <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the claims object to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> and the redacted JSON payload that was signed.</returns>
        public ValueTask<(SdToken<string> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdJwtTokenVerboseAsync(
            ToJsonBytesDelegate<T> serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return claims.IssueSdJwtTokenVerboseAsync(
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
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/>, validating that all
        /// disclosable paths are under <c>/credentialSubject</c>.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public ValueTask<SdTokenResult> IssueSdJwtAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdJwtAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/> using an explicit
        /// <see cref="SigningDelegate"/> — the parameter-taking canonical body. Validates
        /// that all disclosable paths are under <c>/credentialSubject</c>. The
        /// registry-resolving overload above derives the signing function from the key's
        /// tag and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<SdTokenResult> IssueSdJwtAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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
            byte[] jsonBytes = serializer(credential).ToArray();

            (SdTokenResult result, _) = await issuePipeline(
                jsonBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return result;
        }


        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> directly. Resolves the signing
        /// function from the key's tag and forwards to the <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public ValueTask<SdToken<string>> IssueSdJwtTokenAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdJwtTokenAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken);
        }


        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/> using an explicit
        /// <see cref="SigningDelegate"/> and returns the consumer-facing
        /// <see cref="SdToken{TEnvelope}"/> directly. Forwards to
        /// <c>IssueSdJwtTokenVerboseAsync</c> and discards the redacted payload.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<SdToken<string>> IssueSdJwtTokenAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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
            (SdToken<string> token, _) = await credential.IssueSdJwtTokenVerboseAsync(
                serializer, issuePipeline, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            return token;
        }


        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> together with the redacted JSON
        /// payload — the parameter-taking canonical body. Validates that all disclosable paths
        /// are under <c>/credentialSubject</c>; the registry-resolving overload below derives the
        /// signing function and forwards here.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="signingDelegate">The signing function to use.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> owning the compact JWS and disclosures, and the redacted JSON payload that was signed.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public async ValueTask<(SdToken<string> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdJwtTokenVerboseAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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
            byte[] jsonBytes = serializer(credential).ToArray();

            (SdTokenResult result, ReadOnlyMemory<byte> redactedPayload) = await issuePipeline(
                jsonBytes, disclosablePaths, generateSalt,
                privateKey, keyId, memoryPool, signingDelegate,
                hashAlgorithm, mediaType, decoyOptions, cancellationToken).ConfigureAwait(false);

            string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
            return (new SdToken<string>(compactJws, result.Disclosures), redactedPayload);
        }


        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/> and returns the
        /// consumer-facing <see cref="SdToken{TEnvelope}"/> together with the redacted JSON
        /// payload, resolving the signing function from the key's tag and forwarding to the
        /// <see cref="SigningDelegate"/>-taking sibling.
        /// </summary>
        /// <param name="serializer">Delegate that serializes the credential to UTF-8 JSON bytes.</param>
        /// <param name="issuePipeline">The JSON issue-pipeline seam wired to <c>Verifiable.Json.SdJwtIssuance.IssueVerboseAsync</c>.</param>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable. All paths must begin with <c>/credentialSubject</c>.</param>
        /// <param name="generateSalt">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="hashAlgorithm">The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.</param>
        /// <param name="mediaType">The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults to <c>"sd-jwt"</c>.</param>
        /// <param name="decoyOptions">Decoy-digest policy (RFC 9901 §4.2.5), invoked once per <c>_sd</c> location. Defaults to <see cref="DecoyDigestOptions.None"/> (no decoys). See <see cref="DecoyDigestPolicy"/>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdToken{TEnvelope}"/> and the redacted JSON payload that was signed.</returns>
        /// <exception cref="ArgumentException">Thrown when any disclosable path does not start with <c>/credentialSubject</c>.</exception>
        public ValueTask<(SdToken<string> Token, ReadOnlyMemory<byte> RedactedPayload)> IssueSdJwtTokenVerboseAsync(
            CredentialToJsonBytesDelegate serializer,
            IssueSdJwtVerboseDelegate issuePipeline,
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

            return credential.IssueSdJwtTokenVerboseAsync(
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
