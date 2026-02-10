using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Credentials;

#pragma warning disable RS0030 // Do not use banned APIs
/// <summary>
/// Extension methods for adding signing capabilities to <see cref="CredentialBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// These extensions enable the builder to capture signing configuration so that
/// <see cref="CredentialBuilder.BuildAsync(Issuer, CredentialSubjectInput, DateTime, IEnumerable{string}?, DateTime?, string?, CancellationToken)"/> 
/// returns signed credentials directly.
/// </para>
/// <para>
/// Two securing mechanisms are supported:
/// </para>
/// <list type="bullet">
/// <item><description>Data Integrity proofs (embedded in the credential JSON).</description></item>
/// <item><description>JOSE/JWS envelopes (credential becomes JWT payload).</description></item>
/// </list>
/// <para>
/// <strong>Time Handling</strong>
/// </para>
/// <para>
/// All timestamps (including <c>proofCreated</c>) are provided explicitly by the caller.
/// The library does not use <see cref="DateTime.UtcNow"/> or <see cref="TimeProvider"/> internally.
/// This ensures full testability and caller control over time sources.
/// </para>
/// <para>
/// This follows the builder pattern principle where "non-moving parts" (signing configuration)
/// are captured in the builder, while "varying parts" (issuer, subject, etc.) are provided
/// at build time.
/// </para>
/// </remarks>
#pragma warning restore RS0030 // Do not use banned APIs
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class CredentialBuilderExtensions
{
    extension(CredentialBuilder builder)
    {
        /// <summary>
        /// Configures the builder to sign credentials using Data Integrity proofs during build.
        /// </summary>
        /// <param name="privateKey">The private key material for signing.</param>
        /// <param name="verificationMethodId">
        /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
        /// </param>
        /// <param name="cryptosuite">
        /// The cryptosuite to use for signing (e.g., <c>EddsaJcs2022CryptosuiteInfo.Instance</c>).
        /// </param>
        /// <param name="proofCreated">
        /// The timestamp for the proof's <c>created</c> field. Must be provided explicitly by the caller.
        /// </param>
        /// <param name="canonicalize">
        /// The canonicalization function for the cryptosuite's algorithm.
        /// </param>
        /// <param name="contextResolver">
        /// Optional delegate for resolving JSON-LD contexts. Required for RDFC-based cryptosuites,
        /// can be null for JCS-based cryptosuites.
        /// </param>
        /// <param name="encodeProofValue">
        /// Delegate for encoding the signature bytes to a proof value string.
        /// </param>
        /// <param name="serialize">Delegate for serializing credentials.</param>
        /// <param name="deserialize">Delegate for deserializing credentials.</param>
        /// <param name="serializeProofOptions">Delegate for serializing proof options.</param>
        /// <param name="encoder">The encoding delegate (e.g., Base58 encoder) passed to the proof value encoder.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <remarks>
        /// <para>
        /// When signing is configured, the builder's transformations will include a final
        /// async transformation that signs the credential. The signing occurs after all
        /// other transformations have been applied.
        /// </para>
        /// <para>
        /// The <paramref name="proofCreated"/> timestamp is captured when this method is called
        /// and will be used for all credentials signed with this builder configuration. If you
        /// need different timestamps per credential, configure signing separately for each.
        /// </para>
        /// <para>
        /// The signing uses the <see cref="CredentialDataIntegrityExtensions.SignAsync"/> method
        /// internally. See that method for details on the proof creation algorithm.
        /// </para>
        /// </remarks>
        public CredentialBuilder WithDataIntegritySigning(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CryptosuiteInfo cryptosuite,
            DateTime proofCreated,
            CanonicalizationDelegate canonicalize,
            ContextResolverDelegate? contextResolver,
            ProofValueEncoderDelegate encodeProofValue,
            CredentialSerializeDelegate serialize,
            CredentialDeserializeDelegate deserialize,
            ProofOptionsSerializeDelegate serializeProofOptions,
            EncodeDelegate encoder,
            MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentNullException.ThrowIfNull(cryptosuite, nameof(cryptosuite));
            ArgumentNullException.ThrowIfNull(canonicalize, nameof(canonicalize));
            ArgumentNullException.ThrowIfNull(encodeProofValue, nameof(encodeProofValue));
            ArgumentNullException.ThrowIfNull(serialize, nameof(serialize));
            ArgumentNullException.ThrowIfNull(deserialize, nameof(deserialize));
            ArgumentNullException.ThrowIfNull(serializeProofOptions, nameof(serializeProofOptions));
            ArgumentNullException.ThrowIfNull(encoder, nameof(encoder));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            return builder.With(async (credential, _, _, cancellationToken) =>
            {
                return await credential.SignAsync(
                    privateKey,
                    verificationMethodId,
                    cryptosuite,
                    proofCreated,
                    canonicalize,
                    contextResolver,
                    encodeProofValue,
                    serialize,
                    deserialize,
                    serializeProofOptions,
                    encoder,
                    memoryPool,
                    cancellationToken).ConfigureAwait(false);
            });
        }


        /// <summary>
        /// Configures the builder to produce JWS-secured credentials.
        /// </summary>
        /// <param name="privateKey">The private key for signing. The key's <see cref="Tag"/> determines the algorithm.</param>
        /// <param name="verificationMethodId">
        /// The DID URL identifying the verification method (e.g., <c>"did:web:example.com#key-1"</c>).
        /// </param>
        /// <param name="credentialSerializer">Delegate for serializing credentials to JSON bytes.</param>
        /// <param name="headerSerializer">Delegate for serializing JWT headers to JSON bytes.</param>
        /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="mediaType">Optional media type for the <c>typ</c> header.</param>
        /// <param name="contentType">Optional content type for the <c>cty</c> header.</param>
        /// <returns>A function that builds and signs credentials as JWS.</returns>
        /// <remarks>
        /// <para>
        /// This method returns a function rather than modifying the builder because JOSE signing
        /// produces a <see cref="JwsMessage"/> rather than a <see cref="VerifiableCredential"/>.
        /// </para>
        /// <para>
        /// Usage:
        /// <code>
        /// var buildAndSign = builder.WithJoseSigning(
        ///     privateKey,
        ///     verificationMethodId,
        ///     credentialSerializer,
        ///     headerSerializer,
        ///     base64UrlEncoder,
        ///     memoryPool);
        /// 
        /// JwsMessage jwsMessage = await buildAndSign(issuer, subject, validFrom, cancellationToken);
        /// string jws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);
        /// </code>
        /// </para>
        /// </remarks>
        public Func<Issuer, CredentialSubjectInput, DateTime, CancellationToken, ValueTask<JwsMessage>> WithJoseSigning(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CredentialToJsonBytesDelegate credentialSerializer,
            JwtHeaderSerializer headerSerializer,
            EncodeDelegate base64UrlEncoder,
            MemoryPool<byte> memoryPool,
            string? mediaType = null,
            string? contentType = null)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentNullException.ThrowIfNull(credentialSerializer, nameof(credentialSerializer));
            ArgumentNullException.ThrowIfNull(headerSerializer, nameof(headerSerializer));
            ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            return async (issuer, subject, validFrom, cancellationToken) =>
            {
                VerifiableCredential credential = await builder.BuildAsync(issuer, subject, validFrom, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);

                return await credential.SignJwsAsync(
                    privateKey,
                    verificationMethodId,
                    credentialSerializer,
                    headerSerializer,
                    base64UrlEncoder,
                    memoryPool,
                    mediaType: mediaType,
                    contentType: contentType,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            };
        }


        /// <summary>
        /// Configures the builder to produce JWS-secured credentials with full build options.
        /// </summary>
        /// <param name="privateKey">The private key for signing.</param>
        /// <param name="verificationMethodId">The DID URL for the <c>kid</c> header.</param>
        /// <param name="credentialSerializer">Delegate for serializing credentials to JSON bytes.</param>
        /// <param name="headerSerializer">Delegate for serializing JWT headers to JSON bytes.</param>
        /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
        /// <param name="memoryPool">Memory pool for signature allocation.</param>
        /// <param name="mediaType">Optional media type for the <c>typ</c> header.</param>
        /// <param name="contentType">Optional content type for the <c>cty</c> header.</param>
        /// <returns>A function that builds and signs credentials as JWS with full options.</returns>
        public Func<Issuer, CredentialSubjectInput, DateTime, IEnumerable<string>?, DateTime?, CancellationToken, ValueTask<JwsMessage>> WithJoseSigningFull(
            PrivateKeyMemory privateKey,
            string verificationMethodId,
            CredentialToJsonBytesDelegate credentialSerializer,
            JwtHeaderSerializer headerSerializer,
            EncodeDelegate base64UrlEncoder,
            MemoryPool<byte> memoryPool,
            string? mediaType = null,
            string? contentType = null)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentNullException.ThrowIfNull(credentialSerializer, nameof(credentialSerializer));
            ArgumentNullException.ThrowIfNull(headerSerializer, nameof(headerSerializer));
            ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            return async (issuer, subject, validFrom, additionalTypes, validUntil, cancellationToken) =>
            {
                VerifiableCredential credential = await builder.BuildAsync(
                    issuer,
                    subject,
                    validFrom,
                    additionalTypes,
                    validUntil,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                return await credential.SignJwsAsync(
                    privateKey,
                    verificationMethodId,
                    credentialSerializer,
                    headerSerializer,
                    base64UrlEncoder,
                    memoryPool,
                    mediaType: mediaType,
                    contentType: contentType,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            };
        }
    }
}