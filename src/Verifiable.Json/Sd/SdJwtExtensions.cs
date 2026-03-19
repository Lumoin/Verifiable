using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Json.Sd;

/// <summary>
/// Extension members for issuing SD-JWT tokens from arbitrary types and
/// <see cref="VerifiableCredential"/> POCOs.
/// </summary>
/// <remarks>
/// <para>
/// These extensions serialize the claims object to JSON internally, eliminating the need
/// for callers to pre-serialize to <c>byte[]</c>. The existing <see cref="SdJwtIssuance"/>
/// byte-level API remains available for callers who manage their own serialization.
/// </para>
/// <para>
/// Serialization uses <see cref="JsonSerializerOptions"/> rather than bare
/// <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo{T}"/> so that
/// registered <see cref="System.Text.Json.Serialization.JsonConverter{T}"/> instances
/// (such as <c>CredentialSubjectConverter</c>) are invoked during serialization.
/// AOT safety is preserved because the options must carry a source-generated
/// <see cref="JsonSerializerOptions.TypeInfoResolver"/>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
public static class SdJwtExtensions
{
    private const string CredentialSubjectPrefix = "/credentialSubject";

    /// <summary>
    /// Generic extension for any claims type.
    /// </summary>
    extension<T>(T claims)
    {
        /// <summary>
        /// Issues an SD-JWT by serializing the claims object to JSON using the provided
        /// <see cref="JsonSerializerOptions"/>.
        /// </summary>
        /// <param name="disclosablePaths">Paths identifying claims that should be selectively disclosable.</param>
        /// <param name="saltFactory">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="options">
        /// Serializer options whose <see cref="JsonSerializerOptions.TypeInfoResolver"/> provides
        /// AOT-safe metadata and whose <see cref="JsonSerializerOptions.Converters"/> are applied
        /// during serialization.
        /// </param>
        /// <param name="hashAlgorithm">
        /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
        /// </param>
        /// <param name="mediaType">
        /// The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults
        /// to <c>"sd-jwt"</c>.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        public ValueTask<SdTokenResult> IssueSdJwtAsync(
            IReadOnlySet<CredentialPath> disclosablePaths,
            SaltFactoryDelegate saltFactory,
            PrivateKeyMemory privateKey,
            string keyId,
            MemoryPool<byte> memoryPool,
            JsonSerializerOptions options,
            string? hashAlgorithm = null,
            string? mediaType = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(claims);

            byte[] jsonBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(claims, options);

            return SdJwtIssuance.IssueAsync(
                jsonBytes, disclosablePaths, saltFactory,
                privateKey, keyId, memoryPool,
                hashAlgorithm, mediaType, cancellationToken);
        }
    }


    /// <summary>
    /// Extension for <see cref="VerifiableCredential"/> that validates all disclosable
    /// paths are under <c>/credentialSubject</c> before issuing.
    /// </summary>
    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Issues an SD-JWT from a <see cref="VerifiableCredential"/>, serializing via
        /// <see cref="JsonSerializerOptions"/> so that registered converters are applied.
        /// Validates that all disclosable paths are under <c>/credentialSubject</c>.
        /// </summary>
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable.
        /// All paths must begin with <c>/credentialSubject</c>.
        /// </param>
        /// <param name="saltFactory">Factory for generating cryptographic salt for each disclosure.</param>
        /// <param name="privateKey">The issuer's signing key.</param>
        /// <param name="keyId">The key identifier for the JWS <c>kid</c> header.</param>
        /// <param name="memoryPool">Memory pool for cryptographic allocations.</param>
        /// <param name="options">
        /// Serializer options whose <see cref="JsonSerializerOptions.TypeInfoResolver"/> provides
        /// AOT-safe metadata and whose <see cref="JsonSerializerOptions.Converters"/> are applied
        /// during serialization.
        /// </param>
        /// <param name="hashAlgorithm">
        /// The hash algorithm identifier in IANA format. Defaults to <c>"sha-256"</c>.
        /// </param>
        /// <param name="mediaType">
        /// The media type for the JWS <c>typ</c> header. When <see langword="null"/>, defaults
        /// to <c>"sd-jwt"</c>.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the compact JWS bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when any disclosable path does not start with <c>/credentialSubject</c>.
        /// </exception>
        public ValueTask<SdTokenResult> IssueSdJwtAsync(
            IReadOnlySet<CredentialPath> disclosablePaths,
            SaltFactoryDelegate saltFactory,
            PrivateKeyMemory privateKey,
            string keyId,
            MemoryPool<byte> memoryPool,
            JsonSerializerOptions options,
            string? hashAlgorithm = null,
            string? mediaType = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentNullException.ThrowIfNull(disclosablePaths);

            ValidateCredentialPaths(disclosablePaths);

            byte[] jsonBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(credential, options);

            return SdJwtIssuance.IssueAsync(
                jsonBytes, disclosablePaths, saltFactory,
                privateKey, keyId, memoryPool,
                hashAlgorithm, mediaType, cancellationToken);
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