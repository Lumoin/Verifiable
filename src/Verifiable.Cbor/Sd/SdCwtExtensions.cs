using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// Extension members for issuing SD-CWT tokens from arbitrary types and
/// <see cref="VerifiableCredential"/> POCOs.
/// </summary>
/// <remarks>
/// <para>
/// These extensions serialize the claims object to CBOR internally using a caller-provided
/// serializer, eliminating the need for callers to pre-serialize to <c>byte[]</c>.
/// The existing <see cref="SdCwtIssuance"/> byte-level API remains available for callers
/// who manage their own serialization.
/// </para>
/// <para>
/// Unlike the JSON side where <see cref="System.Text.Json.JsonSerializer"/> provides
/// universal type-to-bytes conversion, CBOR has no universal serializer for arbitrary
/// types. The caller provides a <see cref="Func{T, TResult}"/> that performs the CBOR encoding.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
public static class SdCwtExtensions
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
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable. For CWT integer
        /// keys, use the string representation (e.g., <c>/501</c>).
        /// </param>
        /// <param name="saltFactory">Factory for generating cryptographic salt for each disclosure.</param>
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
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        public ValueTask<SdTokenResult> IssueSdCwtAsync(
            Func<T, byte[]> serializer,
            IReadOnlySet<CredentialPath> disclosablePaths,
            SaltFactoryDelegate saltFactory,
            PrivateKeyMemory privateKey,
            string keyId,
            MemoryPool<byte> memoryPool,
            string? hashAlgorithm = null,
            string? mediaType = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(claims);
            ArgumentNullException.ThrowIfNull(serializer);

            byte[] cborBytes = serializer(claims);

            return SdCwtIssuance.IssueAsync(
                cborBytes, disclosablePaths, saltFactory,
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
        /// Issues an SD-CWT from a <see cref="VerifiableCredential"/>, validating that all
        /// disclosable paths are under <c>/credentialSubject</c>.
        /// </summary>
        /// <param name="serializer">
        /// Delegate that serializes the credential to CBOR bytes. The output must be a
        /// CBOR map with integer keys suitable for CWT processing.
        /// </param>
        /// <param name="disclosablePaths">
        /// Paths identifying claims that should be selectively disclosable.
        /// All paths must begin with <c>/credentialSubject</c>.
        /// </param>
        /// <param name="saltFactory">Factory for generating cryptographic salt for each disclosure.</param>
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
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An <see cref="SdTokenResult"/> with the COSE_Sign1 bytes and disclosures.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when any disclosable path does not start with <c>/credentialSubject</c>.
        /// </exception>
        public ValueTask<SdTokenResult> IssueSdCwtAsync(
            Func<VerifiableCredential, byte[]> serializer,
            IReadOnlySet<CredentialPath> disclosablePaths,
            SaltFactoryDelegate saltFactory,
            PrivateKeyMemory privateKey,
            string keyId,
            MemoryPool<byte> memoryPool,
            string? hashAlgorithm = null,
            string? mediaType = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentNullException.ThrowIfNull(serializer);
            ArgumentNullException.ThrowIfNull(disclosablePaths);

            ValidateCredentialPaths(disclosablePaths);

            byte[] cborBytes = serializer(credential);

            return SdCwtIssuance.IssueAsync(
                cborBytes, disclosablePaths, saltFactory,
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