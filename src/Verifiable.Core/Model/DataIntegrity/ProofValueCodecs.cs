using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Provides default implementations for encoding and decoding proof values.
/// </summary>
/// <seealso cref="Verifiable.Cryptography.MultibaseAlgorithms"/>
/// <seealso cref="Verifiable.Cryptography.MultibaseSerializer"/>
/// <remarks>
/// <para>
/// These static methods can be used directly as delegate implementations or called
/// from custom implementations. They use <see cref="Verifiable.Cryptography.MultibaseSerializer"/> internally.
/// </para>
/// <para>
/// <strong>Usage example:</strong>
/// </para>
/// <code>
/// var signedCredential = await credential.SignAsync(
///     privateKey,
///     verificationMethodId,
///     cryptosuite,
///     proofCreated,
///     canonicalize,
///     contextResolver,
///     ProofValueCodecs.EncodeBase58Btc,  // Use directly as delegate
///     ProofValueCodecs.DecodeBase58Btc,
///     serialize,
///     deserialize,
///     serializeProofOptions,
///     base58Encoder,
///     base58Decoder,
///     pool,
///     cancellationToken);
/// </code>
/// </remarks>
public static class ProofValueCodecs
{
    /// <summary>
    /// Encodes signature bytes to a Base58Btc multibase proof value.
    /// </summary>
    /// <param name="signatureBytes">The raw signature bytes to encode.</param>
    /// <param name="encoder">The Base58 encoding delegate.</param>
    /// <param name="pool">Memory pool for temporary allocations.</param>
    /// <returns>The multibase-encoded proof value with 'z' prefix.</returns>
    /// <remarks>
    /// <para>
    /// This produces a proof value in the format required by Data Integrity specifications:
    /// a 'z' prefix followed by Base58Btc-encoded signature bytes.
    /// </para>
    /// <para>
    /// No codec header is prepended to the signature bytes, as signatures do not use
    /// multicodec headers (unlike public keys).
    /// </para>
    /// </remarks>
    public static string EncodeBase58Btc(
        ReadOnlySpan<byte> signatureBytes,
        EncodeDelegate encoder,
        MemoryPool<byte> pool)
    {
        return MultibaseSerializer.Encode(
            signatureBytes,
            codecHeader: ReadOnlySpan<byte>.Empty,
            MultibaseAlgorithms.Base58Btc,
            encoder,
            pool);
    }


    /// <summary>
    /// Decodes a Base58Btc multibase proof value to signature bytes.
    /// </summary>
    /// <param name="proofValue">The multibase-encoded proof value (must start with 'z').</param>
    /// <param name="decoder">The Base58 decoding delegate.</param>
    /// <param name="pool">Memory pool for allocating the result buffer.</param>
    /// <returns>The decoded signature bytes. The caller must dispose the returned memory.</returns>
    /// <exception cref="FormatException">Thrown when the proof value format is invalid.</exception>
    /// <remarks>
    /// <para>
    /// This expects a proof value with 'z' prefix (Base58Btc multibase).
    /// No codec header is expected or stripped from the decoded bytes.
    /// </para>
    /// </remarks>
    public static IMemoryOwner<byte> DecodeBase58Btc(
        string proofValue,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
    {
        return MultibaseSerializer.Decode(
            proofValue,
            codecHeaderLength: 0,
            decoder,
            pool);
    }


    /// <summary>
    /// Encodes signature bytes to a Base64Url multibase proof value.
    /// </summary>
    /// <param name="signatureBytes">The raw signature bytes to encode.</param>
    /// <param name="encoder">The Base64Url encoding delegate.</param>
    /// <param name="pool">Memory pool for temporary allocations.</param>
    /// <returns>The multibase-encoded proof value with 'u' prefix.</returns>
    /// <remarks>
    /// <para>
    /// This produces a proof value with 'u' prefix (Base64Url no-pad multibase),
    /// used by some cryptosuites like ecdsa-sd-2023.
    /// </para>
    /// </remarks>
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "This is on purpose.")]
    public static string EncodeBase64Url(
        ReadOnlySpan<byte> signatureBytes,
        EncodeDelegate encoder,
        MemoryPool<byte> pool)
    {
        return MultibaseSerializer.Encode(
            signatureBytes,
            codecHeader: ReadOnlySpan<byte>.Empty,
            MultibaseAlgorithms.Base64Url,
            encoder,
            pool);
    }


    /// <summary>
    /// Decodes a Base64Url multibase proof value to signature bytes.
    /// </summary>
    /// <param name="proofValue">The multibase-encoded proof value (must start with 'u').</param>
    /// <param name="decoder">The Base64Url decoding delegate.</param>
    /// <param name="pool">Memory pool for allocating the result buffer.</param>
    /// <returns>The decoded signature bytes. The caller must dispose the returned memory.</returns>
    /// <exception cref="FormatException">Thrown when the proof value format is invalid.</exception>
    public static IMemoryOwner<byte> DecodeBase64Url(
        string proofValue,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(proofValue);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);
        if(proofValue.Length < 2 || proofValue[0] != MultibaseAlgorithms.Base64Url)
        {
            throw new FormatException("Proof value must start with 'u' for Base64Url encoding.");
        }

        //Decode the payload after the prefix.
        return decoder(proofValue.AsSpan(1), pool);
    }
}