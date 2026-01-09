using System.Buffers;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Delegate for encoding binary data to a string representation.
/// </summary>
/// <param name="data">The binary data to encode.</param>
/// <returns>The encoded string representation.</returns>
/// <remarks>
/// This delegate matches common encoding method signatures like <c>Base58.Bitcoin.Encode</c>
/// and <c>Base64Url.EncodeToString</c>, allowing them to be used directly.
/// For better performance with large data, users can implement custom encoders using TryEncode patterns.
/// </remarks>
public delegate string EncodeDelegate(ReadOnlySpan<byte> data);


/// <summary>
/// Delegate for decoding character data to binary using memory pool allocation.
/// </summary>
/// <param name="source">The encoded character data to decode.</param>
/// <param name="pool">The memory pool to use for allocating the result buffer.</param>
/// <returns>An owned memory buffer containing the decoded bytes.</returns>
/// <remarks>
/// This delegate requires implementations to handle buffer size calculation and allocation
/// from the provided memory pool. The caller is responsible for disposing the returned
/// <see cref="IMemoryOwner{T}"/> to return the buffer to the pool.
/// </remarks>
public delegate IMemoryOwner<byte> DecodeDelegate(ReadOnlySpan<char> source, MemoryPool<byte> pool);


/// <summary>
/// Delegate for simple decoding that returns a byte array.
/// </summary>
/// <param name="source">The encoded character data to decode.</param>
/// <returns>The decoded byte array.</returns>
public delegate byte[] SimpleDecodeDelegate(ReadOnlySpan<char> source);


/// <summary>
/// Provides multibase encoding and decoding operations with efficient memory usage.
/// </summary>
/// <remarks>
/// <para>
/// Multibase is a protocol for disambiguating the encoding of base-encoded data.
/// It prepends a single character prefix that identifies the encoding used.
/// </para>
/// <para>
/// This class also handles multicodec headers, which identify the type of data
/// (e.g., cryptographic key algorithm) encoded in the payload.
/// </para>
/// <para>
/// See <see href="https://github.com/multiformats/multibase">multibase (GitHub)</see>
/// and <see href="https://github.com/multiformats/multicodec">multicodec (GitHub)</see>.
/// </para>
/// </remarks>
public static class MultibaseSerializer
{
    /// <summary>
    /// Threshold for using stack allocation versus memory pool.
    /// </summary>
    private const int StackAllocationThreshold = 256;


    /// <summary>
    /// Prepends a multicodec header to data bytes using pooled memory.
    /// </summary>
    /// <param name="data">The raw data bytes.</param>
    /// <param name="codecHeader">The multicodec header to prepend.</param>
    /// <param name="pool">The memory pool for allocation.</param>
    /// <returns>Pooled memory containing header followed by data. Caller must dispose.</returns>
    /// <remarks>
    /// <para>
    /// This is the fundamental operation for preparing data with a multicodec header.
    /// Higher-level methods like <see cref="Encode"/> use this internally.
    /// </para>
    /// </remarks>
    public static IMemoryOwner<byte> PrependHeader(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> codecHeader,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int totalLength = codecHeader.Length + data.Length;
        var buffer = pool.Rent(totalLength);

        codecHeader.CopyTo(buffer.Memory.Span);
        data.CopyTo(buffer.Memory.Span[codecHeader.Length..]);

        return buffer;
    }


    /// <summary>
    /// Prepends the appropriate multicodec header to a public key based on its algorithm tag.
    /// </summary>
    /// <param name="publicKey">The public key memory with algorithm information in its tag.</param>
    /// <param name="pool">The memory pool for allocation.</param>
    /// <returns>Pooled memory containing header followed by key bytes. Caller must dispose.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="MulticodecHeaderRegistry"/> is not initialized.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if no multicodec header is registered for the key's algorithm.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This overload extracts the <see cref="CryptoAlgorithm"/> from the key's
    /// <see cref="SensitiveMemory.Tag"/> and resolves the appropriate multicodec header
    /// via <see cref="MulticodecHeaderRegistry"/>.
    /// </para>
    /// </remarks>
    public static IMemoryOwner<byte> PrependHeader(PublicKeyMemory publicKey, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(pool);

        var algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        var codecHeader = MulticodecHeaderRegistry.Resolve(algorithm);

        return PrependHeader(publicKey.AsReadOnlySpan(), codecHeader, pool);
    }


    /// <summary>
    /// Encodes data with the specified codec header and multibase prefix.
    /// </summary>
    /// <param name="data">The raw data to encode.</param>
    /// <param name="codecHeader">The multicodec header to prepend to the data before encoding.</param>
    /// <param name="multibasePrefix">The multibase prefix character from <see cref="MultibaseAlgorithms"/>.</param>
    /// <param name="encoder">The encoder delegate that performs the actual encoding.</param>
    /// <param name="pool">The memory pool to use for temporary allocations.</param>
    /// <returns>The multibase encoded string with the specified prefix.</returns>
    /// <remarks>
    /// This method combines the codec header with the data, encodes the combined bytes,
    /// and prepends the multibase prefix character to create the final encoded string.
    /// </remarks>
    public static string Encode(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> codecHeader,
        char multibasePrefix,
        EncodeDelegate encoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        int totalLength = codecHeader.Length + data.Length;

        if(totalLength <= StackAllocationThreshold)
        {
            //Small buffer path: use stack allocation for better performance.
            Span<byte> stackBuffer = stackalloc byte[StackAllocationThreshold];
            var combinedData = stackBuffer[..totalLength];

            codecHeader.CopyTo(combinedData);
            data.CopyTo(combinedData[codecHeader.Length..]);

            string encodedPayload = encoder(combinedData);

            return string.Create(encodedPayload.Length + 1, encodedPayload, (span, state) =>
            {
                span[0] = multibasePrefix;
                state.AsSpan().CopyTo(span[1..]);
            });
        }
        else
        {
            //Large buffer path: use PrependHeader with pooled memory.
            using var buffer = PrependHeader(data, codecHeader, pool);
            string encodedPayload = encoder(buffer.Memory.Span);

            return string.Create(encodedPayload.Length + 1, encodedPayload, (span, state) =>
            {
                span[0] = multibasePrefix;
                state.AsSpan().CopyTo(span[1..]);
            });
        }
    }


    /// <summary>
    /// Convenience overload that uses the default sensitive memory pool.
    /// </summary>
    /// <param name="data">The raw data to encode.</param>
    /// <param name="codecHeader">The multicodec header to prepend to the data before encoding.</param>
    /// <param name="multibasePrefix">The multibase prefix character from <see cref="MultibaseAlgorithms"/>.</param>
    /// <param name="encoder">The encoder delegate that performs the actual encoding.</param>
    /// <returns>The multibase encoded string with the specified prefix.</returns>
    public static string Encode(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> codecHeader,
        char multibasePrefix,
        EncodeDelegate encoder)
    {
        return Encode(data, codecHeader, multibasePrefix, encoder, SensitiveMemoryPool<byte>.Shared);
    }


    /// <summary>
    /// Encodes a cryptographic key with the appropriate multicodec header for the specified algorithm.
    /// </summary>
    /// <param name="keyData">The raw key data to encode.</param>
    /// <param name="algorithm">The cryptographic algorithm of the key.</param>
    /// <param name="encoder">The encoder delegate to use for encoding.</param>
    /// <returns>The multibase encoded key string with base58btc prefix.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="MulticodecHeaderRegistry"/> is not initialized.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if no multicodec header is registered for the algorithm.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method resolves the multicodec header via <see cref="MulticodecHeaderRegistry"/>
    /// and encodes the key using base58btc multibase encoding.
    /// </para>
    /// </remarks>
    public static string EncodeKey(ReadOnlySpan<byte> keyData, CryptoAlgorithm algorithm, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(encoder);

        var codecHeader = MulticodecHeaderRegistry.Resolve(algorithm);
        return Encode(keyData, codecHeader, MultibaseAlgorithms.Base58Btc, encoder);
    }


    /// <summary>
    /// Encodes a public key using the algorithm from its tag.
    /// </summary>
    /// <param name="publicKey">The public key memory with algorithm information in its tag.</param>
    /// <param name="encoder">The encoder delegate to use for encoding.</param>
    /// <returns>The multibase encoded key string with base58btc prefix.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="MulticodecHeaderRegistry"/> is not initialized.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if no multicodec header is registered for the key's algorithm.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This overload extracts the <see cref="CryptoAlgorithm"/> from the key's
    /// <see cref="SensitiveMemory.Tag"/> automatically.
    /// </para>
    /// </remarks>
    public static string EncodeKey(PublicKeyMemory publicKey, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(encoder);

        var algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        return EncodeKey(publicKey.AsReadOnlySpan(), algorithm, encoder);
    }


    /// <summary>
    /// Encodes data for JWK format without any codec header or multibase prefix.
    /// </summary>
    /// <param name="data">The raw data to encode.</param>
    /// <param name="encoder">The encoder delegate to use for encoding.</param>
    /// <returns>The encoded string without any prefix or header.</returns>
    /// <remarks>
    /// JWK format uses raw base64url encoding without multibase prefixes.
    /// </remarks>
    public static string EncodeForJwk(ReadOnlySpan<byte> data, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(encoder);
        return encoder(data);
    }


    /// <summary>
    /// Decodes a multibase encoded string and returns an owned memory buffer.
    /// </summary>
    /// <param name="encoded">The multibase encoded string to decode.</param>
    /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
    /// <param name="decoder">The decoder delegate that performs the actual decoding.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
    /// <exception cref="FormatException">Thrown when the input format is invalid or decoding fails.</exception>
    /// <remarks>
    /// This method removes the multibase prefix, decodes the remaining data,
    /// and then removes the codec header from the decoded bytes.
    /// </remarks>
    public static IMemoryOwner<byte> Decode(
        ReadOnlySpan<char> encoded,
        int codecHeaderLength,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
        {
            throw new FormatException("Input must start with 'z' for base58btc encoding.");
        }

        var encodedPayload = encoded[1..];
        var decodedBuffer = decoder(encodedPayload, pool);

        try
        {
            if(decodedBuffer.Memory.Length < codecHeaderLength)
            {
                throw new FormatException(
                    $"Codec header length ({codecHeaderLength}) exceeds decoded data length ({decodedBuffer.Memory.Length}).");
            }

            int resultLength = decodedBuffer.Memory.Length - codecHeaderLength;
            var resultBuffer = pool.Rent(resultLength);

            decodedBuffer.Memory.Span[codecHeaderLength..].CopyTo(resultBuffer.Memory.Span);

            return resultBuffer;
        }
        finally
        {
            decodedBuffer.Dispose();
        }
    }


    /// <summary>
    /// Convenience overload that uses the default sensitive memory pool.
    /// </summary>
    /// <param name="encoded">The multibase encoded string to decode.</param>
    /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
    /// <param name="decoder">The decoder delegate that performs the actual decoding.</param>
    /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
    public static IMemoryOwner<byte> Decode(
        ReadOnlySpan<char> encoded,
        int codecHeaderLength,
        DecodeDelegate decoder)
    {
        return Decode(encoded, codecHeaderLength, decoder, SensitiveMemoryPool<byte>.Shared);
    }


    /// <summary>
    /// Convenience overload that accepts a simple decode function and memory pool.
    /// </summary>
    /// <param name="encoded">The multibase encoded string to decode.</param>
    /// <param name="codecHeaderLength">The length of the codec header to skip in the decoded data.</param>
    /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>An owned memory buffer containing the decoded data without the codec header.</returns>
    public static IMemoryOwner<byte> Decode(
        ReadOnlySpan<char> encoded,
        int codecHeaderLength,
        SimpleDecodeDelegate simpleDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, MemoryPool<byte> decoderPool)
        {
            byte[] decoded = simpleDecoder(source);
            var buffer = decoderPool.Rent(decoded.Length);
            decoded.CopyTo(buffer.Memory.Span);
            return buffer;
        }

        return Decode(encoded, codecHeaderLength, decoder, pool);
    }


    /// <summary>
    /// Decodes a multibase encoded key and automatically detects the algorithm type.
    /// </summary>
    /// <param name="encoded">The multibase encoded key string.</param>
    /// <param name="decoder">The decoder delegate to use for decoding.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>A tuple containing the decoded key data and the detected algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when the key type cannot be detected.</exception>
    public static (IMemoryOwner<byte> KeyData, CryptoAlgorithm Algorithm) DecodeKey(
        ReadOnlySpan<char> encoded,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
        {
            throw new ArgumentException("Not a valid base58btc multibase string.");
        }

        CryptoAlgorithm detectedAlgorithm = encoded switch
        {
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.Secp256k1,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.Ed25519,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P256,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P384PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P384,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.P521PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.P521,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey, StringComparison.Ordinal) => CryptoAlgorithm.X25519,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048, StringComparison.Ordinal) => CryptoAlgorithm.Rsa2048,
            _ when encoded.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096, StringComparison.Ordinal) => CryptoAlgorithm.Rsa4096,
            _ => throw new ArgumentException("Unknown key type in encoded data.")
        };

        var decodedKeyData = Decode(encoded, codecHeaderLength: 2, decoder, pool);

        return (decodedKeyData, detectedAlgorithm);
    }


    /// <summary>
    /// Decodes a multibase encoded key and automatically detects the algorithm type.
    /// </summary>
    /// <param name="encoded">The multibase encoded key string.</param>
    /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>A tuple containing the decoded key data and the detected algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when the key type cannot be detected.</exception>
    public static (IMemoryOwner<byte> KeyData, CryptoAlgorithm Algorithm) DecodeKey(
        ReadOnlySpan<char> encoded,
        SimpleDecodeDelegate simpleDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, MemoryPool<byte> decoderPool)
        {
            byte[] decoded = simpleDecoder(source);
            var buffer = decoderPool.Rent(decoded.Length);
            decoded.CopyTo(buffer.Memory.Span);
            return buffer;
        }

        return DecodeKey(encoded, decoder, pool);
    }


    /// <summary>
    /// Decodes data from JWK format without any multibase prefix or codec header.
    /// </summary>
    /// <param name="encoded">The base64url encoded string.</param>
    /// <param name="simpleDecoder">A simple decoder that returns a byte array.</param>
    /// <param name="pool">The memory pool to use for allocating the result buffer.</param>
    /// <returns>An owned memory buffer containing the decoded data.</returns>
    /// <exception cref="FormatException">Thrown when decoding fails.</exception>
    public static IMemoryOwner<byte> DecodeFromJwk(
        ReadOnlySpan<char> encoded,
        SimpleDecodeDelegate simpleDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] decoded = simpleDecoder(encoded);
        var buffer = pool.Rent(decoded.Length);
        decoded.CopyTo(buffer.Memory.Span);

        return buffer;
    }
}