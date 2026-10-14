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
/// <returns>
/// An owned memory buffer whose memory holds exactly the decoded bytes, no more: its length is the decoded length,
/// and every consumer of a decoded owner reads the decoded octets as the whole of that memory.
/// </returns>
/// <remarks>
/// <para>
/// This delegate requires implementations to handle buffer size calculation and allocation
/// from the provided memory pool. The caller is responsible for disposing the returned
/// <see cref="IMemoryOwner{T}"/> to return the buffer to the pool.
/// </para>
/// <para>
/// A decoder refuses encoded input it cannot decode with <see cref="FormatException"/>: a character it does not
/// read and a length no encoding has. A base64url decoder also refuses a non-empty input that decodes to no octets
/// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>: "Note that the
/// base64url encoding of the empty octet sequence is the empty string.") and never rents a buffer of no octets
/// from <paramref name="pool"/>; that rule is stated for base64url, and this file's two adapters of a
/// <see cref="SimpleDecodeDelegate"/> for the base58btc multibase form rent as many octets as the simple decoder
/// answers. A caller that decodes presented input answers the refusal as malformed input. Any other exception a
/// decoder raises is the decoder's own fault, not a property of the input, and propagates to the caller.
/// </para>
/// <para>
/// The throwing .NET <c>Base64Url</c> overloads (<c>DecodeFromChars</c> returning the octets, and
/// <c>TryDecodeFromChars</c>) accept the padding character <c>=</c>, skip white space, and refuse a character
/// outside the alphabet and a length of 1 modulo 4 with <see cref="FormatException"/>; the overload that answers
/// an <c>OperationStatus</c> answers <c>InvalidData</c> instead. A decoder built on them reads one octet sequence
/// from several spellings. A caller that holds presented input to one spelling checks the form itself before it
/// decodes: the compact JWS verify bodies of <c>Jws</c> refuse padding, white space, any character outside the
/// unpadded base64url alphabet and a set bit that carries no octet before any decoder runs.
/// </para>
/// </remarks>
public delegate IMemoryOwner<byte> DecodeDelegate(ReadOnlySpan<char> source, BaseMemoryPool pool);


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
        BaseMemoryPool pool)
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
    /// <see cref="Lumoin.Base.SensitiveData.Tag"/> and resolves the appropriate multicodec header
    /// via <see cref="MulticodecHeaderRegistry"/>.
    /// </para>
    /// </remarks>
    public static IMemoryOwner<byte> PrependHeader(PublicKeyMemory publicKey, BaseMemoryPool pool)
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
        BaseMemoryPool pool)
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
    /// Encodes a cryptographic key with the appropriate multicodec header for the specified algorithm.
    /// </summary>
    /// <param name="keyData">The raw key data to encode.</param>
    /// <param name="algorithm">The cryptographic algorithm of the key.</param>
    /// <param name="encoder">The encoder delegate to use for encoding.</param>
    /// <param name="pool">The memory pool to use for temporary allocations.</param>
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
    public static string EncodeKey(ReadOnlySpan<byte> keyData, CryptoAlgorithm algorithm, EncodeDelegate encoder, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(encoder);

        var codecHeader = MulticodecHeaderRegistry.Resolve(algorithm);
        return Encode(keyData, codecHeader, MultibaseAlgorithms.Base58Btc, encoder, pool);
    }


    /// <summary>
    /// Encodes a public key using the algorithm from its tag.
    /// </summary>
    /// <param name="publicKey">The public key memory with algorithm information in its tag.</param>
    /// <param name="encoder">The encoder delegate to use for encoding.</param>
    /// <param name="pool">The memory pool to use for temporary allocations.</param>
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
    /// <see cref="Lumoin.Base.SensitiveData.Tag"/> automatically.
    /// </para>
    /// </remarks>
    public static string EncodeKey(PublicKeyMemory publicKey, EncodeDelegate encoder, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(encoder);

        var algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        return EncodeKey(publicKey.AsReadOnlySpan(), algorithm, encoder, pool);
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(encoded.Length < 2 || encoded[0] != MultibaseAlgorithms.Base58Btc)
        {
            throw new FormatException("Input must start with 'z' for base58btc encoding.");
        }

        var encodedPayload = encoded[1..];
        using var decodedBuffer = decoder(encodedPayload, pool);

        if(decodedBuffer.Memory.Length < codecHeaderLength)
        {
            throw new FormatException(
                $"Codec header length ({codecHeaderLength}) exceeds decoded Data length ({decodedBuffer.Memory.Length}).");
        }

        int resultLength = decodedBuffer.Memory.Length - codecHeaderLength;
        var resultBuffer = pool.Rent(resultLength);

        decodedBuffer.Memory.Span[codecHeaderLength..].CopyTo(resultBuffer.Memory.Span);

        return resultBuffer;
    }


    /// <summary>
    /// Overload that accepts a simple decode function and memory pool.
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, BaseMemoryPool decoderPool)
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
        BaseMemoryPool pool)
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
            _ => throw new ArgumentException("Unknown key type in encoded Data.")
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> decoder(ReadOnlySpan<char> source, BaseMemoryPool decoderPool)
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(simpleDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] decoded = simpleDecoder(encoded);
        var buffer = pool.Rent(decoded.Length);
        decoded.CopyTo(buffer.Memory.Span);

        return buffer;
    }
}
