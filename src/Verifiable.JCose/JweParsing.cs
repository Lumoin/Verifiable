using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.JCose;

/// <summary>
/// JWE (JSON Web Encryption) compact serialization parsing and assembly.
/// </summary>
/// <remarks>
/// <para>
/// Handles both directions of the compact JWE serialization defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-3.1">RFC 7516 §3.1</see>:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="ParseCompact"/> decodes a compact JWE string into a validated
/// <see cref="AeadMessage"/> ready for key agreement and decryption.
/// </description></item>
/// <item><description>
/// <see cref="JweMessage.ToCompactJwe"/> assembles a compact
/// JWE string from the raw cryptographic components in an <see cref="AeadMessage"/>
/// produced by a driver encrypt function.
/// </description></item>
/// </list>
/// <para>
/// Parallel to <see cref="Jws"/> which handles the three-part JWS compact serialization.
/// </para>
/// </remarks>
public static class JweParsing
{
    /// <summary>
    /// Maximum permitted compact JWE byte count. Tokens larger than this are rejected
    /// before any parsing begins to prevent memory exhaustion.
    /// </summary>
    public const int MaxCompactJweByteCount = 65_536;

    //AES-GCM structural lengths per NIST SP 800-38D.
    private const int AesGcmIvLength = 12;
    private const int AesGcmTagLength = 16;


    /// <summary>
    /// Parses and validates a compact JWE string, returning an <see cref="AeadMessage"/>
    /// ready for key agreement and decryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Security invariants enforced unconditionally:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Token size must not exceed <see cref="MaxCompactJweByteCount"/>.</description></item>
    /// <item><description>Exactly five dot-separated parts per RFC 7516 §3.1.</description></item>
    /// <item><description>The <c>alg</c> header must exactly match <paramref name="expectedAlgorithm"/>.</description></item>
    /// <item><description>The <c>enc</c> header must exactly match <paramref name="expectedEncryption"/>.</description></item>
    /// <item><description>The <c>zip</c> parameter must not be present.</description></item>
    /// <item><description>
    /// The EPK must carry <c>kty</c>, <c>crv</c>, <c>x</c>, and <c>y</c>, and the point
    /// must lie on the declared curve to prevent invalid curve attacks.
    /// </description></item>
    /// <item><description>IV must be exactly 12 bytes for AES-GCM per NIST SP 800-38D.</description></item>
    /// <item><description>Authentication tag must be exactly 16 bytes for AES-GCM per NIST SP 800-38D.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="compactJwe">The compact JWE serialization to parse.</param>
    /// <param name="expectedAlgorithm">
    /// The key management algorithm the caller agreed to, e.g.
    /// <see cref="WellKnownJweAlgorithms.EcdhEs"/>.
    /// </param>
    /// <param name="expectedEncryption">
    /// The content encryption algorithm the caller agreed to, e.g.
    /// <see cref="WellKnownJweEncryptionAlgorithms.A128Gcm"/>.
    /// </param>
    /// <param name="base64UrlDecoder">
    /// Delegate for Base64url decoding into pooled memory, following the same convention
    /// as <see cref="Jws"/> operations.
    /// </param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <returns>The validated <see cref="AeadMessage"/>. The caller owns and must dispose.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="compactJwe"/> exceeds <see cref="MaxCompactJweByteCount"/>.
    /// </exception>
    /// <exception cref="FormatException">
    /// Thrown when any structural or security invariant is violated.
    /// </exception>
    public static AeadMessage ParseCompact(
        string compactJwe,
        string expectedAlgorithm,
        string expectedEncryption,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJwe);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedEncryption);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(compactJwe.Length > MaxCompactJweByteCount)
        {
            throw new ArgumentException(
                $"Compact JWE exceeds the maximum permitted size of {MaxCompactJweByteCount} bytes.",
                nameof(compactJwe));
        }

        if(!TrySplitFiveParts(compactJwe.AsSpan(),
            out ReadOnlySpan<char> headerSpan,
            out ReadOnlySpan<char> ivSpan,
            out ReadOnlySpan<char> ciphertextSpan,
            out ReadOnlySpan<char> authTagSpan))
        {
            throw new FormatException(
                "Compact JWE must contain exactly five dot-separated parts per RFC 7516 §3.1.");
        }

        //Allocate all components with the nullable-with-finally pattern so that every
        //successfully created disposable is released on any subsequent failure path.
        AdditionalData? aad = null;
        Nonce? iv = null;
        Ciphertext? ciphertext = null;
        AuthenticationTag? authTag = null;
        PublicKeyMemory? epk = null;

        try
        {
            //The AAD is the ASCII encoding of the Base64url-encoded protected header exactly
            //as it appeared on the wire, per RFC 7516 §5.1 step 14.
            int aadByteCount = Encoding.ASCII.GetByteCount(headerSpan);
            IMemoryOwner<byte> aadOwner = pool.Rent(aadByteCount);
            Encoding.ASCII.GetBytes(headerSpan, aadOwner.Memory.Span);
            aad = new AdditionalData(aadOwner, CryptoTags.AesGcmAad);

            using IMemoryOwner<byte> headerOwner = base64UrlDecoder(headerSpan.ToString(), pool);

            IReadOnlyDictionary<string, object> header;
            (header, epk) = ParseAndValidateHeader(
                headerOwner.Memory.Span,
                expectedAlgorithm,
                expectedEncryption,
                base64UrlDecoder,
                CryptoFormatConversions.DefaultEpkCrvToTagConverter,
                pool);

            iv = DecodeIv(ivSpan.ToString(), base64UrlDecoder, pool);
            ciphertext = DecodeCiphertext(ciphertextSpan.ToString(), base64UrlDecoder, pool);
            authTag = DecodeAuthTag(authTagSpan.ToString(), base64UrlDecoder, pool);

            AeadMessage result = new AeadMessage(
                header, epk, iv, ciphertext, authTag, aad, expectedEncryption);

            //Ownership transferred to AeadMessage.
            aad = null;
            iv = null;
            ciphertext = null;
            authTag = null;
            epk = null;

            return result;
        }
        finally
        {
            aad?.Dispose();
            iv?.Dispose();
            ciphertext?.Dispose();
            authTag?.Dispose();
            epk?.Dispose();
        }
    }


    private static (IReadOnlyDictionary<string, object> Header, PublicKeyMemory Epk)
        ParseAndValidateHeader(
            ReadOnlySpan<byte> headerJson,
            string expectedAlgorithm,
            string expectedEncryption,
            DecodeDelegate base64UrlDecoder,
            EpkCrvToTagDelegate crvToTagConverter,
            MemoryPool<byte> pool)
    {
        string? alg = JwkJsonReader.ExtractStringValue(headerJson, "alg"u8);
        string? enc = JwkJsonReader.ExtractStringValue(headerJson, "enc"u8);
        bool hasZip = JwkJsonReader.ContainsKey(headerJson, "zip"u8);

        if(alg is null)
        {
            throw new FormatException(
                $"JWE protected header must contain the '{WellKnownJwkValues.Alg}' parameter.");
        }

        if(!string.Equals(alg, expectedAlgorithm, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkValues.Alg}' value '{alg}' does not match the expected " +
                $"algorithm '{expectedAlgorithm}'.");
        }

        if(enc is null)
        {
            throw new FormatException(
                $"JWE protected header must contain the '{WellKnownJwkValues.Enc}' parameter.");
        }

        if(!string.Equals(enc, expectedEncryption, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkValues.Enc}' value '{enc}' does not match the expected " +
                $"encryption '{expectedEncryption}'.");
        }

        if(hasZip)
        {
            throw new FormatException("JWE tokens with 'zip' compression are not permitted.");
        }

        string? kty = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "kty"u8);
        string? crv = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "crv"u8);
        string? x = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "x"u8);
        string? y = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "y"u8);

        if(kty is null || crv is null || x is null || y is null)
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkValues.Epk}' must contain '{WellKnownJwkValues.Kty}', " +
                $"'{WellKnownJwkValues.Crv}', '{WellKnownJwkValues.X}', and '{WellKnownJwkValues.Y}'.");
        }

        if(!WellKnownKeyTypeValues.IsEc(kty))
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkValues.Epk}' must have '{WellKnownJwkValues.Kty}' equal to " +
                $"'{WellKnownKeyTypeValues.Ec}'. Received '{kty}'.");
        }

        PublicKeyMemory epk = DecodeAndValidateEpk(x, y, crv, base64UrlDecoder, crvToTagConverter, pool);

        var epkDict = new Dictionary<string, object>(4)
        {
            [WellKnownJwkValues.Kty] = kty,
            [WellKnownJwkValues.Crv] = crv,
            [WellKnownJwkValues.X] = x,
            [WellKnownJwkValues.Y] = y
        };

        var header = new Dictionary<string, object>(3)
        {
            [WellKnownJwkValues.Alg] = alg,
            [WellKnownJwkValues.Enc] = enc,
            [WellKnownJwkValues.Epk] = epkDict
        };

        return (header, epk);
    }


    private static PublicKeyMemory DecodeAndValidateEpk(
        string xEncoded,
        string yEncoded,
        string crv,
        DecodeDelegate base64UrlDecoder,
        EpkCrvToTagDelegate crvToTagConverter,
        MemoryPool<byte> pool)
    {
        (Tag epkTag, EllipticCurveTypes curveType) = crvToTagConverter(crv);

        using IMemoryOwner<byte> xDecoded = base64UrlDecoder(xEncoded, pool);
        using IMemoryOwner<byte> yDecoded = base64UrlDecoder(yEncoded, pool);

        ReadOnlySpan<byte> xSpan = xDecoded.Memory.Span;
        ReadOnlySpan<byte> ySpan = yDecoded.Memory.Span;

        if(!EllipticCurveUtilities.CheckPointOnCurve(xSpan, ySpan, curveType))
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkValues.Epk}' point is not on the {crv} curve. " +
                $"Possible invalid curve attack.");
        }

        //Combine X and Y into a single uncompressed point: 0x04 || X || Y.
        IMemoryOwner<byte> pointOwner = pool.Rent(1 + xSpan.Length + ySpan.Length);
        pointOwner.Memory.Span[0] = 0x04;
        xSpan.CopyTo(pointOwner.Memory.Span[1..]);
        ySpan.CopyTo(pointOwner.Memory.Span[(1 + xSpan.Length)..]);

        return new PublicKeyMemory(pointOwner, epkTag);
    }


    private static Nonce DecodeIv(
        string ivEncoded,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        //Base64url-encoded 12 bytes = 16 characters (no padding).
        int expectedEncodedLength = 16;
        if(ivEncoded.Length != expectedEncodedLength)
        {
            throw new FormatException(
                $"JWE IV must be exactly {AesGcmIvLength} bytes for AES-GCM per NIST SP 800-38D. " +
                $"Encoded length {ivEncoded.Length} does not correspond to {AesGcmIvLength} bytes.");
        }

        return new Nonce(base64UrlDecoder(ivEncoded, pool), CryptoTags.AesGcmIv);
    }


    private static Ciphertext DecodeCiphertext(
        string ciphertextEncoded,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        if(string.IsNullOrEmpty(ciphertextEncoded))
        {
            throw new FormatException("JWE ciphertext must not be empty.");
        }

        return new Ciphertext(base64UrlDecoder(ciphertextEncoded, pool), CryptoTags.AesGcmCiphertext);
    }


    private static AuthenticationTag DecodeAuthTag(
        string authTagEncoded,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        //Base64url-encoded 16 bytes = 22 characters (no padding).
        int expectedEncodedLength = 22;
        if(authTagEncoded.Length != expectedEncodedLength)
        {
            throw new FormatException(
                $"JWE authentication tag must be exactly {AesGcmTagLength} bytes for AES-GCM " +
                $"per NIST SP 800-38D. Encoded length {authTagEncoded.Length} does not " +
                $"correspond to {AesGcmTagLength} bytes.");
        }

        return new AuthenticationTag(base64UrlDecoder(authTagEncoded, pool), CryptoTags.AesGcmAuthTag);
    }


    private static bool TrySplitFiveParts(
        ReadOnlySpan<char> input,
        out ReadOnlySpan<char> header,
        out ReadOnlySpan<char> iv,
        out ReadOnlySpan<char> ciphertext,
        out ReadOnlySpan<char> authTag)
    {
        header = default;
        iv = default;
        ciphertext = default;
        authTag = default;

        int dot1 = input.IndexOf('.');
        if(dot1 < 0) { return false; }

        header = input[..dot1];
        ReadOnlySpan<char> rest = input[(dot1 + 1)..];

        //Encrypted key slot — empty for ECDH-ES but the separator dot must be present.
        int dot2 = rest.IndexOf('.');
        if(dot2 < 0) { return false; }

        ReadOnlySpan<char> rest2 = rest[(dot2 + 1)..];

        int dot3 = rest2.IndexOf('.');
        if(dot3 < 0) { return false; }

        iv = rest2[..dot3];
        ReadOnlySpan<char> rest3 = rest2[(dot3 + 1)..];

        int dot4 = rest3.IndexOf('.');
        if(dot4 < 0) { return false; }

        ciphertext = rest3[..dot4];
        authTag = rest3[(dot4 + 1)..];

        return !authTag.Contains('.');
    }
}
