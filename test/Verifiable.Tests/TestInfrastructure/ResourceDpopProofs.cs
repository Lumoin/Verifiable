using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds the DPoP proofs a test presents with an access token at a protected resource
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see> and §7.1), reads
/// the resource nonce a challenge carries, and spells the literal <c>DPoP</c> challenges the library's
/// resources answer with, so every resource-side test builds its proofs and states its expected
/// challenges the same way and varies only the member it names.
/// </summary>
/// <remarks>
/// A proof carries <c>htm</c>, <c>htu</c>, <c>iat</c>, <c>jti</c>, the <c>ath</c> hash of the
/// presented token and, when given, the resource <c>nonce</c>; it is signed by the ES256 key the caller
/// names, whose public half the header's <c>jwk</c> carries. A caller can rewrite the serialized
/// protected header before signing, so the proof still verifies under its own key while declaring a
/// header the test names.
/// </remarks>
internal static class ResourceDpopProofs
{
    /// <summary>
    /// The <c>algs</c> value of every <c>DPoP</c> challenge the library's resources answer with, written
    /// out: RFC 9449 §7.1 "The value of the parameter is a space-delimited list of JWS alg (Algorithm)
    /// header values".
    /// </summary>
    public static string AcceptedProofAlgorithms { get; } = "ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA";


    /// <summary>The literal <c>DPoP</c> challenge carrying <paramref name="error"/> and the <c>algs</c> parameter.</summary>
    /// <param name="error">The challenge's <c>error</c>.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    public static string DpopChallenge(string error) => $"DPoP error=\"{error}\", algs=\"{AcceptedProofAlgorithms}\"";


    /// <summary>
    /// Builds and signs a DPoP proof for a request to a protected resource or, with no
    /// <paramref name="accessToken"/>, for a token request, whose proof carries no <c>ath</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: the claim is
    /// carried "When the DPoP proof is used in conjunction with the presentation of an access token in protected
    /// resource access").
    /// </summary>
    /// <param name="key">The DPoP key that signs the proof and whose public half the header carries.</param>
    /// <param name="httpMethod">The <c>htm</c> value.</param>
    /// <param name="htu">The <c>htu</c> value.</param>
    /// <param name="accessToken">The access token the <c>ath</c> claim hashes, or <see langword="null"/> to carry no <c>ath</c>.</param>
    /// <param name="nonce">The <c>nonce</c> value, or <see langword="null"/> to carry none.</param>
    /// <param name="issuedAt">The <c>iat</c> value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="jti">The <c>jti</c> value, or <see langword="null"/> for a fresh unique one.</param>
    /// <param name="alterHeader">Rewrites the serialized protected header before signing, or <see langword="null"/> to keep it.</param>
    /// <returns>The compact DPoP proof.</returns>
    public static async Task<string> BuildAsync(
        DpopKey key,
        string httpMethod,
        string htu,
        string? accessToken,
        string? nonce,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken,
        string? jti = null,
        Action<Dictionary<string, object>>? alterHeader = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        string? ath = accessToken is null
            ? null
            : await ComputeAthAsync(accessToken, cancellationToken).ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = httpMethod,
            Htu = htu,
            Iat = issuedAt,
            Jti = jti ?? Guid.NewGuid().ToString("N"),
            Nonce = nonce,
            Ath = ath
        };

        DpopJwsPartSerializer serializer = alterHeader is null
            ? DpopTestSupport.Serializer
            : DpopTestSupport.Serializer with
            {
                SerializeHeader = header =>
                {
                    Dictionary<string, object> altered = new(DpopTestSupport.Serializer.SerializeHeader(header), StringComparer.Ordinal);
                    alterHeader(altered);

                    return altered;
                }
            };

        return await DpopProofConstruction.BuildAsync(
            claims, key, TestHostShell.Base64UrlEncoder, serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Computes the <c>ath</c> claim of a proof presented with <paramref name="accessToken"/> from its definition in
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The value MUST be the
    /// result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding
    /// of the associated access token's value." The ASCII bytes of the token, written into a buffer rented from the test
    /// pool, are hashed by the project's own SHA-256 provider (<see cref="MicrosoftCryptographicFunctions.ComputeDigestAsync"/>,
    /// called directly and not through the library's <c>ath</c> computation), and the digest is written in base64url
    /// without padding (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>).
    /// </summary>
    /// <param name="accessToken">The access token whose value the claim hashes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The <c>ath</c> value.</returns>
    public static async Task<string> ComputeAthAsync(string accessToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);

        using IMemoryOwner<byte> asciiOwner = TestHostShell.MemoryPool.Rent(accessToken.Length);
        int written = Encoding.ASCII.GetBytes(accessToken, asciiOwner.Memory.Span);
        (DigestValue digest, _) = await MicrosoftCryptographicFunctions.ComputeDigestAsync(
            new ReadOnlySequence<byte>(asciiOwner.Memory[..written]),
            Sha256DigestByteLength,
            CryptoTags.Sha256Digest,
            TestHostShell.MemoryPool,
            DigestClock,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        using(digest)
        {
            return TestHostShell.Base64UrlEncoder(digest.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// Computes the JWK SHA-256 Thumbprint of the public key of the EC DPoP key <paramref name="key"/> from its
    /// definition in <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638 Section 3</see>: "Construct
    /// a JSON object [RFC7159] containing only the required members of a JWK representing the key and with no whitespace
    /// or line breaks before or after any syntactic elements and with the required members ordered lexicographically by
    /// the Unicode [UNICODE] code points of the member names." and "Hash the octets of the UTF-8 representation of this
    /// JSON object with a cryptographic hash function H." The required members of an EC public key are, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3.2">Section 3.2</see>, "crv" "kty" "x" "y"; their
    /// values are read from the public JWK the proof header carries. The UTF-8 octets, written into a buffer rented
    /// from the test pool, are hashed by the project's own SHA-256 provider
    /// (<see cref="MicrosoftCryptographicFunctions.ComputeDigestAsync"/>, called directly and not through the
    /// library's thumbprint computation), and the digest is written in base64url without padding
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>), the value
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see> gives
    /// <c>dpop_jkt</c>.
    /// </summary>
    /// <param name="key">The EC DPoP key whose public key is hashed.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base64url JWK SHA-256 Thumbprint.</returns>
    public static async Task<string> ComputeJwkThumbprintAsync(DpopKey key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            key.Material.PublicKey, key.Alg, TestHostShell.Base64UrlEncoder);
        string canonical = $"{{\"crv\":\"{jwk["crv"]}\",\"kty\":\"{jwk["kty"]}\",\"x\":\"{jwk["x"]}\",\"y\":\"{jwk["y"]}\"}}";

        using IMemoryOwner<byte> utf8Owner = TestHostShell.MemoryPool.Rent(Encoding.UTF8.GetByteCount(canonical));
        int written = Encoding.UTF8.GetBytes(canonical, utf8Owner.Memory.Span);
        (DigestValue digest, _) = await MicrosoftCryptographicFunctions.ComputeDigestAsync(
            new ReadOnlySequence<byte>(utf8Owner.Memory[..written]),
            Sha256DigestByteLength,
            CryptoTags.Sha256Digest,
            TestHostShell.MemoryPool,
            DigestClock,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        using(digest)
        {
            return TestHostShell.Base64UrlEncoder(digest.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// The key identifier of a DPoP nonce key whose nonces end in a partial base64url group: the library's nonce is a
    /// one-octet length, this identifier, an 8-octet issue time, a 16-octet audience hash, 16 random octets and a
    /// 32-octet tag, 85 octets for a 12-octet identifier, whose final quantum of 8 bits base64url writes as "two
    /// characters followed by two "=" padding characters"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">RFC 4648 Section 4</see>), so the
    /// padded and the trailing-bit spellings of <see cref="PadNonce"/> and <see cref="SetUnusedBitsOfNonce"/> exist.
    /// </summary>
    public static string PartialGroupNonceKeyId { get; } = "test-hmac-12";


    /// <summary>
    /// The key identifier of a DPoP nonce key whose nonces end in the other partial base64url group: 13 octets, so the
    /// nonce is 86 octets, whose final quantum of 16 bits base64url writes as "three characters followed by one "="
    /// padding character" (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">RFC 4648 Section 4</see>), the
    /// last character carrying two bits no octet carries.
    /// </summary>
    public static string TwoOctetFinalQuantumNonceKeyId { get; } = "test-hmac-013";


    /// <summary>
    /// A base64url decoder that reads more spellings than a conforming encoder writes, written from
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">Section 3.5</see>: every character of Table 2 is
    /// read by its value, the base64 characters <c>+</c> and <c>/</c> of Table 1 are read as 62 and 63 beside <c>-</c>
    /// and <c>_</c>, and the bits of the last character that no octet carries are ignored (Section 3.5: "decoders MAY
    /// chose to reject an encoding if the pad bits have not been set to zero", so a decoder that accepts them conforms).
    /// A text of a length no unpadded encoding has, or holding any other character, is refused with
    /// <see cref="FormatException"/>; the owner it answers holds exactly the decoded octets.
    /// </summary>
    public static DecodeDelegate PermissiveBase64UrlDecoder { get; } = (source, pool) =>
    {
        //RFC 4648 Section 4: a final quantum of 8 bits is two characters and one of 16 bits three, so a text of
        //length 1 modulo 4 encodes no octet sequence.
        int remainder = source.Length % 4;
        if(source.Length == 0 || remainder == 1)
        {
            throw new FormatException("No unpadded base64 text of this length encodes an octet sequence.");
        }

        int octetCount = (source.Length / 4 * 3) + (remainder == 0 ? 0 : remainder - 1);
        IMemoryOwner<byte> owner = pool.Rent(octetCount);
        Span<byte> octets = owner.Memory.Span;
        int accumulator = 0;
        int bitCount = 0;
        int written = 0;
        foreach(char c in source)
        {
            int value = PermissiveBase64Value(c);
            if(value < 0)
            {
                owner.Dispose();
                throw new FormatException($"U+{(int)c:X4} is no base64 or base64url character.");
            }

            accumulator = (accumulator << 6) | value;
            bitCount += 6;
            if(bitCount >= 8)
            {
                bitCount -= 8;
                octets[written++] = (byte)(accumulator >> bitCount);
                accumulator &= (1 << bitCount) - 1;
            }
        }

        //The bitCount bits left are the pad bits of the last character; this decoder ignores them.

        return owner;
    };


    /// <summary>
    /// Writes <paramref name="nonce"/> with its first <c>-</c> or <c>_</c> as the base64 character of the same value,
    /// <c>+</c> or <c>/</c> (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">RFC 4648 Section 4</see>,
    /// Table 1, against Section 5's Table 2): the same octets in a spelling no base64url encoder writes.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it, holding a <c>-</c> or a <c>_</c>.</param>
    /// <returns>The nonce in the base64 spelling of that character.</returns>
    public static string SpellNonceInTheBase64Alphabet(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        int index = nonce.IndexOfAny(['-', '_']);
        if(index < 0)
        {
            throw new AssertFailedException($"The nonce holds no '-' or '_' to spell in the base64 alphabet: '{nonce}'.");
        }

        char base64Character = nonce[index] == '-' ? '+' : '/';

        return string.Concat(nonce.AsSpan(0, index), base64Character.ToString(), nonce.AsSpan(index + 1));
    }


    /// <summary>
    /// Whether <see cref="PermissiveBase64UrlDecoder"/> reads <paramref name="presented"/> as exactly the octets of
    /// <paramref name="supplied"/>, so a row shows that a refusal of the presented spelling is not the decoder's.
    /// </summary>
    /// <param name="presented">The spelling presented.</param>
    /// <param name="supplied">The nonce as the issuer supplied it.</param>
    /// <returns><see langword="true"/> when both texts decode to the same octets.</returns>
    public static bool IsReadAsTheSuppliedOctetsByThePermissiveDecoder(string presented, string supplied)
    {
        ArgumentNullException.ThrowIfNull(presented);
        ArgumentNullException.ThrowIfNull(supplied);

        using IMemoryOwner<byte> presentedOctets = PermissiveBase64UrlDecoder(presented, TestHostShell.MemoryPool);
        using IMemoryOwner<byte> suppliedOctets = PermissiveBase64UrlDecoder(supplied, TestHostShell.MemoryPool);

        return presentedOctets.Memory.Span.SequenceEqual(suppliedOctets.Memory.Span);
    }


    /// <summary>
    /// Fills a nonce's random field with octets whose every bit is set, so the issued nonce's base64url text holds the
    /// character <c>_</c> (value 63, <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section
    /// 5</see>) wherever six of those bits make one character; a row arranges the issued text with it and reads no
    /// randomness from it.
    /// </summary>
    public static FillEntropyDelegate RandomFieldOfOnes { get; } = destination => destination.Fill(0xFF);


    /// <summary>The value of <paramref name="c"/> in RFC 4648 Table 2, or Table 1 for <c>+</c> and <c>/</c>.</summary>
    /// <param name="c">The character.</param>
    /// <returns>The value, 0 to 63, or -1 for any other character.</returns>
    private static int PermissiveBase64Value(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '-' or '+' => 62,
        '_' or '/' => 63,
        _ => -1
    };


    /// <summary>
    /// Writes the octets of <paramref name="nonce"/> followed by one more octet in base64url without padding
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>): a canonical value whose
    /// octets begin with every octet the issuer wrote.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it.</param>
    /// <returns>The extended nonce.</returns>
    public static string ExtendNonceByAnOctet(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        using IMemoryOwner<byte> decoded = TestHostShell.Base64UrlDecoder(nonce, TestHostShell.MemoryPool);
        int length = decoded.Memory.Length;
        using IMemoryOwner<byte> extended = TestHostShell.MemoryPool.Rent(length + 1);
        decoded.Memory.Span.CopyTo(extended.Memory.Span);
        extended.Memory.Span[length] = 0x2A;

        return TestHostShell.Base64UrlEncoder(extended.Memory.Span[..(length + 1)]);
    }


    /// <summary>
    /// Appends to <paramref name="nonce"/> the <c>=</c> padding that
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see> base64url writes to complete
    /// its final group: the same octets in a spelling RFC 7515 Section 2 omits.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it, its length no multiple of four.</param>
    /// <returns>The padded nonce.</returns>
    public static string PadNonce(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        int remainder = nonce.Length % 4;
        if(remainder == 0)
        {
            throw new AssertFailedException($"The nonce ends in a whole base64url group and has no padded spelling: '{nonce}'.");
        }

        return nonce + new string('=', 4 - remainder);
    }


    /// <summary>
    /// Sets the lowest bit of the last character of <paramref name="nonce"/>, a bit no octet carries when the value ends
    /// in a partial group: <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">RFC 4648 Section 3.5</see>,
    /// "These pad bits MUST be set to zero by conforming encoders", so the value is another spelling of the same octets
    /// that no conforming encoder writes.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it, its last group partial.</param>
    /// <returns>The nonce with a pad bit set.</returns>
    public static string SetUnusedBitsOfNonce(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        if(nonce.Length % 4 == 0)
        {
            throw new AssertFailedException($"The nonce ends in a whole base64url group and has no pad bits: '{nonce}'.");
        }

        int last = Base64UrlAlphabet.IndexOf(nonce[^1], StringComparison.Ordinal);
        if(last < 0 || (last & 1) != 0)
        {
            throw new AssertFailedException($"The nonce's last character is no base64url character with its pad bits zero: '{nonce}'.");
        }

        return string.Concat(nonce.AsSpan(0, nonce.Length - 1), Base64UrlAlphabet[last | 1].ToString());
    }


    /// <summary>
    /// Sets the highest of the bits of the last character of <paramref name="nonce"/> that no octet carries, read from
    /// the length of the text: a text of length 2 modulo 4 ends in a final quantum of 8 bits, whose last character
    /// carries two of them and four pad bits, the highest of value <c>0b1000</c>; a text of length 3 modulo 4 ends in a
    /// final quantum of 16 bits, whose last character carries four of them and two pad bits, the highest of value
    /// <c>0b10</c> (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">RFC 4648 Section 4</see>). Section 3.5:
    /// "These pad bits MUST be set to zero by conforming encoders", so the value is another spelling of the same octets
    /// that no conforming encoder writes, and a decoder that ignores pad bits reads it as the supplied octets, while a
    /// pad-bit check whose mask leaves the highest out passes it as the canonical spelling.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it, its last group partial.</param>
    /// <returns>The nonce with the highest pad bit of its last character set.</returns>
    public static string SetHighestUnusedBitOfNonce(string nonce)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        int highestPadBit = (nonce.Length % 4) switch
        {
            2 => 0b1000,
            3 => 0b10,
            _ => throw new AssertFailedException($"The nonce's length is no unpadded base64url length ending in a partial group: '{nonce}'.")
        };

        int last = Base64UrlAlphabet.IndexOf(nonce[^1], StringComparison.Ordinal);
        if(last < 0 || (last & ((highestPadBit << 1) - 1)) != 0)
        {
            throw new AssertFailedException($"The nonce's last character is no base64url character with its pad bits zero: '{nonce}'.");
        }

        return string.Concat(nonce.AsSpan(0, nonce.Length - 1), Base64UrlAlphabet[last | highestPadBit].ToString());
    }


    /// <summary>
    /// Sets one of the bits of the last character of <paramref name="nonce"/> that no octet carries, the one at
    /// <paramref name="padBitIndex"/> counted from the lowest at 0, the count of such bits read from the length of the
    /// text: a text of length 2 modulo 4 ends in a final quantum of 8 bits, whose last character carries two of them and
    /// four pad bits (indexes 0 to 3); a text of length 3 modulo 4 ends in a final quantum of 16 bits, whose last
    /// character carries four of them and two pad bits (indexes 0 and 1)
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-4">RFC 4648 Section 4</see>).
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">RFC 4648 Section 3.5</see>: "only the first two
    /// bits of the next symbol are used. These pad bits MUST be set to zero by conforming encoders", so the value is
    /// another spelling of the same octets that no conforming encoder writes, and a decoder that ignores pad bits reads it
    /// as the supplied octets, while a pad-bit check whose mask leaves that bit out passes it as the canonical spelling.
    /// </summary>
    /// <param name="nonce">The nonce as the issuer supplied it, its last group partial and its pad bits zero.</param>
    /// <param name="padBitIndex">The index of the pad bit to set, counted from the lowest pad bit at 0.</param>
    /// <returns>The nonce with that one pad bit of its last character set.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The last character of <paramref name="nonce"/> carries no pad bit at <paramref name="padBitIndex"/>.</exception>
    public static string SetPadBitOfNonce(string nonce, int padBitIndex)
    {
        ArgumentNullException.ThrowIfNull(nonce);

        int padBitCount = (nonce.Length % 4) switch
        {
            2 => 4,
            3 => 2,
            _ => throw new AssertFailedException($"The nonce's length is no unpadded base64url length ending in a partial group: '{nonce}'.")
        };

        ArgumentOutOfRangeException.ThrowIfNegative(padBitIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(padBitIndex, padBitCount);

        int last = Base64UrlAlphabet.IndexOf(nonce[^1], StringComparison.Ordinal);
        if(last < 0 || (last & ((1 << padBitCount) - 1)) != 0)
        {
            throw new AssertFailedException($"The nonce's last character is no base64url character with its pad bits zero: '{nonce}'.");
        }

        return string.Concat(nonce.AsSpan(0, nonce.Length - 1), Base64UrlAlphabet[last | (1 << padBitIndex)].ToString());
    }


    /// <summary>The base64url alphabet of <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see>, Table 2, in value order.</summary>
    private static string Base64UrlAlphabet { get; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


    /// <summary>The length in bytes of a SHA-256 digest, the hash RFC 9449 Section 4.2 names for <c>ath</c>.</summary>
    private static int Sha256DigestByteLength { get; } = 32;

    /// <summary>The fixed clock the digest provider stamps its event with; the computation reads no time of its own.</summary>
    private static TimeProvider DigestClock { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// Reads the single <c>DPoP-Nonce</c> header of a resource's nonce challenge.
    /// </summary>
    /// <param name="response">The challenge response.</param>
    /// <returns>The nonce the resource provided.</returns>
    public static string ReadNonce(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);

        return response.Headers.TryGetValues("DPoP-Nonce", out IEnumerable<string>? nonces)
            ? nonces.Single()
            : throw new AssertFailedException($"The response ({(int)response.StatusCode}) carries no DPoP-Nonce header.");
    }
}
