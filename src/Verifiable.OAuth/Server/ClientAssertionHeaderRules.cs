using System.Buffers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The rules a client assertion's compact form and protected header break before any key or secret is read, whichever key
/// source or method then verifies it, each naming one fact about the assertion, never a value judged.
/// </summary>
public enum ClientAssertionHeaderRefusal
{
    /// <summary>
    /// The assertion is not a compact JWS of three non-empty base64url segments (RFC 7515 Section 7.1), or it is longer than the
    /// verifier reads: no valid JWT, which RFC 7523 Section 3.2 answers <c>invalid_client</c>.
    /// </summary>
    NotACompactJws,

    /// <summary>The assertion's protected header is not one JSON object naming each member once (RFC 7515 Section 4).</summary>
    HeaderNotAnObject,

    /// <summary>
    /// The protected header names no signature algorithm: its <c>alg</c> is absent, is no string, is empty, or is <c>none</c> in
    /// any letter case (RFC 7515 Section 4.1.1: the parameter "MUST be present"; RFC 7518 Section 3.6; RFC 8725 Section 3.2).
    /// </summary>
    SignatureAlgorithmNotNamed,

    /// <summary>
    /// The protected header carries <c>crit</c>, and this verifier understands no extension it could list (RFC 7515 Section
    /// 4.1.11: "If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS
    /// is invalid"): a list naming an extension, the empty list producers "MUST NOT use", a value that is no list of names, and a
    /// list naming a parameter RFC 7515 or RFC 7518 defines, which the list "MUST NOT include", alike.
    /// </summary>
    CriticalHeaderParameterNotUnderstood
}


/// <summary>
/// The reading of a client assertion's protected header before any key or secret is read (<see cref="ClientAssertionHeaderRules.Read"/>):
/// the header's members and the signature algorithm it names, or the rule refused.
/// </summary>
public sealed record ClientAssertionHeaderReading
{
    /// <summary>Creates a reading.</summary>
    /// <param name="header">The header's members, or <see langword="null"/> where no header object was read.</param>
    /// <param name="algorithm">The algorithm the header names, or <see langword="null"/> for a refusal.</param>
    /// <param name="refusal">The rule refused, or <see langword="null"/> for a header read.</param>
    private ClientAssertionHeaderReading(IReadOnlyDictionary<string, object>? header, string? algorithm, ClientAssertionHeaderRefusal? refusal)
    {
        Header = header;
        Algorithm = algorithm;
        Refusal = refusal;
    }


    /// <summary>
    /// The protected header's members, read unverified and trusted for nothing but what they name: present for a header read as one
    /// JSON object, whatever rule then refused it, so a caller may record what a refused header named; <see langword="null"/> where
    /// the assertion is no compact JWS or its header no object.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Header { get; }

    /// <summary>The signature algorithm the header names, as it spells it; <see langword="null"/> for a refusal.</summary>
    public string? Algorithm { get; }

    /// <summary>The rule refused; <see langword="null"/> for a header read.</summary>
    public ClientAssertionHeaderRefusal? Refusal { get; }


    /// <summary>The reading of a header every rule holds for.</summary>
    /// <param name="header">The header's members.</param>
    /// <param name="algorithm">The algorithm it names.</param>
    /// <returns>The reading.</returns>
    public static ClientAssertionHeaderReading Read(IReadOnlyDictionary<string, object> header, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        return new ClientAssertionHeaderReading(header, algorithm, refusal: null);
    }


    /// <summary>The refusal of an assertion under a rule.</summary>
    /// <param name="refusal">The rule.</param>
    /// <param name="header">The header's members where it was read as one JSON object before the rule refused it, or <see langword="null"/>.</param>
    /// <returns>The reading.</returns>
    public static ClientAssertionHeaderReading Refused(ClientAssertionHeaderRefusal refusal, IReadOnlyDictionary<string, object>? header) =>
        new(header, algorithm: null, refusal);
}


/// <summary>
/// The authorization server's one reading of a client assertion's compact form and protected header before any key or secret is
/// read, shared by every key source and every assertion method - a <c>client_secret_jwt</c> assertion
/// (<see cref="ClientSecretAssertionVerification.AdmitHeader"/>), a <c>private_key_jwt</c> assertion under a published key set
/// (<see cref="PrivateKeyJwtClientAuthentication"/>), and one under a key a host registered for its client alike: the assertion
/// is a compact JWS of three non-empty base64url segments (RFC 7515 Section 7.1) no longer than <see cref="Jws.DefaultMaxJwsLength"/>,
/// its protected header is one JSON object naming each member once (RFC 7515 Section 4), that header names a signature algorithm
/// and not <c>none</c> in any letter case (RFC 7515 Section 4.1.1; RFC 7518 Section 3.6; RFC 8725 Section 3.2), and it lists no
/// critical extension, since this verifier understands none (RFC 7515 Section 4.1.11). Which algorithms are accepted and which key
/// the header selects stay the caller's: the method's policy and the key source's. Nothing the assertion presents throws.
/// </summary>
public static class ClientAssertionHeaderRules
{
    /// <summary>The characters of the base64url alphabet (RFC 4648 Section 5), unpadded as RFC 7515 Section 2 writes a segment.</summary>
    private static SearchValues<char> Base64UrlCharacters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");


    /// <summary>Reads a client assertion's protected header by the rules nothing of a key or a secret decides.</summary>
    /// <param name="clientAssertion">The request's <c>client_assertion</c>.</param>
    /// <param name="base64UrlDecoder">Decodes the protected header segment.</param>
    /// <param name="headerDeserializer">Reads the protected header's members.</param>
    /// <param name="pool">The pool the decoded header is rented from.</param>
    /// <returns>The header and the algorithm it names, or the rule refused.</returns>
    public static ClientAssertionHeaderReading Read(
        string clientAssertion,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(clientAssertion);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        if(clientAssertion.Length > Jws.DefaultMaxJwsLength
            || SigningInputLengthOf(clientAssertion) is not int signingInputLength
            || !IsSignatureSegment(clientAssertion.AsSpan(signingInputLength + 1)))
        {
            return ClientAssertionHeaderReading.Refused(ClientAssertionHeaderRefusal.NotACompactJws, header: null);
        }

        if(ReadHeader(clientAssertion.AsSpan(0, clientAssertion.IndexOf('.', StringComparison.Ordinal)), base64UrlDecoder, headerDeserializer, pool)
            is not { } header)
        {
            return ClientAssertionHeaderReading.Refused(ClientAssertionHeaderRefusal.HeaderNotAnObject, header: null);
        }

        if(SignatureAlgorithmNamedBy(header) is not string algorithm)
        {
            return ClientAssertionHeaderReading.Refused(ClientAssertionHeaderRefusal.SignatureAlgorithmNotNamed, header);
        }

        //RFC 7515 Section 4.1.11: a recipient holds the JWS invalid where it does not understand an extension crit lists, and
        //no extension is understood here, so the parameter's presence alone - whatever it holds - refuses the assertion.
        if(header.ContainsKey(WellKnownJoseHeaderNames.Crit))
        {
            return ClientAssertionHeaderReading.Refused(ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood, header);
        }

        return ClientAssertionHeaderReading.Read(header, algorithm);
    }


    /// <summary>
    /// The length of a compact JWS's signing input - its protected header segment, the period and its payload segment - when the
    /// JWS is three non-empty base64url segments, or <see langword="null"/> when it is not.
    /// </summary>
    /// <param name="compactJws">The compact serialization.</param>
    /// <returns>The signing input's length in characters, each one octet, or <see langword="null"/>.</returns>
    internal static int? SigningInputLengthOf(string compactJws)
    {
        var firstPeriod = compactJws.IndexOf('.', StringComparison.Ordinal);
        var lastPeriod = compactJws.LastIndexOf('.', StringComparison.Ordinal);

        if(firstPeriod <= 0 || lastPeriod <= firstPeriod + 1)
        {
            return null;
        }

        var header = compactJws.AsSpan(0, firstPeriod);
        var payload = compactJws.AsSpan(firstPeriod + 1, lastPeriod - firstPeriod - 1);

        return header.ContainsAnyExcept(Base64UrlCharacters) || payload.ContainsAnyExcept(Base64UrlCharacters)
            ? null
            : lastPeriod;
    }


    /// <summary>Whether a compact JWS's signature segment is non-empty and written in the base64url alphabet (RFC 7515 Section 2).</summary>
    /// <param name="segment">The segment after the signing input's last period.</param>
    /// <returns><see langword="true"/> for a segment that could carry a signature or a MAC.</returns>
    internal static bool IsSignatureSegment(ReadOnlySpan<char> segment) => !segment.IsEmpty && !segment.ContainsAnyExcept(Base64UrlCharacters);


    /// <summary>A base64url segment's octets, or <see langword="null"/> when the decoder refuses it; the caller disposes them.</summary>
    /// <param name="segment">The segment.</param>
    /// <param name="base64UrlDecoder">The decoder.</param>
    /// <param name="pool">The pool the octets are rented from.</param>
    /// <returns>The octets, or <see langword="null"/>.</returns>
    internal static IMemoryOwner<byte>? DecodedOrNull(ReadOnlySpan<char> segment, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        try
        {
            return base64UrlDecoder(segment, pool);
        }
        catch(FormatException)
        {
            return null;
        }
    }


    /// <summary>
    /// The octets an unpadded base64url segment of the given length decodes to: six bits a character, the bits short of a whole
    /// octet at the end dropped.
    /// </summary>
    /// <param name="characters">The segment's length.</param>
    /// <returns>The decoded length.</returns>
    internal static int DecodedLengthOf(int characters) => characters * 3 / 4;


    /// <summary>
    /// The signature algorithm a protected header names, or <see langword="null"/> when it names none: its <c>alg</c> is absent,
    /// is no string, is empty, or is <c>none</c> in any letter case (<see cref="WellKnownJwaValues.IsNoneInAnyLetterCase"/>).
    /// </summary>
    /// <param name="header">The protected header's members.</param>
    /// <returns>The algorithm's name as the header spells it, or <see langword="null"/>.</returns>
    private static string? SignatureAlgorithmNamedBy(IReadOnlyDictionary<string, object> header) =>
        header.TryGetValue(WellKnownJoseHeaderNames.Alg, out var value)
        && value is string { Length: > 0 } algorithm
        && !WellKnownJwaValues.IsNoneInAnyLetterCase(algorithm)
            ? algorithm
            : null;


    /// <summary>
    /// The protected header of a compact JWS, read unverified: the segment base64url-decoded, exactly one JSON object naming each
    /// member once, parsed by the header reader given; <see langword="null"/> for a segment of any other content, never throwing.
    /// </summary>
    /// <param name="segment">The header segment.</param>
    /// <param name="base64UrlDecoder">Decodes the segment.</param>
    /// <param name="headerDeserializer">Reads the object's members.</param>
    /// <param name="pool">The pool the decoded segment is rented from.</param>
    /// <returns>The members, or <see langword="null"/>.</returns>
    private static IReadOnlyDictionary<string, object>? ReadHeader(
        ReadOnlySpan<char> segment, DecodeDelegate base64UrlDecoder, JwtHeaderDeserializer headerDeserializer, BaseMemoryPool pool)
    {
        using var decoded = DecodedOrNull(segment, base64UrlDecoder, pool);

        if(decoded is null)
        {
            return null;
        }

        var octets = decoded.Memory.Span[..DecodedLengthOf(segment.Length)];

        if(octets.TrimStart(" \t\n\r"u8) is not [(byte)'{', ..] || !JwkJsonReader.IsWellFormedJsonDocument(octets))
        {
            return null;
        }

        try
        {
            return headerDeserializer(octets);
        }
        catch(Exception exception) when(exception is FormatException or InvalidOperationException or JsonException)
        {
            return null;
        }
    }
}
