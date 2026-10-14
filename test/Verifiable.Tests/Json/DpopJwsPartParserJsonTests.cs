using System.Text;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.Json;

/// <summary>
/// The rows of <see cref="DpopJwsPartParserJson.Default"/>, the library's reading of the protected header and the
/// payload of a DPoP proof (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>),
/// each over hand-written UTF-8 JSON, since a proof builder writes a dictionary and can neither repeat a member name nor
/// carry a member of a JSON type its model does not hold.
/// </summary>
[TestClass]
internal sealed class DpopJwsPartParserJsonTests
{
    /// <summary>
    /// The members of the P-256 public key the header rows carry in their <c>jwk</c>, from RFC 9449 Figure 4. A constant,
    /// not a property, because the data rows' attribute arguments are composed of it and must be constants.
    /// </summary>
    private const string EcJwkMembers =
        "\"kty\":\"EC\",\"x\":\"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs\",\"y\":\"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA\",\"crv\":\"P-256\"";


    /// <summary>
    /// The reverse solidus that opens a JSON escape, kept apart from the escape's letters so the data rows spell an
    /// escape sequence as JSON text. A constant, not a property, because the data rows' attribute arguments are composed
    /// of it and must be constants.
    /// </summary>
    private const string Backslash = "\\";

    /// <summary>
    /// The JSON escape of the UTF-16 code unit D800 standing alone, a high surrogate with no low surrogate after it. A
    /// constant, not a property, because the data rows' attribute arguments are composed of it and must be constants.
    /// </summary>
    private const string EscapedUnpairedSurrogate = Backslash + "uD800";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515 Section 4</see>: "The Header Parameter
    /// names within the JOSE Header MUST be unique; JWS parsers MUST either reject JWSs with duplicate Header Parameter
    /// names or use a JSON parser that returns only the lexically last duplicate member name". A header that names
    /// <c>alg</c> twice is refused with <see cref="FormatException"/>.
    /// </summary>
    [TestMethod]
    public void AHeaderThatRepeatsAParameterNameIsRefused()
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"alg\":\"ES384\",\"jwk\":{" + EcJwkMembers + "}}")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519 Section 4</see>: "The Claim Names within a
    /// JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON parser
    /// that returns only the lexically last duplicate member name". A payload that names <c>jti</c> twice is refused
    /// with <see cref="FormatException"/>.
    /// </summary>
    [TestMethod]
    public void AClaimsSetThatRepeatsAClaimNameIsRefused()
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseClaims(Utf8(
            "{\"jti\":\"-BwC3ESc6acc2lTc\",\"jti\":\"other\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":1562262616}")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see>: "The member names within a
    /// JWK MUST be unique; JWK parsers MUST either reject JWKs with duplicate member names or use a JSON parser that
    /// returns only the lexically last duplicate member name". A header whose <c>jwk</c> names <c>x</c> twice is refused
    /// with <see cref="FormatException"/>.
    /// </summary>
    [TestMethod]
    public void AJwkThatRepeatsAMemberNameIsRefused()
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + ",\"x\":\"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs\"}}")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: ... 7. The jwk JOSE Header Parameter does not contain a
    /// private key." A member that names private key material is kept whatever JSON type it is written in, so that check
    /// reads it: <c>oth</c>, which <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7">RFC 7518 Section
    /// 6.3.2.7</see> defines as an array ("The "oth" (other primes info) parameter contains an array of information about
    /// any third and subsequent primes"), and <c>d</c> written as a JSON number. A header whose <c>jwk</c> carries either
    /// beside the members of an EC public key is read with that member in its <c>jwk</c>.
    /// </summary>
    /// <param name="member">The private member's name.</param>
    /// <param name="value">The member's JSON value.</param>
    [TestMethod]
    [DataRow("oth", "[{\"r\":\"AQAB\",\"d\":\"AQAB\",\"t\":\"AQAB\"}]", DisplayName = "oth an array")]
    [DataRow("d", "1", DisplayName = "d a JSON number")]
    public void AJwkMemberNamingPrivateMaterialIsKeptWhateverItsJsonType(string member, string value)
    {
        DpopProofHeader header = DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + ",\"" + member + "\":" + value + "}}"));

        Assert.IsTrue(header.Jwk.ContainsKey(member), $"The jwk keeps the private member '{member}'.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 Section 4.2</see>: "The "use" (public key
    /// use) parameter identifies the intended use of the public key. ... The "use" value is a case-sensitive string." A
    /// <c>use</c> member is one the reading understands, so it is kept whatever JSON type it is written in, as its raw
    /// JSON text, and the validator's check of the public key's use reads it: a header whose <c>jwk</c> carries
    /// <c>"use": 1</c> or <c>"use": ["sig"]</c> beside the members of an EC public key is read with <c>use</c> in its
    /// <c>jwk</c>, its value that JSON text.
    /// </summary>
    /// <param name="value">The <c>use</c> member's JSON value.</param>
    [TestMethod]
    [DataRow("1", DisplayName = "use a JSON number")]
    [DataRow("[\"sig\"]", DisplayName = "use a JSON array")]
    public void AJwkUseMemberIsKeptWhateverItsJsonType(string value)
    {
        DpopProofHeader header = DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + ",\"use\":" + value + "}}"));

        Assert.IsTrue(header.Jwk.TryGetValue("use", out string? use), "The jwk keeps the member 'use'.");
        Assert.AreEqual(value, use);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see>: "the ABNF in this
    /// specification allows member names and string values to contain bit sequences that cannot encode Unicode
    /// characters ... The behavior of software that receives JSON texts containing such values is unpredictable". A
    /// segment carrying the JSON escape of an unpaired UTF-16 surrogate encodes no Unicode text, so it is refused as the
    /// reading's every refusal is, with <see cref="FormatException"/>: a header whose <c>alg</c> value is that escape,
    /// and a header whose <c>jwk</c> carries a member whose name is that escape.
    /// </summary>
    /// <param name="json">The header's JSON.</param>
    [TestMethod]
    [DataRow("{\"typ\":\"dpop+jwt\",\"alg\":\"" + EscapedUnpairedSurrogate + "\",\"jwk\":{" + EcJwkMembers + "}}", DisplayName = "alg an escaped unpaired surrogate")]
    [DataRow("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + ",\"" + EscapedUnpairedSurrogate + "\":\"AQAB\"}}", DisplayName = "a jwk member name an escaped unpaired surrogate")]
    public void AMemberWhoseEscapesEncodeNoUnicodeTextIsRefused(string json)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseHeader(Utf8(json)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 Section 4</see>: "Additional members can
    /// be present in the JWK; if not understood by implementations encountering them, they MUST be ignored." A header
    /// whose <c>jwk</c> carries the array members <c>key_ops</c> and <c>x5c</c> beside the members of an EC public key
    /// is read, and its <c>jwk</c> holds the four string members <c>kty</c>, <c>x</c>, <c>y</c> and <c>crv</c> alone.
    /// </summary>
    [TestMethod]
    public void AJwkMemberOfAnotherJsonTypeIsIgnoredAndItsStringMembersAreRead()
    {
        DpopProofHeader header = DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers
            + ",\"key_ops\":[\"verify\"],\"x5c\":[\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\"]}}"));

        Assert.HasCount(4, header.Jwk);
        Assert.AreEqual("EC", header.Jwk["kty"]);
        Assert.AreEqual("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", header.Jwk["x"]);
        Assert.AreEqual("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA", header.Jwk["y"]);
        Assert.AreEqual("P-256", header.Jwk["crv"]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The JOSE Header of a
    /// DPoP JWT MUST contain at least the following parameters: ... jwk: Represents the public key chosen by the client
    /// in JSON Web Key (JWK) [RFC7517] format". A header whose <c>jwk</c> is a JSON string, and a header with no
    /// <c>jwk</c>, carry no JWK and are refused with <see cref="FormatException"/>.
    /// </summary>
    /// <param name="json">The header's JSON.</param>
    [TestMethod]
    [DataRow("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":\"EC\"}", DisplayName = "jwk a JSON string")]
    [DataRow("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}", DisplayName = "no jwk")]
    public void AJwkThatIsNoJsonObjectOrIsAbsentIsRefused(string json)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseHeader(Utf8(json)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The JOSE Header of a
    /// DPoP JWT MUST contain at least the following parameters: typ ... alg ... jwk". The header of Figure 4 is read
    /// into <c>typ</c> <c>dpop+jwt</c>, <c>alg</c> <c>ES256</c> and the four members of its <c>jwk</c>.
    /// </summary>
    [TestMethod]
    public void TheHeaderIsReadIntoItsMembers()
    {
        DpopProofHeader header = DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + "}}"));

        Assert.AreEqual("dpop+jwt", header.Typ);
        Assert.AreEqual("ES256", header.Alg);
        Assert.HasCount(4, header.Jwk);
        Assert.AreEqual("P-256", header.Jwk["crv"]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 4: "The typ JOSE
    /// Header Parameter has the value dpop+jwt." A header with no <c>typ</c> is read with the empty <c>typ</c>, a value
    /// that check refuses, so the validator, not the reading, answers it.
    /// </summary>
    [TestMethod]
    public void AHeaderWithoutTypIsReadWithAnEmptyTyp()
    {
        DpopProofHeader header = DpopJwsPartParserJson.Default.ParseHeader(Utf8(
            "{\"alg\":\"ES256\",\"jwk\":{" + EcJwkMembers + "}}"));

        Assert.AreEqual(string.Empty, header.Typ);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The payload of a DPoP
    /// proof MUST contain at least the following claims: jti ... htm ... htu ... iat", with <c>ath</c> and <c>nonce</c>
    /// when the proof is presented with an access token or after a nonce was provided. A payload carrying all six is
    /// read into each of them, <c>iat</c> as the instant 1562262616 seconds after the epoch.
    /// </summary>
    [TestMethod]
    public void TheClaimsAreReadIntoTheirMembers()
    {
        DpopProofClaims claims = DpopJwsPartParserJson.Default.ParseClaims(Utf8(
            "{\"jti\":\"-BwC3ESc6acc2lTc\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":1562262616,"
            + "\"nonce\":\"eyJ7S_zG.eyJH0-Z.HX4w-7v\",\"ath\":\"fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo\"}"));

        Assert.AreEqual("-BwC3ESc6acc2lTc", claims.Jti);
        Assert.AreEqual("POST", claims.Htm);
        Assert.AreEqual("https://server.example.com/token", claims.Htu);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(1562262616), claims.Iat);
        Assert.AreEqual("eyJ7S_zG.eyJH0-Z.HX4w-7v", claims.Nonce);
        Assert.AreEqual("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", claims.Ath);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The payload of a DPoP
    /// proof MUST contain at least the following claims: jti ... htm ... htu ... iat", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 3: "All required claims
    /// per Section 4.2 are contained in the JWT." A payload missing any one of the four is refused with
    /// <see cref="FormatException"/>.
    /// </summary>
    /// <param name="missingClaim">The required claim the payload leaves out.</param>
    [TestMethod]
    [DataRow("jti")]
    [DataRow("htm")]
    [DataRow("htu")]
    [DataRow("iat")]
    public void AClaimsSetWithoutARequiredClaimIsRefused(string missingClaim)
    {
        Dictionary<string, string> members = new(StringComparer.Ordinal)
        {
            ["jti"] = "\"-BwC3ESc6acc2lTc\"",
            ["htm"] = "\"POST\"",
            ["htu"] = "\"https://server.example.com/token\"",
            ["iat"] = "1562262616"
        };
        _ = members.Remove(missingClaim);
        string json = "{" + string.Join(',', members.Select(static member => $"\"{member.Key}\":{member.Value}")) + "}";

        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseClaims(Utf8(json)));
    }


    /// <summary>
    /// A member of another JSON type than the one its definition names is refused with <see cref="FormatException"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>, "The "alg" value
    /// is a case-sensitive ASCII string containing a StringOrURI value."; RFC 7519
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of <c>iat</c>: "Its value
    /// MUST be a number containing a NumericDate value."; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">Section 4.1.7</see>: "The "jti" value is a
    /// case-sensitive string." The rows: <c>alg</c> a JSON number, <c>iat</c> a JSON string, <c>jti</c> a JSON number.
    /// </summary>
    /// <param name="segment">Which segment the JSON is.</param>
    /// <param name="json">The segment's JSON.</param>
    [TestMethod]
    [DataRow("header", "{\"typ\":\"dpop+jwt\",\"alg\":-7,\"jwk\":{" + EcJwkMembers + "}}", DisplayName = "alg a JSON number")]
    [DataRow("payload", "{\"jti\":\"-BwC3ESc6acc2lTc\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":\"1562262616\"}", DisplayName = "iat a JSON string")]
    [DataRow("payload", "{\"jti\":96,\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":1562262616}", DisplayName = "jti a JSON number")]
    public void AMemberOfAnotherJsonTypeThanItsDefinitionNamesIsRefused(string segment, string json)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => Parse(segment, json));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 2: "The DPoP
    /// HTTP request header field value is a single and well-formed JWT.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 Section 7.2</see>: "Verify that the
    /// resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object conforming to RFC
    /// 7159 [RFC7159]", for the JOSE Header and for the JWT Claims Set alike. A header that is a JSON array, and a
    /// payload that is not JSON, are refused with <see cref="FormatException"/>.
    /// </summary>
    /// <param name="segment">Which segment the text is.</param>
    /// <param name="text">The segment's text.</param>
    [TestMethod]
    [DataRow("header", "[\"ES256\"]", DisplayName = "a header that is a JSON array")]
    [DataRow("payload", "jti=-BwC3ESc6acc2lTc", DisplayName = "a payload that is not JSON")]
    public void ASegmentThatIsNoJsonObjectIsRefused(string segment, string text)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => Parse(segment, text));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>, NumericDate: "A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time, ignoring leap seconds. This is equivalent to the IEEE Std 1003.1, 2013 Edition [POSIX.1] definition
    /// "Seconds Since the Epoch", in which each day is accounted for by exactly 86400 seconds, other than that
    /// non-integer values can be represented." A payload's <c>iat</c> is read as the whole second its number, as
    /// written, falls in: 1562262616.75 and 1562262616.99999999 as 1562262616 seconds after the epoch, -0.5 as the second
    /// before the epoch, 253402300799.99999 as 253402300799 (9999-12-31T23:59:59Z), and the exponent form 1.5e9 as
    /// 1500000000; and the same whole second whatever the number of its fraction's digits:
    /// 1562262616.999999999999999999999999999999 as 1562262616, -0.000000000000000000000000000001 as the second before
    /// the epoch, and 253402300799.999999999999999999999999 as 253402300799; and the same whole second whatever the
    /// exponent that places the point (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">RFC 8259 Section
    /// 6</see>: "A number is represented in base 10 using decimal digits. It contains an integer component that may be
    /// prefixed with an optional minus sign, which may be followed by a fraction part and/or an exponent part."): 15e8 as
    /// 1500000000, 15622626165e-1 and 1562262616.5e0 as 1562262616, -0e0 and 0.0 as the epoch, 1e-400 as the epoch and
    /// -1e-400 as the second before it, and a fraction of forty nines after 1562262616 as 1562262616.
    /// </summary>
    /// <param name="iat">The <c>iat</c> number as written in the payload.</param>
    /// <param name="expectedSeconds">The whole seconds from the epoch the number is read as.</param>
    [TestMethod]
    [DataRow("1562262616.75", 1562262616L, DisplayName = "a quarter second short of the next")]
    [DataRow("1562262616.99999999", 1562262616L, DisplayName = "a near-integer fraction")]
    [DataRow("-0.5", -1L, DisplayName = "a negative fraction")]
    [DataRow("253402300799.99999", 253402300799L, DisplayName = "the greatest representable second")]
    [DataRow("1.5e9", 1500000000L, DisplayName = "an exponent form")]
    [DataRow("1562262616.999999999999999999999999999999", 1562262616L, DisplayName = "a fraction of thirty nines")]
    [DataRow("-0.000000000000000000000000000001", -1L, DisplayName = "a negative fraction of thirty digits")]
    [DataRow("253402300799.999999999999999999999999", 253402300799L, DisplayName = "the greatest representable second with twenty-four nines")]
    [DataRow("15e8", 1500000000L, DisplayName = "an integer with a positive exponent")]
    [DataRow("15622626165e-1", 1562262616L, DisplayName = "an integer with a negative exponent")]
    [DataRow("1562262616.5e0", 1562262616L, DisplayName = "a fraction with a zero exponent")]
    [DataRow("-0e0", 0L, DisplayName = "a negative zero with an exponent")]
    [DataRow("0.0", 0L, DisplayName = "a zero with a fraction")]
    [DataRow("1e-400", 0L, DisplayName = "a positive value below any second")]
    [DataRow("-1e-400", -1L, DisplayName = "a negative value above the second before the epoch")]
    [DataRow("1562262616.9999999999999999999999999999999999999999", 1562262616L, DisplayName = "a fraction of forty nines")]
    public void AnIatWithAFractionIsReadToTheWholeSecondItFallsIn(string iat, long expectedSeconds)
    {
        DpopProofClaims claims = DpopJwsPartParserJson.Default.ParseClaims(Utf8(
            "{\"jti\":\"-BwC3ESc6acc2lTc\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":" + iat + "}"));

        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(expectedSeconds), claims.Iat);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>, NumericDate: "A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time". A payload whose <c>iat</c> is 253402300800, the first second after 9999-12-31T23:59:59Z, names a
    /// date/time the reading holds no instant for and is refused with <see cref="FormatException"/>.
    /// </summary>
    [TestMethod]
    public void AnIatPastTheGreatestRepresentableSecondIsRefused()
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseClaims(Utf8(
            "{\"jti\":\"-BwC3ESc6acc2lTc\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":253402300800}")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>, NumericDate: "A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time". A payload whose <c>iat</c> is a number of more whole seconds than 9999-12-31T23:59:59Z, written with
    /// a fraction or an exponent, names a date/time the reading holds no instant for and is refused with
    /// <see cref="FormatException"/>: 1e400, a whole part of thirteen digits before a fraction, and an exponent beyond
    /// the 32-bit integers.
    /// </summary>
    /// <param name="iat">The <c>iat</c> number as written in the payload.</param>
    [TestMethod]
    [DataRow("1e400", DisplayName = "an exponent of four hundred")]
    [DataRow("1000000000000.5", DisplayName = "a whole part of thirteen digits")]
    [DataRow("1e99999999999", DisplayName = "an exponent beyond the 32-bit integers")]
    public void AnIatWrittenBeyondTheGreatestRepresentableSecondIsRefused(string iat)
    {
        _ = Assert.ThrowsExactly<FormatException>(() => DpopJwsPartParserJson.Default.ParseClaims(Utf8(
            "{\"jti\":\"-BwC3ESc6acc2lTc\",\"htm\":\"POST\",\"htu\":\"https://server.example.com/token\",\"iat\":" + iat + "}")));
    }


    /// <summary>Reads <paramref name="json"/> as the segment <paramref name="segment"/> names.</summary>
    /// <param name="segment"><c>header</c> or <c>payload</c>.</param>
    /// <param name="json">The segment's text.</param>
    /// <returns>The value read.</returns>
    private static object Parse(string segment, string json) => segment switch
    {
        "header" => DpopJwsPartParserJson.Default.ParseHeader(Utf8(json)),
        "payload" => DpopJwsPartParserJson.Default.ParseClaims(Utf8(json)),
        _ => throw new ArgumentOutOfRangeException(nameof(segment), segment, "No such segment.")
    };


    /// <summary>The UTF-8 bytes of <paramref name="text"/>, the form a decoded proof segment reaches the parser in.</summary>
    /// <param name="text">The text.</param>
    /// <returns>The bytes.</returns>
    private static ReadOnlyMemory<byte> Utf8(string text) => Encoding.UTF8.GetBytes(text);
}
