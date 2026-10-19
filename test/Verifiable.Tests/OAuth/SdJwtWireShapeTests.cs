using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json.Sd;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the wire shape of an SD-JWT presentation (RFC 9901 section 4) as the readings that own it refuse it, over presentations an
/// Issuer writes by hand and signs once: the Issuer-signed JWT's protected header segment and each disclosure's elements refused
/// at their readings and carried into the presentation's result as its defect, never thrown out of the verification; a failure of a
/// delegate the default parse composes - the decoder beyond its refusal of text as no base64url, the encoder of the disclosure
/// digests, cancellation - surfacing as the fault it is through the actual default parse; and a status claim whose index lies past
/// the indices the library's lists hold told from a malformed one.
/// </summary>
[TestClass]
internal sealed class SdJwtWireShapeTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The issuer identifier the credentials are issued under.</summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>The credential query the presentations answer.</summary>
    private static CredentialQueryId QueryId { get; } = new("pid");

    /// <summary>The pool every reading rents from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The protected header segment every well-formed Issuer-signed JWT here carries.</summary>
    private static string IssuerHeaderSegment { get; } = Base64Url.EncodeToString(/*lang=json,strict*/ """{"alg":"ES256","typ":"dc+sd-jwt"}"""u8);


    /// <summary>
    /// RFC 7515 sections 2 and 7.1: a compact JWS is three segments of base64url text, and no base64url text is a whole number of
    /// four-character quanta and one character. An Issuer-signed JWT whose protected header segment is one character is refused
    /// as a compact serialization no conformant Wallet produces - by the wire format's own parse, and, behind a parse that admits
    /// it, by the verification's decoding of the header - never reaching the decoder unguarded; the control, the same credential
    /// under a well-formed header, reads.
    /// </summary>
    /// <param name="parser">The parse the verification composes: the library's default one, or one admitting any issuer JWT.</param>
    /// <returns>A task completing once the presentations are read.</returns>
    [TestMethod]
    [DataRow("default", DisplayName = "Through the default parse")]
    [DataRow("admitting", DisplayName = "Behind a parse admitting any issuer JWT")]
    public async Task AnIssuerHeaderSegmentOfOneCharacterIsRefusedByTheReading(string parser)
    {
        var claims = "\"iss\":\"" + IssuerId + "\",\"vct\":\"urn:eudi:pid:1\",\"iat\":1700000000";
        var control = await IssueAsync(IssuerHeaderSegment, claims).ConfigureAwait(false);
        using var controlKey = control.IssuerPublicKey;
        var oneCharacter = await IssueAsync("e", claims).ConfigureAwait(false);
        using var oneCharacterKey = oneCharacter.IssuerPublicKey;
        ParseSdJwtTokenDelegate parse = parser is "default" ? DefaultParse(TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder) : AdmittingParse;

        var controlRead = await ReadAsync(control.Presentation, controlKey, parse).ConfigureAwait(false);
        var read = await ReadAsync(oneCharacter.Presentation, oneCharacterKey, parse).ConfigureAwait(false);

        Assert.IsTrue(controlRead.IsSuccess, "The control: the same credential under a well-formed header reads.");
        Assert.IsFalse(read.IsSuccess, parser);
        Assert.AreEqual(SdJwtPresentationDefect.CompactSerializationMalformed, read.Error, parser);
    }


    /// <summary>
    /// RFC 9901 sections 4.2.1 and 4.2.2: a disclosure is a JSON array whose salt and, for an object property, claim name are JSON
    /// strings. A disclosure carrying a number for either is refused by the disclosure's reading as a compact serialization no
    /// conformant Wallet produces, carried into the presentation's result; the control, the same disclosure with string elements,
    /// reads and is disclosed.
    /// </summary>
    /// <param name="disclosureCase">The element the disclosure carries as a number.</param>
    /// <returns>A task completing once the presentations are read.</returns>
    [TestMethod]
    [DataRow("salt", DisplayName = "A numeric salt")]
    [DataRow("claim-name", DisplayName = "A numeric claim name")]
    public async Task ADisclosureElementOfAnotherKindIsRefusedByTheDisclosuresReading(string disclosureCase)
    {
        var controlDisclosure = /*lang=json,strict*/ """["c2FsdC1vZi10aGUtY29udHJvbA","given_name","Erika"]""";
        var malformedDisclosure = disclosureCase switch
        {
            "salt" => /*lang=json,strict*/ """[7,"given_name","Erika"]""",
            "claim-name" => /*lang=json,strict*/ """["c2FsdC1vZi10aGUtcm93",7,"Erika"]""",
            _ => throw new ArgumentOutOfRangeException(nameof(disclosureCase), disclosureCase, "No disclosure is named so.")
        };

        var control = await IssueWithDisclosureAsync(controlDisclosure).ConfigureAwait(false);
        using var controlKey = control.IssuerPublicKey;
        var malformed = await IssueWithDisclosureAsync(malformedDisclosure).ConfigureAwait(false);
        using var malformedKey = malformed.IssuerPublicKey;
        var parse = DefaultParse(TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder);

        var controlRead = await ReadAsync(control.Presentation, controlKey, parse).ConfigureAwait(false);
        var read = await ReadAsync(malformed.Presentation, malformedKey, parse).ConfigureAwait(false);

        Assert.IsTrue(controlRead.IsSuccess, "The control: the disclosure with string elements reads.");
        Assert.HasCount(1, controlRead.Value.Credential.Extracted, "The control's disclosure is disclosed.");
        Assert.IsFalse(read.IsSuccess, disclosureCase);
        Assert.AreEqual(SdJwtPresentationDefect.CompactSerializationMalformed, read.Error, disclosureCase);
    }


    /// <summary>
    /// The default parse (<see cref="SdJwtSerializer.ParseToken"/>) answers the decoder's refusal of a disclosure as no base64url
    /// text, its <see cref="FormatException"/>, as the wire's refusal, which the verification carries as a malformed compact
    /// serialization; every other failure of a delegate it composes surfaces through the verification as the fault it is - an
    /// <see cref="InvalidOperationException"/> of the decoder, the decoder's <see cref="OperationCanceledException"/>, and a
    /// <see cref="FormatException"/> of the encoder computing the disclosure's digest, which is no refusal of the wire.
    /// </summary>
    /// <param name="faultCase">The delegate and the exception it fails with.</param>
    /// <returns>A task completing once the presentation is read.</returns>
    [TestMethod]
    [DataRow("decoder-refusal", DisplayName = "The decoder refuses the disclosure as no base64url text")]
    [DataRow("decoder-fault", DisplayName = "The decoder fails for the disclosure")]
    [DataRow("decoder-cancellation", DisplayName = "The decoder is cancelled on the disclosure")]
    [DataRow("encoder-format-fault", DisplayName = "The digest encoder fails with a FormatException")]
    public async Task ACallbackFaultSurfacesThroughTheDefaultParseAndItsRefusalIsTheWires(string faultCase)
    {
        var disclosure = /*lang=json,strict*/ """["c2FsdC1vZi10aGUtZmF1bHQ","given_name","Erika"]""";
        var issued = await IssueWithDisclosureAsync(disclosure).ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;
        var encodedDisclosure = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(disclosure));

        var parse = faultCase switch
        {
            "decoder-refusal" => DefaultParse(DecoderFailingOn(encodedDisclosure, static () => new FormatException("No base64url text.")), TestSetup.Base64UrlEncoder),
            "decoder-fault" => DefaultParse(DecoderFailingOn(encodedDisclosure, static () => new InvalidOperationException("The decoder failed.")), TestSetup.Base64UrlEncoder),
            "decoder-cancellation" => DefaultParse(DecoderFailingOn(encodedDisclosure, static () => new OperationCanceledException("The decoding was cancelled.")), TestSetup.Base64UrlEncoder),
            "encoder-format-fault" => DefaultParse(TestSetup.Base64UrlDecoder, static _ => throw new FormatException("The encoder failed.")),
            _ => throw new ArgumentOutOfRangeException(nameof(faultCase), faultCase, "No fault is named so.")
        };

        switch(faultCase)
        {
            case "decoder-refusal":
                var refused = await ReadAsync(issued.Presentation, issuerKey, parse).ConfigureAwait(false);
                Assert.AreEqual(SdJwtPresentationDefect.CompactSerializationMalformed, refused.Error, "The decoder's refusal is the wire's.");
                break;
            case "decoder-fault":
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => ReadAsync(issued.Presentation, issuerKey, parse)).ConfigureAwait(false);
                break;
            case "decoder-cancellation":
                _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => ReadAsync(issued.Presentation, issuerKey, parse)).ConfigureAwait(false);
                break;
            default:
                _ = await Assert.ThrowsExactlyAsync<FormatException>(() => ReadAsync(issued.Presentation, issuerKey, parse)).ConfigureAwait(false);
                break;
        }
    }


    /// <summary>
    /// Token Status List section 6.2: the <c>idx</c> is a non-negative integer, bounded from below alone. A credential whose index
    /// is the largest a list the library holds is read with its reference; one whose index is one past it carries a well-formed
    /// claim whose status the library cannot check, answered as that defect - which the executors route as an undeterminable
    /// status - never as a malformed status claim; a negative index is a malformed one.
    /// </summary>
    /// <param name="indexJson">The <c>idx</c> as the Issuer writes it.</param>
    /// <param name="expected">What the reading answers: <c>read</c>, or the defect's name.</param>
    /// <returns>A task completing once the presentation is read.</returns>
    [TestMethod]
    [DataRow("2147483647", "read", DisplayName = "The largest index a list holds")]
    [DataRow("2147483648", nameof(SdJwtPresentationDefect.StatusIndexBeyondCapacity), DisplayName = "One past the largest index a list holds")]
    [DataRow("-1", nameof(SdJwtPresentationDefect.StatusClaimMalformed), DisplayName = "A negative index")]
    public async Task AStatusIndexPastTheListsCapacityIsToldFromAMalformedClaim(string indexJson, string expected)
    {
        var issued = await IssueAsync(
            IssuerHeaderSegment,
            "\"iss\":\"" + IssuerId + "\",\"vct\":\"urn:eudi:pid:1\",\"iat\":1700000000,\"status\":{\"status_list\":{\"idx\":" + indexJson + ",\"uri\":\"https://issuer.example.com/statuslists/1\"}}")
            .ConfigureAwait(false);
        using var issuerKey = issued.IssuerPublicKey;

        var read = await ReadAsync(issued.Presentation, issuerKey, DefaultParse(TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder)).ConfigureAwait(false);

        if(expected is "read")
        {
            Assert.IsTrue(read.IsSuccess, indexJson);
            Assert.AreEqual(int.MaxValue, read.Value.Credential.Status?.StatusList?.Index, indexJson);

            return;
        }

        Assert.IsFalse(read.IsSuccess, indexJson);
        Assert.AreEqual(Enum.Parse<SdJwtPresentationDefect>(expected), read.Error, indexJson);
    }


    /// <summary>The library's default parse of the wire format, composing the decoder and the encoder given.</summary>
    /// <param name="decoder">The decoder the parse composes.</param>
    /// <param name="encoder">The encoder the parse computes the disclosure digests with.</param>
    /// <returns>The parse.</returns>
    private static ParseSdJwtTokenDelegate DefaultParse(DecodeDelegate decoder, EncodeDelegate encoder) =>
        serialized => SdJwtSerializer.ParseToken(serialized, decoder, encoder, Pool, TestSalts.TestSaltTag, WellKnownHashAlgorithms.Sha256Iana);


    /// <summary>A parse admitting any issuer JWT: the presentation's text before its first separator, carrying no disclosure.</summary>
    /// <param name="serialized">The presentation.</param>
    /// <returns>The token.</returns>
    private static SdToken<string> AdmittingParse(string serialized) => new(serialized.Split('~')[0], []);


    /// <summary>A decoder decoding as the library's test wiring does, except that it fails for one text with the exception given.</summary>
    /// <param name="failingText">The text it fails for.</param>
    /// <param name="failure">The exception it fails with.</param>
    /// <returns>The decoder.</returns>
    private static DecodeDelegate DecoderFailingOn(string failingText, Func<Exception> failure) => (source, pool) =>
        source.SequenceEqual(failingText) ? throw failure() : TestSetup.Base64UrlDecoder(source, pool);


    /// <summary>Reads a presentation with the parse given and a trust framework resolving the issuer key given.</summary>
    /// <param name="presentation">The presentation.</param>
    /// <param name="issuerKey">The issuer key.</param>
    /// <param name="parse">The parse of the wire format.</param>
    /// <returns>The reading.</returns>
    private async Task<Result<VpTokenParsed, SdJwtPresentationDefect>> ReadAsync(string presentation, PublicKeyMemory issuerKey, ParseSdJwtTokenDelegate parse) =>
        await SdJwtVpTokenVerification.VerifyAsync(
            presentation,
            QueryId,
            parse,
            static token => SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder),
            (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(issuerKey),
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            saltReuseSeam: null,
            parseX5c: null,
            resolveTrustedAuthorityEvidence: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// The Issuer writes a credential selectively disclosing one claim by the disclosure's JSON text given: the disclosure encoded
    /// as base64url, its digest (RFC 9901 section 4.2.3, SHA-256 over the encoded text) in the claims set's <c>_sd</c>, and the
    /// presentation the Issuer-signed JWT, the disclosure and the closing separator.
    /// </summary>
    /// <param name="disclosureJson">The disclosure's JSON text.</param>
    /// <returns>The issued credential.</returns>
    private async Task<HandIssuedCredential> IssueWithDisclosureAsync(string disclosureJson)
    {
        var encodedDisclosure = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(disclosureJson));
        var digest = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(encodedDisclosure)));
        var issued = await IssueAsync(
            IssuerHeaderSegment,
            "\"iss\":\"" + IssuerId + "\",\"vct\":\"urn:eudi:pid:1\",\"iat\":1700000000,\"_sd_alg\":\"sha-256\",\"_sd\":[\"" + digest + "\"]")
            .ConfigureAwait(false);

        return issued with { Presentation = issued.IssuerSignedJwt + "~" + encodedDisclosure + "~" };
    }


    /// <summary>
    /// Signs the claims set of the members given under a fresh P-256 Issuer key, over the exact protected header segment given and
    /// the claims set's bytes; the presentation is the Issuer-signed JWT and its separator.
    /// </summary>
    /// <param name="headerSegment">The protected header segment as the Issuer writes it.</param>
    /// <param name="members">The claims set's members' JSON text.</param>
    /// <returns>The issued credential.</returns>
    private async Task<HandIssuedCredential> IssueAsync(string headerSegment, string members)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var issuerPrivateKey = issuerKeys.PrivateKey;

        var signingInput = headerSegment + "." + Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{" + members + "}"));

        using var signature = await issuerPrivateKey.SignAsync(Encoding.ASCII.GetBytes(signingInput), Pool, TestContext.CancellationToken).ConfigureAwait(false);
        var issuerSignedJwt = signingInput + "." + Base64Url.EncodeToString(signature.AsReadOnlySpan());

        return new HandIssuedCredential(issuerSignedJwt, issuerSignedJwt + "~", issuerKeys.PublicKey);
    }
}
