using Microsoft.Extensions.Time.Testing;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the authorization server's check of a <c>client_secret_jwt</c> assertion's MAC
/// (<see cref="ClientSecretAssertionVerification"/>) against the client's one composition
/// (<see cref="ClientAssertionCredential.OfClientSecret"/> through <see cref="ClientAssertionSigning"/>): an assertion the
/// composition MACed verifies under the same secret and algorithm, and every other assertion is refused typed - another
/// secret's, one whose payload or MAC changed, one under an algorithm that is no HMAC algorithm, one checked under a secret
/// shorter than the hash output, and one that is no compact JWS.
/// </summary>
[TestClass]
internal sealed class ClientSecretAssertionVerificationTests
{
    /// <summary>The test context, carrying the cancellation token every call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the assertions' claims are computed from.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The pool every buffer is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier the assertions name.</summary>
    private const string ClientId = "https://client.example.com";

    /// <summary>The token endpoint the assertions are audienced at.</summary>
    private const string TokenEndpoint = "https://as.example.com/token";

    /// <summary>A secret of 64 octets, long enough for every HMAC algorithm of RFC 7518 Section 3.2.</summary>
    private const string LongClientSecret = "client-secret-the-authorization-server-issued-0123456789abcdefgh";

    /// <summary>Another secret of 64 octets, the one an assertion is checked under when it was MACed under the first.</summary>
    private const string AnotherClientSecret = "another-secret-the-authorization-server-issued-0123456789abcdefg";

    /// <summary>Serializes a protected header.</summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serializes a claims set.</summary>
    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// The round trip: an assertion the client's composition MACed under a secret verifies under that secret and algorithm,
    /// for each of RFC 7518 Section 3.2's three algorithms, and the verdict names the algorithm.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    [TestMethod]
    [DataRow("HS256")]
    [DataRow("HS384")]
    [DataRow("HS512")]
    public async Task AnAssertionTheCompositionMacedVerifiesUnderItsSecret(string algorithm)
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, algorithm).ConfigureAwait(false);

        var verdict = await VerifyAsync(assertion, secret, algorithm).ConfigureAwait(false);

        Assert.IsTrue(verdict.IsSuccess, "The composition's own MAC verifies under its secret.");
        Assert.AreEqual(algorithm, verdict.Value);
    }


    /// <summary>
    /// RFC 7523 Section 3 item 9: an assertion MACed under one secret is refused under another of the same length, typed
    /// <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/> naming the algorithm.
    /// </summary>
    [TestMethod]
    public async Task AnAssertionUnderAnotherSecretIsRefused()
    {
        using var secret = SecretOf(LongClientSecret);
        using var another = SecretOf(AnotherClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        var verdict = await VerifyAsync(assertion, another, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        Assert.IsFalse(verdict.IsSuccess, "Another secret verifies no MAC of this one.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        Assert.AreEqual(WellKnownJwaValues.Hs256, verdict.Error.Algorithm);
    }


    /// <summary>
    /// The MAC covers the signing input: an assertion whose payload segment is another one's, or whose MAC lost an octet or
    /// carries an extra one, is refused <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/>, while the
    /// assertion itself still verifies, so each refusal is the change's.
    /// </summary>
    [TestMethod]
    public async Task AnAssertionWhosePayloadOrMacChangedIsRefused()
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var other = await ComposeAsync(secret, WellKnownJwaValues.Hs256, "another-jti").ConfigureAwait(false);
        var parts = assertion.Split('.');
        var otherParts = other.Split('.');
        var macOctets = TestSetup.Base64UrlDecoder(parts[2], Pool);
        var mac = macOctets.Memory.Span[..32].ToArray();
        macOctets.Dispose();

        var changed = new[]
        {
            $"{parts[0]}.{otherParts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.{TestSetup.Base64UrlEncoder(mac.AsSpan(0, 31))}",
            $"{parts[0]}.{parts[1]}.{TestSetup.Base64UrlEncoder([.. mac, 0])}"
        };

        Assert.IsTrue((await VerifyAsync(assertion, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false)).IsSuccess);

        foreach(var candidate in changed)
        {
            var verdict = await VerifyAsync(candidate, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

            Assert.IsFalse(verdict.IsSuccess, $"The changed assertion '{candidate}' carries no MAC of its signing input.");
            Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        }
    }


    /// <summary>
    /// A value that is no compact JWS of three base64url segments carries no MAC: two segments, four, an empty header, a
    /// segment outside the alphabet, padding, an empty signature and a value past <see cref="Jws.DefaultMaxJwsLength"/> are
    /// each refused <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/> and none throws.
    /// </summary>
    [TestMethod]
    public async Task AValueThatIsNoCompactJwsIsRefusedWithoutThrowing()
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var parts = assertion.Split('.');

        var malformed = new[]
        {
            $"{parts[0]}.{parts[1]}",
            $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[2]}",
            $".{parts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.",
            $"{parts[0]}é.{parts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.{parts[2]}=",
            $"{parts[0]}.{parts[1]}.{parts[2]}+",
            $"{parts[0]}.{new string('A', Jws.DefaultMaxJwsLength)}.{parts[2]}"
        };

        foreach(var candidate in malformed)
        {
            var verdict = await VerifyAsync(candidate, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

            Assert.IsFalse(verdict.IsSuccess, "A value that is no compact JWS verifies nothing.");
            Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        }
    }


    /// <summary>
    /// RFC 7518 Section 3.2: the check refuses a secret shorter than the algorithm's hash output before any MAC is computed,
    /// typed <see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/> carrying the octets the
    /// secret carries and the octets the algorithm needs; a secret of exactly the hash output's length is checked.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="hashOutputLength">Its hash output's length in octets.</param>
    [TestMethod]
    [DataRow("HS256", 32)]
    [DataRow("HS384", 48)]
    [DataRow("HS512", 64)]
    public async Task ASecretShorterThanTheHashOutputIsRefusedBeforeAnyMac(string algorithm, int hashOutputLength)
    {
        using var sufficient = SecretOf(new string('s', hashOutputLength));
        using var shortSecret = SecretOf(new string('s', hashOutputLength - 1));
        var assertion = await ComposeAsync(sufficient, algorithm).ConfigureAwait(false);

        var refused = await VerifyAsync(assertion, shortSecret, algorithm).ConfigureAwait(false);

        Assert.IsFalse(refused.IsSuccess, "A secret shorter than the hash output keys no MAC.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput, refused.Error.Reason);
        Assert.AreEqual(hashOutputLength - 1, refused.Error.SecretOctets);
        Assert.AreEqual(hashOutputLength, refused.Error.RequiredOctets);

        Assert.IsTrue((await VerifyAsync(assertion, sufficient, algorithm).ConfigureAwait(false)).IsSuccess);
    }


    /// <summary>
    /// The check MACs under an HMAC algorithm of RFC 7518 Section 3.2 alone: a signature algorithm and <c>none</c> are refused
    /// <see cref="ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac"/>, naming the algorithm, whatever the
    /// assertion carries; and an assertion MACed under one HMAC algorithm does not verify under another.
    /// </summary>
    /// <param name="algorithm">An algorithm none of the HMAC algorithms names.</param>
    [TestMethod]
    [DataRow("RS256")]
    [DataRow("ES256")]
    [DataRow("none")]
    public async Task AnAlgorithmThatIsNoHmacIsRefused(string algorithm)
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        var refused = await VerifyAsync(assertion, secret, algorithm).ConfigureAwait(false);

        Assert.IsFalse(refused.IsSuccess, "Only an HMAC algorithm verifies a client secret assertion.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac, refused.Error.Reason);
        Assert.AreEqual(algorithm, refused.Error.Algorithm);

        var otherHmac = await VerifyAsync(assertion, secret, WellKnownJwaValues.Hs512).ConfigureAwait(false);
        Assert.IsFalse(otherHmac.IsSuccess, "An HS256 MAC is no HS512 MAC.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, otherHmac.Error.Reason);
    }


    /// <summary>
    /// Before any secret is read, an assertion the client's composition MACed under an accepted HMAC algorithm is admitted under
    /// that algorithm, and the header's own words are judged: an assertion type other than RFC 7523 Section 2.2's JWT bearer
    /// is refused <see cref="ClientSecretAssertionHeaderRefusal.NotJwtBearer"/>; no compact JWS
    /// <see cref="ClientSecretAssertionHeaderRefusal.NotACompactJws"/>; a header that is no JSON object or repeats a member
    /// <see cref="ClientSecretAssertionHeaderRefusal.HeaderNotAnObject"/>; a header naming no algorithm, <c>none</c> in any letter
    /// case, or an algorithm that is no string <see cref="ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotNamed"/>; and a
    /// signature algorithm of the other family or an HMAC algorithm off the list
    /// <see cref="ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotAccepted"/>. None throws.
    /// </summary>
    [TestMethod]
    public async Task TheHeaderIsJudgedBeforeAnySecretIsRead()
    {
        using var secret = SecretOf(LongClientSecret);
        var accepted = new ClientSecretAssertionAlgorithms([WellKnownJwaValues.Hs256]);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var hs512 = await ComposeAsync(secret, WellKnownJwaValues.Hs512).ConfigureAwait(false);
        var parts = assertion.Split('.');

        var admitted = AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, assertion, accepted);

        Assert.IsTrue(admitted.IsAdmitted, "The composition's own HS256 assertion is admitted.");
        Assert.AreEqual(WellKnownJwaValues.Hs256, admitted.Algorithm);

        Assert.AreEqual(ClientSecretAssertionHeaderRefusal.NotJwtBearer, AdmitHeader(null, assertion, accepted).Refusal);
        Assert.AreEqual(ClientSecretAssertionHeaderRefusal.NotJwtBearer, AdmitHeader("urn:ietf:params:oauth:client-assertion-type:saml2-bearer", assertion, accepted).Refusal);

        foreach(var malformed in new[] { $"{parts[0]}.{parts[1]}", $"{parts[0]}.{parts[1]}.", $".{parts[1]}.{parts[2]}", $"{parts[0]}.{parts[1]}.{parts[2]}=", $"{parts[0]}.{new string('A', Jws.DefaultMaxJwsLength)}.{parts[2]}" })
        {
            Assert.AreEqual(ClientSecretAssertionHeaderRefusal.NotACompactJws, AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, malformed, accepted).Refusal, malformed);
        }

        foreach(var header in new[] { "[\"HS256\"]", "\"HS256\"", /*lang=json*/ "{\"alg\":\"HS256\",\"alg\":\"RS256\"}" })
        {
            Assert.AreEqual(ClientSecretAssertionHeaderRefusal.HeaderNotAnObject,
                AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, WithHeader(header, parts), accepted).Refusal, header);
        }

        foreach(var header in new[] { /*lang=json*/ "{\"typ\":\"JWT\"}", /*lang=json*/ "{\"alg\":\"none\"}", /*lang=json*/ "{\"alg\":\"NoNe\"}", /*lang=json*/ "{\"alg\":\"\"}", /*lang=json*/ "{\"alg\":256}" })
        {
            Assert.AreEqual(ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotNamed,
                AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, WithHeader(header, parts), accepted).Refusal, header);
        }

        foreach(var header in new[] { /*lang=json*/ "{\"alg\":\"RS256\"}", /*lang=json*/ "{\"alg\":\"ES256\"}", /*lang=json*/ "{\"alg\":\"hs256\"}" })
        {
            Assert.AreEqual(ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotAccepted,
                AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, WithHeader(header, parts), accepted).Refusal, header);
        }

        Assert.AreEqual(ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotAccepted,
            AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, hs512, accepted).Refusal, "An HMAC algorithm off the list is not accepted.");
    }


    /// <summary>
    /// RFC 7515 Section 4.1.11: a recipient that does not understand an extension the protected header lists in <c>crit</c>
    /// holds the JWS invalid, and this server understands none. An assertion whose MAC the secret verifies - recomputed here
    /// over the very header it carries - is still refused before any secret is read where its header names <c>crit</c>: an
    /// unknown extension, an empty list, a value that is no list, or a list naming a parameter RFC 7515 itself defines.
    /// </summary>
    /// <param name="header">The protected header's JSON text.</param>
    /// <returns>A task completing once the header is judged.</returns>
    [TestMethod]
    [DataRow(/*lang=json*/ "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"crit\":[\"urn:example:ext\"],\"urn:example:ext\":true}")]
    [DataRow(/*lang=json*/ "{\"alg\":\"HS256\",\"crit\":[]}")]
    [DataRow(/*lang=json*/ "{\"alg\":\"HS256\",\"crit\":\"urn:example:ext\",\"urn:example:ext\":1}")]
    [DataRow(/*lang=json*/ "{\"alg\":\"HS256\",\"crit\":[\"alg\"]}")]
    [DataRow(/*lang=json*/ "{\"crit\":[\"b64\"],\"b64\":true,\"alg\":\"HS256\"}")]
    public async Task AHeaderListingACriticalParameterIsRefusedThoughItsMacVerifies(string header)
    {
        using var secret = SecretOf(LongClientSecret);
        var accepted = new ClientSecretAssertionAlgorithms([WellKnownJwaValues.Hs256]);
        var assertion = MacedUnder(LongClientSecret, header, ClaimsOfTheClient("critical-header-jti"));

        Assert.IsTrue((await VerifyAsync(assertion, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false)).IsSuccess,
            "The assertion carries the secret's MAC of its own signing input.");

        var admission = AdmitHeader(WellKnownClientAssertionTypes.JwtBearer, assertion, accepted);

        Assert.IsFalse(admission.IsAdmitted, $"A header naming crit is not admitted: {header}");
        Assert.AreEqual(ClientSecretAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood, admission.Refusal, header);

        var reading = ClientAssertionHeaderRules.Read(assertion, TestSetup.Base64UrlDecoder, HeaderDeserializer, Pool);

        Assert.AreEqual(ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood, reading.Refusal, "The shared reading every key source judges by refuses it alike.");
        Assert.IsNotNull(reading.Header, "The header read as one object is kept for what a refused header named.");
        Assert.IsNull(reading.Algorithm);
    }


    /// <summary>
    /// The one reading every key source judges an assertion's header by, before any key or secret is read: the composition's own
    /// assertion is read with its members and its algorithm, and each rule is refused under its own name, none throwing.
    /// </summary>
    /// <returns>A task completing once every header is read.</returns>
    [TestMethod]
    public async Task TheSharedReadingNamesEachRuleOfTheHeader()
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var parts = assertion.Split('.');

        var read = ClientAssertionHeaderRules.Read(assertion, TestSetup.Base64UrlDecoder, HeaderDeserializer, Pool);

        Assert.IsNull(read.Refusal);
        Assert.AreEqual(WellKnownJwaValues.Hs256, read.Algorithm);
        Assert.IsNotNull(read.Header);
        Assert.AreEqual(WellKnownJwkValues.TypeJwt, read.Header[WellKnownJoseHeaderNames.Typ]);

        var cases = new[]
        {
            new HeaderCase($"{parts[0]}.{parts[1]}", ClientAssertionHeaderRefusal.NotACompactJws),
            new HeaderCase($"{parts[0]}.{parts[1]}.{parts[2]}=", ClientAssertionHeaderRefusal.NotACompactJws),
            new HeaderCase(WithHeader("[\"HS256\"]", parts), ClientAssertionHeaderRefusal.HeaderNotAnObject),
            new HeaderCase(WithHeader(/*lang=json*/ "{\"alg\":\"HS256\",\"alg\":\"RS256\"}", parts), ClientAssertionHeaderRefusal.HeaderNotAnObject),
            new HeaderCase(WithHeader(/*lang=json*/ "{\"alg\":\"NONE\"}", parts), ClientAssertionHeaderRefusal.SignatureAlgorithmNotNamed),
            new HeaderCase(WithHeader(/*lang=json*/ "{\"typ\":\"JWT\"}", parts), ClientAssertionHeaderRefusal.SignatureAlgorithmNotNamed),
            new HeaderCase(WithHeader(/*lang=json*/ "{\"alg\":\"ES256\",\"crit\":[\"exp\"]}", parts), ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood)
        };

        foreach(var headerCase in cases)
        {
            var refused = ClientAssertionHeaderRules.Read(headerCase.Assertion, TestSetup.Base64UrlDecoder, HeaderDeserializer, Pool);

            Assert.AreEqual(headerCase.Expected, refused.Refusal, headerCase.Assertion);
            Assert.IsNull(refused.Algorithm);
            Assert.AreEqual(headerCase.Expected is ClientAssertionHeaderRefusal.SignatureAlgorithmNotNamed or ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood, refused.Header is not null, headerCase.Assertion);
        }
    }


    /// <summary>An assertion and the rule the shared reading refuses it under.</summary>
    /// <param name="Assertion">The compact value.</param>
    /// <param name="Expected">The rule.</param>
    private sealed record HeaderCase(string Assertion, ClientAssertionHeaderRefusal Expected);


    /// <summary>
    /// The accepted algorithms are named once and hold HMAC algorithms alone: a list naming a signature algorithm, <c>none</c>,
    /// a name in another letter case, a name twice, or nothing is refused when it is made; a list of HMAC algorithms accepts
    /// exactly the names it holds, in the order it names them.
    /// </summary>
    [TestMethod]
    public void TheAcceptedAlgorithmsHoldHmacAlgorithmsAlone()
    {
        var refused = new[] { new[] { "RS256" }, ["HS256", "ES256"], ["none"], ["hs256"], ["HS256", "HS256"], [] };

        foreach(var algorithms in refused)
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new ClientSecretAssertionAlgorithms(algorithms), string.Join(',', algorithms));
        }

        var accepted = new ClientSecretAssertionAlgorithms([WellKnownJwaValues.Hs512, WellKnownJwaValues.Hs256]);

        Assert.AreSequenceEqual(new List<string> { WellKnownJwaValues.Hs512, WellKnownJwaValues.Hs256 }, accepted.Algorithms.ToList(), "The list keeps the order it names.");
        Assert.IsTrue(accepted.Accepts(WellKnownJwaValues.Hs256));
        Assert.IsTrue(accepted.Accepts(WellKnownJwaValues.Hs512));
        Assert.IsFalse(accepted.Accepts(WellKnownJwaValues.Hs384), "An HMAC algorithm the list does not name is not accepted.");
        Assert.IsFalse(accepted.Accepts("hs256"), "The comparison is exact.");
        Assert.IsFalse(accepted.Accepts(null));
    }


    /// <summary>
    /// The registered method chooses the family an assertion is verified under: <c>client_secret_jwt</c> the MAC family,
    /// <c>private_key_jwt</c> the signature family, every method known to present no assertion neither, and a method neither
    /// family judges - attestation-based, SPIFFE, or one an application defined - is answered unsupported, never taken for one that
    /// presents no assertion.
    /// </summary>
    [TestMethod]
    public void TheRegisteredMethodChoosesTheFamily()
    {
        Assert.AreEqual(ClientAssertionFamily.MessageAuthenticationCode, ClientAssertionFamilies.Of(ClientAuthenticationMethod.ClientSecretJwt));
        Assert.AreEqual(ClientAssertionFamily.DigitalSignature, ClientAssertionFamilies.Of(ClientAuthenticationMethod.PrivateKeyJwt));

        foreach(var method in new[] { ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretBasic, ClientAuthenticationMethod.ClientSecretPost, ClientAuthenticationMethod.TlsClientAuth, ClientAuthenticationMethod.SelfSignedTlsClientAuth })
        {
            Assert.AreEqual(ClientAssertionFamily.NoAssertion, ClientAssertionFamilies.Of(method), ClientAuthenticationMethodNames.GetName(method));
        }

        foreach(var method in new[] { ClientAuthenticationMethod.AttestJwtClientAuth, ClientAuthenticationMethod.SpiffeJwt, UnfamiliarMethod })
        {
            Assert.AreEqual(ClientAssertionFamily.Unsupported, ClientAssertionFamilies.Of(method),
                $"A method neither family judges, {method.Code}, is not concluded to present no assertion.");
        }
    }


    /// <summary>An application-defined client authentication method, which no rule of the library knows.</summary>
    private static ClientAuthenticationMethod UnfamiliarMethod { get; } = ClientAuthenticationMethod.Create(41_797);


    /// <summary>Judges an assertion's header as the authorization server does before any secret is read.</summary>
    /// <param name="assertionType">The request's assertion type.</param>
    /// <param name="assertion">The assertion.</param>
    /// <param name="accepted">The accepted algorithms.</param>
    /// <returns>The admission.</returns>
    private static ClientSecretAssertionHeaderAdmission AdmitHeader(string? assertionType, string assertion, ClientSecretAssertionAlgorithms accepted) =>
        ClientSecretAssertionVerification.AdmitHeader(assertionType, assertion, accepted, TestSetup.Base64UrlDecoder, HeaderDeserializer, Pool);


    /// <summary>An assertion's segments with its protected header replaced by the JSON text given, base64url-encoded.</summary>
    /// <param name="header">The header's JSON text.</param>
    /// <param name="parts">The assertion's segments.</param>
    /// <returns>The compact value.</returns>
    private static string WithHeader(string header, string[] parts) =>
        $"{TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header))}.{parts[1]}.{parts[2]}";


    /// <summary>
    /// A compact value composed of the protected header and the claims given, both serialized here and only then MACed: the
    /// HMAC-SHA-256 of the signing input under the secret's UTF-8 octets, computed by the platform's own HMAC apart from the
    /// library's.
    /// </summary>
    /// <param name="secret">The secret.</param>
    /// <param name="header">The header's JSON text, as the producer intends it.</param>
    /// <param name="claims">The claims the assertion carries.</param>
    /// <returns>The compact value.</returns>
    private static string MacedUnder(string secret, string header, JwtPayload claims)
    {
        var payloadSegment = TestSetup.Base64UrlEncoder(PayloadSerializer(claims));
        var signingInput = $"{TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header))}.{payloadSegment}";
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.ASCII.GetBytes(signingInput));

        return $"{signingInput}.{TestSetup.Base64UrlEncoder(mac)}";
    }


    /// <summary>
    /// The claims a client assertion of the client carries at the fixture clock (RFC 7523 Section 3): <c>iss</c> and <c>sub</c>
    /// the client, <c>aud</c> the token endpoint, the identifier given, <c>iat</c> now and <c>exp</c> a minute after.
    /// </summary>
    /// <param name="jti">The assertion's identifier.</param>
    /// <returns>The claims.</returns>
    private JwtPayload ClaimsOfTheClient(string jti)
    {
        var now = TimeProvider.GetUtcNow();

        return new JwtPayload(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Sub] = ClientId,
            [WellKnownJwtClaimNames.Aud] = TokenEndpoint,
            [WellKnownJwtClaimNames.Jti] = jti,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(1).ToUnixTimeSeconds()
        };
    }


    /// <summary>Reads a protected header.</summary>
    private static JwtHeaderDeserializer HeaderDeserializer { get; } =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("The header parsed to null.");


    /// <summary>Composes an assertion through the client's one composition under a secret and an algorithm.</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <returns>The compact assertion.</returns>
    private ValueTask<string> ComposeAsync(PrivateKeyMemory secret, string algorithm) =>
        ComposeAsync(secret, algorithm, "secret-assertion-jti");


    /// <summary>Composes an assertion through the client's one composition under a secret, an algorithm and an identifier.</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="jti">The assertion's identifier.</param>
    /// <returns>The compact assertion.</returns>
    private async ValueTask<string> ComposeAsync(PrivateKeyMemory secret, string algorithm, string jti)
    {
        var key = ClientAssertionCredential.OfClientSecret(secret, algorithm);
        Assert.IsTrue(key.IsSuccess, "The secret keys the algorithm.");

        var now = TimeProvider.GetUtcNow();

        return await ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            jti,
            now,
            now.AddMinutes(1),
            key.Value,
            WellKnownJwkValues.TypeJwt,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Checks an assertion's MAC under a secret and an algorithm.</summary>
    /// <param name="assertion">The assertion.</param>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The algorithm judged.</param>
    /// <returns>The verdict.</returns>
    private ValueTask<Result<string, ClientAssertionCredentialRefusal>> VerifyAsync(string assertion, PrivateKeyMemory secret, string algorithm) =>
        ClientSecretAssertionVerification.VerifyAsync(
            assertion, secret, algorithm, TestSetup.Base64UrlDecoder, Pool, context: null, TestContext.CancellationToken);


    /// <summary>A client secret's UTF-8 octets as the library carries one, untagged, in pooled memory the caller disposes.</summary>
    /// <param name="secret">The secret.</param>
    /// <returns>The key holding the octets.</returns>
    private static PrivateKeyMemory SecretOf(string secret)
    {
        var octets = Encoding.UTF8.GetBytes(secret);
        var owner = Pool.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, Tag.Empty);
    }
}
