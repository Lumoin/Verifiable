using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Claim-rule matrix for <see cref="PrivateKeyJwtClientAuthentication"/> — the RFC 7523 §2.2/§3/§3.2
/// <c>private_key_jwt</c> client-authentication seam draft-ietf-oauth-client-id-metadata-document-02
/// §8.2 (CIMD-047/048/049/050) requires. Part A exercises the pure
/// <see cref="PrivateKeyJwtClientAuthentication.Validate"/> claim rules directly, mirroring
/// <c>Rfc7523AssertionValidationTests</c>'s style. Part B exercises the full
/// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
/// pipeline — parse, key resolution from a JWKS, real signature verification, then the claim rules —
/// against a project-crypto-generated P-256 key pair via <see cref="TestKeyMaterialProvider"/> and
/// <see cref="ClientAssertionSigning"/>, never <c>System.Security.Cryptography</c> directly.
/// </summary>
[TestClass]
internal sealed class PrivateKeyJwtClientAuthenticationTests
{
    private const string ClientId = "https://client.example/app";
    private const string Issuer = "https://issuer.test/tenant-a";
    private const string SigningKeyId = "test-client-key-1";

    private static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    public TestContext TestContext { get; set; } = null!;


    //Part A — the pure claim-rule checker. No crypto, no host: JwtPayload is constructed directly,
    //exactly as an already-signature-verified assertion payload would arrive.

    private static JwtPayload ValidPayload() =>
        new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Sub] = ClientId,
            [WellKnownJwtClaimNames.Aud] = Issuer,
            [WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = "assertion-jti-1"
        };


    private static PrivateKeyJwtClientAuthenticationResult Validate(JwtPayload payload) =>
        PrivateKeyJwtClientAuthentication.Validate(payload, ClientId, [Issuer], Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        PrivateKeyJwtClientAuthenticationResult result = Validate(ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(ClientId, result.ClientId);
        Assert.AreEqual("assertion-jti-1", result.Jti);
        Assert.IsNotNull(result.Expiration);
    }


    /// <summary>RFC 7523 §3 item 1: a wrong <c>iss</c> (not the client_id) is rejected.</summary>
    [TestMethod]
    public void WrongIssuerIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iss] = "https://impostor.example/app";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.ClientId);
    }


    /// <summary>RFC 7523 §3 item 2.B: a wrong <c>sub</c> (not the client_id) is rejected.</summary>
    [TestMethod]
    public void WrongSubjectIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Sub] = "https://impostor.example/app";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>RFC 7523 §3 item 3: an <c>aud</c> naming a foreign authorization server is rejected.</summary>
    [TestMethod]
    public void ForeignAudienceIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://other-as.example/";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// An <c>aud</c> array carrying the accepted issuer ALONGSIDE a foreign value is rejected outright
    /// — every element must be an accepted AS identity, not merely one of them.
    /// </summary>
    [TestMethod]
    public void ForeignAudienceMixedIntoArrayIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { Issuer, "https://evil.example/" };

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>Missing <c>aud</c> is rejected (RFC 7523 §3 item 3).</summary>
    [TestMethod]
    public void MissingAudienceIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Aud);

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// RFC 7523 §3 item 3: "The token endpoint URL of the authorization server MAY be used as a
    /// value for an aud element" — a caller that additionally accepts the token endpoint URL sees an
    /// assertion audienced to it validate.
    /// </summary>
    [TestMethod]
    public void TokenEndpointUrlIsAnAcceptedAlternateAudience()
    {
        const string TokenEndpoint = "https://issuer.test/tenant-a/token";

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = TokenEndpoint;

        PrivateKeyJwtClientAuthenticationResult result = PrivateKeyJwtClientAuthentication.Validate(
            payload, ClientId, [Issuer, TokenEndpoint], Now, Skew);

        Assert.IsTrue(result.IsValid, result.FailureReason);
    }


    /// <summary>RFC 7523 §3 item 4: an expired assertion (subject to skew) is rejected.</summary>
    [TestMethod]
    public void ExpiredAssertionIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>"iat sanity": an <c>iat</c> claiming issuance far in the future is rejected.</summary>
    [TestMethod]
    public void AbsurdFutureIssuedAtIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddYears(10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddYears(10).AddMinutes(5).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>A missing <c>jti</c> is rejected — required for this profile's replay defense.</summary>
    [TestMethod]
    public void MissingJtiIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Jti);

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>RFC 7523 §3 item 5: a future <c>nbf</c> (beyond skew) makes the assertion not yet valid.</summary>
    [TestMethod]
    public void FutureNotBeforeIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = Now.AddMinutes(2).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary><c>exp</c> at or before <c>iat</c> is an internally inconsistent, non-positive lifetime.</summary>
    [TestMethod]
    public void ExpiryAtOrBeforeIssuedAtIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-1).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    //Part B — the full BuildValidator() pipeline: real compact-JWS parsing, key resolution from a
    //ClientJwks JSON document, real P-256 signature verification, then Validate. TestHostShell supplies
    //a fully-wired EndpointServer (codecs, crypto); the ClientRecord under test is a local `with` copy
    //that is never re-registered with the dispatcher — the delegate is invoked directly, which is the
    //seam this test targets.

    [TestMethod]
    public async Task HappyPathWithProjectCryptoGeneratedKeyAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values within a set a SHOULD, so a duplicate can arrive. A registered key
    /// set carrying two keys under the
    /// SAME <c>kid</c> must refuse the assertion outright — a first-match scan that trusts whichever
    /// element sits first lets whoever controls the array's order pick which key is trusted.
    /// </summary>
    [TestMethod]
    public async Task DuplicateKeyIdInRegisteredSetIsRefused()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        const string DuplicateKeyId = "duplicated-kid";

        var firstKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var secondKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(firstKeys.PublicKey), DuplicateKeyId),
                    (JwkOf(secondKeys.PublicKey), DuplicateKeyId))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString,
                firstKeys.PrivateKey, DuplicateKeyId).ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated,
                "A key identifier repeated across the registered set must refuse rather than pick a winner.");
        }
        finally
        {
            firstKeys.PublicKey.Dispose();
            firstKeys.PrivateKey.Dispose();
            secondKeys.PublicKey.Dispose();
            secondKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional only for a single-key set; a multi-key set with no <c>kid</c> header on the
    /// assertion carries no way to tell which key was meant, so it is refused rather than defaulting
    /// to whichever key sits first in the registered set.
    /// </summary>
    [TestMethod]
    public async Task TwoKeySetWithNoKidHeaderIsRefused()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var firstKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var secondKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(firstKeys.PublicKey), "key-a"),
                    (JwkOf(secondKeys.PublicKey), "key-b"))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionWithoutKidAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, firstKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated, "A multi-key set with no kid header must refuse, not pick the first key.");
        }
        finally
        {
            firstKeys.PublicKey.Dispose();
            firstKeys.PrivateKey.Dispose();
            secondKeys.PublicKey.Dispose();
            secondKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>: <c>kid</c>
    /// is optional, so a legitimate single-key set with no <c>kid</c> header must still authenticate.
    /// Green both before and after the duplicate/no-kid refusal fix — the regression guard on it.
    /// </summary>
    [TestMethod]
    public async Task SingleKeySetWithNoKidHeaderStillAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionWithoutKidAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "A single-key set with no kid header must still authenticate (RFC 7517 §4.5: kid is optional).");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A rotated set publishing both the old and the new key: the assertion's <c>kid</c> selects the
    /// new key by identifier and authenticates, proving selection tracks the identifier rather than
    /// array position.
    /// </summary>
    [TestMethod]
    public async Task RotatedKeySetSelectsTheNewKeyByKid()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        const string OldKeyId = "old-key";
        const string NewKeyId = "new-key";

        var oldKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var newKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(oldKeys.PublicKey), OldKeyId),
                    (JwkOf(newKeys.PublicKey), NewKeyId))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString,
                newKeys.PrivateKey, NewKeyId).ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "The current key's kid must select it out of a rotated set that still carries the old key.");
        }
        finally
        {
            oldKeys.PublicKey.Dispose();
            oldKeys.PrivateKey.Dispose();
            newKeys.PublicKey.Dispose();
            newKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task TamperedSignatureIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            string[] segments = assertion.Split('.');
            Assert.HasCount(3, segments);
            char firstSignatureChar = segments[2][0];
            char flipped = firstSignatureChar == 'A' ? 'B' : 'A';
            string tampered = string.Join('.', segments[0], segments[1], flipped + segments[2][1..]);

            RequestFields fields = BuildFields(tampered);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// An assertion signed by a DIFFERENT key than the one published in <c>ClientJwks</c> is rejected —
    /// proves the signature check verifies against the REGISTERED key, not merely that some signature
    /// is present.
    /// </summary>
    [TestMethod]
    public async Task AssertionSignedByAnUnregisteredKeyIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var registeredKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var attackerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            //The published JWKS carries the REGISTERED public key; the assertion is signed with the
            //ATTACKER's distinct private key.
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, registeredKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, attackerKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            registeredKeys.PublicKey.Dispose();
            registeredKeys.PrivateKey.Dispose();
            attackerKeys.PublicKey.Dispose();
            attackerKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7519 §4: "The JWT Claim Names within a Claims Set MUST be unique." An assertion whose
    /// Claims Set repeats <c>sub</c> — the attacker's value first, the honest client id last — is
    /// refused (401 <c>invalid_client</c> at the token endpoint this delegate feeds) rather than
    /// crashing the caller. Only the payload segment is rebuilt by hand (never through this
    /// repository's serializers) and re-signed with the SAME client private key, so only the
    /// payload's well-formedness gate — not an invalid signature — can be responsible for the
    /// refusal. The call completing and returning <see langword="false"/>, rather than an escaped
    /// exception, is itself part of what this test proves.
    /// </summary>
    [TestMethod]
    public async Task AssertionWithDuplicateSubClaimIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            string[] segments = assertion.Split('.');
            using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(segments[1], BaseMemoryPool.Shared);
            string payloadJson = Encoding.UTF8.GetString(payloadOwner.Memory.Span);

            //Splice an attacker-controlled "sub" ahead of the honest one already in the serialized
            //payload — raw string surgery, not a Dictionary<string,object> round trip, since a
            //dictionary cannot itself carry two entries under the same key.
            string tamperedPayloadJson = payloadJson.Insert(1, "\"sub\":\"attacker-client\",");
            string tamperedPayloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedPayloadJson));

            byte[] signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{tamperedPayloadB64}");
            using Signature signature = await clientKeys.PrivateKey.SignAsync(signingInput, BaseMemoryPool.Shared)
                .ConfigureAwait(false);
            string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
            string tamperedAssertion = $"{segments[0]}.{tamperedPayloadB64}.{signatureB64}";

            RequestFields fields = BuildFields(tamperedAssertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task MissingClientAssertionTypeIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = new();
            fields[OAuthRequestParameterNames.ClientAssertion] = assertion;
            //client_assertion_type deliberately omitted.
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task WrongClientAssertionTypeIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = new();
            fields[OAuthRequestParameterNames.ClientAssertionType] = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
            fields[OAuthRequestParameterNames.ClientAssertion] = assertion;
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task MissingClientJwksFailsClosed()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            //A confidential-looking registration with no published key material at all.
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591 §2</see>'s <c>jwks_uri</c>
    /// registration — "URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document,
    /// which contains the client's public keys... these keys might be used by some applications for
    /// validating signed requests made to the token endpoint when using JWTs for client authentication"
    /// — authenticates once the caller wires the key-set resolution seam.
    /// </summary>
    [TestMethod]
    public async Task RegisteredJwksUriWithAWiredResolutionSeamAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            Uri jwksUri = new("https://client.example/jwks.json");
            string jwksJson = BuildJwksJson((JwkOf(clientKeys.PublicKey), SigningKeyId));

            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwksUri = jwksUri
            };

            ValueTask<JwksUriResolution> ResolveJwksUriAsync(Uri uri, ExchangeContext context, CancellationToken ct) =>
                ValueTask.FromResult(new JwksUriResolution
                {
                    Outcome = JwksUriResolutionOutcome.Resolved,
                    Jwks = jwksJson
                });

            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator(
                resolveJwksUriAsync: ResolveJwksUriAsync);

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "A registration with only a jwks_uri must authenticate once the caller wires a key-set resolution seam.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The same RFC 7591 §2 <c>jwks_uri</c> registration with NO resolution seam wired fails closed —
    /// the application owns what reaches the wire, so nothing here dereferences <c>jwks_uri</c> on its
    /// own; the refusal is identical to a registration with no key material at all
    /// (<see cref="MissingClientJwksFailsClosed"/>).
    /// </summary>
    [TestMethod]
    public async Task RegisteredJwksUriWithNoResolutionSeamWiredFailsClosed()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwksUri = new Uri("https://client.example/jwks.json")
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(null, fields, registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated,
                "A jwks_uri registration with no resolution seam wired must fail closed, not dereference it on its own.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    private static ClientRecord BuildConfidentialRegistration(ClientRecord baseline, PublicKeyMemory clientPublicKey)
    {
        string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientPublicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            clientPublicKey, alg, TestSetup.Base64UrlEncoder);

        return baseline with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            ClientJwks = BuildJwksJson((jwk, SigningKeyId))
        };
    }


    /// <summary>
    /// Builds a JWK Set JSON document carrying one key per <paramref name="keys"/> entry, each tagged
    /// with its paired <c>kid</c> — callers pass the same <c>kid</c> twice to build a duplicate-identifier
    /// fixture.
    /// </summary>
    private static string BuildJwksJson(params (IReadOnlyDictionary<string, string> Jwk, string Kid)[] keys)
    {
        StringBuilder sb = new();
        _ = sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[");
        for(int index = 0; index < keys.Length; ++index)
        {
            if(index > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            foreach(KeyValuePair<string, string> member in keys[index].Jwk)
            {
                _ = sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
            }

            _ = sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(keys[index].Kid).Append("\"}");
        }

        _ = sb.Append(']').Append('}');

        return sb.ToString();
    }


    private static IReadOnlyDictionary<string, string> JwkOf(PublicKeyMemory publicKey)
    {
        string alg = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);

        return DpopJwkUtilities.ToJwk(publicKey, alg, TestSetup.Base64UrlEncoder);
    }


    private async Task<string> SignAssertionAsync(
        EndpointServer server, string clientId, string audience, PrivateKeyMemory clientPrivateKey,
        string signingKeyId = SigningKeyId)
    {
        var oauth = server.OAuth();
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        return await ClientAssertionSigning.SignAsync(
            clientId,
            audience,
            Guid.NewGuid().ToString("N"),
            now.AddMinutes(-1),
            now.AddMinutes(5),
            clientPrivateKey,
            signingKeyId,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs a client assertion with no <c>kid</c> header member at all — the RFC 7517 §4.5 optional
    /// case a legitimate single-key set relies on. Mirrors <see cref="ClientAssertionSigning.SignAsync"/>'s
    /// header and payload shape, since that method requires a non-empty <c>kid</c> and so cannot
    /// produce this header itself.
    /// </summary>
    private async Task<string> SignAssertionWithoutKidAsync(
        EndpointServer server, string clientId, string audience, PrivateKeyMemory clientPrivateKey)
    {
        var oauth = server.OAuth();
        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(clientPrivateKey.Tag);

        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };

        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Sub] = clientId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [WellKnownJwtClaimNames.Iat] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(5).ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            clientPrivateKey,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, oauth.Codecs.Encoder!);
    }


    private static RequestFields BuildFields(string clientAssertion)
    {
        RequestFields fields = new();
        fields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        fields[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;

        return fields;
    }


    private static ExchangeContext BuildContext(EndpointServer server)
    {
        ExchangeContext context = [];
        context.SetServer(server);

        return context;
    }
}
