using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.WellKnown;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Claim-rule matrix for <see cref="PrivateKeyJwtClientAuthentication"/> — the RFC 7523 §2.2/§3/§3.2
/// <c>private_key_jwt</c> client-authentication seam draft-ietf-oauth-client-id-metadata-document-02
/// §8.2 (CIMD-047/048/049/050) requires. Part A exercises the pure
/// <see cref="PrivateKeyJwtClientAuthentication.Validate"/> claim rules directly, mirroring
/// <c>Rfc7523AssertionValidationTests</c>'s style. Part B exercises the full
/// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?)"/>
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

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);

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
        payload.Remove(WellKnownJwtClaimNames.Aud);

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
        payload.Remove(WellKnownJwtClaimNames.Jti);

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
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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


    [TestMethod]
    public async Task TamperedSignatureIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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


    [TestMethod]
    public async Task MissingClientAssertionTypeIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce);

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


    private static ClientRecord BuildConfidentialRegistration(ClientRecord baseline, PublicKeyMemory clientPublicKey)
    {
        string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientPublicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            clientPublicKey, alg, TestSetup.Base64UrlEncoder);

        return baseline with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            ClientJwks = BuildJwksJson(jwk, SigningKeyId)
        };
    }


    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    private async Task<string> SignAssertionAsync(
        EndpointServer server, string clientId, string audience, PrivateKeyMemory clientPrivateKey)
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
            SigningKeyId,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
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
        ExchangeContext context = new();
        context.SetServer(server);

        return context;
    }
}
