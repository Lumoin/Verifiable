using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Unit coverage for <see cref="FederationClientAuthentication"/> — the §8.8
/// <c>private_key_jwt</c> claim rules a federation endpoint applies to a
/// decoded, signature-verified client-authentication JWT. Each test pins one
/// normative rule.
/// </summary>
[TestClass]
internal sealed class FederationClientAuthenticationTests
{
    private const string EndpointEntityId = "https://op.example.com";
    private const string RequesterEntityId = "https://rp.example.com";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);

    private static readonly EntityIdentifier Endpoint = new(EndpointEntityId);
    private static readonly EntityIdentifier Requester = new(RequesterEntityId);


    private static JwtPayload ValidPayload() =>
        new(capacity: 5)
        {
            [WellKnownJwtClaimNames.Iss] = RequesterEntityId,
            [WellKnownJwtClaimNames.Sub] = RequesterEntityId,
            [WellKnownJwtClaimNames.Aud] = EndpointEntityId,
            [WellKnownJwtClaimNames.Jti] = "f81b64a33f20116179",
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds(),
        };


    private static FederationClientAuthenticationResult Validate(JwtPayload payload) =>
        FederationClientAuthentication.Validate(payload, Endpoint, Requester, Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        FederationClientAuthenticationResult result = Validate(ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(RequesterEntityId, result.ClientId);
        Assert.AreEqual("f81b64a33f20116179", result.Jti);
    }


    [TestMethod]
    public void AudienceThatIsNotTheEndpointIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://attacker.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "§8.8: aud must be the endpoint's Entity Identifier.");
    }


    [TestMethod]
    public void MultiValuedAudienceContainingTheEndpointIsRejected()
    {
        //§8.8: the endpoint MUST NOT accept audience values other than its own
        //Entity Identifier — a multi-element array (even one that contains the
        //endpoint) is an audience-injection attempt.
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new List<object> { EndpointEntityId, "https://attacker.example.com" };

        Assert.IsFalse(Validate(payload).IsValid,
            "A multi-valued aud must be rejected even when it contains the endpoint.");
    }


    [TestMethod]
    public void IssuerThatIsNotTheRequesterIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "private_key_jwt: iss must be the requester's Entity Identifier.");
    }


    [TestMethod]
    public void SubjectThatIsNotTheRequesterIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Sub] = "https://impostor.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "private_key_jwt: sub must be the requester's Entity Identifier.");
    }


    [TestMethod]
    public void MissingJtiIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Jti);

        Assert.IsFalse(Validate(payload).IsValid, "jti is required for replay defense.");
    }


    [TestMethod]
    public void MissingExpirationIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Exp);

        Assert.IsFalse(Validate(payload).IsValid, "exp is required.");
    }


    [TestMethod]
    public void ExpiredAssertionIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        Assert.IsFalse(Validate(payload).IsValid, "An expired assertion must be rejected.");
    }
}
