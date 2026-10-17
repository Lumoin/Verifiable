using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests the federation statement readers against RFC 7519 Section 2, which defines a NumericDate as a JSON number in which
/// "non-integer values can be represented": an entity statement's and a trust mark's <c>iat</c> and <c>exp</c> written with a
/// fraction are read as the instants written, to the tick, never refused and never moved to a whole second, and a string of
/// digits is no NumericDate.
/// </summary>
[TestClass]
internal sealed class FederationNumericDateTests
{
    /// <summary>The entity both statements are issued by and about.</summary>
    private const string EntityId = "https://entity.example.com";

    /// <summary>The count of seconds the statements are issued at.</summary>
    private const long IssuedAtSeconds = 1_700_000_000;


    /// <summary>An entity configuration's <c>iat</c> and <c>exp</c> written with a fraction are read to the tick.</summary>
    [TestMethod]
    public void AnEntityStatementsFractionalDatesAreReadToTheTick()
    {
        var header = new UnverifiedJwtHeader { [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt };
        var payload = new UnverifiedJwtPayload
        {
            [WellKnownJwtClaimNames.Iss] = EntityId,
            [WellKnownJwtClaimNames.Sub] = EntityId,
            [WellKnownJwtClaimNames.Iat] = IssuedAtSeconds + 0.25m,
            [WellKnownJwtClaimNames.Exp] = IssuedAtSeconds + 3600.75m
        };

        var parsed = EntityStatementParser.Parse(header, payload);

        Assert.IsTrue(parsed.IsSuccess, parsed.FailureReason);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(IssuedAtSeconds).AddMilliseconds(250), parsed.Statement!.IssuedAt, "The iat is the instant written.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(IssuedAtSeconds + 3600).AddMilliseconds(750), parsed.Statement.ExpiresAt, "The exp is the instant written.");

        payload[WellKnownJwtClaimNames.Exp] = "1700003600";

        Assert.IsFalse(EntityStatementParser.Parse(header, payload).IsSuccess, "A string of digits is no NumericDate.");
    }


    /// <summary>A trust mark's <c>iat</c> and <c>exp</c> written with a fraction are read to the tick.</summary>
    [TestMethod]
    public void ATrustMarksFractionalDatesAreReadToTheTick()
    {
        var header = new UnverifiedJwtHeader { [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkJwt };
        var payload = new UnverifiedJwtPayload
        {
            [WellKnownJwtClaimNames.Iss] = EntityId,
            [WellKnownJwtClaimNames.Sub] = "https://member.example.com",
            [WellKnownFederationClaimNames.TrustMarkType] = "https://entity.example.com/marks/certified",
            [WellKnownJwtClaimNames.Iat] = IssuedAtSeconds + 0.25m,
            [WellKnownJwtClaimNames.Exp] = IssuedAtSeconds + 3600.75m
        };

        var parsed = TrustMarkParser.Parse(header, payload);

        Assert.IsTrue(parsed.IsSuccess, parsed.FailureReason);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(IssuedAtSeconds).AddMilliseconds(250), parsed.Mark!.IssuedAt, "The iat is the instant written.");
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(IssuedAtSeconds + 3600).AddMilliseconds(750), parsed.Mark.ExpiresAt, "The exp is the instant written.");
    }
}
