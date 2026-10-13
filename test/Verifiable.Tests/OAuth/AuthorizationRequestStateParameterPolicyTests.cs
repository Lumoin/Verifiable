using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The <c>state</c> parameter is OPTIONAL on a parsed Authorization Request per
/// OID4VP 1.0 §5 / RFC 6749 §4.1.1; a Wallet MUST accept its absence. The requirement
/// is decided per call via <see cref="StateParameterPolicy"/> — a deployment opts into
/// <see cref="StateParameterPolicy.Required"/> from its own threat analysis. These
/// exercise the inline (form-fields) parse; the signed-JAR parse shares the same gate.
/// </summary>
[TestClass]
internal sealed class AuthorizationRequestStateParameterPolicyTests
{
    private static DateTimeOffset Now { get; } = TestClock.CanonicalEpoch;
    private static TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(5);

    private static JarClaimDeserializer<DcqlQuery> DcqlDeserializer { get; } =
        json => JsonSerializer.Deserialize<DcqlQuery>(json, TestSetup.DefaultSerializationOptions)!;

    private static JarClaimDeserializer<VerifierClientMetadata> ClientMetadataDeserializer { get; } =
        json => JsonSerializer.Deserialize<VerifierClientMetadata>(json, TestSetup.DefaultSerializationOptions)!;


    private static Dictionary<string, string> BaseFields(bool includeState) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = "redirect_uri:https://verifier.example.com/cb",
            [OAuthRequestParameterNames.ResponseType] = Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] = WellKnownResponseModes.DirectPost,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] = "https://verifier.example.com/cb",
            [WellKnownJwtClaimNames.Nonce] = "nonce-abc",
        }.AddStateIf(includeState);


    [TestMethod]
    public void OptionalPolicyAcceptsAbsentState()
    {
        AuthorizationRequestObject request = AuthorizationRequestObjectFormFields.Parse(
            BaseFields(includeState: false),
            DcqlDeserializer, ClientMetadataDeserializer,
            Now, Lifetime, StateParameterPolicy.Optional);

        Assert.IsNull(request.State,
            "OID4VP §5 makes state OPTIONAL; the Optional policy accepts its absence as null.");
    }


    [TestMethod]
    public void RequiredPolicyRejectsAbsentState()
    {
        _ = Assert.ThrowsExactly<FormatException>(
            () => AuthorizationRequestObjectFormFields.Parse(
                BaseFields(includeState: false),
                DcqlDeserializer, ClientMetadataDeserializer,
                Now, Lifetime, StateParameterPolicy.Required));
    }


    [TestMethod]
    public void StatePresentRoundTripsUnderEitherPolicy()
    {
        AuthorizationRequestObject optional = AuthorizationRequestObjectFormFields.Parse(
            BaseFields(includeState: true),
            DcqlDeserializer, ClientMetadataDeserializer,
            Now, Lifetime, StateParameterPolicy.Optional);
        AuthorizationRequestObject required = AuthorizationRequestObjectFormFields.Parse(
            BaseFields(includeState: true),
            DcqlDeserializer, ClientMetadataDeserializer,
            Now, Lifetime, StateParameterPolicy.Required);

        Assert.AreEqual("state-xyz", optional.State);
        Assert.AreEqual("state-xyz", required.State);
    }


    /// <summary>
    /// The library's rule for the caller's own argument: a request object lifetime is at least one and at most
    /// <see cref="int.MaxValue"/> whole seconds, because the library writes <c>iat</c> and <c>exp</c> as whole-second
    /// NumericDates and a lifetime under one second would make <c>exp</c> equal <c>iat</c>. The inline-parameter
    /// parser of an unsigned Authorization Request
    /// (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OpenID for
    /// Verifiable Presentations 1.0 Section 5.9.3</see>) refuses 500 milliseconds with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [TestMethod]
    public void AnInlineRequestObjectLifetimeUnderOneSecondIsRefused()
    {
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => AuthorizationRequestObjectFormFields.Parse(
                BaseFields(includeState: true),
                DcqlDeserializer, ClientMetadataDeserializer,
                Now, TimeSpan.FromMilliseconds(500), StateParameterPolicy.Optional));
    }


    /// <summary>
    /// The library's rule for the caller's own argument: the inline-parameter parser of an unsigned Authorization
    /// Request (<see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OpenID
    /// for Verifiable Presentations 1.0 Section 5.9.3</see>) stamps an absent <c>exp</c> at the whole seconds of the
    /// request object lifetime after <c>iat</c>: one second is accepted and stamped as one second, and 90.7 seconds is
    /// stamped as 90 seconds.
    /// </summary>
    /// <param name="ticks">The request object lifetime, in ticks.</param>
    /// <param name="expectedSeconds">The stamped <c>exp</c> less <c>iat</c>, in seconds.</param>
    [TestMethod]
    [DataRow(10_000_000L, 1L, DisplayName = "one second")]
    [DataRow(907_000_000L, 90L, DisplayName = "90.7 seconds")]
    public void AnInlineRequestObjectIsStampedForTheWholeSecondsOfItsLifetime(long ticks, long expectedSeconds)
    {
        AuthorizationRequestObject request = AuthorizationRequestObjectFormFields.Parse(
            BaseFields(includeState: true),
            DcqlDeserializer, ClientMetadataDeserializer,
            Now, TimeSpan.FromTicks(ticks), StateParameterPolicy.Optional);

        Assert.AreEqual(TimeSpan.FromSeconds(expectedSeconds), request.Exp - request.Iat);
    }
}


internal static class StateFieldExtensions
{
    public static Dictionary<string, string> AddStateIf(this Dictionary<string, string> fields, bool include)
    {
        if(include)
        {
            fields[OAuthRequestParameterNames.State] = "state-xyz";
        }

        return fields;
    }
}
