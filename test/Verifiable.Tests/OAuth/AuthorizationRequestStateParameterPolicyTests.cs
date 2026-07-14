using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;
using Verifiable.Json;
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
    private static readonly DateTimeOffset Now = TestClock.CanonicalEpoch;
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private static readonly JarClaimDeserializer<DcqlQuery> DcqlDeserializer =
        json => JsonSerializer.Deserialize<DcqlQuery>(json, TestSetup.DefaultSerializationOptions)!;

    private static readonly JarClaimDeserializer<VerifierClientMetadata> ClientMetadataDeserializer =
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
        Assert.ThrowsExactly<FormatException>(
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
