using System.Globalization;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// A refusal of the flow is constructed only with an established origin: every refusal factory takes the origin as a value of
/// <see cref="AuthCodeFlowRefusalOrigin"/> and refuses one that is neither of the two the flow defines, the type's default
/// value among them, and an outcome that is no refusal; a successful or redirecting result carries no origin.
/// </summary>
[TestClass]
internal sealed class AuthCodeFlowEndpointResultTests
{
    /// <summary>The error code every refusal row carries.</summary>
    private const string RefusalErrorCode = "invalid_grant";

    /// <summary>The error description every refusal row carries.</summary>
    private const string RefusalErrorDescription = "The grant was refused.";

    /// <summary>The redirect target the redirecting row carries.</summary>
    private static Uri RedirectTarget { get; } = new("https://as.example.com/authorize?request_uri=urn%3Aexample");

    /// <summary>The callback validation claims the claims rows carry: none.</summary>
    private static IReadOnlyList<Claim> NoClaims { get; } = [];

    /// <summary>The credential refusal the credential row carries.</summary>
    private static ClientAssertionCredentialRefusal CredentialRefusal { get; } = new()
    {
        Reason = ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey
    };


    /// <summary>
    /// A refusal constructed with no origin - the type's default value <see cref="AuthCodeFlowRefusalOrigin.None"/>, which states
    /// neither origin - is refused by every refusal factory, so no refusal reads an origin that was never set as either party's.
    /// </summary>
    /// <param name="outcome">The refusal's outcome.</param>
    [TestMethod]
    [DataRow(AuthCodeFlowEndpointOutcome.BadRequest)]
    [DataRow(AuthCodeFlowEndpointOutcome.InternalError)]
    public void ARefusalConstructedWithNoOriginIsRefusedByEveryRefusalFactory(AuthCodeFlowEndpointOutcome outcome)
    {
        var noOrigin = default(AuthCodeFlowRefusalOrigin);
        Assert.AreEqual(AuthCodeFlowRefusalOrigin.None, noOrigin, "The control: the default value is None, which states no origin.");

        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(outcome, noOrigin, RefusalErrorCode, RefusalErrorDescription));
        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(outcome, noOrigin, RefusalErrorCode, RefusalErrorDescription, NoClaims));
        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(outcome, noOrigin, RefusalErrorCode, RefusalErrorDescription, CredentialRefusal));
    }


    /// <summary>
    /// A refusal constructed with an origin the flow does not define - a value of neither member of
    /// <see cref="AuthCodeFlowRefusalOrigin"/> - is refused by every refusal factory.
    /// </summary>
    /// <param name="undefined">The value outside the two the flow defines.</param>
    [TestMethod]
    [DataRow(3)]
    [DataRow(-1)]
    [DataRow(int.MaxValue)]
    [DataRow(int.MinValue)]
    public void ARefusalConstructedWithAnOriginTheFlowDoesNotDefineIsRefusedByEveryRefusalFactory(int undefined)
    {
        var origin = (AuthCodeFlowRefusalOrigin)undefined;
        Assert.IsFalse(Enum.IsDefined(origin), $"The control: {undefined.ToString(CultureInfo.InvariantCulture)} is no origin the flow defines.");

        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(
            AuthCodeFlowEndpointOutcome.BadRequest, origin, RefusalErrorCode, RefusalErrorDescription));
        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(
            AuthCodeFlowEndpointOutcome.BadRequest, origin, RefusalErrorCode, RefusalErrorDescription, NoClaims));
        AssertOriginRefused(() => AuthCodeFlowEndpointResult.Refused(
            AuthCodeFlowEndpointOutcome.InternalError, origin, RefusalErrorCode, RefusalErrorDescription, CredentialRefusal));
    }


    /// <summary>
    /// An outcome that is no refusal is never constructed as one, whatever origin it is given: a success and a redirect are
    /// constructed by their own factories, which carry no origin.
    /// </summary>
    /// <param name="outcome">The outcome that is no refusal.</param>
    [TestMethod]
    [DataRow(AuthCodeFlowEndpointOutcome.Ok)]
    [DataRow(AuthCodeFlowEndpointOutcome.Redirect)]
    [DataRow((AuthCodeFlowEndpointOutcome)(-1))]
    public void AnOutcomeThatIsNoRefusalIsNeverConstructedAsOne(AuthCodeFlowEndpointOutcome outcome)
    {
        var refused = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => AuthCodeFlowEndpointResult.Refused(
            outcome, AuthCodeFlowRefusalOrigin.ClientJudgement, RefusalErrorCode, RefusalErrorDescription));

        Assert.AreEqual("outcome", refused.ParamName, "The refusal names the outcome as the value refused.");
    }


    /// <summary>
    /// A refusal carries the origin it was constructed with, and the error code and description, through every refusal
    /// factory.
    /// </summary>
    /// <param name="outcome">The refusal's outcome.</param>
    /// <param name="origin">The origin the refusal states.</param>
    [TestMethod]
    [DataRow(AuthCodeFlowEndpointOutcome.BadRequest, AuthCodeFlowRefusalOrigin.AuthorizationServerAnswer)]
    [DataRow(AuthCodeFlowEndpointOutcome.BadRequest, AuthCodeFlowRefusalOrigin.ClientJudgement)]
    [DataRow(AuthCodeFlowEndpointOutcome.InternalError, AuthCodeFlowRefusalOrigin.AuthorizationServerAnswer)]
    [DataRow(AuthCodeFlowEndpointOutcome.InternalError, AuthCodeFlowRefusalOrigin.ClientJudgement)]
    public void ARefusalCarriesTheOriginItWasConstructedWith(AuthCodeFlowEndpointOutcome outcome, AuthCodeFlowRefusalOrigin origin)
    {
        var plain = AuthCodeFlowEndpointResult.Refused(outcome, origin, RefusalErrorCode, RefusalErrorDescription);
        var withClaims = AuthCodeFlowEndpointResult.Refused(outcome, origin, RefusalErrorCode, RefusalErrorDescription, NoClaims);
        var withCredential = AuthCodeFlowEndpointResult.Refused(outcome, origin, RefusalErrorCode, RefusalErrorDescription, CredentialRefusal);

        foreach(var refusal in (AuthCodeFlowEndpointResult[])[plain, withClaims, withCredential])
        {
            Assert.AreEqual(outcome, refusal.Outcome, "The refusal carries its outcome.");
            Assert.AreEqual(origin, refusal.RefusalOrigin, "The refusal carries the origin it was constructed with.");
            Assert.AreEqual(RefusalErrorCode, refusal.ErrorCode, "The refusal carries its error code.");
            Assert.AreEqual(RefusalErrorDescription, refusal.ErrorDescription, "The refusal carries its description.");
            Assert.IsNull(refusal.Body, "A refusal answers no body.");
            Assert.IsNull(refusal.RedirectUri, "A refusal redirects nowhere.");
        }

        Assert.AreSame(CredentialRefusal, withCredential.ClientAssertionCredentialRefusal, "The credential refusal is carried as given.");
        Assert.IsNull(plain.ClientAssertionCredentialRefusal, "A refusal of no credential carries no credential refusal.");
    }


    /// <summary>A successful and a redirecting result carry no refusal origin, no error and no credential refusal.</summary>
    [TestMethod]
    public void ASuccessAndARedirectCarryNoRefusalOrigin()
    {
        var success = AuthCodeFlowEndpointResult.Succeeded(new Dictionary<string, object> { ["flow_id"] = "flow-1" });
        var redirect = AuthCodeFlowEndpointResult.Redirected(RedirectTarget);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, success.Outcome, "The success is an Ok outcome.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, redirect.Outcome, "The redirect is a Redirect outcome.");
        Assert.AreEqual(RedirectTarget, redirect.RedirectUri, "The redirect carries its target.");

        foreach(var result in (AuthCodeFlowEndpointResult[])[success, redirect])
        {
            Assert.IsNull(result.RefusalOrigin, "A result that is no refusal carries no refusal origin.");
            Assert.IsNull(result.ErrorCode, "A result that is no refusal carries no error code.");
            Assert.IsNull(result.ClientAssertionCredentialRefusal, "A result that is no refusal carries no credential refusal.");
        }
    }


    /// <summary>Holds that a refusal factory refused the origin it was given.</summary>
    /// <param name="construct">The construction of the refusal.</param>
    private static void AssertOriginRefused(Func<AuthCodeFlowEndpointResult> construct)
    {
        var refused = Assert.ThrowsExactly<ArgumentOutOfRangeException>(construct);

        Assert.AreEqual("origin", refused.ParamName, "The refusal names the origin as the value refused.");
    }
}
