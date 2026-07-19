using Verifiable.OAuth.Client;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// <see href="https://www.rfc-editor.org/rfc/rfc9207#section-4">RFC 9207 §4</see> / §2.4 client-side
/// issuer validation for <see cref="AuthorizationServerIssuerValidation"/> over an application-owned
/// known-issuer resolver. The application owns the authorization-server store and guarantees §4 issuer
/// uniqueness in how it answers the resolver; the library validates an authorization response's
/// <c>iss</c> against it (a known, uniquely-configured server that ordinally matches the requested one).
/// </summary>
[TestClass]
internal sealed class Rfc9207IssuerUniquenessTests
{
    private static readonly Uri HonestIssuer = new("https://honest.as.example");
    private static readonly Uri ImpersonatorIssuer = new("https://impersonator.as.example");
    private static readonly Uri UnknownIssuer = new("https://unknown.as.example");


    /// <summary>
    /// A resolver over an application-owned set of trusted, uniquely-configured issuers, compared by the
    /// same ordinal rule the library uses.
    /// </summary>
    private static KnownAuthorizationServerIssuerResolver KnownIssuers(params Uri[] issuers)
    {
        return issuer => Array.Exists(
            issuers, known => string.Equals(known.OriginalString, issuer, StringComparison.Ordinal));
    }


    /// <summary>Happy path: the <c>iss</c> is the known, requested authorization server's own issuer.</summary>
    [TestMethod]
    public void AcceptsTheRequestedAuthorizationServer()
    {
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer);

        Assert.IsTrue(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            HonestIssuer.OriginalString, HonestIssuer, isKnown));
    }


    /// <summary>
    /// §2.4 mix-up defense: an <c>iss</c> that maps to a DIFFERENT known authorization server than the
    /// one the request targeted is rejected, even though it is itself a trusted, known server.
    /// </summary>
    [TestMethod]
    public void RejectsIssuerFromADifferentKnownAuthorizationServer()
    {
        //Both are trusted/known, but the request went to HonestIssuer while the response claims the
        //distinct, also-known ImpersonatorIssuer.
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer, ImpersonatorIssuer);

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            ImpersonatorIssuer.OriginalString, HonestIssuer, isKnown));
    }


    /// <summary>An <c>iss</c> the application's resolver does not know is rejected.</summary>
    [TestMethod]
    public void RejectsAnUnknownIssuer()
    {
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer);

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            UnknownIssuer.OriginalString, HonestIssuer, isKnown));
    }


    /// <summary>
    /// The known-issuer requirement in isolation: an <c>iss</c> that ordinally MATCHES the requested
    /// issuer is still rejected when the resolver does not know it — the response must resolve to a
    /// positively known authorization server, not merely match what the request expected. (If the
    /// known-issuer clause were dropped, the ordinal-equality clause alone would accept this.)
    /// </summary>
    [TestMethod]
    public void RejectsAnUnknownIssuerEvenWhenItMatchesTheExpectedIssuer()
    {
        //The resolver knows only HonestIssuer; the request and response both use UnknownIssuer.
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer);

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            UnknownIssuer.OriginalString, UnknownIssuer, isKnown));
    }


    /// <summary>
    /// A missing or malformed <c>iss</c> is rejected as invalid input, not faulted on — this validates
    /// untrusted wire data.
    /// </summary>
    [TestMethod]
    public void RejectsNullOrWhitespaceIssuerWithoutThrowing()
    {
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer);

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(null, HonestIssuer, isKnown));
        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(string.Empty, HonestIssuer, isKnown));
        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid("   ", HonestIssuer, isKnown));
    }


    /// <summary>
    /// Ordinal (RFC 8414 §3.3 / RFC 9207 §2.4 code-point) comparison, not <see cref="Uri"/> normalization:
    /// a trailing-slash variant of the expected issuer is rejected even when the resolver trusts that
    /// variant, so only the ordinal match against the expected issuer can reject it.
    /// </summary>
    [TestMethod]
    public void UsesOrdinalComparisonNotUriNormalization()
    {
        Uri issuerWithTrailingSlash = new("https://honest.as.example/");
        KnownAuthorizationServerIssuerResolver isKnown = KnownIssuers(HonestIssuer, issuerWithTrailingSlash);

        Assert.IsFalse(AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid(
            issuerWithTrailingSlash.OriginalString, HonestIssuer, isKnown));
    }
}
