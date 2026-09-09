using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class OutgoingHeadersDpopExtensionsTests
{
    [TestMethod]
    public void WithDpopSetsTheDpopHeader()
    {
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithDpop("proof-token");

        Assert.IsTrue(headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out string? value));
        Assert.AreEqual("proof-token", value);
    }


    [TestMethod]
    public void WithDpopReplacesAnyPreviousDpopValue()
    {
        OutgoingHeaders headers = OutgoingHeaders.Empty
            .WithDpop("first-proof")
            .WithDpop("second-proof");

        Assert.IsTrue(headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out string? value));
        Assert.AreEqual("second-proof", value);
        Assert.HasCount(1, headers.Values);
    }


    [TestMethod]
    public void WithDpopAndAccessTokenSetsBothHeaders()
    {
        //RFC 9449 §7.1 — resource-server requests carry both the DPoP proof
        //(in the `DPoP` header) and the bound access token (in the
        //`Authorization` header with the `DPoP` scheme).
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithDpopAndAccessToken(
            "proof-jws", "at.abc");

        Assert.HasCount(2, headers.Values);

        Assert.IsTrue(headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out string? dpopValue));
        Assert.AreEqual("proof-jws", dpopValue);

        Assert.IsTrue(headers.Values.TryGetValue(
            WellKnownHttpHeaderNames.Authorization, out string? authValue));
        Assert.AreEqual($"{WellKnownAuthenticationSchemes.DPoP} at.abc", authValue);
    }


    [TestMethod]
    public void ValuesLookupIsCaseInsensitive()
    {
        //RFC 9110 §5.1: "Field names are case-insensitive". A header composed under one
        //casing must be found under a differing casing.
        OutgoingHeaders headers = OutgoingHeaders.Empty.With("X-Custom", "value");

        Assert.IsTrue(headers.Values.TryGetValue("x-custom", out string? value),
            "RFC 9110 §5.1: a header composed under one casing must be found under a differing casing.");
        Assert.AreEqual("value", value);
    }
}
