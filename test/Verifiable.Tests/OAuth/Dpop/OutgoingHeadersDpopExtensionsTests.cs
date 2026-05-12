using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth.Dpop;

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
}
