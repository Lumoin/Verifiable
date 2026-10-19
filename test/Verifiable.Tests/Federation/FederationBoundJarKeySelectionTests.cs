using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests the selection of a Verifier's JAR signing key from its validated chain's subject Entity Configuration
/// (<see cref="FederationBoundJarKeyResolver.ResolveJarSigningKey"/>) through the library's one JWK Set selection: the set judged
/// whole (RFC 7517 section 5), an element that is no object refusing it wherever it stands, a <c>kid</c> on more than one key and
/// more than one key with no <c>kid</c> named refusing it as ambiguous, never a first match or a first key.
/// </summary>
[TestClass]
internal sealed class FederationBoundJarKeySelectionTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The key of the header's <c>kid</c>, and the sole key of a set when the header names none, are selected; a set of the same key
    /// followed by an element that is no object, a set naming the <c>kid</c> on two keys, and a set of two keys for a header naming
    /// none select no key.
    /// </summary>
    /// <param name="setCase">The key set the subject publishes and the header's <c>kid</c>.</param>
    /// <param name="isSelected">Whether a key is selected.</param>
    /// <returns>A task completing once the key is selected.</returns>
    [TestMethod]
    [DataRow("kid-of-one-key", true, DisplayName = "A kid naming the set's one key")]
    [DataRow("no-kid-one-key", true, DisplayName = "No kid, a set of one key")]
    [DataRow("non-object-suffix", false, DisplayName = "The key followed by an element that is no object")]
    [DataRow("kid-on-two-keys", false, DisplayName = "A kid on two keys")]
    [DataRow("no-kid-two-keys", false, DisplayName = "No kid, a set of two keys")]
    public async Task TheJarSigningKeyIsSelectedFromTheWholeSet(string setCase, bool isSelected)
    {
        var now = TestClock.CanonicalEpoch;
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://verifier.example.test"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.test"));
        using var other = FederationTestRing.CreateNode(new EntityIdentifier("https://other.example.test"));

        var key = KeyOf(subject, subject.Kid);
        var keys = setCase switch
        {
            "kid-of-one-key" or "no-kid-one-key" => new List<object> { key },
            "non-object-suffix" => new List<object> { key, "not-a-key" },
            "kid-on-two-keys" => new List<object> { key, KeyOf(other, subject.Kid) },
            "no-kid-two-keys" => new List<object> { key, KeyOf(other, other.Kid) },
            _ => throw new ArgumentOutOfRangeException(nameof(setCase), setCase, "No key set is named so.")
        };

        var minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = keys },
            TestContext.CancellationToken).ConfigureAwait(false);

        var header = new UnverifiedJwtHeader();
        if(setCase is not ("no-kid-one-key" or "no-kid-two-keys"))
        {
            header[WellKnownJwkMemberNames.Kid] = subject.Kid;
        }

        using var selected = FederationBoundJarKeyResolver.ResolveJarSigningKey(minted.Chain, header, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        Assert.AreEqual(isSelected, selected is not null, setCase);
    }


    /// <summary>A copy of a node's published JWK under the key identifier given.</summary>
    /// <param name="node">The node.</param>
    /// <param name="kid">The key identifier the copy carries.</param>
    /// <returns>The JWK's members.</returns>
    private static Dictionary<string, object> KeyOf(FederationTestRingNode node, string kid)
    {
        var published = (IReadOnlyDictionary<string, object>)((List<object>)node.JwksObject["keys"])[0];

        return new Dictionary<string, object>(published, StringComparer.Ordinal) { ["kid"] = kid };
    }
}
