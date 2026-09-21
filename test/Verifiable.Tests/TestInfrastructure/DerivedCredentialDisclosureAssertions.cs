using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Assertions over a data-integrity derived credential's JSON structure, shared by the
/// bbs-2023 spec-vector and property-based tests.
/// </summary>
/// <remarks>
/// Every check resolves a claim through <see cref="JsonLdSelection.TryEvaluate"/>, the same
/// JSON-Pointer walker the derive/verify pipeline itself uses, rather than substring-searching
/// the serialized document: the proof value is a fresh random draw each run, so a short claim
/// value can appear inside it by coincidence, and a text search both fails a correct hiding and
/// passes a real leak that lands under a different literal.
/// </remarks>
internal static class DerivedCredentialDisclosureAssertions
{
    /// <summary>
    /// Asserts that the claim at <paramref name="pointer"/> is disclosed in
    /// <paramref name="derivedRoot"/>: the pointer must resolve, and the resolved value must
    /// equal <paramref name="expectedValue"/>.
    /// </summary>
    /// <param name="derivedRoot">The derived credential's root JSON element.</param>
    /// <param name="pointer">The JSON Pointer (RFC 6901) of the claim expected to be disclosed.</param>
    /// <param name="expectedValue">The value the claim must carry.</param>
    public static void AssertClaimDisclosed(JsonElement derivedRoot, string pointer, string expectedValue)
    {
        bool isResolved = JsonLdSelection.TryEvaluate(derivedRoot, CredentialPath.FromJsonPointer(pointer).JsonPointer, out JsonElement claimElement);
        Assert.IsTrue(isResolved, $"Disclosed claim '{pointer}' must be present.");
        Assert.AreEqual(expectedValue, claimElement.GetString(), $"Disclosed claim '{pointer}' must carry its value.");
    }


    /// <summary>
    /// Asserts that the claim at <paramref name="pointer"/> is hidden in
    /// <paramref name="derivedRoot"/>: the pointer must not resolve, and
    /// <paramref name="hiddenValue"/> must not equal any other leaf value in the disclosed
    /// structure, excluding the proof.
    /// </summary>
    /// <param name="derivedRoot">The derived credential's root JSON element.</param>
    /// <param name="pointer">The JSON Pointer (RFC 6901) of the claim expected to be hidden.</param>
    /// <param name="hiddenValue">The value that must not leak elsewhere in the disclosed structure.</param>
    public static void AssertClaimHidden(JsonElement derivedRoot, string pointer, string hiddenValue)
    {
        bool isResolved = JsonLdSelection.TryEvaluate(derivedRoot, CredentialPath.FromJsonPointer(pointer).JsonPointer, out _);
        Assert.IsFalse(isResolved, $"Undisclosed claim '{pointer}' must be hidden.");

        HashSet<string> leafValues = EnumerateNonProofLeafStrings(derivedRoot).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain(hiddenValue, leafValues, $"Undisclosed claim '{pointer}' value must not appear anywhere in the disclosed structure.");
    }


    /// <summary>
    /// Enumerates every string leaf value reachable from <paramref name="element"/>, skipping any
    /// member named <c>proof</c> at any depth. The proof's bytes are a fresh, cryptographically
    /// random draw each run and carry no claim data, so including them would make an
    /// undisclosed-claim check pass or fail by coincidence rather than by what the disclosed
    /// structure actually reveals.
    /// </summary>
    /// <param name="element">The JSON element to walk.</param>
    /// <returns>Every string leaf value found outside any <c>proof</c> member.</returns>
    public static IEnumerable<string> EnumerateNonProofLeafStrings(JsonElement element) =>
        element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject()
                .Where(property => !property.NameEquals("proof"))
                .SelectMany(property => EnumerateNonProofLeafStrings(property.Value)),
            JsonValueKind.Array => element.EnumerateArray().SelectMany(EnumerateNonProofLeafStrings),
            JsonValueKind.String => [element.GetString()!],
            _ => []
        };
}
