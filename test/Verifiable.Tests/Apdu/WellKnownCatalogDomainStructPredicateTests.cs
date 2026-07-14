using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Table-driven coverage for the domain-struct well-known catalog family's predicates (the
/// WellKnownClaimIds shape: <see langword="static readonly"/> registered-struct fields plus
/// per-member Is* predicates), covering <see cref="WellKnownCtapInstructionCodes"/> and
/// <see cref="WellKnownCtapStatusWords"/> after their property-to-field conversion during the
/// style-conformance wave. Each catalog's own value set is checked so every predicate accepts its
/// own value and rejects every sibling value.
/// </summary>
[TestClass]
internal sealed class WellKnownCatalogDomainStructPredicateTests
{
    /// <summary>Every Is* predicate on <see cref="WellKnownCtapInstructionCodes"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapInstructionCodesPredicatesMatchOnlyTheirOwnValue()
    {
        InstructionCode[] values =
        [
            WellKnownCtapInstructionCodes.NfcCtapMsg,
            WellKnownCtapInstructionCodes.NfcCtapGetResponse,
            WellKnownCtapInstructionCodes.NfcCtapControl,
        ];

        Func<InstructionCode, bool>[] predicates =
        [
            WellKnownCtapInstructionCodes.IsNfcCtapMsg,
            WellKnownCtapInstructionCodes.IsNfcCtapGetResponse,
            WellKnownCtapInstructionCodes.IsNfcCtapControl,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>
    /// The sole Is* predicate on <see cref="WellKnownCtapStatusWords"/> accepts its own value and
    /// rejects a value borrowed from an unrelated <see cref="StatusWord"/> registration.
    /// </summary>
    [TestMethod]
    public void WellKnownCtapStatusWordsPredicateAcceptsOwnValueAndRejectsAnUnrelatedValue()
    {
        Assert.IsTrue(WellKnownCtapStatusWords.IsResponseStatus(WellKnownCtapStatusWords.ResponseStatus));
        Assert.IsFalse(WellKnownCtapStatusWords.IsResponseStatus(StatusWord.Success));
    }
}
