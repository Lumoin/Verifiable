using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the hash-tree half of the validation algorithm of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>:
/// <see cref="XmlEvidenceRecordHashTrees.ComputeRootAsync"/>, which is clause 3.1.1's root rule including its
/// first-<c>Sequence</c>-only exception, and <see cref="XmlEvidenceRecordHashTrees.StateMembership"/>, which is
/// Appendix A step 5.b's bidirectional comparison.
/// </summary>
/// <remarks>
/// Every root the shipped surface reaches is cross-checked against <see cref="XmlEvidenceRecordOracle"/>, which
/// recomputes it from the clause text through a different digest implementation. What the tests assert is
/// therefore a fact about the algorithm the specification states, not about one implementation of it agreeing
/// with itself.
/// </remarks>
[TestClass]
internal sealed class XmlEvidenceRecordHashTreeTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The algorithm every tree of this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;


    /// <summary>
    /// Clause 3.1.1's exception: a first <c>Sequence</c> holding exactly one <c>DigestValue</c> carries that
    /// value forward as it stands — "then its binary value is added to the next list obtained from the next
    /// <c>Sequence</c> element" — rather than hashing it.
    /// </summary>
    [TestMethod]
    public async Task AFirstSequenceOfOneValueIsCarriedForwardUnhashed()
    {
        byte[] leaf = Digest("leaf");
        byte[] sibling = Digest("sibling");
        using XmlEvidenceRecordHashTree tree = BuildTree([[leaf], [sibling]]);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordRootStatus.Computed, computation.Status, "A two-level tree reaches a root.");
        byte[] expected = XmlEvidenceRecordOracle.Combine([leaf, sibling], Algorithm);
        Assert.AreSequenceEqual(expected, computation.Root!.AsReadOnlySpan().ToArray(),
            "The single first value enters the second level unhashed, so the root is the combination of the two values themselves.");
        Assert.AreNotEqual(
            Convert.ToBase64String(XmlEvidenceRecordOracle.Combine([EvidenceRecordOracle.Hash(leaf, Algorithm), sibling], Algorithm)),
            Convert.ToBase64String(computation.Root!.AsReadOnlySpan().ToArray()),
            "Hashing the single first value first — the reading the exception exists to rule out — reaches a different root.");
    }


    /// <summary>
    /// A tree of exactly one <c>Sequence</c> holding one value states that value as its root, which is the same
    /// exception with nothing after it.
    /// </summary>
    [TestMethod]
    public async Task AOneSequenceOneValueTreeStatesThatValueAsItsRoot()
    {
        byte[] leaf = Digest("only");
        using XmlEvidenceRecordHashTree tree = BuildTree([[leaf]]);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordRootStatus.Computed, computation.Status, "One sequence of one value is a well-formed tree.");
        Assert.AreSequenceEqual(leaf, computation.Root!.AsReadOnlySpan().ToArray(),
            "With no later sequence to combine into, the value the exception carried forward is the root.");
    }


    /// <summary>
    /// A first <c>Sequence</c> holding more than one value takes the general rule: sorted, concatenated, hashed.
    /// </summary>
    [TestMethod]
    public async Task AFirstSequenceOfSeveralValuesIsSortedConcatenatedAndHashed()
    {
        byte[] first = Digest("group member one");
        byte[] second = Digest("group member two");
        using XmlEvidenceRecordHashTree tree = BuildTree([[first, second]]);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(XmlEvidenceRecordOracle.Combine([first, second], Algorithm), computation.Root!.AsReadOnlySpan().ToArray(),
            "Clause 3.1.1: the collected values are ordered binary ascending, concatenated and hashed.");
    }


    /// <summary>
    /// THE edge the exception's wording turns on: a LATER <c>Sequence</c> holding exactly one value is not the
    /// exception. It is combined with the carried value like any other level, and a reading that short-circuited
    /// every singleton list would reach a different root.
    /// </summary>
    [TestMethod]
    public async Task ASingleValueDeeperInTheTreeIsCombinedRatherThanCarriedForward()
    {
        byte[] first = Digest("first leaf");
        byte[] second = Digest("second leaf");
        byte[] lonelySibling = Digest("the only node at the next level");
        using XmlEvidenceRecordHashTree tree = BuildTree([[first, second], [lonelySibling]]);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] level = XmlEvidenceRecordOracle.Combine([first, second], Algorithm);
        Assert.AreSequenceEqual(XmlEvidenceRecordOracle.Combine([level, lonelySibling], Algorithm), computation.Root!.AsReadOnlySpan().ToArray(),
            "Clause 3.1.1 states the exception for the FIRST Sequence alone; a single-sibling level deeper in the tree is an ordinary level.");
        Assert.AreNotEqual(
            Convert.ToBase64String(level),
            Convert.ToBase64String(computation.Root!.AsReadOnlySpan().ToArray()),
            "Short-circuiting every singleton list would have stopped at the first level's value and called it the root.");
    }


    /// <summary>
    /// A deeper tree reaches the root the independent oracle reaches, level by level.
    /// </summary>
    [TestMethod]
    public async Task AFourLevelTreeReachesTheRootTheOracleReaches()
    {
        List<byte[]> level0 = [Digest("a"), Digest("b")];
        List<byte[]> level1 = [Digest("c")];
        List<byte[]> level2 = [Digest("d"), Digest("e")];
        List<byte[]> level3 = [Digest("f")];
        using XmlEvidenceRecordHashTree tree = BuildTree([level0, level1, level2, level3]);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] expected = XmlEvidenceRecordTestFactory.RootOf([level0, level1, level2, level3], Algorithm);
        Assert.AreSequenceEqual(expected, computation.Root!.AsReadOnlySpan().ToArray(),
            "Every level is combined in Order, and the independent walk reaches the same value.");
    }


    /// <summary>
    /// A hash tree with no <c>Sequence</c> element, and a <c>Sequence</c> with no <c>DigestValue</c>, are shapes
    /// clause 8's schema does not admit, and neither reaches a root.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyTreeAndAnEmptySequenceBothReachNoRoot()
    {
        using var emptyTree = new XmlEvidenceRecordHashTree { Sequences = [] };
        using XmlEvidenceRecordRootComputation ofEmptyTree = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            emptyTree, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordRootStatus.Malformed, ofEmptyTree.Status, "Clause 8's schema requires at least one Sequence.");
        Assert.IsNull(ofEmptyTree.Root, "Nothing is reported as a root when none was reached.");

        using var valueless = new XmlEvidenceRecordSequence { Order = 1, DigestValues = [] };
        using var emptySequence = new XmlEvidenceRecordHashTree { Sequences = [valueless] };
        using XmlEvidenceRecordRootComputation ofEmptySequence = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            emptySequence, Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordRootStatus.Malformed, ofEmptySequence.Status, "Clause 8's schema requires at least one DigestValue per Sequence.");
    }


    /// <summary>
    /// A hash value that is not as long as the chain's algorithm produces cannot be a digest under it, and the
    /// walk says so rather than hashing whatever it was given.
    /// </summary>
    [TestMethod]
    public async Task AHashValueOfTheWrongLengthStopsTheWalk()
    {
        using XmlEvidenceRecordHashTree tree = BuildTree([[Digest("leaf")]], PkiDigestAlgorithm.Sha256);

        using XmlEvidenceRecordRootComputation computation = await XmlEvidenceRecordHashTrees.ComputeRootAsync(
            tree, PkiDigestAlgorithm.Sha512, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordRootStatus.HashValueLengthMismatch, computation.Status,
            "Clause 4.1.1 makes one algorithm govern every hash value of a chain, so a 32-octet value under a 64-octet algorithm is refused.");
    }


    /// <summary>
    /// Appendix A step 5.b, both directions: every protected value has to be in the first sequence, and — under
    /// the strict reading this library defaults to — the first sequence may hold nothing else.
    /// </summary>
    [TestMethod]
    public void TheMembershipComparisonRunsInBothDirections()
    {
        byte[] mine = Digest("my data object");
        byte[] yours = Digest("somebody else's data object");
        using XmlEvidenceRecordSequence both = BuildSequence([mine, yours]);
        using XmlEvidenceRecordSequence mineAlone = BuildSequence([mine]);

        Assert.AreEqual(
            XmlEvidenceRecordMembershipStatus.Satisfied,
            XmlEvidenceRecordHashTrees.StateMembership([mine, yours], both, requireExclusivity: true),
            "A first sequence holding exactly the protected values satisfies both directions.");

        Assert.AreEqual(
            XmlEvidenceRecordMembershipStatus.ProtectedValueMissing,
            XmlEvidenceRecordHashTrees.StateMembership([mine, yours], mineAlone, requireExclusivity: true),
            "Appendix A step 5.b: a digest value of a protected object that cannot be found in the first sequence is a negative result.");

        Assert.AreEqual(
            XmlEvidenceRecordMembershipStatus.FirstSequenceHoldsExtraneousValue,
            XmlEvidenceRecordHashTrees.StateMembership([mine], both, requireExclusivity: true),
            "Appendix A step 5.b, second direction: a hash value in the first sequence that is not in the protected list is also a negative result.");

        Assert.AreEqual(
            XmlEvidenceRecordMembershipStatus.Satisfied,
            XmlEvidenceRecordHashTrees.StateMembership([mine], both, requireExclusivity: false),
            "Clause 3.3 step 2's SHOULD reading, which this library makes an explicit departure rather than the default.");
    }


    /// <summary>
    /// The ordering is the unsigned lexicographic one over complete digest octets that both this document and
    /// its ASN.1 sibling state, which is why the two share exactly that one primitive and nothing else.
    /// </summary>
    [TestMethod]
    public async Task TheLevelRuleOrdersValuesBinaryAscendingWhateverOrderTheyArriveIn()
    {
        byte[] low = new byte[Algorithm.OutputByteLength];
        byte[] high = new byte[Algorithm.OutputByteLength];
        low[0] = 0x00;
        high[0] = 0xFF;

        using DigestValue forward = await XmlEvidenceRecordHashTrees.CombineAsync(
            [low, high], Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using DigestValue backward = await XmlEvidenceRecordHashTrees.CombineAsync(
            [high, low], Algorithm, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(forward.AsReadOnlySpan().ToArray(), backward.AsReadOnlySpan().ToArray(),
            "Clause 3.1.1 sorts before concatenating, so the order the values arrive in cannot change the result.");
        Assert.AreSequenceEqual(XmlEvidenceRecordOracle.Combine([high, low], Algorithm), forward.AsReadOnlySpan().ToArray(),
            "And the value is the one the independent computation reaches, with the leading zero octet significant.");
    }


    /// <summary>
    /// Computes one digest through the independent oracle, so no test of this class ever hashes anything itself.
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <returns>The digest octets.</returns>
    private static byte[] Digest(string text) =>
        EvidenceRecordOracle.Hash(System.Text.Encoding.UTF8.GetBytes(text), Algorithm);


    /// <summary>
    /// Builds a hash tree model over plain octet lists.
    /// </summary>
    /// <param name="levels">The sequences, leaf list first.</param>
    /// <param name="algorithm">The algorithm the values are tagged under, or <see langword="null"/> for this class's own.</param>
    /// <returns>The tree, which the caller disposes.</returns>
    private static XmlEvidenceRecordHashTree BuildTree(IReadOnlyList<IReadOnlyList<byte[]>> levels, PkiDigestAlgorithm? algorithm = null)
    {
        var sequences = new List<XmlEvidenceRecordSequence>(levels.Count);
        for(int i = 0; i < levels.Count; ++i)
        {
            sequences.Add(BuildSequence(levels[i], i + 1, algorithm));
        }

        return new XmlEvidenceRecordHashTree { Sequences = sequences };
    }


    /// <summary>
    /// Builds one sequence model over plain octet lists.
    /// </summary>
    /// <param name="values">The hash values.</param>
    /// <param name="order">The sequence's <c>Order</c>.</param>
    /// <param name="algorithm">The algorithm the values are tagged under, or <see langword="null"/> for this class's own.</param>
    /// <returns>The sequence, which the caller disposes.</returns>
    private static XmlEvidenceRecordSequence BuildSequence(IReadOnlyList<byte[]> values, int order = 1, PkiDigestAlgorithm? algorithm = null)
    {
        PkiDigestAlgorithm tagged = algorithm ?? Algorithm;
        var digests = new List<DigestValue>(values.Count);
        for(int i = 0; i < values.Count; ++i)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(values[i].Length);
            values[i].AsSpan().CopyTo(owner.Memory.Span);
            digests.Add(new DigestValue(owner, tagged.DigestTag));
        }

        return new XmlEvidenceRecordSequence { Order = order, DigestValues = digests };
    }
}
