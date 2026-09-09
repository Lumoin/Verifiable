using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPMS_CONTEXT</c> against Table 260's own field order — <c>sequence</c> (a big-endian
/// <c>UINT64</c>) followed by <c>savedHandle</c>, <c>hierarchy</c>, and <c>contextBlob</c> — for a session arm
/// under the NULL hierarchy and an object arm under the owner hierarchy, plus <see cref="TpmsContext.Parse"/>'s
/// range refusals and its disposal.
/// </summary>
[TestClass]
internal sealed class TpmsContextFramingTests
{
    /// <summary>
    /// A session context's <c>savedHandle</c> is the session's own handle (here the lower bound of the HMAC
    /// session range) and its <c>hierarchy</c> is always <c>TPM_RH_NULL</c>: "For session and sequence contexts,
    /// the hierarchy is [TPM_RH_NULL]" (quoted with the published text's own "TPM_RC_NULL" corrected — clause
    /// 14.6.3's erratum).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.5, Table 260</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The context takes ownership of the blob passed to its constructor and is itself disposed by AssertFraming's caller via the using declaration.")]
    public void TpmsContextFramesTheSessionArmByteExactlyPerTable260()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var context = new TpmsContext(5UL, TpmiDhSaved.FromValue(0x0200_0000u), TpmiRhHierarchy.Null, Tpm2bContextData.Create([0xAA, 0xBB, 0xCC], pool));

        AssertFraming(
            context,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x07, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    /// <summary>
    /// An object context's <c>savedHandle</c> is one of Table 58's three fixed values (here
    /// <see cref="TpmiDhSaved.OrdinaryTransientObject"/>) and its <c>hierarchy</c> is the object's own — here the
    /// owner hierarchy, "the hierarchy of the context".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.5, Table 260</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The context takes ownership of the blob passed to its constructor and is itself disposed by AssertFraming's caller via the using declaration.")]
    public void TpmsContextFramesTheObjectArmByteExactlyPerTable260()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var context = new TpmsContext(0x2AUL, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Owner, Tpm2bContextData.Create([0x11, 0x22], pool));

        AssertFraming(
            context,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x02, 0x11, 0x22]);
    }

    /// <summary>
    /// With an <see cref="Tpm2bContextData.Empty"/> <c>contextBlob</c>, <see cref="TpmsContext.SerializedSize"/>
    /// is exactly the eight-octet <c>sequence</c>, the two four-octet handles, and the blob's own two-octet size
    /// field — Table 260's fixed-width prefix alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.5, Table 260</see>.
    /// </summary>
    [TestMethod]
    public void TpmsContextSerializedSizeAccountsForAnEmptyContextBlob()
    {
        using var context = new TpmsContext(0UL, TpmiDhSaved.FromValue(TpmiDhSaved.SequenceObject), TpmiRhHierarchy.Null, Tpm2bContextData.Empty);

        Assert.AreEqual(8 + 4 + 4 + 2, context.SerializedSize, "With an Empty contextBlob, SerializedSize is the fixed-width prefix (sequence, savedHandle, hierarchy) plus the blob's own two-octet size field alone.");
    }

    /// <summary>
    /// "If an input value for handle is outside of the range of values used by the TPM, the TPM shall return an
    /// error (TPM_RC_VALUE) and do no additional processing of the context" — an out-of-range <c>savedHandle</c>
    /// is refused before <c>contextBlob</c> is ever reached, so nothing is rented.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.2</see>.
    /// </summary>
    [TestMethod]
    public void TpmsContextParseWithAnOutOfRangeSavedHandleThrowsAndRentsNothing()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x03];
        using var trackingPool = new MeteredHousePool();
        long baselineRented = trackingPool.RentedCount;

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseContext(wire, trackingPool.Pool),
            "A savedHandle outside Table 58's five arms must be refused with TPM_RC_VALUE before contextBlob is reached.");

        Assert.AreEqual(baselineRented, trackingPool.RentedCount, "Nothing must be rented when the parse fails before reaching the pooled contextBlob field.");
    }

    /// <summary>
    /// "If an input value for handle is outside of the range of values used by the TPM, the TPM shall return an
    /// error (TPM_RC_VALUE)" — an out-of-range <c>hierarchy</c> is likewise refused before <c>contextBlob</c> is
    /// ever reached, so nothing is rented.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.2</see>.
    /// </summary>
    [TestMethod]
    public void TpmsContextParseWithAnOutOfRangeHierarchyThrowsAndRentsNothing()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x0A];
        using var trackingPool = new MeteredHousePool();
        long baselineRented = trackingPool.RentedCount;

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseContext(wire, trackingPool.Pool),
            "A hierarchy outside TpmiRhHierarchy's four admitted selectors must be refused with TPM_RC_VALUE before contextBlob is reached.");

        Assert.AreEqual(baselineRented, trackingPool.RentedCount, "Nothing must be rented when the parse fails before reaching the pooled contextBlob field.");
    }

    /// <summary>
    /// <see cref="TpmsContext.Dispose"/> "releases ContextBlob" — the one pooled member Table 260's metadata
    /// fields never rent.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The context is disposed explicitly mid-test to observe the pool's outstanding count before and after, rather than at scope exit via a using declaration.")]
    public void TpmsContextDisposeReleasesTheBlob()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        Tpm2bContextData blob = Tpm2bContextData.Create([0x01, 0x02, 0x03], trackingPool.Pool);
        var context = new TpmsContext(1UL, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Owner, blob);
        Assert.AreEqual(baseline + 1, trackingPool.OutstandingCount, "The blob's rental must be outstanding while the context is alive.");

        context.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the context must release the blob's rental.");
    }

    /// <summary>
    /// Frames <paramref name="context"/> through <see cref="TpmsContext.WriteTo"/> and asserts the octets
    /// reproduce <paramref name="expectedWire"/> exactly, that <see cref="TpmsContext.SerializedSize"/> accounts
    /// for the whole frame, and that <see cref="TpmsContext.Parse"/> reconstructs every field from those same
    /// octets.
    /// </summary>
    /// <param name="context">The context under test.</param>
    /// <param name="expectedWire">The hand-computed Table 260 frame.</param>
    private static void AssertFraming(TpmsContext context, byte[] expectedWire)
    {
        Assert.AreEqual(expectedWire.Length, context.SerializedSize, "SerializedSize must account for the sequence, the two handles, and the blob's own serialized size together.");

        byte[] wire = new byte[expectedWire.Length];
        var writer = new TpmWriter(wire);
        context.WriteTo(ref writer);
        Assert.AreEqual(wire.Length, writer.Written, "WriteTo must fill exactly SerializedSize octets.");
        Assert.AreSequenceEqual(expectedWire, wire, "The written octets must reproduce the hand-computed Table 260 frame exactly.");

        var reader = new TpmReader(wire);
        using TpmsContext parsed = TpmsContext.Parse(ref reader, BaseMemoryPool.Shared);
        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the octets WriteTo produced.");
        Assert.AreEqual(context.Sequence, parsed.Sequence, "Parse must reproduce sequence exactly.");
        Assert.AreEqual(context.SavedHandle.Value, parsed.SavedHandle.Value, "Parse must reproduce savedHandle exactly.");
        Assert.AreEqual(context.Hierarchy.Value, parsed.Hierarchy.Value, "Parse must reproduce hierarchy exactly.");
        Assert.IsTrue(parsed.ContextBlob.Span.SequenceEqual(context.ContextBlob.Span), "Parse must reproduce contextBlob's octets exactly.");
    }

    /// <summary>
    /// Parses a <c>TPMS_CONTEXT</c> from a complete wire fragment, so a refusal can be asserted as a single
    /// expression (a <see cref="TpmReader"/> is a <see langword="ref"/> struct and cannot be captured by a lambda).
    /// </summary>
    /// <param name="wire">The wire fragment beginning at <c>sequence</c>.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    private static void ParseContext(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        using TpmsContext context = TpmsContext.Parse(ref reader, pool);
    }
}
