using System;
using Verifiable.Tpm.Spec;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves <see cref="TpmiDhSaved"/> against Table 58's five admitted arms: the round trip through
/// <see cref="TpmiDhSaved.WriteTo"/>/<see cref="TpmiDhSaved.Parse"/>, each arm's own predicates, the parse
/// refusal outside the union, and the unchecked <see cref="TpmiDhSaved.FromValue"/> factory.
/// </summary>
[TestClass]
internal sealed class TpmiDhSavedTests
{
    /// <summary>
    /// Table 58 admits five arms — the HMAC session range, the policy session range, and three fixed object
    /// values — each round-tripping through <see cref="TpmiDhSaved.WriteTo"/>/<see cref="TpmiDhSaved.Parse"/>
    /// and each answering only its own arm's predicates <see langword="true"/>: "an HMAC session context", "a
    /// policy session context", "an ordinary transient object", "a sequence object", "a transient object with
    /// the stClear attribute SET".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.12, Table 58</see>.
    /// </summary>
    /// <param name="value">The raw handle value under test.</param>
    /// <param name="isHmacSession">The expected <see cref="TpmiDhSaved.IsHmacSession"/>.</param>
    /// <param name="isPolicySession">The expected <see cref="TpmiDhSaved.IsPolicySession"/>.</param>
    /// <param name="isSession">The expected <see cref="TpmiDhSaved.IsSession"/>.</param>
    /// <param name="isOrdinaryObject">The expected <see cref="TpmiDhSaved.IsOrdinaryObject"/>.</param>
    /// <param name="isSequenceObject">The expected <see cref="TpmiDhSaved.IsSequenceObject"/>.</param>
    /// <param name="isStClearObject">The expected <see cref="TpmiDhSaved.IsStClearObject"/>.</param>
    /// <param name="isObject">The expected <see cref="TpmiDhSaved.IsObject"/>.</param>
    [TestMethod]
    [DataRow(0x0200_0000u, true, false, true, false, false, false, false, DisplayName = "the HMAC session range, lower bound")]
    [DataRow(0x02FF_FFFFu, true, false, true, false, false, false, false, DisplayName = "the HMAC session range, upper bound")]
    [DataRow(0x0300_0000u, false, true, true, false, false, false, false, DisplayName = "the policy session range, lower bound")]
    [DataRow(0x03FF_FFFFu, false, true, true, false, false, false, false, DisplayName = "the policy session range, upper bound")]
    [DataRow(0x8000_0000u, false, false, false, true, false, false, true, DisplayName = "an ordinary transient object")]
    [DataRow(0x8000_0001u, false, false, false, false, true, false, true, DisplayName = "a sequence object")]
    [DataRow(0x8000_0002u, false, false, false, false, false, true, true, DisplayName = "a transient object with the stClear attribute SET")]
    public void TpmiDhSavedRoundTripsAndPredicatesEachTable58Arm(
        uint value,
        bool isHmacSession,
        bool isPolicySession,
        bool isSession,
        bool isOrdinaryObject,
        bool isSequenceObject,
        bool isStClearObject,
        bool isObject)
    {
        Assert.IsTrue(TpmiDhSaved.IsSaved(value), "Every DataRow value in this test names one of Table 58's five arms.");

        TpmiDhSaved original = TpmiDhSaved.FromValue(value);
        TpmiDhSaved parsed = RoundTrip(original);

        Assert.AreEqual(value, parsed.Value, "The round trip through WriteTo/Parse must reproduce the raw value exactly.");
        Assert.AreEqual(isHmacSession, parsed.IsHmacSession, "IsHmacSession must match Table 58's HMAC session range alone.");
        Assert.AreEqual(isPolicySession, parsed.IsPolicySession, "IsPolicySession must match Table 58's policy session range alone.");
        Assert.AreEqual(isSession, parsed.IsSession, "IsSession must be the union of IsHmacSession and IsPolicySession.");
        Assert.AreEqual(isOrdinaryObject, parsed.IsOrdinaryObject, "IsOrdinaryObject must match OrdinaryTransientObject (0x80000000) alone.");
        Assert.AreEqual(isSequenceObject, parsed.IsSequenceObject, "IsSequenceObject must match SequenceObject (0x80000001) alone.");
        Assert.AreEqual(isStClearObject, parsed.IsStClearObject, "IsStClearObject must match StClearTransientObject (0x80000002) alone.");
        Assert.AreEqual(isObject, parsed.IsObject, "IsObject must be the union of the three fixed object values.");
    }

    /// <summary>
    /// "If an input value for handle is outside of the range of values used by the TPM, the TPM shall return an
    /// error (TPM_RC_VALUE) and do no additional processing of the context." — a value naming none of Table 58's
    /// five arms is refused by both <see cref="TpmiDhSaved.IsSaved"/> and <see cref="TpmiDhSaved.Parse"/>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.2</see>.
    /// </summary>
    /// <param name="value">The raw handle value under test.</param>
    [TestMethod]
    [DataRow(0x8000_0003u, DisplayName = "one past the three fixed object values")]
    [DataRow(0x0100_0000u, DisplayName = "an NV Index handle")]
    [DataRow(0x4000_0001u, DisplayName = "a permanent handle (TPM_RH_OWNER)")]
    [DataRow(0x8100_0000u, DisplayName = "a persistent object handle")]
    public void TpmiDhSavedParseAndIsSavedRefuseAValueOutsideTable58sFiveArms(uint value)
    {
        Assert.IsFalse(TpmiDhSaved.IsSaved(value), "A value outside Table 58's five arms must not be reported as saved.");

        byte[] wire = new byte[sizeof(uint)];
        var writer = new TpmWriter(wire);
        writer.WriteUInt32(value);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseSaved(wire),
            "A value outside Table 58's five arms must be refused with TPM_RC_VALUE at parse.");
    }

    /// <summary>
    /// <see cref="TpmiDhSaved.FromValue"/> constructs a handle without checking Table 58's admitted set — "for a
    /// value already known good", matching <see cref="TpmiDhContext.FromValue"/>'s own unchecked idiom.
    /// </summary>
    [TestMethod]
    public void TpmiDhSavedFromValueSkipsValidation()
    {
        TpmiDhSaved handle = TpmiDhSaved.FromValue(0x8000_0003u);

        Assert.AreEqual(0x8000_0003u, handle.Value, "FromValue must store the raw value verbatim.");
        Assert.IsFalse(TpmiDhSaved.IsSaved(handle.Value), "FromValue's argument here is not itself one of Table 58's five arms, proving no validation ran.");
    }

    /// <summary>
    /// Round-trips <paramref name="original"/> through <see cref="TpmiDhSaved.WriteTo"/> and
    /// <see cref="TpmiDhSaved.Parse"/>, asserting the wire consumes exactly the four octets a handle occupies.
    /// </summary>
    /// <param name="original">The handle to round-trip.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiDhSaved RoundTrip(TpmiDhSaved original)
    {
        byte[] wire = new byte[sizeof(uint)];
        var writer = new TpmWriter(wire);
        original.WriteTo(ref writer);
        Assert.AreEqual(wire.Length, writer.Written, "WriteTo must fill exactly the four-octet handle.");

        var reader = new TpmReader(wire);
        TpmiDhSaved parsed = TpmiDhSaved.Parse(ref reader);
        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the four octets WriteTo produced.");

        return parsed;
    }

    /// <summary>
    /// Parses a saved-context handle from a complete wire fragment, so a refusal can be asserted as a single
    /// expression (a <see cref="TpmReader"/> is a <see langword="ref"/> struct and cannot be captured by a lambda).
    /// </summary>
    /// <param name="wire">The four-octet handle wire fragment.</param>
    private static void ParseSaved(byte[] wire)
    {
        var reader = new TpmReader(wire);
        _ = TpmiDhSaved.Parse(ref reader);
    }
}
