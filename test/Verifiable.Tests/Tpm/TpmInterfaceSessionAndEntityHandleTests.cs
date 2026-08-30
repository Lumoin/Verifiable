namespace Verifiable.Tests.Tpm;

/// <summary>
/// Round-trip and refusal proofs for the session, entity, PCR, and persistent-object handle interface types
/// added alongside <see cref="TpmHandleRanges"/>'s PCR, HMAC session, and policy session range constants:
/// <see cref="TpmiShHmac"/>, <see cref="TpmiShPolicy"/>, <see cref="TpmiDhPcr"/>, <see cref="TpmiDhPersistent"/>,
/// <see cref="TpmiDhContext"/>, and <see cref="TpmiDhEntity"/>. Each type is a plain <c>uint</c>-backed record
/// struct, so a byte-identical <c>Parse</c>/<c>WriteTo</c> round trip is proven directly over
/// <see cref="TpmReader"/>/<see cref="TpmWriter"/> without a memory pool.
/// </summary>
/// <remarks>
/// Every throwing <c>Parse</c> call is wrapped through one of the private <c>ParseXxx</c> helpers below rather
/// than closing over a local <see cref="TpmReader"/> directly inside the <c>Assert.ThrowsExactly</c> lambda: a
/// <c>ref struct</c> local cannot be captured by a lambda expression, so the helper builds the reader from the
/// ordinary <c>byte[]</c> the lambda captures instead — the same shape <c>TpmResponseHardeningTests</c> uses.
/// </remarks>
[TestClass]
internal sealed class TpmInterfaceSessionAndEntityHandleTests
{
    /// <summary>
    /// Encodes a raw handle value as the 4-octet big-endian wire form <see cref="TpmWriter.WriteUInt32"/>
    /// produces, so a test can build a <see cref="TpmReader"/> over exactly the bytes a real command or
    /// response would carry.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The 4-octet big-endian encoding.</returns>
    private static byte[] EncodeHandle(uint value)
    {
        byte[] buffer = new byte[sizeof(uint)];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt32(value);

        return buffer;
    }

    /// <summary>Parses an HMAC session handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiShHmac ParseShHmac(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiShHmac.Parse(ref reader);
    }

    /// <summary>Parses a policy session handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiShPolicy ParseShPolicy(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiShPolicy.Parse(ref reader);
    }

    /// <summary>Parses a PCR handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_RH_NULL</c> form is admitted.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiDhPcr ParseDhPcr(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiDhPcr.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses a persistent-object handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiDhPersistent ParseDhPersistent(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiDhPersistent.Parse(ref reader);
    }

    /// <summary>Parses a context handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiDhContext ParseDhContext(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiDhContext.Parse(ref reader);
    }

    /// <summary>Parses an entity handle from 4 wire octets.</summary>
    /// <param name="wireBytes">The 4-octet big-endian handle encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_RH_NULL</c> form is admitted.</param>
    /// <returns>The parsed handle.</returns>
    private static TpmiDhEntity ParseDhEntity(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiDhEntity.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>
    /// <see cref="TpmiShHmac.Parse"/> admits the whole HMAC session range and <see cref="TpmiShHmac.WriteTo"/>
    /// reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.9, Table 55).
    /// </summary>
    /// <param name="value">A value drawn from the HMAC session range: its first, an interior, and its last octet.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.HMAC_SESSION_FIRST, DisplayName = "HMAC_SESSION_FIRST")]
    [DataRow(TpmHandleRanges.HMAC_SESSION_FIRST + 0x51, DisplayName = "HMAC_SESSION_FIRST+0x51")]
    [DataRow(TpmHandleRanges.HMAC_SESSION_LAST, DisplayName = "HMAC_SESSION_LAST")]
    public void TpmiShHmacParsesInRangeValueAndRoundTripsByteIdentically(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiShHmac handle = ParseShHmac(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiShHmac.IsHmacSession(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle outside the HMAC session range is refused by <see cref="TpmiShHmac.Parse"/> with
    /// <c>TPM_RC_VALUE</c>, and <see cref="TpmiShHmac.IsHmacSession"/> reports it as not admitted (TPM 2.0
    /// Library Part 2, Section 9.9, Table 55).
    /// </summary>
    /// <param name="value">A policy session handle, a transient object handle, and a permanent handle.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.POLICY_SESSION_FIRST, DisplayName = "POLICY_SESSION_FIRST")]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "TPM_RH_OWNER")]
    public void TpmiShHmacRefusesOutOfRangeValue(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiShHmac.IsHmacSession(value));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseShHmac(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiShHmac.FromValue"/> is the unvalidated escape hatch for a value already known good — it
    /// admits a value outside the HMAC session range without throwing (TPM 2.0 Library Part 2, Section 9.9).
    /// </summary>
    [TestMethod]
    public void TpmiShHmacFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.TRANSIENT_FIRST;

        TpmiShHmac handle = TpmiShHmac.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiShHmac"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value unchanged
    /// for callers composing a handle area from typed session handles (TPM 2.0 Library Part 2, Section 9.9).
    /// </summary>
    [TestMethod]
    public void TpmiShHmacConvertsImplicitlyToTpmHandle()
    {
        TpmiShHmac hmac = TpmiShHmac.FromValue(TpmHandleRanges.HMAC_SESSION_FIRST);

        TpmHandle handle = hmac;

        Assert.AreEqual(TpmHandleRanges.HMAC_SESSION_FIRST, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiShPolicy.Parse"/> admits the whole policy session range and
    /// <see cref="TpmiShPolicy.WriteTo"/> reproduces the exact wire bytes it was parsed from (TPM 2.0 Library
    /// Part 2, Section 9.10, Table 56).
    /// </summary>
    /// <param name="value">A value drawn from the policy session range: its first, an interior, and its last octet.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.POLICY_SESSION_FIRST, DisplayName = "POLICY_SESSION_FIRST")]
    [DataRow(TpmHandleRanges.POLICY_SESSION_FIRST + 0x51, DisplayName = "POLICY_SESSION_FIRST+0x51")]
    [DataRow(TpmHandleRanges.POLICY_SESSION_LAST, DisplayName = "POLICY_SESSION_LAST")]
    public void TpmiShPolicyParsesInRangeValueAndRoundTripsByteIdentically(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiShPolicy handle = ParseShPolicy(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiShPolicy.IsPolicySession(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle outside the policy session range is refused by <see cref="TpmiShPolicy.Parse"/> with
    /// <c>TPM_RC_VALUE</c>, and <see cref="TpmiShPolicy.IsPolicySession"/> reports it as not admitted (TPM 2.0
    /// Library Part 2, Section 9.10, Table 56).
    /// </summary>
    /// <param name="value">An HMAC session handle, a transient object handle, and a permanent handle.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.HMAC_SESSION_LAST, DisplayName = "HMAC_SESSION_LAST")]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, DisplayName = "TPM_RH_PLATFORM")]
    public void TpmiShPolicyRefusesOutOfRangeValue(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiShPolicy.IsPolicySession(value));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseShPolicy(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiShPolicy.FromValue"/> is the unvalidated escape hatch — it admits a value outside the
    /// policy session range without throwing (TPM 2.0 Library Part 2, Section 9.10).
    /// </summary>
    [TestMethod]
    public void TpmiShPolicyFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.TRANSIENT_LAST;

        TpmiShPolicy handle = TpmiShPolicy.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiShPolicy"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value
    /// unchanged (TPM 2.0 Library Part 2, Section 9.10).
    /// </summary>
    [TestMethod]
    public void TpmiShPolicyConvertsImplicitlyToTpmHandle()
    {
        TpmiShPolicy policy = TpmiShPolicy.FromValue(TpmHandleRanges.POLICY_SESSION_FIRST);

        TpmHandle handle = policy;

        Assert.AreEqual(TpmHandleRanges.POLICY_SESSION_FIRST, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhPcr.Parse"/> admits the whole PCR range in its bare form and
    /// <see cref="TpmiDhPcr.WriteTo"/> reproduces the exact wire bytes it was parsed from (TPM 2.0 Library
    /// Part 2, Section 9.7, Table 53).
    /// </summary>
    /// <param name="value">A value drawn from the PCR range: PCR 0, an interior PCR, and the range's top octet.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.PCR_FIRST, DisplayName = "PCR_FIRST")]
    [DataRow(TpmHandleRanges.PCR_FIRST + 7, DisplayName = "PCR_FIRST+7")]
    [DataRow(TpmHandleRanges.PCR_LAST, DisplayName = "PCR_LAST")]
    public void TpmiDhPcrParsesInRangeValueAndRoundTripsByteIdentically(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiDhPcr handle = ParseDhPcr(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiDhPcr.IsPcr(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle outside the PCR range is refused by <see cref="TpmiDhPcr.Parse"/> with <c>TPM_RC_VALUE</c>, and
    /// <see cref="TpmiDhPcr.IsPcr"/> reports it as not admitted, even with <c>isNullAdmitted</c> set — the
    /// range check and the NULL admission are independent (TPM 2.0 Library Part 2, Section 9.7, Table 53).
    /// </summary>
    /// <param name="value">An NV Index handle and a transient object handle, both outside the PCR range.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.NV_INDEX_FIRST, DisplayName = "NV_INDEX_FIRST")]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    public void TpmiDhPcrRefusesOutOfRangeValue(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiDhPcr.IsPcr(value));
        Assert.IsFalse(TpmiDhPcr.IsPcr(value, isNullAdmitted: true));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhPcr(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiDhPcr.Parse"/> refuses <c>TPM_RH_NULL</c> with <c>TPM_RC_VALUE</c> — the
    /// conditional value requires <c>isNullAdmitted</c> (TPM 2.0 Library Part 2, Section 9.7, Table 53, the
    /// <c>+TPM_RH_NULL</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiDhPcrBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeHandle((uint)TpmRh.TPM_RH_NULL);

        Assert.IsFalse(TpmiDhPcr.IsPcr((uint)TpmRh.TPM_RH_NULL));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhPcr(wireBytes));
    }

    /// <summary>
    /// The <c>+</c> form of <see cref="TpmiDhPcr.Parse"/> (<c>isNullAdmitted: true</c>) admits
    /// <c>TPM_RH_NULL</c> and round-trips it byte-identically (TPM 2.0 Library Part 2, Section 9.7, Table 53,
    /// the <c>+TPM_RH_NULL</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiDhPcrPlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeHandle((uint)TpmRh.TPM_RH_NULL);

        TpmiDhPcr handle = ParseDhPcr(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(handle.IsNull);
        Assert.IsTrue(TpmiDhPcr.IsPcr((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiDhPcr.FromValue"/> is the unvalidated escape hatch — it admits a value outside the PCR
    /// range without throwing (TPM 2.0 Library Part 2, Section 9.7).
    /// </summary>
    [TestMethod]
    public void TpmiDhPcrFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.TRANSIENT_FIRST;

        TpmiDhPcr handle = TpmiDhPcr.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhPcr"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value unchanged
    /// (TPM 2.0 Library Part 2, Section 9.7).
    /// </summary>
    [TestMethod]
    public void TpmiDhPcrConvertsImplicitlyToTpmHandle()
    {
        TpmiDhPcr pcr = TpmiDhPcr.FromValue(TpmHandleRanges.PCR_FIRST + 3);

        TpmHandle handle = pcr;

        Assert.AreEqual(TpmHandleRanges.PCR_FIRST + 3, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhPersistent.Parse"/> admits the whole persistent-object range and
    /// <see cref="TpmiDhPersistent.WriteTo"/> reproduces the exact wire bytes it was parsed from (TPM 2.0
    /// Library Part 2, Section 9.5, Table 51).
    /// </summary>
    /// <param name="value">A value drawn from the persistent-object range: its first, an interior, and its last octet.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.PERSISTENT_FIRST, DisplayName = "PERSISTENT_FIRST")]
    [DataRow(TpmHandleRanges.PERSISTENT_FIRST + 0x20, DisplayName = "PERSISTENT_FIRST+0x20")]
    [DataRow(TpmHandleRanges.PERSISTENT_LAST, DisplayName = "PERSISTENT_LAST")]
    public void TpmiDhPersistentParsesInRangeValueAndRoundTripsByteIdentically(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiDhPersistent handle = ParseDhPersistent(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiDhPersistent.IsPersistent(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle outside the persistent-object range is refused by <see cref="TpmiDhPersistent.Parse"/> with
    /// <c>TPM_RC_VALUE</c>, and <see cref="TpmiDhPersistent.IsPersistent"/> reports it as not admitted (TPM 2.0
    /// Library Part 2, Section 9.5, Table 51).
    /// </summary>
    /// <param name="value">A transient object handle and an NV Index handle, both outside the persistent range.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    [DataRow(TpmHandleRanges.NV_INDEX_FIRST, DisplayName = "NV_INDEX_FIRST")]
    public void TpmiDhPersistentRefusesOutOfRangeValue(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiDhPersistent.IsPersistent(value));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhPersistent(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiDhPersistent.FromValue"/> is the unvalidated escape hatch — it admits a value outside the
    /// persistent-object range without throwing (TPM 2.0 Library Part 2, Section 9.5).
    /// </summary>
    [TestMethod]
    public void TpmiDhPersistentFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.TRANSIENT_FIRST;

        TpmiDhPersistent handle = TpmiDhPersistent.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhPersistent"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value
    /// unchanged (TPM 2.0 Library Part 2, Section 9.5).
    /// </summary>
    [TestMethod]
    public void TpmiDhPersistentConvertsImplicitlyToTpmHandle()
    {
        TpmiDhPersistent persistent = TpmiDhPersistent.FromValue(TpmHandleRanges.PERSISTENT_FIRST);

        TpmHandle handle = persistent;

        Assert.AreEqual(TpmHandleRanges.PERSISTENT_FIRST, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhContext.Parse"/> admits a handle from each of the three ranges
    /// <c>TPM2_ContextSave()</c>/<c>TPM2_FlushContext()</c> operate over — HMAC session, policy session, and
    /// transient object — and <see cref="TpmiDhContext.WriteTo"/> reproduces the exact wire bytes it was parsed
    /// from (TPM 2.0 Library Part 2, Section 9.11, Table 57).
    /// </summary>
    /// <param name="value">A handle from the HMAC session, policy session, and transient object ranges in turn.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.HMAC_SESSION_FIRST, DisplayName = "HMAC_SESSION_FIRST")]
    [DataRow(TpmHandleRanges.POLICY_SESSION_LAST, DisplayName = "POLICY_SESSION_LAST")]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    public void TpmiDhContextParsesEachUnionedRangeAndRoundTripsByteIdentically(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiDhContext handle = ParseDhContext(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiDhContext.IsContext(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle outside all three unioned ranges is refused by <see cref="TpmiDhContext.Parse"/> with
    /// <c>TPM_RC_VALUE</c>, and <see cref="TpmiDhContext.IsContext"/> reports it as not admitted — a saved or
    /// loaded context is never a persistent object, an NV Index, or a permanent handle (TPM 2.0 Library Part 2,
    /// Section 9.11, Table 57).
    /// </summary>
    /// <param name="value">A persistent object handle, an NV Index handle, and a permanent handle.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.PERSISTENT_FIRST, DisplayName = "PERSISTENT_FIRST")]
    [DataRow(TpmHandleRanges.NV_INDEX_FIRST, DisplayName = "NV_INDEX_FIRST")]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "TPM_RH_OWNER")]
    public void TpmiDhContextRefusesHandleOutsideTheUnionedRanges(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiDhContext.IsContext(value));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhContext(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiDhContext.FromValue"/> is the unvalidated escape hatch — it admits a value outside every
    /// unioned range without throwing (TPM 2.0 Library Part 2, Section 9.11).
    /// </summary>
    [TestMethod]
    public void TpmiDhContextFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.PERSISTENT_FIRST;

        TpmiDhContext handle = TpmiDhContext.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhContext"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value
    /// unchanged (TPM 2.0 Library Part 2, Section 9.11).
    /// </summary>
    [TestMethod]
    public void TpmiDhContextConvertsImplicitlyToTpmHandle()
    {
        TpmiDhContext context = TpmiDhContext.FromValue(TpmHandleRanges.TRANSIENT_FIRST);

        TpmHandle handle = context;

        Assert.AreEqual(TpmHandleRanges.TRANSIENT_FIRST, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhEntity.Parse"/> admits each of the four named permanent handles and round-trips it
    /// byte-identically (TPM 2.0 Library Part 2, Section 9.6, Table 52).
    /// </summary>
    /// <param name="value">Each of <c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c>, and <c>TPM_RH_LOCKOUT</c>.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "TPM_RH_OWNER")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, DisplayName = "TPM_RH_PLATFORM")]
    [DataRow((uint)TpmRh.TPM_RH_LOCKOUT, DisplayName = "TPM_RH_LOCKOUT")]
    public void TpmiDhEntityAdmitsTheNamedPermanentHandles(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiDhEntity handle = ParseDhEntity(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiDhEntity.IsEntity(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiDhEntity.Parse"/> admits a handle from each of the object, NV Index, PCR, and
    /// vendor-specific authorization ranges the table unions in, and round-trips it byte-identically (TPM 2.0
    /// Library Part 2, Section 9.6, Table 52).
    /// </summary>
    /// <param name="value">A transient, persistent, NV Index, PCR, and vendor-authorization handle in turn.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.TRANSIENT_FIRST, DisplayName = "TRANSIENT_FIRST")]
    [DataRow(TpmHandleRanges.PERSISTENT_LAST, DisplayName = "PERSISTENT_LAST")]
    [DataRow(TpmHandleRanges.NV_INDEX_FIRST, DisplayName = "NV_INDEX_FIRST")]
    [DataRow(TpmHandleRanges.PCR_LAST, DisplayName = "PCR_LAST")]
    [DataRow((uint)TpmRh.TPM_RH_AUTH_00, DisplayName = "TPM_RH_AUTH_00")]
    [DataRow((uint)TpmRh.TPM_RH_AUTH_FF, DisplayName = "TPM_RH_AUTH_FF")]
    public void TpmiDhEntityAdmitsEachUnionedRange(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        TpmiDhEntity handle = ParseDhEntity(wireBytes);

        Assert.AreEqual(value, handle.Value);
        Assert.IsTrue(TpmiDhEntity.IsEntity(value));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A handle in none of the named permanent handles, the four unioned ranges, or the vendor-authorization
    /// range is refused by <see cref="TpmiDhEntity.Parse"/> with <c>TPM_RC_VALUE</c>, and
    /// <see cref="TpmiDhEntity.IsEntity"/> reports it as not admitted (TPM 2.0 Library Part 2, Section 9.6,
    /// Table 52).
    /// </summary>
    /// <param name="value">A session handle, an unlisted permanent handle, and the octet just past the vendor-authorization range.</param>
    [TestMethod]
    [DataRow(TpmHandleRanges.HMAC_SESSION_FIRST, DisplayName = "HMAC_SESSION_FIRST")]
    [DataRow((uint)TpmRh.TPM_RH_REVOKE, DisplayName = "TPM_RH_REVOKE")]
    [DataRow((uint)TpmRh.TPM_RH_AUTH_FF + 1, DisplayName = "TPM_RH_AUTH_FF+1")]
    public void TpmiDhEntityRefusesHandleOutsideEveryAdmittedSet(uint value)
    {
        byte[] wireBytes = EncodeHandle(value);

        Assert.IsFalse(TpmiDhEntity.IsEntity(value));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhEntity(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiDhEntity.Parse"/> refuses <c>TPM_RH_NULL</c> with <c>TPM_RC_VALUE</c> —
    /// the conditional value requires <c>isNullAdmitted</c> (TPM 2.0 Library Part 2, Section 9.6, Table 52, the
    /// <c>+TPM_RH_NULL</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiDhEntityBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeHandle((uint)TpmRh.TPM_RH_NULL);

        Assert.IsFalse(TpmiDhEntity.IsEntity((uint)TpmRh.TPM_RH_NULL));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseDhEntity(wireBytes));
    }

    /// <summary>
    /// The <c>+</c> form of <see cref="TpmiDhEntity.Parse"/> (<c>isNullAdmitted: true</c>) admits
    /// <c>TPM_RH_NULL</c> and round-trips it byte-identically (TPM 2.0 Library Part 2, Section 9.6, Table 52,
    /// the <c>+TPM_RH_NULL</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiDhEntityPlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeHandle((uint)TpmRh.TPM_RH_NULL);

        TpmiDhEntity handle = ParseDhEntity(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(handle.IsNull);
        Assert.IsTrue(TpmiDhEntity.IsEntity((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] outBytes = new byte[sizeof(uint)];
        var writer = new TpmWriter(outBytes);
        handle.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiDhEntity.FromValue"/> is the unvalidated escape hatch — it admits a value outside every
    /// admitted set without throwing (TPM 2.0 Library Part 2, Section 9.6).
    /// </summary>
    [TestMethod]
    public void TpmiDhEntityFromValueDoesNotValidate()
    {
        const uint outOfRange = TpmHandleRanges.HMAC_SESSION_FIRST;

        TpmiDhEntity handle = TpmiDhEntity.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
    }

    /// <summary>
    /// <see cref="TpmiDhEntity"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value
    /// unchanged (TPM 2.0 Library Part 2, Section 9.6).
    /// </summary>
    [TestMethod]
    public void TpmiDhEntityConvertsImplicitlyToTpmHandle()
    {
        TpmiDhEntity entity = TpmiDhEntity.Owner;

        TpmHandle handle = entity;

        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, handle.Value);
    }
}
