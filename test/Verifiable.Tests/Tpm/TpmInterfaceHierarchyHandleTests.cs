namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for the hierarchy-family closed-set and range-constrained handle interface types (TPMI_RH_*):
/// <see cref="TpmiRhNvIndex"/>, <see cref="TpmiRhNvDefinedIndex"/>, <see cref="TpmiRhNvLegacyIndex"/>,
/// <see cref="TpmiRhNvAuth"/>, <see cref="TpmiRhEndorsement"/>,
/// <see cref="TpmiRhProvision"/>, <see cref="TpmiRhPlatform"/>, <see cref="TpmiRhOwner"/>,
/// <see cref="TpmiRhLockout"/>, <see cref="TpmiRhClear"/>, <see cref="TpmiRhBaseHierarchy"/>,
/// <see cref="TpmiRhEnables"/>, <see cref="TpmiRhHierarchyPolicy"/>, and <see cref="TpmiRhHierarchyAuth"/>.
/// </summary>
[TestClass]
internal sealed class TpmInterfaceHierarchyHandleTests
{
    /// <summary>
    /// A reader-position delegate matching every bare <c>Parse(ref TpmReader)</c> overload in this family, so
    /// the refusal assertions below can be shared without a reflection-driven loop over the twelve types.
    /// </summary>
    private delegate T ParseHandle<T>(ref TpmReader reader);

    /// <summary>
    /// Encodes a raw handle value as the 4-octet big-endian wire representation these types read and write.
    /// </summary>
    /// <param name="value">The handle value.</param>
    /// <returns>The encoded buffer.</returns>
    private static byte[] Encode(uint value)
    {
        byte[] buffer = new byte[sizeof(uint)];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt32(value);

        return buffer;
    }

    /// <summary>
    /// Asserts that parsing <paramref name="buffer"/> with <paramref name="parse"/> throws
    /// <see cref="InvalidOperationException"/> — the table's <c>TPM_RC_VALUE</c> response.
    /// </summary>
    /// <param name="buffer">The encoded handle that the table excludes.</param>
    /// <param name="parse">The type's <c>Parse</c> method.</param>
    private static void AssertRefuses<T>(byte[] buffer, ParseHandle<T> parse)
    {
        var reader = new TpmReader(buffer);

        try
        {
            _ = parse(ref reader);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// TPMI_RH_NV_INDEX (Part 2, clause 9.25, Table 72): the ordinary NV index range
    /// (<c>{NV_INDEX_FIRST:NV_INDEX_LAST}</c>) parses and writes back byte-identical at both range endpoints.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexRoundTripsOrdinaryRange()
    {
        foreach(uint value in new[] { TpmHandleRanges.NV_INDEX_FIRST, TpmHandleRanges.NV_INDEX_LAST })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvIndex handle = TpmiRhNvIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_INDEX (Part 2, clause 9.25, Table 72): the external NV index range parses and writes back
    /// byte-identical at both range endpoints. <c>TPM_HT_EXTERNAL_NV</c> is 0x11 (Part 2, clause 7.2, Table 35);
    /// shifted into the handle's MSO (<c>HR_SHIFT</c> = 24, Part 2, clause 7.5, Table 37) that is
    /// <c>EXTERNAL_NV_FIRST</c> = 0x1100_0000 and <c>EXTERNAL_NV_LAST</c> = <c>EXTERNAL_NV_FIRST</c> +
    /// 0x00FF_FFFF = 0x11FF_FFFF.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexRoundTripsExternalRange()
    {
        foreach(uint value in new[] { 0x1100_0000u, 0x11FF_FFFFu })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvIndex handle = TpmiRhNvIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_INDEX (Part 2, clause 9.25, Table 72): the permanent NV index range parses and writes back
    /// byte-identical at both range endpoints. <c>TPM_HT_PERMANENT_NV</c> is 0x12 (Part 2, clause 7.3,
    /// Table 35); shifted into the handle's MSO (<c>HR_SHIFT</c> = 24, Part 2, clause 7.5, Table 37) that is
    /// <c>PERMANENT_NV_FIRST</c> = 0x1200_0000 and <c>PERMANENT_NV_LAST</c> = <c>PERMANENT_NV_FIRST</c> +
    /// 0x00FF_FFFF = 0x12FF_FFFF.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexRoundTripsPermanentRange()
    {
        foreach(uint value in new[] { 0x1200_0000u, 0x12FF_FFFFu })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvIndex handle = TpmiRhNvIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_INDEX (Part 2, clause 9.25, Table 72): a permanent hierarchy handle falls outside every
    /// admitted range and is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexRefusesAPermanentHierarchyHandle()
    {
        Assert.IsFalse(TpmiRhNvIndex.IsNvIndex((uint)TpmRh.TPM_RH_OWNER));

        AssertRefuses<TpmiRhNvIndex>(Encode((uint)TpmRh.TPM_RH_OWNER), (ref TpmReader reader) => TpmiRhNvIndex.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhNvIndex.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhNvIndex.IsNvIndex"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexFromValueDoesNotValidate()
    {
        uint outOfRange = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhNvIndex handle = TpmiRhNvIndex.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
        Assert.IsFalse(TpmiRhNvIndex.IsNvIndex(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhNvIndex"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvIndexConvertsImplicitlyToTpmHandle()
    {
        var handle = new TpmiRhNvIndex(TpmHandleRanges.NV_INDEX_FIRST);

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_NV_DEFINED_INDEX (Part 2, clause 9.26, Table 73): the ordinary NV index range
    /// (<c>{NV_INDEX_FIRST:NV_INDEX_LAST}</c>) parses and writes back byte-identical at both range endpoints.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvDefinedIndexRoundTripsOrdinaryRange()
    {
        foreach(uint value in new[] { TpmHandleRanges.NV_INDEX_FIRST, TpmHandleRanges.NV_INDEX_LAST })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvDefinedIndex handle = TpmiRhNvDefinedIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_DEFINED_INDEX (Part 2, clause 9.26, Table 73): the second admitted row,
    /// <c>{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}</c>, parses and writes back byte-identical at both range
    /// endpoints. <c>TPM_HT_EXTERNAL_NV</c> is 0x11 (Part 2, clause 7.2, Table 35); shifted into the handle's
    /// MSO (<c>HR_SHIFT</c> = 24, Part 2, clause 7.5, Table 37) that is <c>EXTERNAL_NV_FIRST</c> = 0x1100_0000
    /// and <c>EXTERNAL_NV_LAST</c> = 0x11FF_FFFF.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvDefinedIndexRoundTripsExternalRange()
    {
        foreach(uint value in new[] { TpmHandleRanges.EXTERNAL_NV_FIRST, TpmHandleRanges.EXTERNAL_NV_LAST })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvDefinedIndex handle = TpmiRhNvDefinedIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_DEFINED_INDEX (Part 2, clause 9.26, Table 73): the permanent NV index range is the one row
    /// TPMI_RH_NV_INDEX (Table 72) carries and this type does not — "It does not apply to permanent NV Indexes,
    /// which are architecturally defined" — so both range endpoints are out of range and refused with
    /// <c>TPM_RC_VALUE</c>, while <see cref="TpmiRhNvIndex"/> admits the very same values.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvDefinedIndexRefusesAPermanentNvIndex()
    {
        foreach(uint value in new[] { TpmHandleRanges.PERMANENT_NV_FIRST, TpmHandleRanges.PERMANENT_NV_LAST })
        {
            Assert.IsFalse(TpmiRhNvDefinedIndex.IsDefinedIndex(value));
            Assert.IsTrue(TpmiRhNvIndex.IsNvIndex(value));

            AssertRefuses<TpmiRhNvDefinedIndex>(Encode(value), (ref TpmReader reader) => TpmiRhNvDefinedIndex.Parse(ref reader));
        }
    }

    /// <summary>
    /// <see cref="TpmiRhNvDefinedIndex.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhNvDefinedIndex.IsDefinedIndex"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvDefinedIndexFromValueDoesNotValidate()
    {
        uint outOfRange = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhNvDefinedIndex handle = TpmiRhNvDefinedIndex.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
        Assert.IsFalse(TpmiRhNvDefinedIndex.IsDefinedIndex(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhNvDefinedIndex"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvDefinedIndexConvertsImplicitlyToTpmHandle()
    {
        var handle = new TpmiRhNvDefinedIndex(TpmHandleRanges.NV_INDEX_FIRST);

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_NV_LEGACY_INDEX (Part 2, clause 9.27, Table 74): the single admitted row,
    /// <c>{NV_INDEX_FIRST:NV_INDEX_LAST}</c>, parses and writes back byte-identical at both range endpoints.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvLegacyIndexRoundTripsOrdinaryRange()
    {
        foreach(uint value in new[] { TpmHandleRanges.NV_INDEX_FIRST, TpmHandleRanges.NV_INDEX_LAST })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhNvLegacyIndex handle = TpmiRhNvLegacyIndex.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_LEGACY_INDEX (Part 2, clause 9.27, Table 74): the external NV index range is the row
    /// TPMI_RH_NV_DEFINED_INDEX (Table 73) carries and this type does not, so both range endpoints are out of
    /// range and refused with <c>TPM_RC_VALUE</c>, while <see cref="TpmiRhNvDefinedIndex"/> admits the very
    /// same values.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvLegacyIndexRefusesAnExternalNvIndex()
    {
        foreach(uint value in new[] { TpmHandleRanges.EXTERNAL_NV_FIRST, TpmHandleRanges.EXTERNAL_NV_LAST })
        {
            Assert.IsFalse(TpmiRhNvLegacyIndex.IsLegacyIndex(value));
            Assert.IsTrue(TpmiRhNvDefinedIndex.IsDefinedIndex(value));

            AssertRefuses<TpmiRhNvLegacyIndex>(Encode(value), (ref TpmReader reader) => TpmiRhNvLegacyIndex.Parse(ref reader));
        }
    }

    /// <summary>
    /// TPMI_RH_NV_LEGACY_INDEX (Part 2, clause 9.27, Table 74): the permanent NV index range is likewise absent
    /// from the table's single admitted row, so both range endpoints are refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvLegacyIndexRefusesAPermanentNvIndex()
    {
        foreach(uint value in new[] { TpmHandleRanges.PERMANENT_NV_FIRST, TpmHandleRanges.PERMANENT_NV_LAST })
        {
            Assert.IsFalse(TpmiRhNvLegacyIndex.IsLegacyIndex(value));

            AssertRefuses<TpmiRhNvLegacyIndex>(Encode(value), (ref TpmReader reader) => TpmiRhNvLegacyIndex.Parse(ref reader));
        }
    }

    /// <summary>
    /// <see cref="TpmiRhNvLegacyIndex.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhNvLegacyIndex.IsLegacyIndex"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvLegacyIndexFromValueDoesNotValidate()
    {
        uint outOfRange = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhNvLegacyIndex handle = TpmiRhNvLegacyIndex.FromValue(outOfRange);

        Assert.AreEqual(outOfRange, handle.Value);
        Assert.IsFalse(TpmiRhNvLegacyIndex.IsLegacyIndex(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhNvLegacyIndex"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvLegacyIndexConvertsImplicitlyToTpmHandle()
    {
        var handle = new TpmiRhNvLegacyIndex(TpmHandleRanges.NV_INDEX_FIRST);

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_NV_AUTH (Part 2, clause 9.23, Table 70): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthRoundTripsPlatformAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhNvAuth handle = TpmiRhNvAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhNvAuth.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_NV_AUTH (Part 2, clause 9.23, Table 70): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthRoundTripsOwnerAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhNvAuth handle = TpmiRhNvAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhNvAuth.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_NV_AUTH (Part 2, clause 9.23, Table 70): the NV index range (<c>{NV_INDEX_FIRST:NV_INDEX_LAST}</c>,
    /// the index's own <c>authValue</c>) parses and writes back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthRoundTripsNvIndexRange()
    {
        byte[] original = Encode(TpmHandleRanges.NV_INDEX_LAST);
        var reader = new TpmReader(original);

        TpmiRhNvAuth handle = TpmiRhNvAuth.Parse(ref reader);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_NV_AUTH (Part 2, clause 9.23, Table 70): the Lockout Authorization is not one of the three
    /// admitted selectors and is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthRefusesLockoutAuthorization()
    {
        Assert.IsFalse(TpmiRhNvAuth.IsNvAuth((uint)TpmRh.TPM_RH_LOCKOUT));

        AssertRefuses<TpmiRhNvAuth>(Encode((uint)TpmRh.TPM_RH_LOCKOUT), (ref TpmReader reader) => TpmiRhNvAuth.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhNvAuth.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhNvAuth.IsNvAuth"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_LOCKOUT;

        TpmiRhNvAuth handle = TpmiRhNvAuth.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhNvAuth.IsNvAuth(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhNvAuth"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhNvAuthConvertsImplicitlyToTpmHandle()
    {
        TpmiRhNvAuth handle = TpmiRhNvAuth.Owner;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_ENDORSEMENT (Part 2, clause 9.20, Table 67): <c>TPM_RH_ENDORSEMENT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementRoundTripsEndorsementHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_ENDORSEMENT);
        var reader = new TpmReader(original);

        TpmiRhEndorsement handle = TpmiRhEndorsement.Parse(ref reader);
        Assert.AreEqual(TpmiRhEndorsement.Endorsement, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENDORSEMENT (Part 2, clause 9.20, Table 67): the bare form refuses <c>TPM_RH_NULL</c> — the
    /// table's <c>+TPM_RH_NULL</c> row applies only when the caller opts in.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementBareFormRefusesNullHierarchy()
    {
        Assert.IsFalse(TpmiRhEndorsement.IsEndorsement((uint)TpmRh.TPM_RH_NULL));

        AssertRefuses<TpmiRhEndorsement>(Encode((uint)TpmRh.TPM_RH_NULL), (ref TpmReader reader) => TpmiRhEndorsement.Parse(ref reader));
    }

    /// <summary>
    /// TPMI_RH_ENDORSEMENT (Part 2, clause 9.20, Table 67): the <c>+TPM_RH_NULL</c> form admits and round-trips
    /// the null hierarchy.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementPlusFormAdmitsNullHierarchy()
    {
        Assert.IsTrue(TpmiRhEndorsement.IsEndorsement((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] original = Encode((uint)TpmRh.TPM_RH_NULL);
        var reader = new TpmReader(original);

        TpmiRhEndorsement handle = TpmiRhEndorsement.Parse(ref reader, isNullAdmitted: true);
        Assert.AreEqual(TpmiRhEndorsement.Null, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENDORSEMENT (Part 2, clause 9.20, Table 67): a hierarchy other than endorsement is refused
    /// regardless of whether the null form is admitted.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementRefusesTheOwnerHierarchy()
    {
        Assert.IsFalse(TpmiRhEndorsement.IsEndorsement((uint)TpmRh.TPM_RH_OWNER, isNullAdmitted: true));

        AssertRefuses<TpmiRhEndorsement>(Encode((uint)TpmRh.TPM_RH_OWNER), (ref TpmReader reader) => TpmiRhEndorsement.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhEndorsement.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhEndorsement.IsEndorsement"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhEndorsement handle = TpmiRhEndorsement.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhEndorsement.IsEndorsement(handle.Value, isNullAdmitted: true));
    }

    /// <summary>
    /// <see cref="TpmiRhEndorsement"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhEndorsementConvertsImplicitlyToTpmHandle()
    {
        TpmiRhEndorsement handle = TpmiRhEndorsement.Endorsement;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_PROVISION (Part 2, clause 9.21, Table 68): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhProvisionRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhProvision handle = TpmiRhProvision.Parse(ref reader);
        Assert.AreEqual(TpmiRhProvision.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_PROVISION (Part 2, clause 9.21, Table 68): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhProvisionRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhProvision handle = TpmiRhProvision.Parse(ref reader);
        Assert.AreEqual(TpmiRhProvision.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_PROVISION (Part 2, clause 9.21, Table 68): the endorsement hierarchy is not one of the two
    /// admitted selectors and is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhProvisionRefusesEndorsementHierarchy()
    {
        Assert.IsFalse(TpmiRhProvision.IsProvision((uint)TpmRh.TPM_RH_ENDORSEMENT));

        AssertRefuses<TpmiRhProvision>(Encode((uint)TpmRh.TPM_RH_ENDORSEMENT), (ref TpmReader reader) => TpmiRhProvision.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhProvision.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhProvision.IsProvision"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhProvisionFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_ENDORSEMENT;

        TpmiRhProvision handle = TpmiRhProvision.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhProvision.IsProvision(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhProvision"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhProvisionConvertsImplicitlyToTpmHandle()
    {
        TpmiRhProvision handle = TpmiRhProvision.Platform;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_PLATFORM (Part 2, clause 9.18, Table 65): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhPlatformRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhPlatform handle = TpmiRhPlatform.Parse(ref reader);
        Assert.AreEqual(TpmiRhPlatform.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_PLATFORM (Part 2, clause 9.18, Table 65): this table admits exactly one value; any other
    /// hierarchy, such as <c>TPM_RH_OWNER</c>, is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhPlatformRefusesTheOwnerHierarchy()
    {
        Assert.IsFalse(TpmiRhPlatform.IsPlatform((uint)TpmRh.TPM_RH_OWNER));

        AssertRefuses<TpmiRhPlatform>(Encode((uint)TpmRh.TPM_RH_OWNER), (ref TpmReader reader) => TpmiRhPlatform.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhPlatform.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhPlatform.IsPlatform"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhPlatformFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhPlatform handle = TpmiRhPlatform.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhPlatform.IsPlatform(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhPlatform"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhPlatformConvertsImplicitlyToTpmHandle()
    {
        TpmiRhPlatform handle = TpmiRhPlatform.Platform;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_OWNER (Part 2, clause 9.19, Table 66): <c>TPM_RH_OWNER</c> parses and writes back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhOwner handle = TpmiRhOwner.Parse(ref reader);
        Assert.AreEqual(TpmiRhOwner.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_OWNER (Part 2, clause 9.19, Table 66): the bare form refuses <c>TPM_RH_NULL</c> — the table's
    /// <c>+TPM_RH_NULL</c> row applies only when the caller opts in.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerBareFormRefusesNullHierarchy()
    {
        Assert.IsFalse(TpmiRhOwner.IsOwner((uint)TpmRh.TPM_RH_NULL));

        AssertRefuses<TpmiRhOwner>(Encode((uint)TpmRh.TPM_RH_NULL), (ref TpmReader reader) => TpmiRhOwner.Parse(ref reader));
    }

    /// <summary>
    /// TPMI_RH_OWNER (Part 2, clause 9.19, Table 66): the <c>+TPM_RH_NULL</c> form admits and round-trips the
    /// null hierarchy.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerPlusFormAdmitsNullHierarchy()
    {
        Assert.IsTrue(TpmiRhOwner.IsOwner((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] original = Encode((uint)TpmRh.TPM_RH_NULL);
        var reader = new TpmReader(original);

        TpmiRhOwner handle = TpmiRhOwner.Parse(ref reader, isNullAdmitted: true);
        Assert.AreEqual(TpmiRhOwner.Null, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_OWNER (Part 2, clause 9.19, Table 66): a hierarchy other than owner is refused regardless of
    /// whether the null form is admitted.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerRefusesThePlatformHierarchy()
    {
        Assert.IsFalse(TpmiRhOwner.IsOwner((uint)TpmRh.TPM_RH_PLATFORM, isNullAdmitted: true));

        AssertRefuses<TpmiRhOwner>(Encode((uint)TpmRh.TPM_RH_PLATFORM), (ref TpmReader reader) => TpmiRhOwner.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhOwner.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhOwner.IsOwner"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_PLATFORM;

        TpmiRhOwner handle = TpmiRhOwner.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhOwner.IsOwner(handle.Value, isNullAdmitted: true));
    }

    /// <summary>
    /// <see cref="TpmiRhOwner"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhOwnerConvertsImplicitlyToTpmHandle()
    {
        TpmiRhOwner handle = TpmiRhOwner.Owner;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_LOCKOUT (Part 2, clause 9.24, Table 71): <c>TPM_RH_LOCKOUT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhLockoutRoundTripsLockoutAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_LOCKOUT);
        var reader = new TpmReader(original);

        TpmiRhLockout handle = TpmiRhLockout.Parse(ref reader);
        Assert.AreEqual(TpmiRhLockout.Lockout, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_LOCKOUT (Part 2, clause 9.24, Table 71): this table admits exactly one value; any other
    /// hierarchy, such as <c>TPM_RH_PLATFORM</c>, is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhLockoutRefusesThePlatformHierarchy()
    {
        Assert.IsFalse(TpmiRhLockout.IsLockout((uint)TpmRh.TPM_RH_PLATFORM));

        AssertRefuses<TpmiRhLockout>(Encode((uint)TpmRh.TPM_RH_PLATFORM), (ref TpmReader reader) => TpmiRhLockout.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhLockout.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhLockout.IsLockout"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhLockoutFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_PLATFORM;

        TpmiRhLockout handle = TpmiRhLockout.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhLockout.IsLockout(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhLockout"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhLockoutConvertsImplicitlyToTpmHandle()
    {
        TpmiRhLockout handle = TpmiRhLockout.Lockout;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_CLEAR (Part 2, clause 9.22, Table 69): <c>TPM_RH_LOCKOUT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhClearRoundTripsLockoutAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_LOCKOUT);
        var reader = new TpmReader(original);

        TpmiRhClear handle = TpmiRhClear.Parse(ref reader);
        Assert.AreEqual(TpmiRhClear.Lockout, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_CLEAR (Part 2, clause 9.22, Table 69): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhClearRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhClear handle = TpmiRhClear.Parse(ref reader);
        Assert.AreEqual(TpmiRhClear.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_CLEAR (Part 2, clause 9.22, Table 69): the owner hierarchy is not one of the two admitted
    /// selectors and is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhClearRefusesTheOwnerHierarchy()
    {
        Assert.IsFalse(TpmiRhClear.IsClear((uint)TpmRh.TPM_RH_OWNER));

        AssertRefuses<TpmiRhClear>(Encode((uint)TpmRh.TPM_RH_OWNER), (ref TpmReader reader) => TpmiRhClear.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhClear.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhClear.IsClear"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhClearFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_OWNER;

        TpmiRhClear handle = TpmiRhClear.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhClear.IsClear(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhClear"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhClearConvertsImplicitlyToTpmHandle()
    {
        TpmiRhClear handle = TpmiRhClear.Lockout;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_BASE_HIERARCHY (Part 2, clause 9.17, Table 64): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhBaseHierarchy handle = TpmiRhBaseHierarchy.Parse(ref reader);
        Assert.AreEqual(TpmiRhBaseHierarchy.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_BASE_HIERARCHY (Part 2, clause 9.17, Table 64): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhBaseHierarchy handle = TpmiRhBaseHierarchy.Parse(ref reader);
        Assert.AreEqual(TpmiRhBaseHierarchy.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_BASE_HIERARCHY (Part 2, clause 9.17, Table 64): <c>TPM_RH_ENDORSEMENT</c> parses and writes
    /// back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyRoundTripsEndorsementHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_ENDORSEMENT);
        var reader = new TpmReader(original);

        TpmiRhBaseHierarchy handle = TpmiRhBaseHierarchy.Parse(ref reader);
        Assert.AreEqual(TpmiRhBaseHierarchy.Endorsement, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_BASE_HIERARCHY (Part 2, clause 9.17, Table 64): unlike its TPMI_RH_HIERARCHY_AUTH sibling
    /// (Table 62), this table carries no Lockout Authorization row, so <c>TPM_RH_LOCKOUT</c> is refused with
    /// <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyRefusesLockoutAuthorization()
    {
        Assert.IsFalse(TpmiRhBaseHierarchy.IsBaseHierarchy((uint)TpmRh.TPM_RH_LOCKOUT));

        AssertRefuses<TpmiRhBaseHierarchy>(Encode((uint)TpmRh.TPM_RH_LOCKOUT), (ref TpmReader reader) => TpmiRhBaseHierarchy.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhBaseHierarchy.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhBaseHierarchy.IsBaseHierarchy"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_LOCKOUT;

        TpmiRhBaseHierarchy handle = TpmiRhBaseHierarchy.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhBaseHierarchy.IsBaseHierarchy(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhBaseHierarchy"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw
    /// value.
    /// </summary>
    [TestMethod]
    public void TpmiRhBaseHierarchyConvertsImplicitlyToTpmHandle()
    {
        TpmiRhBaseHierarchy handle = TpmiRhBaseHierarchy.Endorsement;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhEnables handle = TpmiRhEnables.Parse(ref reader);
        Assert.AreEqual(TpmiRhEnables.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhEnables handle = TpmiRhEnables.Parse(ref reader);
        Assert.AreEqual(TpmiRhEnables.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): <c>TPM_RH_ENDORSEMENT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesRoundTripsEndorsementHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_ENDORSEMENT);
        var reader = new TpmReader(original);

        TpmiRhEnables handle = TpmiRhEnables.Parse(ref reader);
        Assert.AreEqual(TpmiRhEnables.Endorsement, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): <c>TPM_RH_PLATFORM_NV</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesRoundTripsPlatformNvEnable()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM_NV);
        var reader = new TpmReader(original);

        TpmiRhEnables handle = TpmiRhEnables.Parse(ref reader);
        Assert.AreEqual(TpmiRhEnables.PlatformNv, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): the bare form refuses <c>TPM_RH_NULL</c> — the
    /// table's <c>+TPM_RH_NULL</c> row applies only when the caller opts in.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesBareFormRefusesNullHierarchy()
    {
        Assert.IsFalse(TpmiRhEnables.IsEnables((uint)TpmRh.TPM_RH_NULL));

        AssertRefuses<TpmiRhEnables>(Encode((uint)TpmRh.TPM_RH_NULL), (ref TpmReader reader) => TpmiRhEnables.Parse(ref reader));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): the <c>+TPM_RH_NULL</c> form admits and round-trips
    /// the null hierarchy.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesPlusFormAdmitsNullHierarchy()
    {
        Assert.IsTrue(TpmiRhEnables.IsEnables((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] original = Encode((uint)TpmRh.TPM_RH_NULL);
        var reader = new TpmReader(original);

        TpmiRhEnables handle = TpmiRhEnables.Parse(ref reader, isNullAdmitted: true);
        Assert.AreEqual(TpmiRhEnables.Null, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_ENABLES (Part 2, clause 9.14, Table 61): the Lockout Authorization is not one of the four named
    /// selectors and is refused with <c>TPM_RC_VALUE</c>, regardless of whether the null form is admitted.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesRefusesLockoutAuthorization()
    {
        Assert.IsFalse(TpmiRhEnables.IsEnables((uint)TpmRh.TPM_RH_LOCKOUT, isNullAdmitted: true));

        AssertRefuses<TpmiRhEnables>(Encode((uint)TpmRh.TPM_RH_LOCKOUT), (ref TpmReader reader) => TpmiRhEnables.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhEnables.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhEnables.IsEnables"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_LOCKOUT;

        TpmiRhEnables handle = TpmiRhEnables.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhEnables.IsEnables(handle.Value, isNullAdmitted: true));
    }

    /// <summary>
    /// <see cref="TpmiRhEnables"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw value.
    /// </summary>
    [TestMethod]
    public void TpmiRhEnablesConvertsImplicitlyToTpmHandle()
    {
        TpmiRhEnables handle = TpmiRhEnables.PlatformNv;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyPolicy.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): <c>TPM_RH_PLATFORM</c> parses and writes
    /// back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyPolicy.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): <c>TPM_RH_ENDORSEMENT</c> parses and writes
    /// back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRoundTripsEndorsementHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_ENDORSEMENT);
        var reader = new TpmReader(original);

        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyPolicy.Endorsement, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): <c>TPM_RH_LOCKOUT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRoundTripsLockoutAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_LOCKOUT);
        var reader = new TpmReader(original);

        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyPolicy.Lockout, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): the Authenticated Countdown Timer range
    /// (<c>{TPM_RH_ACT_0:TPM_RH_ACT_F}</c>) parses and writes back byte-identical at both range endpoints.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRoundTripsActRange()
    {
        foreach(uint value in new[] { (uint)TpmRh.TPM_RH_ACT_0, (uint)TpmRh.TPM_RH_ACT_F })
        {
            byte[] original = Encode(value);
            var reader = new TpmReader(original);

            TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Parse(ref reader);
            Assert.AreEqual(value, handle.Value);

            byte[] written = new byte[sizeof(uint)];
            var writer = new TpmWriter(written);
            handle.WriteTo(ref writer);

            Assert.IsTrue(original.AsSpan().SequenceEqual(written));
        }
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_POLICY (Part 2, clause 9.16, Table 63): unlike its TPMI_RH_HIERARCHY_AUTH and
    /// TPMI_RH_ENABLES siblings (Tables 62 and 61), this table carries no <c>+TPM_RH_NULL</c> row, so
    /// <c>TPM_RH_NULL</c> is refused with <c>TPM_RC_VALUE</c>.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyRefusesNullHierarchy()
    {
        Assert.IsFalse(TpmiRhHierarchyPolicy.IsHierarchyPolicy((uint)TpmRh.TPM_RH_NULL));

        AssertRefuses<TpmiRhHierarchyPolicy>(Encode((uint)TpmRh.TPM_RH_NULL), (ref TpmReader reader) => TpmiRhHierarchyPolicy.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhHierarchyPolicy.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhHierarchyPolicy.IsHierarchyPolicy"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_NULL;

        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhHierarchyPolicy.IsHierarchyPolicy(handle.Value));
    }

    /// <summary>
    /// <see cref="TpmiRhHierarchyPolicy"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw
    /// value.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyPolicyConvertsImplicitlyToTpmHandle()
    {
        TpmiRhHierarchyPolicy handle = TpmiRhHierarchyPolicy.Lockout;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): <c>TPM_RH_OWNER</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthRoundTripsOwnerHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_OWNER);
        var reader = new TpmReader(original);

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyAuth.Owner, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): <c>TPM_RH_PLATFORM</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthRoundTripsPlatformHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_PLATFORM);
        var reader = new TpmReader(original);

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyAuth.Platform, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): <c>TPM_RH_ENDORSEMENT</c> parses and writes
    /// back byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthRoundTripsEndorsementHierarchy()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_ENDORSEMENT);
        var reader = new TpmReader(original);

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyAuth.Endorsement, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): <c>TPM_RH_LOCKOUT</c> parses and writes back
    /// byte-identical.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthRoundTripsLockoutAuthorization()
    {
        byte[] original = Encode((uint)TpmRh.TPM_RH_LOCKOUT);
        var reader = new TpmReader(original);

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Parse(ref reader);
        Assert.AreEqual(TpmiRhHierarchyAuth.Lockout, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): the bare form refuses <c>TPM_RH_NULL</c> — the
    /// table's <c>+TPM_RH_NULL</c> row applies only when the caller opts in.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthBareFormRefusesNullHierarchy()
    {
        Assert.IsFalse(TpmiRhHierarchyAuth.IsHierarchyAuth((uint)TpmRh.TPM_RH_NULL));

        AssertRefuses<TpmiRhHierarchyAuth>(Encode((uint)TpmRh.TPM_RH_NULL), (ref TpmReader reader) => TpmiRhHierarchyAuth.Parse(ref reader));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): the <c>+TPM_RH_NULL</c> form admits and
    /// round-trips the null hierarchy.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthPlusFormAdmitsNullHierarchy()
    {
        Assert.IsTrue(TpmiRhHierarchyAuth.IsHierarchyAuth((uint)TpmRh.TPM_RH_NULL, isNullAdmitted: true));

        byte[] original = Encode((uint)TpmRh.TPM_RH_NULL);
        var reader = new TpmReader(original);

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Parse(ref reader, isNullAdmitted: true);
        Assert.AreEqual(TpmiRhHierarchyAuth.Null, handle);

        byte[] written = new byte[sizeof(uint)];
        var writer = new TpmWriter(written);
        handle.WriteTo(ref writer);

        Assert.IsTrue(original.AsSpan().SequenceEqual(written));
    }

    /// <summary>
    /// TPMI_RH_HIERARCHY_AUTH (Part 2, clause 9.15, Table 62): unlike its TPMI_RH_ENABLES sibling (Table 61),
    /// this table carries no Platform NV row, so <c>TPM_RH_PLATFORM_NV</c> is refused with <c>TPM_RC_VALUE</c>,
    /// regardless of whether the null form is admitted.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthRefusesPlatformNvEnable()
    {
        Assert.IsFalse(TpmiRhHierarchyAuth.IsHierarchyAuth((uint)TpmRh.TPM_RH_PLATFORM_NV, isNullAdmitted: true));

        AssertRefuses<TpmiRhHierarchyAuth>(Encode((uint)TpmRh.TPM_RH_PLATFORM_NV), (ref TpmReader reader) => TpmiRhHierarchyAuth.Parse(ref reader));
    }

    /// <summary>
    /// <see cref="TpmiRhHierarchyAuth.FromValue"/> is the unvalidated escape hatch: it accepts a value
    /// <see cref="TpmiRhHierarchyAuth.IsHierarchyAuth"/> refuses, carrying it through unchanged.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthFromValueDoesNotValidate()
    {
        uint outOfSet = (uint)TpmRh.TPM_RH_PLATFORM_NV;

        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.FromValue(outOfSet);

        Assert.AreEqual(outOfSet, handle.Value);
        Assert.IsFalse(TpmiRhHierarchyAuth.IsHierarchyAuth(handle.Value, isNullAdmitted: true));
    }

    /// <summary>
    /// <see cref="TpmiRhHierarchyAuth"/> converts implicitly to <see cref="TpmHandle"/>, carrying the raw
    /// value.
    /// </summary>
    [TestMethod]
    public void TpmiRhHierarchyAuthConvertsImplicitlyToTpmHandle()
    {
        TpmiRhHierarchyAuth handle = TpmiRhHierarchyAuth.Lockout;

        TpmHandle converted = handle;

        Assert.AreEqual(handle.Value, converted.Value);
    }
}
