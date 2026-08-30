using System;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves <see cref="TpmsCreationData.Parse"/> against Table 261's <c>pcrDigest</c> row and, together with
/// <see cref="TpmsCreationInfo.Parse"/> and <see cref="Tpm2bAttest.Parse"/>, against the leak-safety a malformed
/// tail must preserve — modeled on <see cref="TpmSpecBufferAndListTests"/>. Every wire buffer here is hand-built
/// with <see cref="TpmWriter"/> from Table 261's own field order — never produced by the parser under test — so a
/// fixture regression in the parser cannot also regress the oracle it is checked against.
/// </summary>
[TestClass]
internal sealed class TpmCreationDataCarrierTests
{
    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> exposes a size-0 <see cref="TpmsCreationData.PcrDigest"/> for
    /// an empty <c>pcrSelect</c>, and every sibling field exactly as written — Table 261's own row:
    /// "pcrDigest.size shall be zero if the pcrSelect list is empty"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.1, Table 261, printed page 206).
    /// </summary>
    [TestMethod]
    public void ParseWithEmptyPcrSelectExposesZeroSizePcrDigestAndEveryFieldAsWritten()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] ownerHandle = [0x40, 0x00, 0x00, 0x01]; //TPM_RH_OWNER, the permanent-handle Name form (Table 261).
        byte[] wire = BuildCreationDataWire(
            pcrSelectWire: EmptyPcrSelectWire,
            pcrDigest: ReadOnlySpan<byte>.Empty,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_NULL,
            parentName: ownerHandle,
            parentQualifiedName: ownerHandle,
            outsideInfo: ReadOnlySpan<byte>.Empty);

        var reader = new TpmReader(wire);
        using TpmsCreationData creationData = TpmsCreationData.Parse(ref reader, pool);

        Assert.AreEqual(0, creationData.PcrSelect.Count, "An empty pcrSelect carries no selections.");
        Assert.AreEqual(0, creationData.PcrDigest.Size, "Table 261: pcrDigest.size shall be zero if the pcrSelect list is empty.");
        Assert.AreEqual(TpmaLocality.TPM_LOC_ZERO, creationData.Locality);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, creationData.ParentNameAlg);
        Assert.IsTrue(creationData.ParentName.IsHandleName, "A NULL parentNameAlg carries the 4-byte handle form.");
        Assert.AreEqual(0x4000_0001u, creationData.ParentName.Handle);
        Assert.IsTrue(creationData.ParentQualifiedName.IsHandleName);
        Assert.AreEqual(0x4000_0001u, creationData.ParentQualifiedName.Handle);
        Assert.AreEqual(0, creationData.OutsideInfo.Length);
        Assert.AreEqual(wire.Length, reader.Consumed, "Every declared field is consumed with nothing left over.");
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> also accepts a full-width <see cref="TpmsCreationData.PcrDigest"/>
    /// for an empty <c>pcrSelect</c> — the form silicon built from the Reference Code's <c>FillInCreationData</c>
    /// emits, because that routine runs its hash unconditionally rather than sizing <c>pcrDigest</c> to zero for
    /// an empty selection
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 4: Supporting Routines, printed pages 722-723). <see cref="Tpm2bDigest.Parse"/>
    /// is purely size-driven, so both the normative size-0 form (proved above) and this interop form round-trip
    /// through <see cref="TpmsCreationData.PcrDigest"/> byte-for-byte.
    /// </summary>
    [TestMethod]
    public void ParseWithEmptyPcrSelectAndFullWidthPcrDigestAcceptsTheSiliconForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] ownerHandle = [0x40, 0x00, 0x00, 0x01];
        byte[] fullWidthPcrDigest = new byte[32];
        Array.Fill(fullWidthPcrDigest, (byte)0xAB);
        byte[] wire = BuildCreationDataWire(
            pcrSelectWire: EmptyPcrSelectWire,
            pcrDigest: fullWidthPcrDigest,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_NULL,
            parentName: ownerHandle,
            parentQualifiedName: ownerHandle,
            outsideInfo: ReadOnlySpan<byte>.Empty);

        var reader = new TpmReader(wire);
        using TpmsCreationData creationData = TpmsCreationData.Parse(ref reader, pool);

        Assert.AreEqual(0, creationData.PcrSelect.Count, "The Reference Code's divergent row still names an empty selection.");
        Assert.AreEqual(32, creationData.PcrDigest.Size, "A full-width digest parses at its declared size, exactly as any other TPM2B_DIGEST.");
        Assert.IsTrue(creationData.PcrDigest.AsReadOnlySpan().SequenceEqual(fullWidthPcrDigest), "The digest octets survive the parse unchanged.");
        Assert.AreEqual(wire.Length, reader.Consumed);
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> refuses a <c>parentQualifiedName</c> over
    /// <see cref="Tpm2bName.MaxSize"/> and releases every already-rented carrier — the <c>pcrSelect</c> (one
    /// genuine SHA-256 bank, 3-octet bitmap), <c>pcrDigest</c> (32 octets) and <c>parentName</c> (34 octets), all
    /// given real, non-empty content so the balance proof is not vacuous for any of the three — before the
    /// exception leaves. The bound is <c>TPM2B_NAME</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.4.3, Table 105), not a Table 261 row.
    /// </summary>
    [TestMethod]
    public void ParseWithOversizeParentQualifiedNameThrowsAndReleasesEarlierRentals()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] pcrSelectBitmap = [0x01, 0x00, 0x00]; //PCR 0 selected; sizeofSelect = 3 (Table 107's PCR_SELECT_MIN).
        byte[] pcrSelectWire = BuildPcrSelectWire(TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelectBitmap);
        byte[] pcrDigest = new byte[32];
        Array.Fill(pcrDigest, (byte)0x11);
        byte[] parentName = new byte[34]; //A real digest-form Name: 2-octet nameAlg prefix + 32-octet digest.
        Array.Fill(parentName, (byte)0x22);
        byte[] oversizeParentQualifiedName = new byte[Tpm2bName.MaxSize + 1];
        Array.Fill(oversizeParentQualifiedName, (byte)0x33);

        byte[] wire = BuildCreationDataWire(
            pcrSelectWire: pcrSelectWire,
            pcrDigest: pcrDigest,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_SHA256,
            parentName: parentName,
            parentQualifiedName: oversizeParentQualifiedName,
            outsideInfo: ReadOnlySpan<byte>.Empty);

        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a plain
        //try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmsCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "pcrSelect's, pcrDigest's and parentName's rentals must be released when parentQualifiedName is refused.");
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> refuses an <c>outsideInfo</c> over
    /// <see cref="Tpm2bData.MaxSize"/> and releases every already-rented carrier — <c>pcrDigest</c>,
    /// <c>parentName</c> and <c>parentQualifiedName</c>, each given real, non-empty content — before the
    /// exception leaves. The bound is <c>TPM2B_DATA</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.3, Table 91).
    /// </summary>
    [TestMethod]
    public void ParseWithOversizeOutsideInfoThrowsAndReleasesEarlierRentals()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] pcrDigest = new byte[32];
        Array.Fill(pcrDigest, (byte)0x44);
        byte[] parentName = new byte[34];
        Array.Fill(parentName, (byte)0x55);
        byte[] parentQualifiedName = new byte[34];
        Array.Fill(parentQualifiedName, (byte)0x66);
        byte[] oversizeOutsideInfo = new byte[Tpm2bData.MaxSize + 1];
        Array.Fill(oversizeOutsideInfo, (byte)0x77);

        byte[] wire = BuildCreationDataWire(
            pcrSelectWire: EmptyPcrSelectWire,
            pcrDigest: pcrDigest,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_SHA256,
            parentName: parentName,
            parentQualifiedName: parentQualifiedName,
            outsideInfo: oversizeOutsideInfo);

        var reader = new TpmReader(wire);

        try
        {
            _ = TpmsCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "pcrDigest's, parentName's and parentQualifiedName's rentals must be released when outsideInfo is refused.");
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationInfo.Parse"/> refuses a <c>creationHash</c> over
    /// <see cref="Tpm2bDigest.MaxSize"/> and releases the already-rented <c>objectName</c> (34 octets of real
    /// content) before the exception leaves. The bound is <c>TPM2B_DIGEST</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.2, Table 90); the structure itself is Part 2, clause
    /// 10.12.7, Table 130.
    /// </summary>
    [TestMethod]
    public void CreationInfoParseWithOversizeCreationHashThrowsAndReleasesObjectName()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] objectName = new byte[34];
        Array.Fill(objectName, (byte)0x88);
        byte[] oversizeCreationHash = new byte[Tpm2bDigest.MaxSize + 1];
        Array.Fill(oversizeCreationHash, (byte)0x99);

        byte[] wire = BuildCreationInfoWire(objectName, oversizeCreationHash);
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmsCreationInfo.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "objectName's rental must be released when creationHash is refused.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bAttest.Parse"/> — the production wire entry point for every attestation command
    /// (<c>TPM2_CertifyCreation</c>, <c>TPM2_Certify</c>, <c>TPM2_GetTime</c>, <c>TPM2_NV_Certify</c>,
    /// <c>TPM2_Quote</c>), not the inner <see cref="TpmsCreationInfo.Parse"/> the sibling fixture above calls
    /// directly — releases <c>rawStorage</c> when the enclosed <c>TPMS_CREATION_INFO</c>'s <c>creationHash</c>
    /// declares a size past <see cref="Tpm2bDigest.MaxSize"/>: <c>qualifiedSigner</c>, <c>extraData</c> and
    /// <c>objectName</c> are each given real, non-empty content so the balance proof is not vacuous for any of
    /// them. The bound is <c>TPM2B_DIGEST</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.2, Table 90), reached through the
    /// <c>TPM2B_ATTEST</c> envelope (clause 10.11.13, Table 155) and the <c>TPMS_ATTEST</c>/<c>TPMU_ATTEST</c>
    /// layers between it and <c>TPMS_CREATION_INFO</c> (clause 10.11.12, Table 154; clause 10.11.11, Table 153;
    /// clause 10.11.7, Table 130).
    /// </summary>
    [TestMethod]
    public void Tpm2bAttestParseWithOversizeCreationHashThrowsAndReleasesRawStorage()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] qualifiedSigner = new byte[34];
        Array.Fill(qualifiedSigner, (byte)0xA1);
        byte[] extraData = new byte[16];
        Array.Fill(extraData, (byte)0xA2);
        byte[] objectName = new byte[34];
        Array.Fill(objectName, (byte)0xA3);
        byte[] oversizeCreationHash = new byte[Tpm2bDigest.MaxSize + 1];
        Array.Fill(oversizeCreationHash, (byte)0xA4);

        byte[] creationInfoWire = BuildCreationInfoWire(objectName, oversizeCreationHash);
        byte[] attestWire = BuildAttestWireWithCreationBody(qualifiedSigner, extraData, creationInfoWire);
        byte[] wire = BuildTpm2bAttestWire(attestWire);

        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a plain
        //try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bAttest.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "rawStorage, qualifiedSigner, extraData and objectName must all be released when the enclosed TPMS_CREATION_INFO refuses an oversize creationHash.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bCreationData.Parse"/> — the wire entry point, not the inner
    /// <see cref="TpmsCreationData.Parse"/> the earlier fixtures call directly — releases <c>rawStorage</c> when
    /// the inner parse it drives refuses an oversize <c>parentQualifiedName</c>: <c>pcrSelect</c> (one genuine
    /// SHA-256 bank), <c>pcrDigest</c> (32 octets) and <c>parentName</c> (34 octets) are also released, all given
    /// real, non-empty content so the balance proof is not vacuous for any of them. The bound is
    /// <c>TPM2B_NAME</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.4.3, Table 105), reached through the
    /// <c>TPM2B_CREATION_DATA</c> envelope (clause 15.2, Table 262) that this test frames the malformation in.
    /// </summary>
    [TestMethod]
    public void Tpm2bCreationDataParseWithOversizeParentQualifiedNameThrowsAndReleasesRawStorage()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] pcrSelectBitmap = [0x01, 0x00, 0x00];
        byte[] pcrSelectWire = BuildPcrSelectWire(TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelectBitmap);
        byte[] pcrDigest = new byte[32];
        Array.Fill(pcrDigest, (byte)0x11);
        byte[] parentName = new byte[34];
        Array.Fill(parentName, (byte)0x22);
        byte[] oversizeParentQualifiedName = new byte[Tpm2bName.MaxSize + 1];
        Array.Fill(oversizeParentQualifiedName, (byte)0x33);

        byte[] creationDataWire = BuildCreationDataWire(
            pcrSelectWire: pcrSelectWire,
            pcrDigest: pcrDigest,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_SHA256,
            parentName: parentName,
            parentQualifiedName: oversizeParentQualifiedName,
            outsideInfo: ReadOnlySpan<byte>.Empty);
        byte[] wire = BuildTpm2bCreationDataWire(creationDataWire);

        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a plain
        //try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "rawStorage, pcrSelect, pcrDigest and parentName must all be released when the inner TpmsCreationData.Parse refuses an oversize parentQualifiedName.");
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> releases the already-rented <c>pcrSelect</c> (one genuine
    /// SHA-256 bank, non-empty so the balance proof is not vacuous) when <c>pcrDigest</c> declares 32 octets but
    /// the wire ends after only 4 — a buffer truncated mid-field rather than a declared length over
    /// <see cref="Tpm2bDigest.MaxSize"/>. This is <see cref="Tpm2bDigest.Parse"/>'s own bounds-before-rent guard:
    /// the declared size is checked against the remaining octets before any storage is rented, so the truncation
    /// throws <see cref="ArgumentOutOfRangeException"/> without renting a fifth carrier at all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.2, Table 90).
    /// </summary>
    [TestMethod]
    public void ParseWithTruncatedPcrDigestThrowsAndReleasesPcrSelect()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] pcrSelectBitmap = [0x01, 0x00, 0x00];
        byte[] pcrSelectWire = BuildPcrSelectWire(TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelectBitmap);
        byte[] wire = BuildCreationDataWireTruncatedAtPcrDigest(pcrSelectWire, declaredSize: 32, presentOctets: 4);

        var reader = new TpmReader(wire);

        try
        {
            _ = TpmsCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "pcrSelect's rental must be released when a truncated pcrDigest throws before it can rent its own storage.");
    }

    /// <summary>
    /// Proves <see cref="TpmsCreationData.Parse"/> releases the already-rented <c>pcrSelect</c> (one genuine
    /// SHA-256 bank) and <c>pcrDigest</c> (32 octets), both non-empty so the balance proof is not vacuous, when
    /// <c>parentName</c> declares 34 octets but the wire ends after only 4 — <see cref="Tpm2bName.Parse"/>'s own
    /// bounds-before-rent guard throws <see cref="ArgumentOutOfRangeException"/> before it rents a third carrier.
    /// The bound is <c>TPM2B_NAME</c>'s own
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.4.3, Table 105).
    /// </summary>
    [TestMethod]
    public void ParseWithTruncatedParentNameThrowsAndReleasesPcrSelectAndPcrDigest()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] pcrSelectBitmap = [0x01, 0x00, 0x00];
        byte[] pcrSelectWire = BuildPcrSelectWire(TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelectBitmap);
        byte[] pcrDigest = new byte[32];
        Array.Fill(pcrDigest, (byte)0xEE);
        byte[] wire = BuildCreationDataWireTruncatedAtParentName(
            pcrSelectWire,
            pcrDigest,
            TpmaLocality.TPM_LOC_ZERO,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            declaredSize: 34,
            presentOctets: 4);

        var reader = new TpmReader(wire);

        try
        {
            _ = TpmsCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "pcrSelect's and pcrDigest's rentals must be released when a truncated parentName throws before it can rent its own storage.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bCreationData.Parse"/> refuses a <c>TPM2B_CREATION_DATA</c> whose <c>size</c> field
    /// declares more octets than the wire actually holds, and does so WITHOUT ever renting <c>rawStorage</c> —
    /// the declared size is checked against the reader's remaining octets before the rental, so the truncation
    /// throws <see cref="ArgumentOutOfRangeException"/> before a single rent is issued. This is pinned on
    /// <see cref="MeteredHousePool.RentedCount"/> rather than <see cref="MeteredHousePool.OutstandingCount"/>:
    /// an implementation that rented and then released on the same throw would leave the balance unchanged too,
    /// so only the raw rent count distinguishes "never rented" from "rented and returned"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 15.2, Table 262).
    /// </summary>
    [TestMethod]
    public void Tpm2bCreationDataParseWithTruncatedOuterEnvelopeThrowsAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baselineOutstanding = trackingPool.OutstandingCount;
        long baselineRented = trackingPool.RentedCount;

        byte[] ownerHandle = [0x40, 0x00, 0x00, 0x01];
        byte[] creationDataWire = BuildCreationDataWire(
            pcrSelectWire: EmptyPcrSelectWire,
            pcrDigest: ReadOnlySpan<byte>.Empty,
            locality: TpmaLocality.TPM_LOC_ZERO,
            parentNameAlg: TpmAlgIdConstants.TPM_ALG_NULL,
            parentName: ownerHandle,
            parentQualifiedName: ownerHandle,
            outsideInfo: ReadOnlySpan<byte>.Empty);
        byte[] wire = BuildTruncatedTpm2bCreationDataWire(creationDataWire, missingTrailingOctets: 3);

        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bCreationData.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baselineRented, trackingPool.RentedCount, "A TPM2B_CREATION_DATA size declaring more octets than the buffer holds must throw before rawStorage is ever rented.");
        Assert.AreEqual(baselineOutstanding, trackingPool.OutstandingCount, "With nothing rented, nothing can be left outstanding either.");
    }

    /// <summary>
    /// Gets the marshaled <c>TPML_PCR_SELECTION</c> octets for an empty selection: a bare zero <c>count</c> and
    /// no entries (TPM 2.0 Library Part 2, clause 10.8.7, Table 128). Most fixtures in this file exercise
    /// <see cref="TpmsCreationData.PcrDigest"/> and the leak-safety of a malformed tail, neither of which turns
    /// on a non-empty PCR selection list — that content is covered separately by
    /// <see cref="TpmInHouseSimulatorCreationDataTests"/> — so this is their shared <c>pcrSelect</c> wire.
    /// </summary>
    private static ReadOnlySpan<byte> EmptyPcrSelectWire => [0x00, 0x00, 0x00, 0x00];

    /// <summary>
    /// Hand-builds the marshaled octets of a single-bank, non-empty <c>TPML_PCR_SELECTION</c> — <c>count</c> = 1
    /// followed by one <c>TPMS_PCR_SELECTION</c> entry — so a fixture can prove <see cref="TpmlPcrSelection"/>'s
    /// own rental is released on a later field's refusal rather than only its dispose-immune
    /// <see cref="TpmlPcrSelection.Empty"/> instance (TPM 2.0 Library Part 2, clause 10.8.7, Table 128).
    /// </summary>
    /// <param name="hashAlgorithm">The bank's hash algorithm.</param>
    /// <param name="pcrSelectBitmap">The bank's <c>pcrSelect</c> bitmap octets.</param>
    /// <returns>The marshaled <c>TPML_PCR_SELECTION</c> buffer.</returns>
    private static byte[] BuildPcrSelectWire(TpmAlgIdConstants hashAlgorithm, ReadOnlySpan<byte> pcrSelectBitmap)
    {
        int size = sizeof(uint) + sizeof(ushort) + sizeof(byte) + pcrSelectBitmap.Length;
        byte[] wire = new byte[size];
        var writer = new TpmWriter(wire);
        writer.WriteUInt32(1);
        writer.WriteUInt16((ushort)hashAlgorithm);
        writer.WriteByte((byte)pcrSelectBitmap.Length);
        writer.WriteBytes(pcrSelectBitmap);

        return wire;
    }

    /// <summary>
    /// Hand-builds a <c>TPMS_CREATION_DATA</c> wire buffer field-by-field with <see cref="TpmWriter"/>, in Table
    /// 246's own order.
    /// </summary>
    /// <param name="pcrSelectWire">The already-marshaled <c>TPML_PCR_SELECTION</c> octets — <see cref="EmptyPcrSelectWire"/> or a <see cref="BuildPcrSelectWire"/> result.</param>
    /// <param name="pcrDigest">The <c>pcrDigest</c> octets to frame after <paramref name="pcrSelectWire"/>.</param>
    /// <param name="locality">The <c>locality</c> octet.</param>
    /// <param name="parentNameAlg">The <c>parentNameAlg</c>.</param>
    /// <param name="parentName">The <c>parentName</c> octets.</param>
    /// <param name="parentQualifiedName">The <c>parentQualifiedName</c> octets.</param>
    /// <param name="outsideInfo">The <c>outsideInfo</c> octets.</param>
    /// <returns>The marshaled <c>TPMS_CREATION_DATA</c> buffer.</returns>
    private static byte[] BuildCreationDataWire(
        ReadOnlySpan<byte> pcrSelectWire,
        ReadOnlySpan<byte> pcrDigest,
        TpmaLocality locality,
        TpmAlgIdConstants parentNameAlg,
        ReadOnlySpan<byte> parentName,
        ReadOnlySpan<byte> parentQualifiedName,
        ReadOnlySpan<byte> outsideInfo)
    {
        int size = pcrSelectWire.Length
            + sizeof(ushort) + pcrDigest.Length
            + sizeof(byte)
            + sizeof(ushort)
            + sizeof(ushort) + parentName.Length
            + sizeof(ushort) + parentQualifiedName.Length
            + sizeof(ushort) + outsideInfo.Length;

        byte[] wire = new byte[size];
        var writer = new TpmWriter(wire);
        writer.WriteBytes(pcrSelectWire);
        writer.WriteTpm2b(pcrDigest);
        writer.WriteByte((byte)locality);
        writer.WriteUInt16((ushort)parentNameAlg);
        writer.WriteTpm2b(parentName);
        writer.WriteTpm2b(parentQualifiedName);
        writer.WriteTpm2b(outsideInfo);

        return wire;
    }

    /// <summary>
    /// Wraps an already-marshaled <c>TPMS_CREATION_DATA</c> buffer in a well-formed <c>TPM2B_CREATION_DATA</c>
    /// envelope: a <c>size</c> field equal to <paramref name="creationDataWire"/>'s own length, followed by every
    /// one of its octets (TPM 2.0 Library Part 2, clause 15.2, Table 262). Used to drive a malformation nested
    /// inside the creation data through <see cref="Tpm2bCreationData.Parse"/> — the wire entry point — rather
    /// than through <see cref="TpmsCreationData.Parse"/> directly.
    /// </summary>
    /// <param name="creationDataWire">The marshaled <c>TPMS_CREATION_DATA</c> octets to frame.</param>
    /// <returns>The marshaled <c>TPM2B_CREATION_DATA</c> buffer.</returns>
    private static byte[] BuildTpm2bCreationDataWire(byte[] creationDataWire)
    {
        byte[] wire = new byte[sizeof(ushort) + creationDataWire.Length];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)creationDataWire.Length);
        writer.WriteBytes(creationDataWire);

        return wire;
    }

    /// <summary>
    /// Wraps a prefix of an already-marshaled <c>TPMS_CREATION_DATA</c> buffer in a <c>TPM2B_CREATION_DATA</c>
    /// envelope whose <c>size</c> field names <paramref name="creationDataWire"/>'s FULL length while the wire
    /// itself carries only that many octets minus <paramref name="missingTrailingOctets"/> — a buffer truncated
    /// after the envelope's own size prefix (TPM 2.0 Library Part 2, clause 15.2, Table 262).
    /// </summary>
    /// <param name="creationDataWire">The marshaled <c>TPMS_CREATION_DATA</c> octets whose full length is declared.</param>
    /// <param name="missingTrailingOctets">The number of trailing octets to omit from the wire while still declaring the full length.</param>
    /// <returns>The truncated <c>TPM2B_CREATION_DATA</c> buffer.</returns>
    private static byte[] BuildTruncatedTpm2bCreationDataWire(byte[] creationDataWire, int missingTrailingOctets)
    {
        int presentLength = creationDataWire.Length - missingTrailingOctets;
        byte[] wire = new byte[sizeof(ushort) + presentLength];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)creationDataWire.Length);
        writer.WriteBytes(creationDataWire.AsSpan(0, presentLength));

        return wire;
    }

    /// <summary>
    /// Hand-builds a <c>TPMS_CREATION_DATA</c> wire buffer that ends mid-<c>pcrDigest</c>: a real, non-empty
    /// <paramref name="pcrSelectWire"/> followed by a <c>TPM2B_DIGEST</c> size prefix of
    /// <paramref name="declaredSize"/> octets but only <paramref name="presentOctets"/> of content, with nothing
    /// written for any of Table 261's later fields (TPM 2.0 Library Part 2, clause 10.3.2, Table 90).
    /// </summary>
    /// <param name="pcrSelectWire">The already-marshaled <c>TPML_PCR_SELECTION</c> octets preceding the digest.</param>
    /// <param name="declaredSize">The <c>pcrDigest</c> size the wire declares.</param>
    /// <param name="presentOctets">The number of digest octets actually present before the buffer ends.</param>
    /// <returns>The truncated <c>TPMS_CREATION_DATA</c> buffer.</returns>
    private static byte[] BuildCreationDataWireTruncatedAtPcrDigest(byte[] pcrSelectWire, ushort declaredSize, int presentOctets)
    {
        byte[] presentDigestOctets = new byte[presentOctets];
        Array.Fill(presentDigestOctets, (byte)0xCC);

        byte[] wire = new byte[pcrSelectWire.Length + sizeof(ushort) + presentOctets];
        var writer = new TpmWriter(wire);
        writer.WriteBytes(pcrSelectWire);
        writer.WriteUInt16(declaredSize);
        writer.WriteBytes(presentDigestOctets);

        return wire;
    }

    /// <summary>
    /// Hand-builds a <c>TPMS_CREATION_DATA</c> wire buffer that ends mid-<c>parentName</c>: a real, non-empty
    /// <paramref name="pcrSelectWire"/>, a real <paramref name="pcrDigest"/>, the <c>locality</c> octet and
    /// <paramref name="parentNameAlg"/>, followed by a <c>TPM2B_NAME</c> size prefix of
    /// <paramref name="declaredSize"/> octets but only <paramref name="presentOctets"/> of content, with nothing
    /// written for any field after it (TPM 2.0 Library Part 2, clause 10.4.3, Table 105).
    /// </summary>
    /// <param name="pcrSelectWire">The already-marshaled <c>TPML_PCR_SELECTION</c> octets.</param>
    /// <param name="pcrDigest">The <c>pcrDigest</c> octets.</param>
    /// <param name="locality">The <c>locality</c> octet.</param>
    /// <param name="parentNameAlg">The <c>parentNameAlg</c>.</param>
    /// <param name="declaredSize">The <c>parentName</c> size the wire declares.</param>
    /// <param name="presentOctets">The number of Name octets actually present before the buffer ends.</param>
    /// <returns>The truncated <c>TPMS_CREATION_DATA</c> buffer.</returns>
    private static byte[] BuildCreationDataWireTruncatedAtParentName(
        byte[] pcrSelectWire,
        byte[] pcrDigest,
        TpmaLocality locality,
        TpmAlgIdConstants parentNameAlg,
        ushort declaredSize,
        int presentOctets)
    {
        byte[] presentNameOctets = new byte[presentOctets];
        Array.Fill(presentNameOctets, (byte)0xDD);

        int size = pcrSelectWire.Length
            + sizeof(ushort) + pcrDigest.Length
            + sizeof(byte)
            + sizeof(ushort)
            + sizeof(ushort) + presentOctets;

        byte[] wire = new byte[size];
        var writer = new TpmWriter(wire);
        writer.WriteBytes(pcrSelectWire);
        writer.WriteTpm2b(pcrDigest);
        writer.WriteByte((byte)locality);
        writer.WriteUInt16((ushort)parentNameAlg);
        writer.WriteUInt16(declaredSize);
        writer.WriteBytes(presentNameOctets);

        return wire;
    }

    /// <summary>
    /// Hand-builds a <c>TPMS_CREATION_INFO</c> wire buffer field-by-field with <see cref="TpmWriter"/>: the
    /// <c>objectName</c> then the <c>creationHash</c> (TPM 2.0 Library Part 2, clause 10.11.7, Table 130).
    /// </summary>
    /// <param name="objectName">The <c>objectName</c> octets.</param>
    /// <param name="creationHash">The <c>creationHash</c> octets.</param>
    /// <returns>The marshaled <c>TPMS_CREATION_INFO</c> buffer.</returns>
    private static byte[] BuildCreationInfoWire(ReadOnlySpan<byte> objectName, ReadOnlySpan<byte> creationHash)
    {
        int size = sizeof(ushort) + objectName.Length + sizeof(ushort) + creationHash.Length;
        byte[] wire = new byte[size];
        var writer = new TpmWriter(wire);
        writer.WriteTpm2b(objectName);
        writer.WriteTpm2b(creationHash);

        return wire;
    }

    /// <summary>
    /// Hand-builds a <c>TPMS_ATTEST</c> wire buffer field-by-field with <see cref="TpmWriter"/>: a TPM-generated
    /// <c>magic</c>, <c>type</c> = <c>TPM_ST_ATTEST_CREATION</c>, <paramref name="qualifiedSigner"/>,
    /// <paramref name="extraData"/>, a zeroed <c>TPMS_CLOCK_INFO</c>, a zero <c>firmwareVersion</c>, then the
    /// already-marshaled <c>TPMU_ATTEST</c> creation body — the layout <see cref="TpmuAttest.Parse"/> selects on
    /// <c>TPM_ST_ATTEST_CREATION</c> (TPM 2.0 Library Part 2, clause 10.11.12, Table 154; clause 10.11.11, Table
    /// 177).
    /// </summary>
    /// <param name="qualifiedSigner">The <c>qualifiedSigner</c> Name octets.</param>
    /// <param name="extraData">The <c>extraData</c> octets.</param>
    /// <param name="creationInfoWire">The already-marshaled <c>TPMS_CREATION_INFO</c> octets forming the <c>attested</c> body.</param>
    /// <returns>The marshaled <c>TPMS_ATTEST</c> buffer.</returns>
    private static byte[] BuildAttestWireWithCreationBody(ReadOnlySpan<byte> qualifiedSigner, ReadOnlySpan<byte> extraData, byte[] creationInfoWire)
    {
        int size = sizeof(uint)
            + sizeof(ushort)
            + sizeof(ushort) + qualifiedSigner.Length
            + sizeof(ushort) + extraData.Length
            + TpmsClockInfo.SerializedSize
            + sizeof(ulong)
            + creationInfoWire.Length;

        byte[] wire = new byte[size];
        var writer = new TpmWriter(wire);
        writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_CREATION);
        writer.WriteTpm2b(qualifiedSigner);
        writer.WriteTpm2b(extraData);
        writer.WriteUInt64(0); //clock
        writer.WriteUInt32(0); //resetCount
        writer.WriteUInt32(0); //restartCount
        writer.WriteByte(0);   //safe
        writer.WriteUInt64(0); //firmwareVersion
        writer.WriteBytes(creationInfoWire);

        return wire;
    }

    /// <summary>
    /// Wraps an already-marshaled <c>TPMS_ATTEST</c> buffer in a well-formed <c>TPM2B_ATTEST</c> envelope: a
    /// <c>size</c> field equal to <paramref name="attestWire"/>'s own length, followed by every one of its octets
    /// (TPM 2.0 Library Part 2, clause 10.11.13, Table 182). Used to drive a malformation nested inside the
    /// attestation through <see cref="Tpm2bAttest.Parse"/> — the wire entry point — rather than through
    /// <see cref="TpmsCreationInfo.Parse"/> directly.
    /// </summary>
    /// <param name="attestWire">The marshaled <c>TPMS_ATTEST</c> octets to frame.</param>
    /// <returns>The marshaled <c>TPM2B_ATTEST</c> buffer.</returns>
    private static byte[] BuildTpm2bAttestWire(byte[] attestWire)
    {
        byte[] wire = new byte[sizeof(ushort) + attestWire.Length];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)attestWire.Length);
        writer.WriteBytes(attestWire);

        return wire;
    }
}
