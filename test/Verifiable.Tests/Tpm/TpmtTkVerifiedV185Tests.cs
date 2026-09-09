using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proving tests for the v185 <see cref="TpmtTkVerified"/> shape: the three-tag <c>tag</c> field (Table 112),
/// the conditional <c>metadata</c> union (Table 111), the <c>digest</c>-to-<c>hmac</c> field rename, and the
/// <see cref="TpmtTkVerified.FromMarshaled"/> adoption contract.
/// </summary>
[TestClass]
internal sealed class TpmtTkVerifiedV185Tests
{
    /// <summary>
    /// A <c>TPM_ST_VERIFIED</c> ticket carries no <c>metadata</c> (Table 111's <c>verified</c> arm is
    /// <c>TPMS_EMPTY</c>) and round-trips its <c>hmac</c> byte-identically
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111; clause 10.6.5, Table 113).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseWriteToRoundTripsVerifiedTagByteIdentically()
    {
        byte[] wire =
        [
            0x80, 0x22, //tag = TPM_ST_VERIFIED.
            0x40, 0x00, 0x00, 0x01, //hierarchy = TPM_RH_OWNER.
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD //hmac: size 4.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, ticket.Tag);
        Assert.AreEqual(TpmiRhHierarchy.Owner, ticket.Hierarchy);
        Assert.IsNull(ticket.Metadata, "TPM_ST_VERIFIED selects TPMS_EMPTY (Table 111); the wire carries no metadata octets.");
        Assert.AreSequenceEqual(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, ticket.Hmac.ToArray());
        Assert.AreEqual(wire.Length, ticket.SerializedSize);
        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the octets WriteTo framed.");

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        ticket.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// A <c>TPM_ST_MESSAGE_VERIFIED</c> ticket is the other <c>TPMS_EMPTY</c> arm (Table 111's
    /// <c>messageVerified</c>) and round-trips exactly like <c>TPM_ST_VERIFIED</c>, carrying no metadata octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111; clause 10.6.5, Table 112).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseWriteToRoundTripsMessageVerifiedTagByteIdentically()
    {
        byte[] wire =
        [
            0x80, 0x26, //tag = TPM_ST_MESSAGE_VERIFIED.
            0x40, 0x00, 0x00, 0x0B, //hierarchy = TPM_RH_ENDORSEMENT.
            0x00, 0x03, 0x01, 0x02, 0x03 //hmac: size 3.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, ticket.Tag);
        Assert.AreEqual(TpmiRhHierarchy.Endorsement, ticket.Hierarchy);
        Assert.IsNull(ticket.Metadata, "TPM_ST_MESSAGE_VERIFIED selects TPMS_EMPTY (Table 111); the wire carries no metadata octets.");
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, ticket.Hmac.ToArray());
        Assert.AreEqual(wire.Length, ticket.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        ticket.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// A <c>TPM_ST_DIGEST_VERIFIED</c> ticket carries the <c>digestVerified</c> arm — a plain
    /// <c>TPMI_ALG_HASH</c> metadata octet pair between <c>hierarchy</c> and <c>hmac</c> — and round-trips both
    /// fields byte-identically
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111; clause 10.6.5, Table 112).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseWriteToRoundTripsDigestVerifiedTagWithMetadataByteIdentically()
    {
        byte[] wire =
        [
            0x80, 0x27, //tag = TPM_ST_DIGEST_VERIFIED.
            0x40, 0x00, 0x00, 0x0C, //hierarchy = TPM_RH_PLATFORM.
            0x00, 0x0B, //metadata = TPM_ALG_SHA256 (digestVerified arm).
            0x00, 0x02, 0x11, 0x22 //hmac: size 2.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreEqual(TpmStConstants.TPM_ST_DIGEST_VERIFIED, ticket.Tag);
        Assert.AreEqual(TpmiRhHierarchy.Platform, ticket.Hierarchy);
        Assert.IsTrue(ticket.Metadata.HasValue, "TPM_ST_DIGEST_VERIFIED selects the digestVerified arm, a real TPMI_ALG_HASH.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, ticket.Metadata!.Value.Value);
        Assert.AreSequenceEqual(new byte[] { 0x11, 0x22 }, ticket.Hmac.ToArray());
        Assert.AreEqual(wire.Length, ticket.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        ticket.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// A tag outside Table 112's three-value set — here <c>TPM_ST_HASHCHECK</c>, another ticket's own tag — is
    /// refused before the hierarchy or any later field is read
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5, Table 112; <c>TPM_RC_TAG</c>).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseRefusesAForeignTicketTag()
    {
        byte[] wire =
        [
            0x80, 0x24, //tag = TPM_ST_HASHCHECK — not one of Table 112's three TPMT_TK_VERIFIED tags.
            0x40, 0x00, 0x00, 0x01, //hierarchy = TPM_RH_OWNER.
            0x00, 0x00 //hmac: empty.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmtTkVerified.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// The <c>&lt;TPM_ST_VERIFIED, TPM_RH_NULL, 0x0000&gt;</c> tuple is the shared <see cref="TpmtTkVerified.Null"/>
    /// sentinel, exactly as the pre-v185 wire format already returned it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5, Table 113).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseOfTheNullTupleReturnsTheSharedSentinelForVerifiedTag()
    {
        byte[] wire =
        [
            0x80, 0x22, //tag = TPM_ST_VERIFIED.
            0x40, 0x00, 0x00, 0x07, //hierarchy = TPM_RH_NULL.
            0x00, 0x00 //hmac: empty.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreSame(TpmtTkVerified.Null, ticket, "The VERIFIED-tagged NULL tuple is the shared dispose-immune sentinel.");
        Assert.IsTrue(ticket.IsNull);
        Assert.IsNull(ticket.Metadata);
    }

    /// <summary>
    /// The <c>&lt;TPM_ST_MESSAGE_VERIFIED, TPM_RH_NULL, 0x0000&gt;</c> tuple is a distinct, storage-less instance
    /// that keeps its own tag — the shared sentinel is VERIFIED-tagged only, so a MESSAGE_VERIFIED NULL ticket
    /// cannot reuse it without losing the tag a caller framed it with
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5, Table 113's three-tag NULL tuple).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseOfTheNullTupleForMessageVerifiedIsAStorageLessInstanceKeepingItsTag()
    {
        byte[] wire =
        [
            0x80, 0x26, //tag = TPM_ST_MESSAGE_VERIFIED.
            0x40, 0x00, 0x00, 0x07, //hierarchy = TPM_RH_NULL.
            0x00, 0x00 //hmac: empty.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreNotSame(TpmtTkVerified.Null, ticket, "The shared sentinel carries TPM_ST_VERIFIED; a MESSAGE_VERIFIED NULL ticket is a separate instance.");
        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, ticket.Tag);
        Assert.IsTrue(ticket.IsNull);
        Assert.IsNull(ticket.Metadata);
        Assert.AreEqual(wire.Length, ticket.SerializedSize);
    }

    /// <summary>
    /// The <c>&lt;TPM_ST_DIGEST_VERIFIED, TPM_RH_NULL, 0x0000&gt;</c> tuple is silent on <c>metadata</c>, but
    /// Table 111's <c>digestVerified</c> arm is a plain <c>TPMI_ALG_HASH</c> with no NULL admission, so the wire
    /// still carries a real hash algorithm even in the NULL form
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111; clause 10.6.5, Table 113).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseOfTheNullTupleForDigestVerifiedKeepsItsMetadataHash()
    {
        byte[] wire =
        [
            0x80, 0x27, //tag = TPM_ST_DIGEST_VERIFIED.
            0x40, 0x00, 0x00, 0x07, //hierarchy = TPM_RH_NULL.
            0x00, 0x0C, //metadata = TPM_ALG_SHA384 — the NULL tuple still names a real hash algorithm.
            0x00, 0x00 //hmac: empty.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtTkVerified ticket = TpmtTkVerified.Parse(ref reader, pool);

        Assert.AreEqual(TpmStConstants.TPM_ST_DIGEST_VERIFIED, ticket.Tag);
        Assert.IsTrue(ticket.IsNull);
        Assert.IsTrue(ticket.Metadata.HasValue, "Table 111's digestVerified arm admits no NULL selector, even for a NULL ticket.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, ticket.Metadata!.Value.Value);
        Assert.AreEqual(wire.Length, ticket.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        ticket.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// A <c>TPM_ST_DIGEST_VERIFIED</c> ticket whose <c>metadata</c> octets name an algorithm that is not a hash
    /// at all is refused: Table 111's <c>digestVerified</c> arm is a <c>TPMI_ALG_HASH</c>, and unmarshaling one
    /// with an unadmitted selector is <c>TPM_RC_HASH</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111; clause 9.31, Table 77).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseRefusesADigestVerifiedTicketCarryingANonHashMetadataSelector()
    {
        byte[] wire =
        [
            0x80, 0x27, //tag = TPM_ST_DIGEST_VERIFIED.
            0x40, 0x00, 0x00, 0x01, //hierarchy = TPM_RH_OWNER.
            0x00, 0x01 //metadata = TPM_ALG_RSA — not a hash algorithm.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmtTkVerified.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// A declared <c>hmac</c> size exceeding the octets actually remaining in the reader disposes the rental it
    /// already asked for rather than leaving it outstanding, so a truncated frame never orphans a rental
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5, Table 113's <c>hmac</c> field).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedParseTruncatedHmacLeavesPoolBalanced()
    {
        byte[] wire =
        [
            0x80, 0x22, //tag = TPM_ST_VERIFIED.
            0x40, 0x00, 0x00, 0x01, //hierarchy = TPM_RH_OWNER.
            0x00, 0x0A, 0x01, 0x02 //hmac: declares size 10, but only 2 octets follow.
        ];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmtTkVerified.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The rental the declared size sized is disposed in the catch path, so the pool returns to baseline.");
    }

    /// <summary>
    /// <see cref="TpmtTkVerified.FromMarshaled"/> refuses a tag outside Table 112's three-value set and disposes
    /// the rental it was handed rather than orphaning it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.5, Table 112; <c>TPM_RC_TAG</c>).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedFromMarshaledRefusesAForeignTagAndDisposesTheRental()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var hmac = trackingPool.Pool.Rent(4);
        hmac.Memory.Span[..4].Fill(0xAB);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => TpmtTkVerified.FromMarshaled(TpmStConstants.TPM_ST_HASHCHECK, TpmiRhHierarchy.Owner, null, hmac, 4),
            "TPM_ST_HASHCHECK is another ticket's tag, not one of Table 112's three TPMT_TK_VERIFIED values.");

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// <see cref="TpmtTkVerified.FromMarshaled"/> refuses a <c>TPM_ST_DIGEST_VERIFIED</c> adoption with no
    /// <c>metadata</c> supplied — Table 111's <c>digestVerified</c> arm is a real value, not an optional one —
    /// and disposes the rental it was handed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedFromMarshaledRefusesMissingMetadataForDigestVerifiedAndDisposesTheRental()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var hmac = trackingPool.Pool.Rent(3);
        hmac.Memory.Span[..3].Fill(0xCD);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => TpmtTkVerified.FromMarshaled(TpmStConstants.TPM_ST_DIGEST_VERIFIED, TpmiRhHierarchy.Owner, null, hmac, 3),
            "TPM_ST_DIGEST_VERIFIED requires the digestVerified metadata arm.");

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// <see cref="TpmtTkVerified.FromMarshaled"/> refuses a <c>TPM_ST_VERIFIED</c> adoption that supplies
    /// <c>metadata</c> anyway — Table 111's <c>verified</c> arm is <c>TPMS_EMPTY</c>, so a non-null value
    /// mismatches the tag's own arm — and disposes the rental it was handed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111).
    /// </summary>
    [TestMethod]
    public void TpmtTkVerifiedFromMarshaledRefusesMetadataSuppliedForVerifiedAndDisposesTheRental()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var hmac = trackingPool.Pool.Rent(2);
        hmac.Memory.Span[..2].Fill(0xEF);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => TpmtTkVerified.FromMarshaled(TpmStConstants.TPM_ST_VERIFIED, TpmiRhHierarchy.Owner, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), hmac, 2),
            "TPM_ST_VERIFIED selects the TPMS_EMPTY arm; a supplied metadata value mismatches it.");

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }
}
