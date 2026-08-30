using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Round-trip and pool-balance proofs for the TPM2B sized-buffer and TPML list structures created for the
/// wire-type census: <see cref="Tpm2bMaxNvBuffer"/>, <see cref="Tpm2bMaxBuffer"/>, <see cref="Tpm2bOperand"/>, <see cref="Tpm2bTimeout"/>,
/// <see cref="TpmlHandle"/>, <see cref="TpmlCc"/>, <see cref="TpmlAlg"/>; plus <see cref="Tpm2bData"/>'s
/// aliasing accessor, <see cref="TpmlDigest"/>'s wire-writing addition and <see cref="TpmlDigest.Adopt"/>,
/// <see cref="TpmlPcrSelection"/>, and the credential carriers <see cref="Tpm2bIdObject"/> and
/// <see cref="Tpm2bEncryptedSecret"/>. The two command inputs that carry a <c>TPM2B_OPERAND</c> as a
/// caller-owned buffer rather than as the carrier — <see cref="PolicyNvInput"/> and
/// <see cref="PolicyCounterTimerInput"/> — are proved against the same bound here, because the bound is the
/// structure's and the input is where a client-side caller meets it.
/// </summary>
/// <remarks>
/// <see cref="TpmlPcrSelection"/> carries TWO bounds from two different tables, and the cases here keep them
/// apart because the simulator maps them to different response codes: the LIST's <c>count</c> is bounded by
/// <c>{:HASH_COUNT}</c> with <c>#TPM_RC_SIZE</c> (TPM 2.0 Library Part 2, clause 10.8.7, Table 128), while each
/// selection's <c>sizeofSelect</c> is bounded by <c>{PCR_SELECT_MIN:}</c> and its bitmap by
/// <c>{:PCR_SELECT_MAX}</c> with <c>#TPM_RC_VALUE</c> (clause 10.5.2, Table 107, over clause 10.5.1's
/// equation 1). Both <c>sizeofSelect</c> cases additionally read the pool balance, since the width is what sizes
/// the rental the parse would otherwise make before the bound is known. A third case covers
/// <see cref="TpmlPcrSelection.RetainImplementedPcrs"/>, the in-place mask that clears every bit naming a
/// register or a bank an implementation does not hold while leaving the marshaled width untouched — the
/// filtering an attestation's echoed selection is subject to (Part 3, clause 18.4).
/// </remarks>
[TestClass]
internal sealed class TpmSpecBufferAndListTests
{
    /// <summary>
    /// Proves <see cref="Tpm2bData.AsReadOnlyMemory"/> exposes the same bytes as <see cref="Tpm2bData.Span"/>,
    /// matching the aliasing contract <see cref="Tpm2bName.AsReadOnlyMemory"/> establishes (Part 2, §10.3.3).
    /// </summary>
    [TestMethod]
    public void Tpm2bDataAsReadOnlyMemoryMatchesSpanBytes()
    {
        byte[] original = [0x01, 0x02, 0x03, 0x04, 0x05];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bData data = Tpm2bData.Create(original, pool);
        ReadOnlyMemory<byte> memory = data.AsReadOnlyMemory();

        Assert.IsTrue(memory.Span.SequenceEqual(data.Span), "The aliased memory exposes exactly the carrier's octets.");
    }

    /// <summary>
    /// Proves an empty <see cref="Tpm2bData"/>'s <see cref="Tpm2bData.AsReadOnlyMemory"/> returns
    /// <see cref="ReadOnlyMemory{T}.Empty"/> rather than dereferencing the null sentinel storage.
    /// </summary>
    [TestMethod]
    public void Tpm2bDataEmptyAsReadOnlyMemoryIsEmpty()
    {
        using Tpm2bData data = Tpm2bData.Empty;

        ReadOnlyMemory<byte> memory = data.AsReadOnlyMemory();

        Assert.IsTrue(memory.IsEmpty, "The empty sentinel aliases no storage.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bData.AsReadOnlyMemory"/> refuses to run once the carrier is disposed, matching
    /// every other accessor's <see cref="ObjectDisposedException"/> guard.
    /// </summary>
    [TestMethod]
    public void Tpm2bDataAsReadOnlyMemoryThrowsAfterDispose()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Tpm2bData data = Tpm2bData.Create([0xAA, 0xBB], pool);
        data.Dispose();

        _ = Assert.ThrowsExactly<ObjectDisposedException>(() => data.AsReadOnlyMemory());
    }

    /// <summary>
    /// Proves <see cref="TpmlDigest.WriteTo"/> reproduces the exact wire bytes <see cref="TpmlDigest.Parse"/>
    /// consumed, for a non-empty digest list (TPM 2.0 Library Part 2, clause 10.8.5, Table 126).
    /// </summary>
    [TestMethod]
    public void TpmlDigestWriteToRoundtripsByteIdentical()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x00, 0x02, 0xAA, 0xBB, //digest[0]: size 2.
            0x00, 0x03, 0x01, 0x02, 0x03 //digest[1]: size 3.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmlDigest list = TpmlDigest.Parse(ref reader, pool);

        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(wire.Length, list.GetSerializedSize());

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreEqual(wire.Length, writer.Written);
        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves an empty digest list round-trips as a bare zero count (TPM 2.0 Library Part 2, clause 10.8.5).
    /// </summary>
    [TestMethod]
    public void TpmlDigestEmptyWriteToRoundtrips()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmlDigest list = TpmlDigest.Parse(ref reader, pool);

        Assert.AreEqual(0, list.Count);
        Assert.AreEqual(4, list.GetSerializedSize());

        byte[] rewritten = new byte[4];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="TpmlDigest.Adopt"/> marshals to the literal Table 126 wire bytes — count as UINT32,
    /// then each entry as a size-prefixed TPM2B_DIGEST — and that parsing those written bytes back reproduces
    /// the adopted octets, round-tripping the zero-copy adoption path end to end against spec-derived bytes
    /// rather than against a second call to <see cref="TpmlDigest.Create"/>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.8.5, Table 126).
    /// </summary>
    [TestMethod]
    public void TpmlDigestAdoptRoundtripsToLiteralWireBytes()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x00, 0x02, 0xAA, 0xBB, //digest[0]: size 2.
            0x00, 0x03, 0x01, 0x02, 0x03 //digest[1]: size 3.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var alreadyBuilt = new List<Tpm2bDigest>
        {
            Tpm2bDigest.Create(new byte[] { 0xAA, 0xBB }, pool),
            Tpm2bDigest.Create(new byte[] { 0x01, 0x02, 0x03 }, pool)
        };

        using TpmlDigest adopted = TpmlDigest.Adopt(alreadyBuilt);
        Assert.AreEqual(wire.Length, adopted.GetSerializedSize());

        byte[] written = new byte[wire.Length];
        var writer = new TpmWriter(written);
        adopted.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, written, "Adopt marshals to the literal Table 126 wire bytes derived from the spec, not merely bytes equal to a second Create call.");

        var reader = new TpmReader(written);
        using TpmlDigest reparsed = TpmlDigest.Parse(ref reader, pool);

        Assert.AreEqual(2, reparsed.Count);
        Assert.AreSequenceEqual(new byte[] { 0xAA, 0xBB }, reparsed[0].AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, reparsed[1].AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Proves <see cref="TpmlDigest.Adopt"/> disposes every already-built entry in the rejected list — both the
    /// one before the <see langword="null"/> entry and the one after it — leaving the pool balanced, so a
    /// rejected adoption never orphans a pinned rental regardless of where the null entry sits, and a caller
    /// never disposes an entry it already handed to the failed call
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.8.5, Table 126).
    /// </summary>
    [TestMethod]
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of 'first' and 'third' transfers to TpmlDigest.Adopt on the very next statement, which disposes both on its null-entry refusal path; the test proves exactly that.")]
    public void TpmlDigestAdoptOnNullEntryReleasesAlreadyAcceptedDigestsAndBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bDigest first = Tpm2bDigest.Create([0x01, 0x02], trackingPool.Pool);
        Tpm2bDigest third = Tpm2bDigest.Create([0x03, 0x04, 0x05], trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        List<Tpm2bDigest> withNullEntry = [first, null!, third];

        _ = Assert.ThrowsExactly<ArgumentException>(() => TpmlDigest.Adopt(withNullEntry));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Every already-built entry is disposed when a later entry is rejected, whether it sits before or after the null entry, so both real rentals come back too.");
    }

    /// <summary>
    /// Proves <see cref="TpmlPcrSelection.Parse"/> then <see cref="TpmlPcrSelection.WriteTo"/> reproduce the
    /// original wire bytes exactly for a selection carrying the narrowest conformant <c>sizeofSelect</c>
    /// (TPM 2.0 Library Part 2, clause 10.8.7, Table 128, over clause 10.5.2, Table 107's member).
    /// </summary>
    [TestMethod]
    public void TpmlPcrSelectionParseWriteToRoundtripsByteIdentical()
    {
        //count = 1, then { SHA-256, 3, 0x01 0x00 0x80 } — PCR 0 and PCR 23 over the three octets PCR_SELECT_MIN
        //names for a 24-register platform.
        byte[] wire = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x01, 0x00, 0x80];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        using TpmlPcrSelection selection = TpmlPcrSelection.Parse(ref reader, pool);
        Assert.HasCount(1, selection.Selections);
        Assert.AreEqual(
            sizeof(uint) + sizeof(ushort) + sizeof(byte) + TpmlPcrSelection.PcrSelectMin, selection.GetSerializedSize(),
            "A sizeofSelect of PCR_SELECT_MIN octets parses to a bitmap of exactly that width, so the list marshals back to count + hash + sizeofSelect + those octets.");

        byte[] written = new byte[selection.GetSerializedSize()];
        var writer = new TpmWriter(written);
        selection.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, written);
    }

    /// <summary>
    /// Proves <see cref="TpmlPcrSelection.Parse"/> refuses a <c>sizeofSelect</c> of zero — below
    /// <see cref="TpmlPcrSelection.PcrSelectMin"/> — before it rents anything for the bitmap that width would
    /// size.
    /// </summary>
    /// <remarks>
    /// The bound is the member's own: <c>sizeofSelect {PCR_SELECT_MIN:}</c> with <c>#TPM_RC_VALUE</c> (TPM 2.0
    /// Library Part 2, clause 10.5.2, Table 107; <c>PCR_SELECT_MIN</c> itself is clause 10.5.1's equation 1). The
    /// exception type is what distinguishes it from the list's count bound, which is <c>#TPM_RC_SIZE</c> and
    /// raises <see cref="InvalidOperationException"/> — the simulator's parse maps the two to different response
    /// codes.
    /// </remarks>
    [TestMethod]
    public void TpmlPcrSelectionParseBelowPcrSelectMinThrowsAndRentsNothing()
    {
        //count = 1, then { SHA-256, 0 } — a bitmap of no octets at all.
        byte[] wire = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x00];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmlPcrSelection.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The width is settled before the rental it sizes, so a refused parse leaves nothing outstanding.");
    }

    /// <summary>
    /// Proves <see cref="TpmlPcrSelection.Parse"/> refuses a <c>sizeofSelect</c> above
    /// <see cref="TpmlPcrSelection.PcrSelectMax"/>, the other side of Table 107's
    /// <c>pcrSelect[sizeofSelect] {:PCR_SELECT_MAX}</c> bound, and that an earlier selection's rental is released
    /// when a later one is refused.
    /// </summary>
    [TestMethod]
    public void TpmlPcrSelectionParseAbovePcrSelectMaxThrowsAndReleasesEarlierRentals()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        //count = 2: a well-formed SHA-256 selection, then a SHA-384 one naming a width beyond PCR_SELECT_MAX.
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x0B, 0x03, 0x01, 0x00, 0x00,
            0x00, 0x0C, (byte)(TpmlPcrSelection.PcrSelectMax + 1)
        ];
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmlPcrSelection.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The first selection's rental must be released when a later selection is refused.");
    }

    /// <summary>
    /// Proves <see cref="TpmlPcrSelection.RetainImplementedPcrs"/> clears exactly the bits an implementation
    /// cannot answer for — every bit of a bank it has not allocated, and the bits above its register count in one
    /// it has — while leaving the list's marshaled width untouched.
    /// </summary>
    /// <remarks>
    /// The reference's <c>FilterPcr</c> does both in place ("if the required bank does not exist, clear input
    /// selection"; otherwise mask against the bank's own allocation), and the entry is retained either way, which
    /// is why the width cannot move (TPM 2.0 Library Part 2, clause 10.5.1's own statement that PCR beyond the
    /// bitmap "are not selected").
    /// </remarks>
    [TestMethod]
    public void TpmlPcrSelectionRetainImplementedPcrsClearsUnheldBitsAndKeepsTheWidth()
    {
        //count = 2: SHA-256 with every bit of a four-octet bitmap set, then an unallocated SHA-384 bank.
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x0B, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x0C, 0x03, 0xFF, 0xFF, 0xFF
        ];
        byte[] expected =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x0B, 0x04, 0xFF, 0xFF, 0xFF, 0x00,
            0x00, 0x0C, 0x03, 0x00, 0x00, 0x00
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        using TpmlPcrSelection selection = TpmlPcrSelection.Parse(ref reader, pool);
        int sizeBeforeFiltering = selection.GetSerializedSize();

        ReadOnlySpan<TpmAlgIdConstants> implementedBanks = [TpmAlgIdConstants.TPM_ALG_SHA256];
        selection.RetainImplementedPcrs(implementedBanks, implementedPcrCount: 24);

        Assert.AreEqual(sizeBeforeFiltering, selection.GetSerializedSize(), "Filtering clears bits in place, so the marshaled width cannot move.");

        byte[] written = new byte[selection.GetSerializedSize()];
        var writer = new TpmWriter(written);
        selection.WriteTo(ref writer);

        Assert.AreSequenceEqual(expected, written);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxNvBuffer.Parse"/> then <see cref="Tpm2bMaxNvBuffer.WriteTo"/> reproduce the
    /// original wire bytes exactly (TPM 2.0 Library Part 2, clause 10.3.9, Table 97).
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x05, 0x10, 0x20, 0x30, 0x40, 0x50];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Parse(ref reader, pool);

        Assert.AreEqual(5, buffer.Length);
        Assert.AreEqual(wire.Length, reader.Consumed);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        buffer.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxNvBuffer.MaxSize"/> (2048 octets) itself is accepted by
    /// <see cref="Tpm2bMaxNvBuffer.Create"/> (TPM 2.0 Library Part 2, Table 97).
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferAtMaxSizeIsAccepted()
    {
        byte[] payload = new byte[Tpm2bMaxNvBuffer.MaxSize];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(payload, pool);

        Assert.AreEqual(Tpm2bMaxNvBuffer.MaxSize, buffer.Length);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxNvBuffer.Create"/> refuses content one octet over <see cref="Tpm2bMaxNvBuffer.MaxSize"/>.
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferCreateOverMaxSizeThrows()
    {
        byte[] payload = new byte[Tpm2bMaxNvBuffer.MaxSize + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bMaxNvBuffer.Create(payload, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxNvBuffer.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bMaxNvBuffer.MaxSize"/> before renting or reading the payload (<c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferParseOverMaxSizeThrows()
    {
        byte[] wire = [0x08, 0x01]; //Size = 2049.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bMaxNvBuffer.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves a non-empty <see cref="Tpm2bMaxNvBuffer"/> rents from the pool and returns the rental on
    /// <see cref="Tpm2bMaxNvBuffer.Dispose"/>, balancing back to the pre-rental baseline.
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferBalancesOnPoolForNonEmptyContent()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create([0x01, 0x02, 0x03], trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        buffer.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves the <see cref="Tpm2bMaxNvBuffer.Empty"/> sentinel rents nothing from the pool, since
    /// <see cref="Tpm2bMaxNvBuffer.Create"/> short-circuits an empty span before renting.
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxNvBufferEmptyRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(ReadOnlySpan<byte>.Empty, trackingPool.Pool);

        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxBuffer.Parse"/> then <see cref="Tpm2bMaxBuffer.WriteTo"/> reproduce the
    /// original wire bytes exactly (TPM 2.0 Library Part 2, clause 10.3.8, Table 96).
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxBufferParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x04, 0x61, 0x62, 0x63, 0x64];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bMaxBuffer buffer = Tpm2bMaxBuffer.Parse(ref reader, pool);

        Assert.AreEqual(4, buffer.Length);
        Assert.AreEqual(wire.Length, reader.Consumed);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        buffer.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxBuffer.MaxSize"/> itself is accepted while one octet more is refused — Table
    /// 98 leaves <c>MAX_2B_BUFFER_SIZE</c> TPM-dependent and states only its floor ("required to be at least
    /// 1,024"), which is the value this library fixes it at.
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxBufferAcceptsItsBoundAndRefusesOneOctetMore()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bMaxBuffer buffer = Tpm2bMaxBuffer.Create(new byte[Tpm2bMaxBuffer.MaxSize], pool))
        {
            Assert.AreEqual(Tpm2bMaxBuffer.MaxSize, buffer.Length);
        }

        byte[] tooLarge = new byte[Tpm2bMaxBuffer.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bMaxBuffer.Create(tooLarge, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bMaxBuffer.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bMaxBuffer.MaxSize"/> before renting or reading the payload (<c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxBufferParseOverMaxSizeThrows()
    {
        byte[] wire = [0x04, 0x01]; //Size = 1025.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bMaxBuffer.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves a non-empty <see cref="Tpm2bMaxBuffer"/> rents from the pool and returns the rental on
    /// <see cref="Tpm2bMaxBuffer.Dispose"/>, while the <see cref="Tpm2bMaxBuffer.Empty"/> sentinel rents
    /// nothing at all.
    /// </summary>
    [TestMethod]
    public void Tpm2bMaxBufferBalancesOnPoolAndItsEmptySentinelRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bMaxBuffer buffer = Tpm2bMaxBuffer.Create([0x01, 0x02, 0x03], trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        buffer.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);

        using Tpm2bMaxBuffer empty = Tpm2bMaxBuffer.Create(ReadOnlySpan<byte>.Empty, trackingPool.Pool);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bOperand.Parse"/> then <see cref="Tpm2bOperand.WriteTo"/> reproduce the original
    /// wire bytes exactly (TPM 2.0 Library Part 2, clause 10.3.6, Table 94).
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bOperand operand = Tpm2bOperand.Parse(ref reader, pool);

        Assert.AreEqual(4, operand.Length);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        operand.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bOperand.MaxSize"/> (64 octets, this library's largest supported digest) is
    /// accepted by <see cref="Tpm2bOperand.Create"/>, matching Table 94's "size limited to the same as the
    /// digest structure".
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandAtMaxSizeIsAccepted()
    {
        byte[] payload = new byte[Tpm2bOperand.MaxSize];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bOperand operand = Tpm2bOperand.Create(payload, pool);

        Assert.AreEqual(Tpm2bOperand.MaxSize, operand.Length);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bOperand.Create"/> refuses content one octet over <see cref="Tpm2bOperand.MaxSize"/>.
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandCreateOverMaxSizeThrows()
    {
        byte[] payload = new byte[Tpm2bOperand.MaxSize + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bOperand.Create(payload, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bOperand.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bOperand.MaxSize"/> before renting or reading the payload (<c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandParseOverMaxSizeThrows()
    {
        byte[] wire = [0x00, 0x41]; //Size = 65.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bOperand.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves a non-empty <see cref="Tpm2bOperand"/> rents from the pool and returns the rental on
    /// <see cref="Tpm2bOperand.Dispose"/>, balancing back to the pre-rental baseline.
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandBalancesOnPoolForNonEmptyContent()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bOperand operand = Tpm2bOperand.Create([0x01, 0x02, 0x03, 0x04], trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        operand.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bPublicKeyRsa.Parse"/> then <see cref="Tpm2bPublicKeyRsa.WriteTo"/> reproduce the
    /// original wire bytes exactly. TPM 2.0 Library Part 2, clause 11.2.4.5, printed page 173 introduces the
    /// structure — "This Table 194 sized buffer holds the largest RSA public key supported by the TPM" — and
    /// Table 194, printed page 174 frames it as a <c>UINT16 size</c> ahead of <c>buffer[size]</c>.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x04, 0xC0, 0xFF, 0xEE, 0x01];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bPublicKeyRsa modulus = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

        Assert.AreEqual(4, modulus.Size);
        Assert.AreEqual(wire.Length, modulus.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        modulus.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> — Table 194's <c>buffer[size] {: MAX_RSA_KEY_BYTES}</c>
    /// bound (TPM 2.0 Library Part 2, printed page 174), 512 octets at the RSA-4096 this library supports — is
    /// accepted by <see cref="Tpm2bPublicKeyRsa.Create"/>, so the refusal one octet further on pins the bound
    /// and not merely a size.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaAtMaxRsaKeyBytesIsAccepted()
    {
        byte[] modulusOctets = new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bPublicKeyRsa modulus = Tpm2bPublicKeyRsa.Create(modulusOctets, pool);

        Assert.AreEqual(Tpm2bPublicKeyRsa.MaxRsaKeyBytes, modulus.Size);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bPublicKeyRsa.Create"/> refuses content one octet over
    /// <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> (Table 194, printed page 174).
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaCreateOverMaxRsaKeyBytesThrows()
    {
        byte[] modulusOctets = new byte[Tpm2bPublicKeyRsa.MaxRsaKeyBytes + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bPublicKeyRsa.Create(modulusOctets, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bPublicKeyRsa.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bPublicKeyRsa.MaxRsaKeyBytes"/> before renting or reading the payload
    /// (<c>TPM_RC_SIZE</c>), so a device answering an over-wide modulus never gets a rental out of the host.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaParseOverMaxRsaKeyBytesThrows()
    {
        byte[] wire = [0x02, 0x01]; //Size = 513.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bPublicKeyRsa.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves a non-empty <see cref="Tpm2bPublicKeyRsa"/> rents from the pool and returns the rental on
    /// <see cref="Tpm2bPublicKeyRsa.Dispose"/>, balancing back to the pre-rental baseline.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaBalancesOnPoolForNonEmptyContent()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bPublicKeyRsa modulus = Tpm2bPublicKeyRsa.Create([0x01, 0x02, 0x03, 0x04], trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        modulus.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves the zero-size form is the shared dispose-immune sentinel: Table 194's <c>size</c> row (TPM 2.0
    /// Library Part 2, printed page 174) says "The value of zero is only valid for create", so the empty form
    /// is a real wire value, and it owns no pooled storage — every caller holds the same instance, so one
    /// consumer disposing it leaves it readable and framable for all the others, and it rents nothing.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyRsaEmptyIsTheSharedDisposeImmuneSentinel()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bPublicKeyRsa fromCreate = Tpm2bPublicKeyRsa.Create(ReadOnlySpan<byte>.Empty, trackingPool.Pool);
        Assert.AreSame(Tpm2bPublicKeyRsa.Empty, fromCreate, "An empty Create yields the shared sentinel rather than a rental.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The sentinel rents nothing.");

        byte[] wire = [0x00, 0x00];
        var reader = new TpmReader(wire);
        Tpm2bPublicKeyRsa fromWire = Tpm2bPublicKeyRsa.Parse(ref reader, trackingPool.Pool);
        Assert.AreSame(Tpm2bPublicKeyRsa.Empty, fromWire, "A zero-size wire value parses back into the same shared sentinel.");

        fromCreate.Dispose();
        fromWire.Dispose();

        Assert.IsTrue(Tpm2bPublicKeyRsa.Empty.IsEmpty, "Disposing the sentinel through leaves it readable.");
        Assert.AreEqual(0, Tpm2bPublicKeyRsa.Empty.Size, "Disposing the sentinel through leaves its size readable.");
        Assert.AreEqual(sizeof(ushort), Tpm2bPublicKeyRsa.Empty.SerializedSize, "The empty form still frames its own size field.");

        byte[] reframed = new byte[sizeof(ushort)];
        var writer = new TpmWriter(reframed);
        Tpm2bPublicKeyRsa.Empty.WriteTo(ref writer);
        Assert.AreSequenceEqual(wire, reframed, "The empty form frames a zero size field and nothing else.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Nothing the sentinel did touched the pool.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bIdObject.Parse"/> then <see cref="Tpm2bIdObject.WriteTo"/> reproduce the original
    /// wire bytes exactly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.3, Table 245).
    /// </summary>
    [TestMethod]
    public void Tpm2bIdObjectParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x04, 0xC0, 0xDE, 0xC0, 0xDE];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bIdObject credential = Tpm2bIdObject.Parse(ref reader, pool);

        Assert.AreEqual(4, credential.Length);
        Assert.AreEqual(wire.Length, credential.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        credential.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bIdObject.Create"/> accepts a credential blob exactly at
    /// <see cref="Tpm2bIdObject.MaxSize"/> — two TPM2B_DIGEST values, the width Table 244's TPMS_ID_OBJECT
    /// carries — and refuses one octet more
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.2, Table 244, and clause 12.4.3, Table 245).
    /// </summary>
    [TestMethod]
    public void Tpm2bIdObjectAtMaxSizeIsAcceptedAndOneOctetMoreThrows()
    {
        byte[] atBound = new byte[Tpm2bIdObject.MaxSize];
        byte[] pastBound = new byte[Tpm2bIdObject.MaxSize + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bIdObject credential = Tpm2bIdObject.Create(atBound, pool))
        {
            Assert.AreEqual(Tpm2bIdObject.MaxSize, credential.Length);
        }

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bIdObject.Create(pastBound, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bIdObject.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bIdObject.MaxSize"/> before renting or reading the payload, so the pool stays at its
    /// baseline
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.3, Table 245; <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bIdObjectParseOverMaxSizeThrows()
    {
        byte[] wire = [0x00, (byte)(Tpm2bIdObject.MaxSize + 1)]; //Size = 133.
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bIdObject.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bIdObject.Parse"/> refuses a declared size exceeding the octets actually remaining
    /// in the reader before it rents anything, so a truncated credential blob leaves the pool balanced instead
    /// of orphaning a rental the truncated read would otherwise have thrown out of
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.4.3, Table 245).
    /// </summary>
    [TestMethod]
    public void Tpm2bIdObjectParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bIdObject.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bEncryptedSecret.Parse"/> then <see cref="Tpm2bEncryptedSecret.WriteTo"/> reproduce
    /// the original wire bytes exactly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224).
    /// </summary>
    [TestMethod]
    public void Tpm2bEncryptedSecretParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x03, 0x01, 0x02, 0x03];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bEncryptedSecret secret = Tpm2bEncryptedSecret.Parse(ref reader, pool);

        Assert.AreEqual(3, secret.Length);
        Assert.AreEqual(wire.Length, secret.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        secret.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bEncryptedSecret.Create"/> accepts a secret exactly at
    /// <see cref="Tpm2bEncryptedSecret.MaxSize"/> — the widest TPMU_ENCRYPTED_SECRET arm, <c>rsa[MAX_RSA_KEY_BYTES]</c>
    /// — and refuses one octet more
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, Table 223, and clause 11.4.3, Table 224).
    /// </summary>
    [TestMethod]
    public void Tpm2bEncryptedSecretAtMaxSizeIsAcceptedAndOneOctetMoreThrows()
    {
        byte[] atBound = new byte[Tpm2bEncryptedSecret.MaxSize];
        byte[] pastBound = new byte[Tpm2bEncryptedSecret.MaxSize + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bEncryptedSecret secret = Tpm2bEncryptedSecret.Create(atBound, pool))
        {
            Assert.AreEqual(Tpm2bEncryptedSecret.MaxSize, secret.Length);
        }

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bEncryptedSecret.Create(pastBound, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bEncryptedSecret.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bEncryptedSecret.MaxSize"/> before renting or reading the payload, so the pool stays at
    /// its baseline
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224; <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bEncryptedSecretParseOverMaxSizeThrows()
    {
        byte[] wire = [0x02, 0x01]; //Size = 513.
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bEncryptedSecret.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bEncryptedSecret.Parse"/> refuses a declared size exceeding the octets actually
    /// remaining in the reader before it rents anything, so a truncated secret leaves the pool balanced instead
    /// of orphaning a rental the truncated read would otherwise have thrown out of
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.4.3, Table 224).
    /// </summary>
    [TestMethod]
    public void Tpm2bEncryptedSecretParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bEncryptedSecret.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// Proves <see cref="PolicyNvInput"/> refuses an <c>operandB</c> the <c>TPM2B_OPERAND</c> wire type cannot
    /// carry at construction, so a caller learns the bound before a command is framed rather than from the
    /// TPM's own <c>TPM_RC_SIZE</c> after a round trip. Part 2, clause 10.3.6, Table 94 bounds
    /// <c>TPM2B_OPERAND</c> by the digest structure's <c>sizeof(TPMU_HA)</c>; the operand exactly AT the bound
    /// is accepted, so the refusal pins the bound and not merely a size.
    /// </summary>
    [TestMethod]
    public void PolicyNvInputRefusesAnOperandOverTheOperandBound()
    {
        byte[] atBound = new byte[Tpm2bOperand.MaxSize];
        byte[] pastBound = new byte[Tpm2bOperand.MaxSize + 1];

        var admitted = new PolicyNvInput(0x0100_0001, 0x0100_0001, 0x0300_0000, atBound, 0, TpmEoConstants.TPM_EO_EQ);
        Assert.IsTrue(admitted.OperandB.Span.SequenceEqual(atBound), "An operand exactly at the bound is admitted unchanged.");

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new PolicyNvInput(0x0100_0001, 0x0100_0001, 0x0300_0000, pastBound, 0, TpmEoConstants.TPM_EO_EQ));
    }

    /// <summary>
    /// Proves <see cref="PolicyCounterTimerInput"/> refuses an <c>operandB</c> past the same
    /// <c>TPM2B_OPERAND</c> bound (Part 2, clause 10.3.6, Table 94) at construction, and admits one exactly at
    /// the bound.
    /// </summary>
    [TestMethod]
    public void PolicyCounterTimerInputRefusesAnOperandOverTheOperandBound()
    {
        byte[] atBound = new byte[Tpm2bOperand.MaxSize];
        byte[] pastBound = new byte[Tpm2bOperand.MaxSize + 1];

        var admitted = new PolicyCounterTimerInput(0x0300_0000, atBound, 0, TpmEoConstants.TPM_EO_EQ);
        Assert.IsTrue(admitted.OperandB.Span.SequenceEqual(atBound), "An operand exactly at the bound is admitted unchanged.");

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new PolicyCounterTimerInput(0x0300_0000, pastBound, 0, TpmEoConstants.TPM_EO_EQ));
    }

    /// <summary>
    /// Proves the <see cref="Tpm2bOperand.Empty"/> sentinel rents nothing from the pool.
    /// </summary>
    [TestMethod]
    public void Tpm2bOperandEmptyRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        using Tpm2bOperand operand = Tpm2bOperand.Create(ReadOnlySpan<byte>.Empty, trackingPool.Pool);

        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.Parse"/> then <see cref="Tpm2bTimeout.WriteTo"/> reproduce the original
    /// wire bytes exactly for a short (non-8-octet) timeout value (TPM 2.0 Library Part 2, clause 10.3.10,
    /// Table 98).
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire = [0x00, 0x03, 0x01, 0x02, 0x03];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bTimeout timeout = Tpm2bTimeout.Parse(ref reader, pool);

        Assert.AreEqual(3, timeout.Length);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        timeout.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.Value"/> reads a short wire form as a big-endian integer zero-extended
    /// on the left, and that <see cref="Tpm2bTimeout.ExpiresOnReset"/> is <see langword="false"/> when bit 63
    /// of the widened form is clear.
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutValueZeroExtendsShortWireForm()
    {
        byte[] wire = [0x00, 0x03, 0x01, 0x02, 0x03];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bTimeout timeout = Tpm2bTimeout.Parse(ref reader, pool);

        Assert.AreEqual(0x0000000000010203UL, timeout.Value);
        Assert.IsFalse(timeout.ExpiresOnReset);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.ExpiresOnReset"/> reads bit 63 of the full 8-octet wire form, per the
    /// Reference Code note under Table 98 ("the MSb is used as a flag to indicate whether a ticket expires on
    /// TPM Reset or TPM Restart").
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutExpiresOnResetReadsTopBitOfFullWireForm()
    {
        byte[] wire = [0x00, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bTimeout timeout = Tpm2bTimeout.Parse(ref reader, pool);

        Assert.AreEqual(0x8000000000000001UL, timeout.Value);
        Assert.IsTrue(timeout.ExpiresOnReset);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.Create(ulong, bool, BaseMemoryPool)"/> sets bit 63 of the constructed
    /// 8-octet form when the accompanying ticket expires on TPM Reset or TPM Restart, and otherwise reaches the
    /// wire carrying every octet of the supplied value as given — a bit 63 the caller already packed there
    /// included, since the flag is folded in rather than rewritten (TPM 2.0 Library Part 2, Table 98's
    /// Reference Code note: "the MSb is used as a flag to indicate whether a ticket expires on TPM Reset or TPM
    /// Restart").
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutCreateFromValuePacksExpiresOnResetFlag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bTimeout expiring = Tpm2bTimeout.Create(0x1234UL, expiresOnReset: true, pool);
        Assert.AreEqual(0x8000000000001234UL, expiring.Value);
        Assert.IsTrue(expiring.ExpiresOnReset);

        using Tpm2bTimeout persisting = Tpm2bTimeout.Create(0x1234UL, expiresOnReset: false, pool);
        Assert.AreEqual(0x0000000000001234UL, persisting.Value);
        Assert.IsFalse(persisting.ExpiresOnReset);

        using Tpm2bTimeout preFlagged = Tpm2bTimeout.Create(0x8000000000001234UL, expiresOnReset: false, pool);
        Assert.AreEqual(0x8000000000001234UL, preFlagged.Value, "A value that already carries the flag in bit 63 reaches the wire unchanged.");
        Assert.IsTrue(preFlagged.ExpiresOnReset, "The caller's own bit 63 survives an unset expiresOnReset argument.");
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.MaxSize"/> (<c>sizeof(UINT64)</c> = 8 octets) is accepted by
    /// <see cref="Tpm2bTimeout.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> (TPM 2.0 Library Part 2, Table 98).
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutAtMaxSizeIsAccepted()
    {
        byte[] payload = new byte[Tpm2bTimeout.MaxSize];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bTimeout timeout = Tpm2bTimeout.Create(payload, pool);

        Assert.AreEqual(Tpm2bTimeout.MaxSize, timeout.Length);
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> refuses content one octet
    /// over <see cref="Tpm2bTimeout.MaxSize"/>.
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutCreateOverMaxSizeThrows()
    {
        byte[] payload = new byte[Tpm2bTimeout.MaxSize + 1];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentException>(() => Tpm2bTimeout.Create(payload, pool));
    }

    /// <summary>
    /// Proves <see cref="Tpm2bTimeout.Parse"/> refuses a wire size one octet over
    /// <see cref="Tpm2bTimeout.MaxSize"/> before renting or reading the payload (<c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutParseOverMaxSizeThrows()
    {
        byte[] wire = [0x00, 0x09]; //Size = 9.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = Tpm2bTimeout.Parse(ref reader, pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves a non-empty <see cref="Tpm2bTimeout"/> rents from the pool and returns the rental on
    /// <see cref="Tpm2bTimeout.Dispose"/>, balancing back to the pre-rental baseline.
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutBalancesOnPoolForNonEmptyContent()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        Tpm2bTimeout timeout = Tpm2bTimeout.Create(0x2A2AUL, expiresOnReset: false, trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        timeout.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves the <see cref="Tpm2bTimeout.Empty"/> sentinel rents nothing from the pool.
    /// </summary>
    [TestMethod]
    public void Tpm2bTimeoutEmptyRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        using Tpm2bTimeout timeout = Tpm2bTimeout.Create(ReadOnlySpan<byte>.Empty, trackingPool.Pool);

        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Proves <see cref="TpmlHandle.Parse"/> then <see cref="TpmlHandle.WriteTo"/> reproduce the original wire
    /// bytes exactly for a non-empty list (TPM 2.0 Library Part 2, clause 10.8.4, Table 125).
    /// </summary>
    [TestMethod]
    public void TpmlHandleParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x81, 0x00, 0x00, 0x01, //persistent handle.
            0x80, 0x00, 0x00, 0x02 //transient handle.
        ];
        var reader = new TpmReader(wire);
        TpmlHandle list = TpmlHandle.Parse(ref reader);

        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(0x81000001u, list[0].Value);
        Assert.AreEqual(0x80000002u, list[1].Value);
        Assert.AreEqual(wire.Length, list.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves an empty handle list round-trips as a bare zero count and yields <see cref="TpmlHandle.Empty"/>.
    /// </summary>
    [TestMethod]
    public void TpmlHandleEmptyWireRoundtrips()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00];
        var reader = new TpmReader(wire);
        TpmlHandle list = TpmlHandle.Parse(ref reader);

        Assert.IsTrue(list.IsEmpty);
        Assert.AreEqual(0, list.Count);
    }

    /// <summary>
    /// Proves <see cref="TpmlHandle.Parse"/> refuses a wire-declared count that cannot possibly fit in the
    /// remaining buffer, rather than sizing the backing array from a hostile length (Part 2, §10.8.4;
    /// <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void TpmlHandleParseRefusesCountExceedingRemainingBuffer()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0xFF]; //count = 255, zero bytes remain for elements.
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmlHandle.Parse(ref reader);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves <see cref="TpmlCc.Parse"/> then <see cref="TpmlCc.WriteTo"/> reproduce the original wire bytes
    /// exactly for a non-empty list (TPM 2.0 Library Part 2, clause 10.8.1, Table 122).
    /// </summary>
    [TestMethod]
    public void TpmlCcParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x00, 0x00, 0x01, 0x20, //TPM_CC_EvictControl.
            0x00, 0x00, 0x01, 0x21 //TPM_CC_HierarchyControl.
        ];
        var reader = new TpmReader(wire);
        TpmlCc list = TpmlCc.Parse(ref reader);

        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(TpmCcConstants.TPM_CC_EvictControl, list[0]);
        Assert.AreEqual(TpmCcConstants.TPM_CC_HierarchyControl, list[1]);
        Assert.AreEqual(wire.Length, list.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves an empty command-code list round-trips as a bare zero count and yields <see cref="TpmlCc.Empty"/>.
    /// </summary>
    [TestMethod]
    public void TpmlCcEmptyWireRoundtrips()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00];
        var reader = new TpmReader(wire);
        TpmlCc list = TpmlCc.Parse(ref reader);

        Assert.IsTrue(list.IsEmpty);
        Assert.AreEqual(0, list.Count);
    }

    /// <summary>
    /// Proves <see cref="TpmlCc.Parse"/> refuses a wire-declared count that cannot possibly fit in the
    /// remaining buffer (Part 2, §10.8.1; <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void TpmlCcParseRefusesCountExceedingRemainingBuffer()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0xFF]; //count = 255, zero bytes remain for elements.
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmlCc.Parse(ref reader);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves <see cref="TpmlCca.Parse"/> then <see cref="TpmlCca.WriteTo"/> reproduce the original wire bytes
    /// exactly for a non-empty list. TPM 2.0 Library Part 2, clause 10.8.2, Table 123, printed page 146 frames
    /// a <c>UINT32 count</c> ahead of <c>commandAttributes[count]</c>, each entry a 4-octet <c>TPMA_CC</c>.
    /// </summary>
    [TestMethod]
    public void TpmlCcaParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x00, 0x00, 0x01, 0x20, //TPMA_CC whose commandIndex is TPM_CC_EvictControl, no attribute bits set.
            0x04, 0x00, 0x01, 0x21 //TPMA_CC whose commandIndex is TPM_CC_HierarchyControl, one attribute bit set.
        ];
        var reader = new TpmReader(wire);
        TpmlCca list = TpmlCca.Parse(ref reader);

        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(0x0000_0120u, list[0].Value);
        Assert.AreEqual(0x0400_0121u, list[1].Value);
        Assert.AreEqual(wire.Length, list.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves an empty command-attribute list round-trips as a bare zero count and yields
    /// <see cref="TpmlCca.Empty"/> — a shape Table 123, printed page 146 admits explicitly ("number of values
    /// in the commandAttributes list may be 0").
    /// </summary>
    [TestMethod]
    public void TpmlCcaEmptyWireRoundtrips()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00];
        var reader = new TpmReader(wire);
        TpmlCca list = TpmlCca.Parse(ref reader);

        Assert.IsTrue(list.IsEmpty);
        Assert.AreEqual(0, list.Count);
        Assert.AreSame(TpmlCca.Empty, list, "A zero count parses back into the shared empty instance.");
        Assert.AreEqual(wire.Length, list.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten, "The empty list frames a bare zero count and nothing else.");
    }

    /// <summary>
    /// Proves <see cref="TpmlCca.Parse"/> refuses a wire-declared count that cannot possibly fit in the
    /// remaining buffer, so a malformed response never sizes a backing array from an attacker-chosen count
    /// (Part 2, clause 10.8.2, Table 123, printed page 146).
    /// </summary>
    [TestMethod]
    public void TpmlCcaParseRefusesCountExceedingRemainingBuffer()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0xFF]; //count = 255, zero bytes remain for elements.
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmlCca.Parse(ref reader);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Proves <see cref="TpmlAlg.Parse"/> then <see cref="TpmlAlg.WriteTo"/> reproduce the original wire bytes
    /// exactly for a non-empty list (TPM 2.0 Library Part 2, clause 10.8.3, Table 124).
    /// </summary>
    [TestMethod]
    public void TpmlAlgParseWriteToRoundtripsByteIdentical()
    {
        byte[] wire =
        [
            0x00, 0x00, 0x00, 0x02, //count = 2.
            0x00, 0x0B, //TPM_ALG_SHA256.
            0x00, 0x01 //TPM_ALG_RSA.
        ];
        var reader = new TpmReader(wire);
        TpmlAlg list = TpmlAlg.Parse(ref reader);

        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, list[0]);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, list[1]);
        Assert.AreEqual(wire.Length, list.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        list.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// Proves an empty algorithm list round-trips as a bare zero count and yields <see cref="TpmlAlg.Empty"/>.
    /// </summary>
    [TestMethod]
    public void TpmlAlgEmptyWireRoundtrips()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0x00];
        var reader = new TpmReader(wire);
        TpmlAlg list = TpmlAlg.Parse(ref reader);

        Assert.IsTrue(list.IsEmpty);
        Assert.AreEqual(0, list.Count);
    }

    /// <summary>
    /// Proves <see cref="TpmlAlg.Parse"/> refuses a wire-declared count that cannot possibly fit in the
    /// remaining buffer (Part 2, §10.8.3; <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void TpmlAlgParseRefusesCountExceedingRemainingBuffer()
    {
        byte[] wire = [0x00, 0x00, 0x00, 0xFF]; //count = 255, zero bytes remain for elements.
        var reader = new TpmReader(wire);

        //TpmReader is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            _ = TpmlAlg.Parse(ref reader);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// Every one of the four tickets round-trips through the wire byte-identically: what <c>WriteTo</c> frames,
    /// <c>Parse</c> reconstructs into the same tag, the same hierarchy and the same digest, and re-framing that
    /// reconstruction reproduces the original octets. The four are separate structures with separate tags —
    /// <c>TPMT_TK_CREATION</c> (Part 2, clause 10.6.3, Table 110), <c>TPMT_TK_VERIFIED</c> (clause 10.6.5,
    /// Table 113), <c>TPMT_TK_AUTH</c> (clause 10.6.6, Table 114) and <c>TPMT_TK_HASHCHECK</c> (clause 10.6.7,
    /// Table 115) — and each frames the same three fields: the tag, a <c>TPMI_RH_HIERARCHY+</c> selector, and a
    /// <c>TPM2B_DIGEST</c>.
    /// </summary>
    [TestMethod]
    public void EveryTicketRoundTripsThroughTheWireByteIdentically()
    {
        byte[] digest = new byte[32];
        digest.AsSpan().Fill(0x5A);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(TpmtTkCreation creation = MintCreationTicket(TpmiRhHierarchy.Owner, digest, pool))
        {
            AssertTicketRoundTrip(
                creation.SerializedSize,
                (ref TpmWriter w) => creation.WriteTo(ref w),
                static (ref TpmReader r, BaseMemoryPool p) =>
                {
                    using TpmtTkCreation parsed = TpmtTkCreation.Parse(ref r, p);

                    return DescribeTicket(
                        (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
                },
                (ushort)creation.Tag, TpmiRhHierarchy.Owner.Value, digest, "TPMT_TK_CREATION", pool);
        }

        using(TpmtTkVerified verified = TpmtTkVerified.FromMarshaled(TpmStConstants.TPM_ST_VERIFIED, TpmiRhHierarchy.Platform, null, CopyToRental(digest, pool), digest.Length))
        {
            AssertTicketRoundTrip(
                verified.SerializedSize,
                (ref TpmWriter w) => verified.WriteTo(ref w),
                static (ref TpmReader r, BaseMemoryPool p) =>
                {
                    using TpmtTkVerified parsed = TpmtTkVerified.Parse(ref r, p);

                    return DescribeTicket(
                        (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Hmac, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
                },
                (ushort)verified.Tag, TpmiRhHierarchy.Platform.Value, digest, "TPMT_TK_VERIFIED", pool);
        }

        using(TpmtTkAuth auth = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Endorsement, digest, pool))
        {
            AssertTicketRoundTrip(
                auth.SerializedSize,
                (ref TpmWriter w) => auth.WriteTo(ref w),
                static (ref TpmReader r, BaseMemoryPool p) =>
                {
                    using TpmtTkAuth parsed = TpmtTkAuth.Parse(ref r, p);

                    return DescribeTicket(
                        (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
                },
                (ushort)auth.Tag, TpmiRhHierarchy.Endorsement.Value, digest, "TPMT_TK_AUTH", pool);
        }

        using(TpmtTkHashcheck hashcheck = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, digest, pool))
        {
            AssertTicketRoundTrip(
                hashcheck.SerializedSize,
                (ref TpmWriter w) => hashcheck.WriteTo(ref w),
                static (ref TpmReader r, BaseMemoryPool p) =>
                {
                    using TpmtTkHashcheck parsed = TpmtTkHashcheck.Parse(ref r, p);

                    return DescribeTicket(
                        (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
                },
                (ushort)hashcheck.Tag, TpmiRhHierarchy.Owner.Value, digest, "TPMT_TK_HASHCHECK", pool);
        }

        //The NULL forms travel the same wire and must reconstruct identically: clause 10.6.2's tuple is the
        //ticket's own tag, TPM_RH_NULL and an Empty Buffer, so the round trip has to survive a zero-width digest.
        TpmtTkCreation nullCreation = TpmtTkCreation.Null;
        AssertTicketRoundTrip(
            nullCreation.SerializedSize,
            (ref TpmWriter w) => nullCreation.WriteTo(ref w),
            static (ref TpmReader r, BaseMemoryPool p) =>
            {
                TpmtTkCreation parsed = TpmtTkCreation.Parse(ref r, p);

                return DescribeTicket(
                    (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
            },
            (ushort)nullCreation.Tag, TpmiRhHierarchy.Null.Value, [], "TPMT_TK_CREATION (NULL)", pool);

        TpmtTkVerified nullVerified = TpmtTkVerified.Null;
        AssertTicketRoundTrip(
            nullVerified.SerializedSize,
            (ref TpmWriter w) => nullVerified.WriteTo(ref w),
            static (ref TpmReader r, BaseMemoryPool p) =>
            {
                TpmtTkVerified parsed = TpmtTkVerified.Parse(ref r, p);

                return DescribeTicket(
                    (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Hmac, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
            },
            (ushort)nullVerified.Tag, TpmiRhHierarchy.Null.Value, [], "TPMT_TK_VERIFIED (NULL)", pool);

        TpmtTkAuth nullAuth = TpmtTkAuth.Null;
        AssertTicketRoundTrip(
            nullAuth.SerializedSize,
            (ref TpmWriter w) => nullAuth.WriteTo(ref w),
            static (ref TpmReader r, BaseMemoryPool p) =>
            {
                TpmtTkAuth parsed = TpmtTkAuth.Parse(ref r, p);

                return DescribeTicket(
                    (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
            },
            (ushort)nullAuth.Tag, TpmiRhHierarchy.Null.Value, [], "TPMT_TK_AUTH (NULL)", pool);

        TpmtTkHashcheck nullHashcheck = TpmtTkHashcheck.Null;
        AssertTicketRoundTrip(
            nullHashcheck.SerializedSize,
            (ref TpmWriter w) => nullHashcheck.WriteTo(ref w),
            static (ref TpmReader r, BaseMemoryPool p) =>
            {
                TpmtTkHashcheck parsed = TpmtTkHashcheck.Parse(ref r, p);

                return DescribeTicket(
                    (ushort)parsed.Tag, parsed.Hierarchy.Value, parsed.Digest, parsed.SerializedSize, (ref TpmWriter w) => parsed.WriteTo(ref w), p);
            },
            (ushort)nullHashcheck.Tag, TpmiRhHierarchy.Null.Value, [], "TPMT_TK_HASHCHECK (NULL)", pool);
    }

    /// <summary>
    /// The NULL form of every ticket is the tuple clause 10.6.2 defines — the ticket's own tag, the NULL
    /// hierarchy and an Empty Buffer digest — and each is the shared dispose-immune sentinel: it owns no pooled
    /// storage, so one consumer disposing it leaves it readable and framable for every other, and framing it
    /// produces the tag, <c>TPM_RH_NULL</c>, and a zero size field.
    /// </summary>
    [TestMethod]
    public void EveryNullTicketIsTheSharedDisposeImmuneSentinel()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        AssertNullTicket(
            TpmtTkCreation.Null.IsNull, TpmtTkCreation.Null.Hierarchy, TpmtTkCreation.Null.Digest.Length, TpmtTkCreation.Null.SerializedSize,
            (ushort)TpmStConstants.TPM_ST_CREATION, TpmtTkCreation.Null.Dispose, () => TpmtTkCreation.Null.Digest.Length, trackingPool.Pool,
            (ref TpmWriter w) => TpmtTkCreation.Null.WriteTo(ref w));
        AssertNullTicket(
            TpmtTkVerified.Null.IsNull, TpmtTkVerified.Null.Hierarchy, TpmtTkVerified.Null.Hmac.Length, TpmtTkVerified.Null.SerializedSize,
            (ushort)TpmStConstants.TPM_ST_VERIFIED, TpmtTkVerified.Null.Dispose, () => TpmtTkVerified.Null.Hmac.Length, trackingPool.Pool,
            (ref TpmWriter w) => TpmtTkVerified.Null.WriteTo(ref w));
        AssertNullTicket(
            TpmtTkAuth.Null.IsNull, TpmtTkAuth.Null.Hierarchy, TpmtTkAuth.Null.Digest.Length, TpmtTkAuth.Null.SerializedSize,
            (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED, TpmtTkAuth.Null.Dispose, () => TpmtTkAuth.Null.Digest.Length, trackingPool.Pool,
            (ref TpmWriter w) => TpmtTkAuth.Null.WriteTo(ref w));
        AssertNullTicket(
            TpmtTkHashcheck.Null.IsNull, TpmtTkHashcheck.Null.Hierarchy, TpmtTkHashcheck.Null.Digest.Length, TpmtTkHashcheck.Null.SerializedSize,
            (ushort)TpmStConstants.TPM_ST_HASHCHECK, TpmtTkHashcheck.Null.Dispose, () => TpmtTkHashcheck.Null.Digest.Length, trackingPool.Pool,
            (ref TpmWriter w) => TpmtTkHashcheck.Null.WriteTo(ref w));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A NULL ticket owns no pooled storage, so framing four of them rents nothing beyond the framing buffers.");
    }

    /// <summary>
    /// A ticket whose <c>hierarchy</c> field is not one of Table 59's selectors is refused at the wire read:
    /// all four tickets type the field <c>TPMI_RH_HIERARCHY+</c> (Tables 109 through 112), and Table 59 names
    /// <c>TPM_RC_VALUE</c> as the response when unmarshaling that type fails. A transient object handle is the
    /// case that matters, because it is exactly what a caller confusing an object's handle with its hierarchy
    /// would present.
    /// </summary>
    [TestMethod]
    public void ATicketNamingANonHierarchyHandleIsRefusedAtTheWireRead()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const uint TransientHandle = 0x8000_0000;

        AssertHierarchyRefused((ushort)TpmStConstants.TPM_ST_CREATION, TransientHandle, (ref TpmReader r, BaseMemoryPool p) => TpmtTkCreation.Parse(ref r, p).Dispose(), pool);
        AssertHierarchyRefused((ushort)TpmStConstants.TPM_ST_VERIFIED, TransientHandle, (ref TpmReader r, BaseMemoryPool p) => TpmtTkVerified.Parse(ref r, p).Dispose(), pool);
        AssertHierarchyRefused((ushort)TpmStConstants.TPM_ST_AUTH_SECRET, TransientHandle, (ref TpmReader r, BaseMemoryPool p) => TpmtTkAuth.Parse(ref r, p).Dispose(), pool);
        AssertHierarchyRefused((ushort)TpmStConstants.TPM_ST_HASHCHECK, TransientHandle, (ref TpmReader r, BaseMemoryPool p) => TpmtTkHashcheck.Parse(ref r, p).Dispose(), pool);
    }

    /// <summary>
    /// A ticket whose <c>tag</c> is not the one its own structure fixes is refused at the wire read. Each of the
    /// four tables declares the tag as a fixed value and names <c>TPM_RC_TAG</c> for anything else — Table 110
    /// (<c>TPM_ST_CREATION</c>) and Table 113 (<c>TPM_ST_VERIFIED</c>) on printed page 141, Table 114
    /// (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c>) and Table 115 (<c>TPM_ST_HASHCHECK</c>) on
    /// printed page 143. Every arm here supplies a hierarchy the ticket WOULD accept, so only the tag can
    /// account for the refusal — and each arm offers a tag another ticket type uses legally, which is exactly
    /// the confusion the rule forecloses.
    /// </summary>
    [TestMethod]
    public void ATicketCarryingAnotherTicketsTagIsRefusedAtTheWireRead()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const uint OwnerHierarchy = (uint)TpmRh.TPM_RH_OWNER;

        AssertTagRefused((ushort)TpmStConstants.TPM_ST_VERIFIED, OwnerHierarchy, (ref TpmReader r, BaseMemoryPool p) => TpmtTkCreation.Parse(ref r, p).Dispose(), pool);
        AssertTagRefused((ushort)TpmStConstants.TPM_ST_CREATION, OwnerHierarchy, (ref TpmReader r, BaseMemoryPool p) => TpmtTkVerified.Parse(ref r, p).Dispose(), pool);
        AssertTagRefused((ushort)TpmStConstants.TPM_ST_HASHCHECK, OwnerHierarchy, (ref TpmReader r, BaseMemoryPool p) => TpmtTkAuth.Parse(ref r, p).Dispose(), pool);
        AssertTagRefused((ushort)TpmStConstants.TPM_ST_AUTH_SIGNED, OwnerHierarchy, (ref TpmReader r, BaseMemoryPool p) => TpmtTkHashcheck.Parse(ref r, p).Dispose(), pool);
    }

    /// <summary>
    /// <c>TPM2_GetCapability(TPM_CAP_COMMANDS)</c> returns a <c>TPML_CCA</c> of <c>TPMA_CC</c> attribute words,
    /// not the bare <c>TPM_CC</c> command codes <c>TPM_CAP_PP_COMMANDS</c> and <c>TPM_CAP_AUDIT_COMMANDS</c>
    /// return: "This Table 123 list is only used in TPM2_GetCapability(capability == TPM_CAP_COMMANDS)" (Part 2,
    /// clause 10.8.2), and Table 138 selects <c>TPML_CCA</c> for <c>command</c> against <c>TPML_CC</c> for
    /// <c>ppCommands</c> and <c>auditCommands</c>. The three arms are therefore three distinct members, and a
    /// parsed capability data populates exactly the one its selector names.
    /// </summary>
    [TestMethod]
    public void CapabilityDataSeparatesCommandAttributesFromCommandCodes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //A TPMA_CC whose commandIndex is TPM_CC_Startup with one command handle and the NV attribute set: the
        //attribute bits are what distinguishes this arm from a bare command-code list.
        var attribute = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Startup, cHandles: 1);

        using(TpmsCapabilityData commands = ParseCapability(TpmCapConstants.TPM_CAP_COMMANDS, attribute.Value, pool))
        {
            Assert.IsNotNull(commands.CommandAttributes, "TPM_CAP_COMMANDS populates the TPML_CCA member.");
            Assert.IsNull(commands.PhysicalPresenceCommands, "TPM_CAP_COMMANDS is not the ppCommands member.");
            Assert.IsNull(commands.AuditCommands, "TPM_CAP_COMMANDS is not the auditCommands member.");
            Assert.HasCount(1, commands.CommandAttributes!.CommandAttributes, "The list carries exactly the one attribute word framed.");
            Assert.AreEqual((ushort)TpmCcConstants.TPM_CC_Startup, commands.CommandAttributes[0].COMMAND_INDEX, "The low 16 bits of a TPMA_CC are its commandIndex.");
            Assert.AreEqual((byte)1, commands.CommandAttributes[0].C_HANDLES, "The attribute bits ride alongside the index, which is what makes this a TPML_CCA rather than a TPML_CC.");
        }

        using(TpmsCapabilityData ppCommands = ParseCapability(TpmCapConstants.TPM_CAP_PP_COMMANDS, (uint)TpmCcConstants.TPM_CC_Clear, pool))
        {
            Assert.IsNotNull(ppCommands.PhysicalPresenceCommands, "TPM_CAP_PP_COMMANDS populates its own TPML_CC member.");
            Assert.IsNull(ppCommands.CommandAttributes, "A command-code list is not the TPML_CCA member.");
            Assert.AreEqual(TpmCcConstants.TPM_CC_Clear, ppCommands.PhysicalPresenceCommands![0], "The list carries bare command codes.");
        }

        using(TpmsCapabilityData auditCommands = ParseCapability(TpmCapConstants.TPM_CAP_AUDIT_COMMANDS, (uint)TpmCcConstants.TPM_CC_Clear, pool))
        {
            Assert.IsNotNull(auditCommands.AuditCommands, "TPM_CAP_AUDIT_COMMANDS populates its own TPML_CC member.");
            Assert.IsNull(auditCommands.PhysicalPresenceCommands, "auditCommands and ppCommands are distinct union members (Table 138).");
        }

        using(TpmsCapabilityData handles = ParseCapability(TpmCapConstants.TPM_CAP_HANDLES, 0x8000_0000u, pool))
        {
            Assert.IsNotNull(handles.Handles, "TPM_CAP_HANDLES populates the TPML_HANDLE member.");
            Assert.AreEqual(0x8000_0000u, handles.Handles![0].Value, "The handle list carries the handles framed.");
        }
    }

    /// <summary>
    /// Frames a ticket, parses the octets back through the ticket's own <c>Parse</c>, re-frames the
    /// reconstruction, and asserts the second framing reproduces the first octet for octet — and that the
    /// reconstructed tag, hierarchy and digest are the ones that went in.
    /// </summary>
    /// <param name="serializedSize">The structure's own serialized size.</param>
    /// <param name="write">The structure's <c>WriteTo</c>.</param>
    /// <param name="roundTrip">Parses the framed octets through the ticket's own <c>Parse</c> and re-frames the result.</param>
    /// <param name="expectedTag">The tag the ticket was built with.</param>
    /// <param name="expectedHierarchy">The hierarchy handle value the ticket was built with.</param>
    /// <param name="expectedDigest">The digest octets the ticket was built with.</param>
    /// <param name="ticketName">The ticket's own name, quoted in the failure message.</param>
    /// <param name="pool">The memory pool.</param>
    private static void AssertTicketRoundTrip(
        int serializedSize, TicketWriter write, TicketRoundTripper roundTrip,
        ushort expectedTag, uint expectedHierarchy, ReadOnlySpan<byte> expectedDigest, string ticketName, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> framed = pool.Rent(serializedSize);
        var writer = new TpmWriter(framed.Memory.Span[..serializedSize]);
        write(ref writer);
        Assert.AreEqual(serializedSize, writer.Written, $"{ticketName} must write exactly the octets its SerializedSize declares.");

        byte[] original = framed.Memory.Span[..serializedSize].ToArray();

        var reader = new TpmReader(original);
        TicketFacts reconstructed = roundTrip(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, $"{ticketName}.Parse must consume exactly the octets WriteTo framed.");
        Assert.AreEqual(expectedTag, reconstructed.Tag, $"{ticketName} must reconstruct the tag it was framed with.");
        Assert.AreEqual(expectedHierarchy, reconstructed.Hierarchy, $"{ticketName} must reconstruct the hierarchy it was framed with.");
        Assert.AreSequenceEqual(
            expectedDigest.ToArray(), reconstructed.Digest, $"{ticketName} must reconstruct the digest it was framed with.");
        Assert.AreSequenceEqual(
            original, reconstructed.Reframed, $"{ticketName} must re-frame its reconstruction into the very octets it was parsed from.");
    }

    /// <summary>
    /// Reads a parsed ticket's three fields and frames it again, so one helper can compare any of the four
    /// against the octets they came from.
    /// </summary>
    /// <param name="tag">The parsed tag.</param>
    /// <param name="hierarchy">The parsed hierarchy handle value.</param>
    /// <param name="digest">The parsed digest octets.</param>
    /// <param name="serializedSize">The parsed ticket's own serialized size.</param>
    /// <param name="write">The parsed ticket's <c>WriteTo</c>.</param>
    /// <param name="pool">The memory pool the re-framing buffer comes from.</param>
    /// <returns>The reconstructed ticket's fields and its re-framed octets.</returns>
    private static TicketFacts DescribeTicket(
        ushort tag, uint hierarchy, ReadOnlySpan<byte> digest, int serializedSize, TicketWriter write, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> reframed = pool.Rent(serializedSize);
        var writer = new TpmWriter(reframed.Memory.Span[..serializedSize]);
        write(ref writer);

        return new TicketFacts(tag, hierarchy, digest.ToArray(), reframed.Memory.Span[..serializedSize].ToArray());
    }

    /// <summary>
    /// A reconstructed ticket's three fields plus the octets re-framing it produced.
    /// </summary>
    /// <param name="Tag">The reconstructed structure tag.</param>
    /// <param name="Hierarchy">The reconstructed hierarchy handle value.</param>
    /// <param name="Digest">The reconstructed digest octets.</param>
    /// <param name="Reframed">The octets the reconstruction frames back onto the wire.</param>
    private sealed record TicketFacts(ushort Tag, uint Hierarchy, byte[] Digest, byte[] Reframed);

    /// <summary>The shape of a ticket's <c>WriteTo</c>, so one helper can frame any of the four.</summary>
    /// <param name="writer">The writer.</param>
    private delegate void TicketWriter(ref TpmWriter writer);

    /// <summary>The shape of a ticket's <c>Parse</c>, so one helper can drive any of the four.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool.</param>
    private delegate void TicketParser(ref TpmReader reader, BaseMemoryPool pool);

    /// <summary>Parses a ticket off the wire and re-frames it, so one helper can round-trip any of the four.</summary>
    /// <param name="reader">The reader positioned at the framed ticket.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reconstructed ticket's fields and its re-framed octets.</returns>
    private delegate TicketFacts TicketRoundTripper(ref TpmReader reader, BaseMemoryPool pool);

    /// <summary>Asserts one NULL ticket is the clause 10.6.2 tuple and survives being disposed through.</summary>
    /// <param name="isNull">The ticket's own NULL predicate.</param>
    /// <param name="hierarchy">The ticket's hierarchy field.</param>
    /// <param name="digestLength">The ticket's digest width.</param>
    /// <param name="serializedSize">The ticket's serialized size.</param>
    /// <param name="expectedTag">The tag the ticket's NULL form carries.</param>
    /// <param name="dispose">The ticket's own <c>Dispose</c>.</param>
    /// <param name="digestLengthAfterDisposal">Reads the digest width again once the sentinel has been disposed through.</param>
    /// <param name="pool">The memory pool the framing buffer comes from.</param>
    /// <param name="write">The ticket's <c>WriteTo</c>.</param>
    private static void AssertNullTicket(
        bool isNull, TpmiRhHierarchy hierarchy, int digestLength, int serializedSize, ushort expectedTag,
        Action dispose, Func<int> digestLengthAfterDisposal, BaseMemoryPool pool, TicketWriter write)
    {
        Assert.IsTrue(isNull, "The NULL form is the NULL hierarchy with an Empty Buffer digest.");
        Assert.IsTrue(hierarchy.IsNull, "A NULL ticket names TPM_RH_NULL.");
        Assert.AreEqual(0, digestLength, "A NULL ticket carries an Empty Buffer digest.");
        Assert.AreEqual(sizeof(ushort) + sizeof(uint) + sizeof(ushort), serializedSize, "The NULL tuple frames as tag, hierarchy, and an empty TPM2B_DIGEST.");

        using IMemoryOwner<byte> framed = pool.Rent(serializedSize);
        var writer = new TpmWriter(framed.Memory.Span[..serializedSize]);
        write(ref writer);

        byte[] expected = [(byte)(expectedTag >> 8), (byte)expectedTag, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00];
        Assert.AreSequenceEqual(expected, framed.Memory.Span[..serializedSize].ToArray(), "A NULL ticket frames its tag, TPM_RH_NULL, and a zero size field.");

        dispose();
        Assert.AreEqual(0, digestLengthAfterDisposal(), "The shared sentinel stays readable after any one consumer disposes it.");
    }

    /// <summary>Hand-frames a ticket naming a non-hierarchy handle and asserts the parse refuses it.</summary>
    /// <param name="tag">The ticket's structure tag.</param>
    /// <param name="hierarchy">The out-of-set handle to frame.</param>
    /// <param name="parse">The ticket's <c>Parse</c>.</param>
    /// <param name="pool">The memory pool.</param>
    private static void AssertHierarchyRefused(ushort tag, uint hierarchy, TicketParser parse, BaseMemoryPool pool)
    {
        byte[] framed = new byte[sizeof(ushort) + sizeof(uint) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(framed, tag);
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(sizeof(ushort)), hierarchy);
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(sizeof(ushort) + sizeof(uint)), 0);

        try
        {
            var reader = new TpmReader(framed);
            parse(ref reader, pool);
            Assert.Fail($"A ticket tagged 0x{tag:X4} naming handle 0x{hierarchy:X8} must be refused.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>Frames a ticket carrying a tag its own structure does not fix and asserts the parse refuses it.</summary>
    /// <param name="tag">The tag to frame, legal for some other ticket type but not for the one parsing.</param>
    /// <param name="hierarchy">A hierarchy the parsing ticket accepts, so only the tag can refuse the frame.</param>
    /// <param name="parse">The ticket's own <c>Parse</c>.</param>
    /// <param name="pool">The memory pool.</param>
    private static void AssertTagRefused(ushort tag, uint hierarchy, TicketParser parse, BaseMemoryPool pool)
    {
        byte[] framed = new byte[sizeof(ushort) + sizeof(uint) + sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(framed, tag);
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(sizeof(ushort)), hierarchy);
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(sizeof(ushort) + sizeof(uint)), 0);

        try
        {
            var reader = new TpmReader(framed);
            parse(ref reader, pool);
            Assert.Fail($"A ticket carrying tag 0x{tag:X4} must be refused by a structure that fixes a different tag.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>Frames a one-element capability list of the given arm and parses it back.</summary>
    /// <param name="capability">The capability selector.</param>
    /// <param name="element">The single 4-octet element the list carries.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed capability data; the caller disposes it.</returns>
    private static TpmsCapabilityData ParseCapability(TpmCapConstants capability, uint element, BaseMemoryPool pool)
    {
        byte[] framed = new byte[sizeof(uint) * 3];
        BinaryPrimitives.WriteUInt32BigEndian(framed, (uint)capability);
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(sizeof(uint)), 1);
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(sizeof(uint) * 2), element);

        var reader = new TpmReader(framed);

        return TpmsCapabilityData.Parse(ref reader, pool);
    }

    /// <summary>Copies octets into a pooled rental a ticket adopter can take ownership of.</summary>
    /// <param name="octets">The octets to copy.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rental holding the octets.</returns>
    private static IMemoryOwner<byte> CopyToRental(byte[] octets, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> rental = pool.Rent(octets.Length);
        octets.CopyTo(rental.Memory.Span);

        return rental;
    }

    /// <summary>Frames and parses a creation ticket, which has no direct construction factory of its own.</summary>
    /// <param name="hierarchy">The hierarchy the ticket names.</param>
    /// <param name="digest">The ticket's HMAC octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The minted ticket; the caller disposes it.</returns>
    private static TpmtTkCreation MintCreationTicket(TpmiRhHierarchy hierarchy, byte[] digest, BaseMemoryPool pool) =>
        TpmtTkCreation.FromMarshaled(hierarchy, CopyToRental(digest, pool), digest.Length);
}
