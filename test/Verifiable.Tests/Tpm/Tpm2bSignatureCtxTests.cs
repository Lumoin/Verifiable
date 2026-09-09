using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proving tests for <see cref="Tpm2bSignatureCtx"/> (TPM2B_SIGNATURE_CTX): the bound-before-truncation parse
/// ordering, empty and max-size round trips, and the <see cref="Tpm2bSignatureCtx.Create"/> factory.
/// </summary>
[TestClass]
internal sealed class Tpm2bSignatureCtxTests
{
    /// <summary>
    /// A declared size of 256 — one octet past <see cref="Tpm2bSignatureCtx.MaxSize"/> — is refused as malformed
    /// before any rental, even though the buffer supplies far fewer trailing octets than the declaration itself
    /// claims: the <see cref="Tpm2bSignatureCtx.MaxSize"/> bound is checked before the octets-remaining check, so
    /// the failure is the size-bound one, not a truncation one
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.8, Table 221; <c>TPM_RC_SIZE</c>).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxParseOverMaxSizeThrowsBeforeRentingEvenWhenTheBufferIsShorterThanDeclared()
    {
        //Declares 256 octets (Tpm2bSignatureCtx.MaxSize + 1) but supplies none of them.
        byte[] wire = [0x01, 0x00];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bSignatureCtx.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// A declared size within <see cref="Tpm2bSignatureCtx.MaxSize"/> but exceeding the octets actually
    /// remaining in the reader is its own, distinct failure from the size-bound one: refused before any rental,
    /// so a truncated context leaves the pool balanced
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.8, Table 221).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize = 255) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bSignatureCtx.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// A zero-length context — the conformant value for ECDSA, RSASSA, and RSAPSS (Table 220's <c>empty[0]</c>
    /// arm) — parses to the shared <see cref="Tpm2bSignatureCtx.Empty"/> instance and re-frames as the same
    /// two-octet zero size field
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7, Table 220; clause 11.3.8, Table 221).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxParsesAndWritesAnEmptyContext()
    {
        byte[] wire = [0x00, 0x00];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        Tpm2bSignatureCtx context = Tpm2bSignatureCtx.Parse(ref reader, pool);

        Assert.AreSame(Tpm2bSignatureCtx.Empty, context, "A zero-length context parses to the shared dispose-immune Empty instance.");
        Assert.IsTrue(context.IsEmpty);
        Assert.AreEqual(0, context.Size);
        Assert.AreEqual(wire.Length, context.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        context.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// A context exactly at <see cref="Tpm2bSignatureCtx.MaxSize"/> — the ML-DSA <c>buffer[255]</c> arm's own
    /// width — is admitted and round-trips byte-identically
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7, Table 220).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxParseWriteToRoundTripsAtMaxSizeByteIdentically()
    {
        byte[] payload = new byte[Tpm2bSignatureCtx.MaxSize];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        byte[] wire = new byte[sizeof(ushort) + payload.Length];
        wire[0] = (byte)(Tpm2bSignatureCtx.MaxSize >> 8);
        wire[1] = (byte)(Tpm2bSignatureCtx.MaxSize & 0xFF);
        payload.CopyTo(wire, sizeof(ushort));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bSignatureCtx context = Tpm2bSignatureCtx.Parse(ref reader, pool);

        Assert.AreEqual(Tpm2bSignatureCtx.MaxSize, context.Size);
        Assert.AreSequenceEqual(payload, context.Context.ToArray());
        Assert.AreEqual(wire.Length, context.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        context.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureCtx.Create"/> copies the source octets into pooled storage rather than aliasing
    /// the caller's buffer, mirroring every other TPM2B factory's copy semantics.
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxCreateFromSpanCopiesTheSourceBytes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] original = [0xDE, 0xAD, 0xBE, 0xEF];

        using Tpm2bSignatureCtx context = Tpm2bSignatureCtx.Create(original, pool);

        Assert.AreEqual(4, context.Size);
        Assert.AreSequenceEqual(original, context.Context.ToArray());

        original[0] = 0x00;
        Assert.AreEqual(0xDE, context.Context[0], "Create must copy the source bytes; mutating the caller's buffer afterward must not be observed.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureCtx.Create"/> admits a context exactly at <see cref="Tpm2bSignatureCtx.MaxSize"/>
    /// and refuses one octet past it — the same union bound the wire form enforces
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7, Table 220).
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxCreateAdmitsTheUnionBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bSignatureCtx atBound = Tpm2bSignatureCtx.Create(new byte[Tpm2bSignatureCtx.MaxSize], pool))
        {
            Assert.AreEqual(Tpm2bSignatureCtx.MaxSize, atBound.Size);
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bSignatureCtx.Create(new byte[Tpm2bSignatureCtx.MaxSize + 1], pool),
            "A context wider than sizeof(TPMU_SIGNATURE_CTX) is not a TPM2B_SIGNATURE_CTX and must be refused.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureCtx.Create"/> given an empty span returns the shared
    /// <see cref="Tpm2bSignatureCtx.Empty"/> instance rather than renting a zero-length buffer.
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureCtxCreateFromAnEmptySpanReturnsTheSharedEmptyInstance()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bSignatureCtx context = Tpm2bSignatureCtx.Create(ReadOnlySpan<byte>.Empty, pool);

        Assert.AreSame(Tpm2bSignatureCtx.Empty, context);
    }
}
