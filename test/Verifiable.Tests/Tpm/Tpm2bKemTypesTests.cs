using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proving tests for <see cref="Tpm2bSharedSecret"/> (TPM2B_SHARED_SECRET) and <see cref="Tpm2bKemCiphertext"/>
/// (TPM2B_KEM_CIPHERTEXT): the bound-before-truncation parse ordering, round trips, the <c>Create</c> factory,
/// and the shared <c>Empty</c> singleton — mirroring <see cref="Tpm2bSignatureCtxTests"/>'s coverage shape for
/// the sibling sized-buffer types
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 2: Structures, clauses 10.3.12 and 10.3.14).
/// </summary>
[TestClass]
internal sealed class Tpm2bKemTypesTests
{
    /// <summary>
    /// A declared size of 65 — one octet past <see cref="Tpm2bSharedSecret.MaxSize"/> — is refused before any
    /// rental: Table 100's <c>MAX_SHARED_SECRET_SIZE</c> bound (64 here, the widest DHKEM Nsecret) is checked before the
    /// octets-remaining check, so the failure is the size-bound one (<c>TPM_RC_SIZE</c> semantics), never a
    /// truncation one, even when the buffer supplies none of the declared octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretParseOverMaxSizeThrowsBeforeRentingEvenWhenTheBufferIsShorterThanDeclared()
    {
        //Declares 65 octets (MaxSize + 1) but supplies none of them.
        byte[] wire = [0x00, 0x41];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bSharedSecret.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// A declared size within <see cref="Tpm2bSharedSecret.MaxSize"/> but exceeding the octets actually
    /// remaining in the reader is its own, distinct failure from the size-bound one: refused before any
    /// rental, so a truncated shared secret leaves the pool balanced
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize = 64) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bSharedSecret.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// A shared secret exactly at <see cref="Tpm2bSharedSecret.MaxSize"/> — the DHKEM(P-521, HKDF-SHA512)
    /// width, the widest this bound covers — is admitted and round-trips byte-identically
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretParseWriteToRoundTripsAtMaxSizeByteIdentically()
    {
        byte[] payload = new byte[Tpm2bSharedSecret.MaxSize];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        byte[] wire = new byte[sizeof(ushort) + payload.Length];
        wire[0] = (byte)(Tpm2bSharedSecret.MaxSize >> 8);
        wire[1] = (byte)(Tpm2bSharedSecret.MaxSize & 0xFF);
        payload.CopyTo(wire, sizeof(ushort));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bSharedSecret secret = Tpm2bSharedSecret.Parse(ref reader, pool);

        Assert.AreEqual(Tpm2bSharedSecret.MaxSize, secret.Size);
        Assert.AreSequenceEqual(payload, secret.AsReadOnlySpan().ToArray());
        Assert.AreEqual(wire.Length, secret.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        secret.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// <see cref="Tpm2bSharedSecret.Create"/> copies the source octets into pooled storage rather than
    /// aliasing the caller's buffer, mirroring every other TPM2B factory's copy semantics
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretCreateFromSpanCopiesTheSourceBytes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] original = [0xDE, 0xAD, 0xBE, 0xEF];

        using Tpm2bSharedSecret secret = Tpm2bSharedSecret.Create(original, pool);

        Assert.AreEqual(4, secret.Size);
        Assert.AreSequenceEqual(original, secret.AsReadOnlySpan().ToArray());

        original[0] = 0x00;
        Assert.AreEqual(0xDE, secret.AsReadOnlySpan()[0], "Create must copy the source bytes; mutating the caller's buffer afterward must not be observed.");
    }

    /// <summary>
    /// <see cref="Tpm2bSharedSecret.Create"/> admits a secret exactly at <see cref="Tpm2bSharedSecret.MaxSize"/>
    /// and refuses one octet past it — the same bound the wire form enforces
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretCreateAdmitsTheBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bSharedSecret atBound = Tpm2bSharedSecret.Create(new byte[Tpm2bSharedSecret.MaxSize], pool))
        {
            Assert.AreEqual(Tpm2bSharedSecret.MaxSize, atBound.Size);
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bSharedSecret.Create(new byte[Tpm2bSharedSecret.MaxSize + 1], pool),
            "A shared secret wider than MAX_SHARED_SECRET_SIZE (64) must be refused.");
    }

    /// <summary>
    /// <see cref="Tpm2bSharedSecret.Empty"/> is a shared, size-zero singleton; a zero-length wire declaration
    /// and <see cref="Tpm2bSharedSecret.Create"/> given an empty span both yield the SAME instance rather than
    /// renting a zero-length buffer
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.12, Table 100).
    /// </summary>
    [TestMethod]
    public void Tpm2bSharedSecretEmptyIsASharedZeroLengthSingleton()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bSharedSecret empty = Tpm2bSharedSecret.Empty;
        Assert.IsTrue(empty.IsEmpty);
        Assert.AreEqual(0, empty.Size);

        byte[] wire = [0x00, 0x00];
        var reader = new TpmReader(wire);
        using Tpm2bSharedSecret parsed = Tpm2bSharedSecret.Parse(ref reader, pool);

        Assert.AreSame(empty, parsed);

        using Tpm2bSharedSecret createdEmpty = Tpm2bSharedSecret.Create(ReadOnlySpan<byte>.Empty, pool);
        Assert.AreSame(empty, createdEmpty);
    }

    /// <summary>
    /// A declared size of 1569 — one octet past <see cref="Tpm2bKemCiphertext.MaxSize"/> — is refused before
    /// any rental: Table 102's <c>sizeof(TPMU_KEM_CIPHERTEXT)</c> bound (1568 here, the
    /// ML-KEM-1024 ciphertext width) is checked before the octets-remaining check
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextParseOverMaxSizeThrowsBeforeRentingEvenWhenTheBufferIsShorterThanDeclared()
    {
        //Declares 1569 octets (MaxSize + 1) but supplies none of them.
        byte[] wire = [0x06, 0x21];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bKemCiphertext.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The MaxSize bound is checked before any rental, so an over-max declared size never rents at all.");
    }

    /// <summary>
    /// A declared size within <see cref="Tpm2bKemCiphertext.MaxSize"/> but exceeding the octets actually
    /// remaining in the reader is refused before any rental, so a truncated ciphertext leaves the pool
    /// balanced
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize = 1568) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bKemCiphertext.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// A ciphertext exactly at <see cref="Tpm2bKemCiphertext.MaxSize"/> — Table 205's <c>TPM_MLKEM_1024</c>
    /// width — is admitted and round-trips byte-identically, comfortably covering the narrower 65-octet ECC
    /// SEC 1 point arm the simulator produces
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.2.6.1, Table 205; clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextParseWriteToRoundTripsAtMaxSizeByteIdentically()
    {
        byte[] payload = new byte[Tpm2bKemCiphertext.MaxSize];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        byte[] wire = new byte[sizeof(ushort) + payload.Length];
        wire[0] = (byte)(Tpm2bKemCiphertext.MaxSize >> 8);
        wire[1] = (byte)(Tpm2bKemCiphertext.MaxSize & 0xFF);
        payload.CopyTo(wire, sizeof(ushort));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using Tpm2bKemCiphertext ciphertext = Tpm2bKemCiphertext.Parse(ref reader, pool);

        Assert.AreEqual(Tpm2bKemCiphertext.MaxSize, ciphertext.Size);
        Assert.AreSequenceEqual(payload, ciphertext.Ciphertext.ToArray());
        Assert.AreEqual(wire.Length, ciphertext.SerializedSize);

        byte[] rewritten = new byte[wire.Length];
        var writer = new TpmWriter(rewritten);
        ciphertext.WriteTo(ref writer);

        Assert.AreSequenceEqual(wire, rewritten);
    }

    /// <summary>
    /// <see cref="Tpm2bKemCiphertext.Create"/> copies the source octets into pooled storage rather than
    /// aliasing the caller's buffer, mirroring every other TPM2B factory's copy semantics
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextCreateFromSpanCopiesTheSourceBytes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] original = [0xDE, 0xAD, 0xBE, 0xEF];

        using Tpm2bKemCiphertext ciphertext = Tpm2bKemCiphertext.Create(original, pool);

        Assert.AreEqual(4, ciphertext.Size);
        Assert.AreSequenceEqual(original, ciphertext.Ciphertext.ToArray());

        original[0] = 0x00;
        Assert.AreEqual(0xDE, ciphertext.Ciphertext[0], "Create must copy the source bytes; mutating the caller's buffer afterward must not be observed.");
    }

    /// <summary>
    /// <see cref="Tpm2bKemCiphertext.Create"/> admits a ciphertext exactly at
    /// <see cref="Tpm2bKemCiphertext.MaxSize"/> and refuses one octet past it — the same bound the wire form
    /// enforces
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextCreateAdmitsTheBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bKemCiphertext atBound = Tpm2bKemCiphertext.Create(new byte[Tpm2bKemCiphertext.MaxSize], pool))
        {
            Assert.AreEqual(Tpm2bKemCiphertext.MaxSize, atBound.Size);
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bKemCiphertext.Create(new byte[Tpm2bKemCiphertext.MaxSize + 1], pool),
            "A ciphertext wider than sizeof(TPMU_KEM_CIPHERTEXT) (1568) must be refused.");
    }

    /// <summary>
    /// <see cref="Tpm2bKemCiphertext.Empty"/> is a shared, size-zero, dispose-immune singleton; a zero-length
    /// wire declaration and <see cref="Tpm2bKemCiphertext.Create"/> given an empty span both yield the SAME
    /// instance, and disposing it (repeatedly, from any holder) never marks it disposed for the others
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public void Tpm2bKemCiphertextEmptyIsASharedDisposeImmuneSingleton()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Tpm2bKemCiphertext empty = Tpm2bKemCiphertext.Empty;

        Assert.IsTrue(empty.IsEmpty);
        Assert.AreEqual(0, empty.Size);

        byte[] wire = [0x00, 0x00];
        var reader = new TpmReader(wire);
        Tpm2bKemCiphertext parsed = Tpm2bKemCiphertext.Parse(ref reader, pool);
        Assert.AreSame(empty, parsed);

        Tpm2bKemCiphertext createdEmpty = Tpm2bKemCiphertext.Create(ReadOnlySpan<byte>.Empty, pool);
        Assert.AreSame(empty, createdEmpty);

        //Every holder's Dispose() is a no-op for the shared Empty instance, so disposing all three (plus one
        //repeated call) must leave it readable rather than throwing ObjectDisposedException.
        empty.Dispose();
        parsed.Dispose();
        createdEmpty.Dispose();
        empty.Dispose();
        Assert.IsTrue(empty.IsEmpty, "Disposing the shared Empty instance (even repeatedly, from every holder) must leave it readable.");
    }
}
