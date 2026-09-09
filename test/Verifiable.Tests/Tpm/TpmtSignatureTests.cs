using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// First proving tests for <see cref="TpmtSignature"/> and its <see cref="TpmuSignature"/> member — round-trip
/// fidelity for both signing families, and the leak-safety <see cref="Tpm2bEccParameter.Parse"/> and
/// <see cref="TpmuSignature.Parse"/> owe a truncated frame, mirroring <see cref="TpmSpecBufferAndListTests"/>'s
/// pool-balance idiom.
/// </summary>
[TestClass]
internal sealed class TpmtSignatureTests
{
    /// <summary>
    /// Proves <see cref="Tpm2bEccParameter.Parse"/> refuses a declared size exceeding the octets actually
    /// remaining in the reader before it rents anything, so a truncated ECC coordinate leaves the pool balanced
    /// rather than orphaning a rental
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.2.5.1, Table 197 — a <c>TPM2B_ECC_PARAMETER</c> bounded
    /// to 66 octets by the largest supported curve, P-521).
    /// </summary>
    [TestMethod]
    public void Tpm2bEccParameterParseTruncatedPayloadLeavesPoolBalanced()
    {
        //Declares 10 octets (within MaxSize = 66) but only 2 follow the size prefix.
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = Tpm2bEccParameter.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated frame never orphans a rental.");
    }

    /// <summary>
    /// Proves <see cref="TpmuSignature.Parse"/>'s ECDSA path disposes <c>signatureR</c> when the subsequent
    /// <c>signatureS</c> parse fails on a truncated frame, so the pool returns to baseline rather than
    /// orphaning the already-successful first rental
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.2, Table 214 — <c>TPMS_SIGNATURE_ECC</c>'s
    /// <c>signatureR</c> then <c>signatureS</c> field order).
    /// </summary>
    [TestMethod]
    public void TpmuSignatureParseEcdsaDisposesSignatureRWhenSignatureSIsTruncated()
    {
        byte[] wire =
        [
            0x00, 0x0B, //hash = TPM_ALG_SHA256.
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, //signatureR: size 4, present in full.
            0x00, 0x0A, 0x01, 0x02 //signatureS: declares size 10, but only 2 octets remain.
        ];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmuSignature.Parse(TpmAlgIdConstants.TPM_ALG_ECDSA, ref reader, trackingPool.Pool);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "signatureR's rental is released when signatureS fails, so nothing is left outstanding.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Parse"/> then <see cref="TpmtSignature.WriteTo"/> reproduce the original
    /// wire bytes exactly for an ECDSA signature
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.6, Table 219 for the <c>sigAlg</c>-then-member
    /// framing, and clause 11.3.2, Table 214 for <c>TPMS_SIGNATURE_ECC</c>'s <c>hash</c>, <c>signatureR</c>,
    /// <c>signatureS</c> field order).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureParseWriteToRoundtripsByteIdenticalForEcdsa()
    {
        byte[] wire =
        [
            0x00, 0x18, //sigAlg = TPM_ALG_ECDSA.
            0x00, 0x0B, //hash = TPM_ALG_SHA256.
            0x00, 0x02, 0xAA, 0xBB, //signatureR: size 2.
            0x00, 0x03, 0x01, 0x02, 0x03 //signatureS: size 3.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtSignature signature = TpmtSignature.Parse(ref reader, pool);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SigAlg);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.Signature.HashAlgorithm);
        Assert.IsTrue(signature.Signature.SignatureR!.AsReadOnlySpan().SequenceEqual(new byte[] { 0xAA, 0xBB }), "signatureR must parse to the wire's octets.");
        Assert.IsTrue(signature.Signature.SignatureS!.AsReadOnlySpan().SequenceEqual(new byte[] { 0x01, 0x02, 0x03 }), "signatureS must parse to the wire's octets.");
        Assert.AreEqual(wire.Length, signature.GetSerializedSize());

        using IMemoryOwner<byte> rewrittenOwner = pool.Rent(wire.Length);
        Span<byte> rewritten = rewrittenOwner.Memory.Span[..wire.Length];
        var writer = new TpmWriter(rewritten);
        signature.WriteTo(ref writer);

        Assert.IsTrue(wire.AsSpan().SequenceEqual(rewritten), "WriteTo must reproduce the original wire bytes exactly.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Parse"/> then <see cref="TpmtSignature.WriteTo"/> reproduce the original
    /// wire bytes exactly for an RSA signature
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.6, Table 219 for the <c>sigAlg</c>-then-member
    /// framing, and clause 11.3.1, Table 212 for <c>TPMS_SIGNATURE_RSA</c>'s <c>hash</c> then <c>sig</c> field
    /// order).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureParseWriteToRoundtripsByteIdenticalForRsa()
    {
        byte[] wire =
        [
            0x00, 0x14, //sigAlg = TPM_ALG_RSASSA.
            0x00, 0x0B, //hash = TPM_ALG_SHA256.
            0x00, 0x04, 0xC0, 0xFF, 0xEE, 0x01 //sig: size 4.
        ];
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var reader = new TpmReader(wire);
        using TpmtSignature signature = TpmtSignature.Parse(ref reader, pool);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SigAlg);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.Signature.HashAlgorithm);
        Assert.IsTrue(signature.Signature.RsaSignature.Buffer.SequenceEqual(new byte[] { 0xC0, 0xFF, 0xEE, 0x01 }), "sig must parse to the wire's octets.");
        Assert.AreEqual(wire.Length, signature.GetSerializedSize());

        using IMemoryOwner<byte> rewrittenOwner = pool.Rent(wire.Length);
        Span<byte> rewritten = rewrittenOwner.Memory.Span[..wire.Length];
        var writer = new TpmWriter(rewritten);
        signature.WriteTo(ref writer);

        Assert.IsTrue(wire.AsSpan().SequenceEqual(rewritten), "WriteTo must reproduce the original wire bytes exactly.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Parse"/> then <see cref="TpmtSignature.WriteTo"/> reproduce the original
    /// wire bytes exactly for an HMAC signature over SHA-256, whose member is a self-contained TPMT_HA (the
    /// digest carries no size field of its own — its length follows from <c>hashAlg</c>) and whose
    /// <see cref="TpmtSignature.HmacDigest"/> exposes the same octets
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.5, Table 218 (TPMU_SIGNATURE's <c>hmac</c> arm) and
    /// clause 10.2.2, Table 89 (TPMT_HA)).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureParseWriteToRoundtripsByteIdenticalForHmacSha256()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> digestOwner = pool.Rent(32);
        Span<byte> digest = digestOwner.Memory.Span[..32];
        for(int i = 0; i < digest.Length; i++)
        {
            digest[i] = (byte)(0x40 + i);
        }

        byte[] wire =
        [
            0x00, 0x05, //sigAlg = TPM_ALG_HMAC.
            0x00, 0x0B, //hashAlg = TPM_ALG_SHA256.
            .. digest //digest: unsized, exactly SHA-256's 32 octets.
        ];
        var reader = new TpmReader(wire);
        using TpmtSignature signature = TpmtSignature.Parse(ref reader, pool);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, signature.SigAlg);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.Signature.HashAlgorithm);
        Assert.IsTrue(signature.HmacDigest!.Value.Span.SequenceEqual(digest), "The parsed HMAC digest must equal the fixture's octets.");
        Assert.AreEqual(wire.Length, signature.GetSerializedSize());

        using IMemoryOwner<byte> rewrittenOwner = pool.Rent(wire.Length);
        Span<byte> rewritten = rewrittenOwner.Memory.Span[..wire.Length];
        var writer = new TpmWriter(rewritten);
        signature.WriteTo(ref writer);

        Assert.IsTrue(wire.AsSpan().SequenceEqual(rewritten), "WriteTo must reproduce the original wire bytes exactly.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Hmac"/> builds the same wire bytes as a hand-computed SHA-384 frame —
    /// SHA-384's 48-octet digest is longer than SHA-256's, confirming the member's length tracks
    /// <c>hashAlg</c>'s digest size rather than a fixed width
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.5, Table 218 (TPMU_SIGNATURE's <c>hmac</c> arm)).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureHmacFactoryFramesASha384DigestByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> digestOwner = pool.Rent(48);
        Span<byte> digest = digestOwner.Memory.Span[..48];
        for(int i = 0; i < digest.Length; i++)
        {
            digest[i] = (byte)(0x80 + i);
        }

        byte[] expectedWire =
        [
            0x00, 0x05, //sigAlg = TPM_ALG_HMAC.
            0x00, 0x0C, //hashAlg = TPM_ALG_SHA384.
            .. digest //digest: unsized, exactly SHA-384's 48 octets.
        ];
        using TpmtSignature signature = TpmtSignature.Hmac(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384), digest, pool);

        Assert.AreEqual(expectedWire.Length, signature.GetSerializedSize());
        Assert.IsTrue(signature.HmacDigest!.Value.Span.SequenceEqual(digest), "The factory must retain the supplied digest exactly.");

        using IMemoryOwner<byte> rewrittenOwner = pool.Rent(expectedWire.Length);
        Span<byte> rewritten = rewrittenOwner.Memory.Span[..expectedWire.Length];
        var writer = new TpmWriter(rewritten);
        signature.WriteTo(ref writer);

        Assert.IsTrue(expectedWire.AsSpan().SequenceEqual(rewritten), "WriteTo must frame the SHA-384 digest byte-exactly.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Parse"/> refuses an HMAC member whose digest is shorter than
    /// <c>hashAlg</c>'s digest size before any rental — the digest carries no size field of its own, so
    /// <see cref="TpmtHa.Parse"/> checks the octets remaining against the digest size <c>hashAlg</c> implies
    /// before it rents, leaving the pool balanced rather than orphaning a rental
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.2.2, Table 89 (TPMT_HA)).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureParseRefusesAnHmacMemberWithATruncatedDigest()
    {
        byte[] wire =
        [
            0x00, 0x05, //sigAlg = TPM_ALG_HMAC.
            0x00, 0x0B, //hashAlg = TPM_ALG_SHA256 (32-octet digest).
            0x01, 0x02, 0x03 //only 3 octets follow, not 32.
        ];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(wire);

        try
        {
            _ = TpmtSignature.Parse(ref reader, trackingPool.Pool);
            Assert.Fail("Expected ArgumentOutOfRangeException.");
        }
        catch(ArgumentOutOfRangeException)
        {
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The remaining-octet check runs before the rental it would otherwise size, so a truncated HMAC digest never orphans a rental.");
    }

    /// <summary>
    /// Proves <see cref="TpmtSignature.Hmac"/> refuses <c>TPM_ALG_NULL</c> as the HMAC hash algorithm — a value
    /// <see cref="TpmtSignature.Parse"/> could never produce for an HMAC member, since <see cref="TpmuSignature"/>
    /// parses the member's hash through <see cref="TpmtHa.Parse"/> with NULL not admitted
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.5, Table 218 (TPMU_SIGNATURE's <c>hmac</c> arm)).
    /// </summary>
    [TestMethod]
    public void TpmtSignatureHmacFactoryRefusesTpmAlgNullAsTheHashAlgorithm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentException>(() => TpmtSignature.Hmac(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), [], pool));
    }
}
