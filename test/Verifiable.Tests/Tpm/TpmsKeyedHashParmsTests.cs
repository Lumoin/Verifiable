using System.Buffers;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <see cref="TpmsKeyedHashParms"/>'s three scheme arms — HMAC, XOR, and the null
/// (sealed data) scheme — against TPM 2.0 Library Part 2's keyed-hash scheme tables.
/// </summary>
[TestClass]
internal sealed class TpmsKeyedHashParmsTests
{
    /// <summary>
    /// Table 176 (TPMS_SCHEME_HMAC): <c>scheme</c> (TPM_ALG_HMAC, 0x0005) then <c>hashAlg</c> (TPM_ALG_SHA256,
    /// 0x000B) — <c>0005 000B</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.20, Table 176</see>.
    /// </summary>
    [TestMethod]
    public void HmacSchemeFramesTheSchemeThenHashAlgByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmsKeyedHashParms parms = TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.IsTrue(parms.IsHmac);
        Assert.IsFalse(parms.IsXor);
        Assert.IsFalse(parms.IsNull);

        byte[] expected = [0x00, 0x05, 0x00, 0x0B];
        Assert.AreEqual(expected.Length, parms.SerializedSize);

        using IMemoryOwner<byte> owner = pool.Rent(expected.Length);
        Span<byte> actual = owner.Memory.Span[..expected.Length];
        var writer = new TpmWriter(actual);
        parms.WriteTo(ref writer);
        Assert.IsTrue(actual.SequenceEqual(expected), "TPMS_SCHEME_HMAC must frame scheme then hashAlg byte-exactly.");

        var reader = new TpmReader(expected);
        TpmsKeyedHashParms parsed = TpmsKeyedHashParms.Parse(ref reader);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, parsed.Scheme);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.HashAlg);
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole frame.");
    }

    /// <summary>
    /// Table 177 (TPMS_SCHEME_XOR): <c>scheme</c> (TPM_ALG_XOR, 0x000A), <c>hashAlg</c> (TPM_ALG_SHA384,
    /// 0x000C), then <c>kdf</c> (TPM_ALG_KDF1_SP800_108, 0x0022) — the XOR arm carries a key-derivation
    /// function the HMAC and null arms do not.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177</see>.
    /// </summary>
    [TestMethod]
    public void XorSchemeFramesTheSchemeHashAlgThenKdfByteExactlyAndRoundTrips()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmsKeyedHashParms parms = TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_SHA384, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108);

        Assert.IsTrue(parms.IsXor);
        Assert.IsFalse(parms.IsHmac);
        Assert.IsFalse(parms.IsNull);

        byte[] expected = [0x00, 0x0A, 0x00, 0x0C, 0x00, 0x22];
        Assert.AreEqual(expected.Length, parms.SerializedSize);

        using IMemoryOwner<byte> owner = pool.Rent(expected.Length);
        Span<byte> actual = owner.Memory.Span[..expected.Length];
        var writer = new TpmWriter(actual);
        parms.WriteTo(ref writer);
        Assert.IsTrue(actual.SequenceEqual(expected), "TPMS_SCHEME_XOR must frame scheme, hashAlg then kdf byte-exactly.");

        var reader = new TpmReader(expected);
        TpmsKeyedHashParms parsed = TpmsKeyedHashParms.Parse(ref reader);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_XOR, parsed.Scheme);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, parsed.HashAlg);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108, parsed.Kdf);
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole frame.");
    }

    /// <summary>
    /// The null scheme (sealed data, no HMAC or XOR key): <c>scheme</c> alone (TPM_ALG_NULL, 0x0010), with no
    /// <c>hashAlg</c> or <c>kdf</c> octets — Table 179's <c>[scheme]details</c> is absent entirely for
    /// <c>TPM_ALG_NULL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.23, Table 179</see>.
    /// </summary>
    [TestMethod]
    public void NullSchemeFramesTheSchemeAloneByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmsKeyedHashParms parms = TpmsKeyedHashParms.SealedData;

        Assert.IsTrue(parms.IsNull);
        Assert.IsFalse(parms.IsHmac);
        Assert.IsFalse(parms.IsXor);

        byte[] expected = [0x00, 0x10];
        Assert.AreEqual(expected.Length, parms.SerializedSize);

        using IMemoryOwner<byte> owner = pool.Rent(expected.Length);
        Span<byte> actual = owner.Memory.Span[..expected.Length];
        var writer = new TpmWriter(actual);
        parms.WriteTo(ref writer);
        Assert.IsTrue(actual.SequenceEqual(expected), "The null scheme must frame the selector alone.");

        var reader = new TpmReader(expected);
        TpmsKeyedHashParms parsed = TpmsKeyedHashParms.Parse(ref reader);
        Assert.IsTrue(parsed.IsNull);
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole frame.");
    }

    /// <summary>
    /// <see cref="TpmsKeyedHashParms.Parse"/> refuses a <c>scheme</c> selector that is none of TPM_ALG_HMAC,
    /// TPM_ALG_XOR, or TPM_ALG_NULL — an unrecognized value leaves the union unsizable, so parsing must stop
    /// (Table 175's <c>#TPM_RC_VALUE</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.19, Table 175</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAnUnrecognizedSchemeSelector()
    {
        byte[] wire = [0x12, 0x34]; //scheme: not TPM_ALG_HMAC, TPM_ALG_XOR, or TPM_ALG_NULL.

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseWire(wire));
    }

    /// <summary>
    /// <see cref="TpmsKeyedHashParms.Parse"/> refuses an HMAC scheme whose <c>hashAlg</c> is not a TCG-defined
    /// hash algorithm at all — parsed through <see cref="TpmiAlgHash.Parse"/> rather than a raw selector read,
    /// so garbage in that slot is refused rather than retained.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.31, Table 77</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAnHmacSchemeWithAnUnrecognizedHashAlg()
    {
        byte[] wire = [0x00, 0x05, 0x12, 0x34]; //scheme: TPM_ALG_HMAC; hashAlg: not a TCG-defined hash algorithm.

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseWire(wire));
    }

    /// <summary>
    /// <see cref="TpmsKeyedHashParms.Parse"/> refuses an XOR scheme whose <c>kdf</c> is none of the key-derivation
    /// functions <c>TPMI_ALG_KDF</c> admits — the slot is <c>TPMI_ALG_KDF+</c>, so TPM_ALG_NULL passes but any
    /// other non-member is refused rather than retained and re-emitted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177; clause 9.36, Table 82</see>.
    /// </summary>
    [TestMethod]
    public void ParseRefusesAnXorSchemeWithAnUnrecognizedKdf()
    {
        byte[] wire = [0x00, 0x0A, 0x00, 0x0B, 0x12, 0x34]; //scheme: TPM_ALG_XOR; hashAlg: TPM_ALG_SHA256; kdf: not a TPMI_ALG_KDF member.

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseWire(wire));
    }

    /// <summary>Parses a wire image through <see cref="TpmsKeyedHashParms.Parse"/>, holding the by-ref reader outside any lambda.</summary>
    /// <param name="wire">The wire octets.</param>
    /// <returns>The parsed structure.</returns>
    private static TpmsKeyedHashParms ParseWire(byte[] wire)
    {
        var reader = new TpmReader(wire);

        return TpmsKeyedHashParms.Parse(ref reader);
    }

    /// <summary>
    /// <see cref="TpmsKeyedHashParms.Parse"/> structurally admits <c>TPM_ALG_NULL</c> as the XOR scheme's
    /// <c>hashAlg</c> — Table 177's note that a NULL hash algorithm here now answers <c>TPM_RC_HASH</c>
    /// describes a semantic refusal by the object's validating command, not a bound this structural parse
    /// enforces itself.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177</see>.
    /// </summary>
    [TestMethod]
    public void ParseStructurallyAdmitsAnXorSchemeWithHashAlgTpmAlgNull()
    {
        byte[] wire = [0x00, 0x0A, 0x00, 0x10, 0x00, 0x22]; //scheme: TPM_ALG_XOR; hashAlg: TPM_ALG_NULL; kdf: TPM_ALG_KDF1_SP800_108.
        var reader = new TpmReader(wire);

        TpmsKeyedHashParms parsed = TpmsKeyedHashParms.Parse(ref reader);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_XOR, parsed.Scheme);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, parsed.HashAlg);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108, parsed.Kdf);
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole frame.");
    }
}
