using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Round-trip and refusal proofs for the algorithm-selector interface types
/// (<see cref="TpmiAlgHash"/>, <see cref="TpmiAlgSigScheme"/>, <see cref="TpmiAlgRsaScheme"/>,
/// <see cref="TpmiAlgEccScheme"/>, <see cref="TpmiAlgPublic"/>, <see cref="TpmiEccCurve"/>,
/// <see cref="TpmiRsaKeyBits"/>, <see cref="TpmiAlgSym"/>, <see cref="TpmiAlgKdf"/>) and the two structures
/// that depend on them (<see cref="TpmtHa"/>, <see cref="TpmtSigScheme"/> over <see cref="TpmuSigScheme"/>).
/// </summary>
/// <remarks>
/// Every throwing <c>Parse</c> call is wrapped through one of the private <c>ParseXxx</c> helpers below rather
/// than closing over a local <see cref="TpmReader"/> directly inside the <c>Assert.ThrowsExactly</c> lambda: a
/// <c>ref struct</c> local cannot be captured by a lambda expression, so the helper builds the reader from the
/// ordinary <c>byte[]</c> the lambda captures instead (the same shape <c>TpmInterfaceSessionAndEntityHandleTests</c>
/// uses).
/// </remarks>
[TestClass]
internal sealed class TpmInterfaceAlgorithmTypeTests
{
    /// <summary>
    /// Encodes an algorithm selector as the 2-octet big-endian wire form <see cref="TpmWriter.WriteUInt16"/>
    /// produces.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The 2-octet big-endian encoding.</returns>
    private static byte[] EncodeAlg(TpmAlgIdConstants value) => EncodeUInt16((ushort)value);

    /// <summary>
    /// Encodes a raw 16-bit value as the 2-octet big-endian wire form <see cref="TpmWriter.WriteUInt16"/>
    /// produces.
    /// </summary>
    /// <param name="value">The raw 16-bit value.</param>
    /// <returns>The 2-octet big-endian encoding.</returns>
    private static byte[] EncodeUInt16(ushort value)
    {
        byte[] buffer = new byte[sizeof(ushort)];
        var writer = new TpmWriter(buffer);
        writer.WriteUInt16(value);

        return buffer;
    }

    /// <summary>Parses a hash algorithm selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgHash ParseAlgHash(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgHash.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses a signature scheme selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgSigScheme ParseAlgSigScheme(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgSigScheme.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses an RSA scheme selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgRsaScheme ParseAlgRsaScheme(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgRsaScheme.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses an ECC scheme selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgEccScheme ParseAlgEccScheme(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgEccScheme.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses a public object type selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgPublic ParseAlgPublic(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgPublic.Parse(ref reader);
    }

    /// <summary>Parses a curve selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNoneAdmitted">Whether the <c>+TPM_ECC_NONE</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiEccCurve ParseEccCurve(byte[] wireBytes, bool isNoneAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiEccCurve.Parse(ref reader, isNoneAdmitted);
    }

    /// <summary>Parses an RSA key size selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiRsaKeyBits ParseRsaKeyBits(byte[] wireBytes)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiRsaKeyBits.Parse(ref reader);
    }

    /// <summary>Parses a symmetric algorithm selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgSym ParseAlgSym(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgSym.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses a KDF selector from 2 wire octets.</summary>
    /// <param name="wireBytes">The 2-octet big-endian encoding.</param>
    /// <param name="isNullAdmitted">Whether the <c>+TPM_ALG_NULL</c> form is admitted.</param>
    /// <returns>The parsed selector.</returns>
    private static TpmiAlgKdf ParseAlgKdf(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmiAlgKdf.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>Parses a hash-agile digest from wire octets under the given pool.</summary>
    /// <param name="wireBytes">The wire encoding.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isNullAdmitted">Whether the algorithm selector may be <c>TPM_ALG_NULL</c>.</param>
    /// <returns>The parsed structure.</returns>
    private static TpmtHa ParseHa(byte[] wireBytes, BaseMemoryPool pool, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmtHa.Parse(ref reader, pool, isNullAdmitted);
    }

    /// <summary>Parses an algorithm-agile signing scheme from wire octets.</summary>
    /// <param name="wireBytes">The wire encoding.</param>
    /// <param name="isNullAdmitted">Whether the scheme selector may be <c>TPM_ALG_NULL</c>.</param>
    /// <returns>The parsed structure.</returns>
    private static TpmtSigScheme ParseSigScheme(byte[] wireBytes, bool isNullAdmitted = false)
    {
        var reader = new TpmReader(wireBytes);

        return TpmtSigScheme.Parse(ref reader, isNullAdmitted);
    }

    /// <summary>
    /// <see cref="TpmiAlgHash.Parse"/> admits a TCG-defined hash algorithm and <see cref="TpmiAlgHash.WriteTo"/>
    /// reproduces the exact wire bytes it was parsed from; <see cref="TpmiAlgHash.DigestSize"/> reports the
    /// algorithm's digest size (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.31, Table 77).
    /// </summary>
    [TestMethod]
    public void TpmiAlgHashParsesHashAlgorithmAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmiAlgHash hash = ParseAlgHash(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, hash.Value);
        Assert.AreEqual(32, hash.DigestSize);
        Assert.IsTrue(TpmiAlgHash.IsAlgHash(hash.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        hash.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A non-hash algorithm is refused by <see cref="TpmiAlgHash.Parse"/> with <c>TPM_RC_HASH</c>, and
    /// <see cref="TpmiAlgHash.IsAlgHash"/> reports it as not admitted (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.31,
    /// Table 77).
    /// </summary>
    [TestMethod]
    public void TpmiAlgHashRefusesNonHashAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_RSA);

        Assert.IsFalse(TpmiAlgHash.IsAlgHash(TpmAlgIdConstants.TPM_ALG_RSA));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgHash(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgHash.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.31, Table 77's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgHashBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.IsFalse(TpmiAlgHash.IsAlgHash(TpmAlgIdConstants.TPM_ALG_NULL));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgHash(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgHash.Parse"/> admits <c>TPM_ALG_NULL</c>, and
    /// <see cref="TpmiAlgHash.DigestSize"/> reports <see langword="null"/> for it (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.31, Table 77's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgHashPlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgHash hash = ParseAlgHash(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(hash.IsNull);
        Assert.IsNull(hash.DigestSize);
    }

    /// <summary>
    /// <see cref="TpmiAlgHash.FromValue"/> is the unvalidated escape hatch for a value already known good — it
    /// admits a non-hash algorithm without throwing (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.31).
    /// </summary>
    [TestMethod]
    public void TpmiAlgHashFromValueDoesNotValidate()
    {
        TpmiAlgHash hash = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_RSA);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, hash.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.Parse"/> admits an asymmetric signing scheme and
    /// <see cref="TpmiAlgSigScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeParsesSchemeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_ECDSA);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, scheme.Value);
        Assert.IsTrue(TpmiAlgSigScheme.IsSigScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A symmetric algorithm is refused by <see cref="TpmiAlgSigScheme.Parse"/> with <c>TPM_RC_SCHEME</c>, and
    /// <see cref="TpmiAlgSigScheme.IsSigScheme"/> reports it as not admitted (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section
    /// 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeRefusesNonSigningAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_AES);

        Assert.IsFalse(TpmiAlgSigScheme.IsSigScheme(TpmAlgIdConstants.TPM_ALG_AES));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgSigScheme(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgSigScheme.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgSigScheme(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgSigScheme.Parse"/> admits <c>TPM_ALG_NULL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.37, Table 83's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemePlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(scheme.IsNull);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.FromValue"/> is the unvalidated escape hatch for a value already known good
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.37).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeFromValueDoesNotValidate()
    {
        TpmiAlgSigScheme scheme = TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_AES);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, scheme.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.Parse"/> admits <c>TPM_ALG_EDDSA</c> — Type "A X" in Part 2, Table 8, one
    /// of the <c>!ALG.ax</c> asymmetric signing schemes Table 83 admits — and
    /// <see cref="TpmiAlgSigScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeParsesEddsaAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_EDDSA);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_EDDSA, scheme.Value);
        Assert.IsTrue(TpmiAlgSigScheme.IsSigScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.Parse"/> admits <c>TPM_ALG_EDDSA_PH</c> — Type "A X" in Part 2, Table 8,
    /// one of the <c>!ALG.ax</c> asymmetric signing schemes Table 83 admits — and
    /// <see cref="TpmiAlgSigScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeParsesEddsaPhAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_EDDSA_PH);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_EDDSA_PH, scheme.Value);
        Assert.IsTrue(TpmiAlgSigScheme.IsSigScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.Parse"/> admits <c>TPM_ALG_LMS</c> — Type "A X C" in Part 2, Table 8 (the
    /// "C" marking it stateful/counter-based), one of the <c>!ALG.ax</c> asymmetric signing schemes Table 83
    /// admits — and <see cref="TpmiAlgSigScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeParsesLmsAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_LMS);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_LMS, scheme.Value);
        Assert.IsTrue(TpmiAlgSigScheme.IsSigScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgSigScheme.Parse"/> admits <c>TPM_ALG_XMSS</c> — Type "A X C" in Part 2, Table 8 (the
    /// "C" marking it stateful/counter-based), one of the <c>!ALG.ax</c> asymmetric signing schemes Table 83
    /// admits — and <see cref="TpmiAlgSigScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.37, Table 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSigSchemeParsesXmssAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_XMSS);

        TpmiAlgSigScheme scheme = ParseAlgSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_XMSS, scheme.Value);
        Assert.IsTrue(TpmiAlgSigScheme.IsSigScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgRsaScheme.Parse"/> admits an RSA encrypting or signing scheme and
    /// <see cref="TpmiAlgRsaScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.4.1, Table 189).
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaSchemeParsesSchemeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_RSASSA);

        TpmiAlgRsaScheme scheme = ParseAlgRsaScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, scheme.Value);
        Assert.IsTrue(TpmiAlgRsaScheme.IsRsaScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// An ECC signing algorithm is refused by <see cref="TpmiAlgRsaScheme.Parse"/> with <c>TPM_RC_VALUE</c>,
    /// and <see cref="TpmiAlgRsaScheme.IsRsaScheme"/> reports it as not admitted (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.4.1, Table 189).
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaSchemeRefusesEccSigningAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_ECDSA);

        Assert.IsFalse(TpmiAlgRsaScheme.IsRsaScheme(TpmAlgIdConstants.TPM_ALG_ECDSA));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgRsaScheme(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgRsaScheme.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.4.1, Table 189's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaSchemeBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgRsaScheme(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgRsaScheme.Parse"/> admits <c>TPM_ALG_NULL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.4.1, Table 189's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaSchemePlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgRsaScheme scheme = ParseAlgRsaScheme(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(scheme.IsNull);
    }

    /// <summary>
    /// <see cref="TpmiAlgRsaScheme.FromValue"/> is the unvalidated escape hatch for a value already known good
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.4.1).
    /// </summary>
    [TestMethod]
    public void TpmiAlgRsaSchemeFromValueDoesNotValidate()
    {
        TpmiAlgRsaScheme scheme = TpmiAlgRsaScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDSA);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, scheme.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgEccScheme.Parse"/> admits an ECC signing or key-exchange scheme and
    /// <see cref="TpmiAlgEccScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.4, Table 200).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeParsesSchemeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_ECDSA);

        TpmiAlgEccScheme scheme = ParseAlgEccScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, scheme.Value);
        Assert.IsTrue(TpmiAlgEccScheme.IsEccScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// An RSA signing algorithm is refused by <see cref="TpmiAlgEccScheme.Parse"/> with <c>TPM_RC_SCHEME</c>,
    /// and <see cref="TpmiAlgEccScheme.IsEccScheme"/> reports it as not admitted (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.4, Table 200).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeRefusesRsaSigningAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_RSASSA);

        Assert.IsFalse(TpmiAlgEccScheme.IsEccScheme(TpmAlgIdConstants.TPM_ALG_RSASSA));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgEccScheme(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgEccScheme.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.4, Table 200's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgEccScheme(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgEccScheme.Parse"/> admits <c>TPM_ALG_NULL</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.5.4, Table 200's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemePlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgEccScheme scheme = ParseAlgEccScheme(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(scheme.IsNull);
    }

    /// <summary>
    /// <see cref="TpmiAlgEccScheme.FromValue"/> is the unvalidated escape hatch for a value already known good
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.5.4).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeFromValueDoesNotValidate()
    {
        TpmiAlgEccScheme scheme = TpmiAlgEccScheme.FromValue(TpmAlgIdConstants.TPM_ALG_RSASSA);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, scheme.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgEccScheme.Parse"/> admits <c>TPM_ALG_EDDSA</c> — Dep "ECC" in Part 2, Table 8, one
    /// of the <c>!ALG.ax</c> signing schemes Table 200's "(ECC)" restriction keeps — and
    /// <see cref="TpmiAlgEccScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.4, Table 200).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeParsesEddsaAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_EDDSA);

        TpmiAlgEccScheme scheme = ParseAlgEccScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_EDDSA, scheme.Value);
        Assert.IsTrue(TpmiAlgEccScheme.IsEccScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgEccScheme.Parse"/> admits <c>TPM_ALG_EDDSA_PH</c> — Dep "ECC" in Part 2, Table 8, one
    /// of the <c>!ALG.ax</c> signing schemes Table 200's "(ECC)" restriction keeps — and
    /// <see cref="TpmiAlgEccScheme.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.4, Table 200).
    /// </summary>
    [TestMethod]
    public void TpmiAlgEccSchemeParsesEddsaPhAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_EDDSA_PH);

        TpmiAlgEccScheme scheme = ParseAlgEccScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_EDDSA_PH, scheme.Value);
        Assert.IsTrue(TpmiAlgEccScheme.IsEccScheme(scheme.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        scheme.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgPublic.Parse"/> admits a public-area object type and
    /// <see cref="TpmiAlgPublic.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 12.2.2, Table 225).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicParsesObjectTypeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_RSA);

        TpmiAlgPublic type = ParseAlgPublic(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, type.Value);
        Assert.IsTrue(TpmiAlgPublic.IsPublic(type.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        type.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <c>TPM_ALG_MLDSA</c> is an object type of the registry-extended <c>!ALG.o</c> class Table 225 names, so
    /// <see cref="TpmiAlgPublic.Parse"/> admits it and <see cref="TpmiAlgPublic.WriteTo"/> reproduces the exact
    /// wire bytes it was parsed from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 12.2.2, Table 225).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicParsesMlDsaObjectTypeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_MLDSA);

        TpmiAlgPublic type = ParseAlgPublic(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_MLDSA, type.Value);
        Assert.IsTrue(TpmiAlgPublic.IsPublic(type.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        type.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <c>TPM_ALG_HASH_MLDSA</c> is an object type of the registry-extended <c>!ALG.o</c> class Table 225 names,
    /// so <see cref="TpmiAlgPublic.Parse"/> admits it and <see cref="TpmiAlgPublic.WriteTo"/> reproduces the
    /// exact wire bytes it was parsed from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 12.2.2, Table 225).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicParsesHashMlDsaObjectTypeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA);

        TpmiAlgPublic type = ParseAlgPublic(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA, type.Value);
        Assert.IsTrue(TpmiAlgPublic.IsPublic(type.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        type.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <c>TPM_ALG_MLKEM</c> is an object type of the registry-extended <c>!ALG.o</c> class Table 225 names, so
    /// <see cref="TpmiAlgPublic.Parse"/> admits it and <see cref="TpmiAlgPublic.WriteTo"/> reproduces the exact
    /// wire bytes it was parsed from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 12.2.2, Table 225).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicParsesMlKemObjectTypeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_MLKEM);

        TpmiAlgPublic type = ParseAlgPublic(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_MLKEM, type.Value);
        Assert.IsTrue(TpmiAlgPublic.IsPublic(type.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        type.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A hash algorithm is refused by <see cref="TpmiAlgPublic.Parse"/> with <c>TPM_RC_TYPE</c>, and
    /// <see cref="TpmiAlgPublic.IsPublic"/> reports it as not admitted (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 12.2.2,
    /// Table 225).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicRefusesNonObjectAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.IsFalse(TpmiAlgPublic.IsPublic(TpmAlgIdConstants.TPM_ALG_SHA256));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgPublic(wireBytes));
    }

    /// <summary>
    /// Table 225 carries no leading <c>+</c>, so <see cref="TpmiAlgPublic.Parse"/> refuses <c>TPM_ALG_NULL</c>
    /// unconditionally — there is no NULL-admitting overload (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 12.2.2, Table
    /// 211).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicRefusesNullSinceTableHasNoPlusForm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.IsFalse(TpmiAlgPublic.IsPublic(TpmAlgIdConstants.TPM_ALG_NULL));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgPublic(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiAlgPublic.FromValue"/> is the unvalidated escape hatch for a value already known good
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 12.2.2).
    /// </summary>
    [TestMethod]
    public void TpmiAlgPublicFromValueDoesNotValidate()
    {
        TpmiAlgPublic type = TpmiAlgPublic.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, type.Value);
    }

    /// <summary>
    /// <see cref="TpmiEccCurve.Parse"/> admits an implemented curve and <see cref="TpmiEccCurve.WriteTo"/>
    /// reproduces the exact wire bytes it was parsed from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.5.5, Table
    /// 200).
    /// </summary>
    [TestMethod]
    public void TpmiEccCurveParsesCurveAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeUInt16((ushort)TpmEccCurveConstants.TPM_ECC_NIST_P256);

        TpmiEccCurve curve = ParseEccCurve(wireBytes);

        Assert.AreEqual(TpmEccCurveConstants.TPM_ECC_NIST_P256, curve.Value);
        Assert.IsTrue(TpmiEccCurve.IsEccCurve(curve.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        curve.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A curve code the TCG registry has not assigned is refused by <see cref="TpmiEccCurve.Parse"/> with
    /// <c>TPM_RC_CURVE</c>, and <see cref="TpmiEccCurve.IsEccCurve"/> reports it as not admitted (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.5, Table 201).
    /// </summary>
    [TestMethod]
    public void TpmiEccCurveRefusesUndefinedCurveCode()
    {
        const ushort undefinedCurve = 0x00FF;
        byte[] wireBytes = EncodeUInt16(undefinedCurve);

        Assert.IsFalse(TpmiEccCurve.IsEccCurve((TpmEccCurveConstants)undefinedCurve));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseEccCurve(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiEccCurve.Parse"/> refuses <c>TPM_ECC_NONE</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.5, Table 201's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiEccCurveBareFormRefusesNone()
    {
        byte[] wireBytes = EncodeUInt16((ushort)TpmEccCurveConstants.TPM_ECC_NONE);

        Assert.IsFalse(TpmiEccCurve.IsEccCurve(TpmEccCurveConstants.TPM_ECC_NONE));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseEccCurve(wireBytes));
    }

    /// <summary>
    /// The <c>isNoneAdmitted: true</c> form of <see cref="TpmiEccCurve.Parse"/> admits <c>TPM_ECC_NONE</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.5, Table 201's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiEccCurvePlusFormAdmitsNone()
    {
        byte[] wireBytes = EncodeUInt16((ushort)TpmEccCurveConstants.TPM_ECC_NONE);

        TpmiEccCurve curve = ParseEccCurve(wireBytes, isNoneAdmitted: true);

        Assert.IsTrue(curve.IsNone);
    }

    /// <summary>
    /// <see cref="TpmiEccCurve.FromValue"/> is the unvalidated escape hatch for a value already known good (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.5.5).
    /// </summary>
    [TestMethod]
    public void TpmiEccCurveFromValueDoesNotValidate()
    {
        const ushort undefinedCurve = 0x00FF;

        TpmiEccCurve curve = TpmiEccCurve.FromValue((TpmEccCurveConstants)undefinedCurve);

        Assert.AreEqual((TpmEccCurveConstants)undefinedCurve, curve.Value);
    }

    /// <summary>
    /// <see cref="TpmiRsaKeyBits.Parse"/> admits a supported RSA key size and
    /// <see cref="TpmiRsaKeyBits.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.4.6, Table 195).
    /// </summary>
    [TestMethod]
    public void TpmiRsaKeyBitsParsesSupportedSizeAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeUInt16(2048);

        TpmiRsaKeyBits keyBits = ParseRsaKeyBits(wireBytes);

        Assert.AreEqual((ushort)2048, keyBits.Value);
        Assert.IsTrue(TpmiRsaKeyBits.IsRsaKeyBits(2048));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        keyBits.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A key size outside the <c>RSA_KEY_SIZES_BITS</c> set is refused by <see cref="TpmiRsaKeyBits.Parse"/>
    /// with <c>TPM_RC_VALUE</c>, and <see cref="TpmiRsaKeyBits.IsRsaKeyBits"/> reports it as not admitted (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.4.6, Table 195).
    /// </summary>
    [TestMethod]
    public void TpmiRsaKeyBitsRefusesUnsupportedSize()
    {
        byte[] wireBytes = EncodeUInt16(1234);

        Assert.IsFalse(TpmiRsaKeyBits.IsRsaKeyBits(1234));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseRsaKeyBits(wireBytes));
    }

    /// <summary>
    /// <see cref="TpmiRsaKeyBits.FromValue"/> is the unvalidated escape hatch for a value already known good
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.4.6).
    /// </summary>
    [TestMethod]
    public void TpmiRsaKeyBitsFromValueDoesNotValidate()
    {
        TpmiRsaKeyBits keyBits = TpmiRsaKeyBits.FromValue(1234);

        Assert.AreEqual((ushort)1234, keyBits.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgSym.Parse"/> admits a symmetric algorithm and <see cref="TpmiAlgSym.WriteTo"/>
    /// reproduces the exact wire bytes it was parsed from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.33, Table 79).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSymParsesAlgorithmAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_AES);

        TpmiAlgSym sym = ParseAlgSym(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, sym.Value);
        Assert.IsTrue(TpmiAlgSym.IsAlgSym(sym.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        sym.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// An asymmetric algorithm is refused by <see cref="TpmiAlgSym.Parse"/> with <c>TPM_RC_SYMMETRIC</c>, and
    /// <see cref="TpmiAlgSym.IsAlgSym"/> reports it as not admitted (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.33,
    /// Table 79).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSymRefusesNonSymmetricAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_RSA);

        Assert.IsFalse(TpmiAlgSym.IsAlgSym(TpmAlgIdConstants.TPM_ALG_RSA));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgSym(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgSym.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.33, Table 79's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSymBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgSym(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgSym.Parse"/> admits <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.33, Table 79's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSymPlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgSym sym = ParseAlgSym(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(sym.IsNull);
    }

    /// <summary>
    /// <see cref="TpmiAlgSym.FromValue"/> is the unvalidated escape hatch for a value already known good (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.33).
    /// </summary>
    [TestMethod]
    public void TpmiAlgSymFromValueDoesNotValidate()
    {
        TpmiAlgSym sym = TpmiAlgSym.FromValue(TpmAlgIdConstants.TPM_ALG_RSA);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, sym.Value);
    }

    /// <summary>
    /// <see cref="TpmiAlgKdf.Parse"/> admits a hash-based key derivation function and
    /// <see cref="TpmiAlgKdf.WriteTo"/> reproduces the exact wire bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.36, Table 82).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfParsesKdfAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_MGF1);

        TpmiAlgKdf kdf = ParseAlgKdf(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_MGF1, kdf.Value);
        Assert.IsTrue(TpmiAlgKdf.IsKdf(kdf.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        kdf.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// <see cref="TpmiAlgKdf.Parse"/> admits <c>TPM_ALG_HKDF</c> — the key derivation function v185 added to
    /// Table 82 for the DHKEM ECC KEM path — and <see cref="TpmiAlgKdf.WriteTo"/> reproduces the exact wire
    /// bytes it was parsed from (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.36, Table 82).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfParsesHkdfAndRoundTripsByteIdentically()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_HKDF);

        TpmiAlgKdf kdf = ParseAlgKdf(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HKDF, kdf.Value);
        Assert.IsTrue(TpmiAlgKdf.IsKdf(kdf.Value));

        byte[] outBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(outBytes);
        kdf.WriteTo(ref writer);

        Assert.AreSequenceEqual(wireBytes, outBytes);
    }

    /// <summary>
    /// A non-KDF algorithm is refused by <see cref="TpmiAlgKdf.Parse"/> with <c>TPM_RC_KDF</c>, and
    /// <see cref="TpmiAlgKdf.IsKdf"/> reports it as not admitted (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 9.36, Table
    /// 83).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfRefusesNonKdfAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_AES);

        Assert.IsFalse(TpmiAlgKdf.IsKdf(TpmAlgIdConstants.TPM_ALG_AES));
        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgKdf(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmiAlgKdf.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.36, Table 82's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseAlgKdf(wireBytes));
    }

    /// <summary>
    /// The <c>isNullAdmitted: true</c> form of <see cref="TpmiAlgKdf.Parse"/> admits <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.36, Table 82's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfPlusFormAdmitsNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmiAlgKdf kdf = ParseAlgKdf(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(kdf.IsNull);
    }

    /// <summary>
    /// <see cref="TpmiAlgKdf.FromValue"/> is the unvalidated escape hatch for a value already known good (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 9.36).
    /// </summary>
    [TestMethod]
    public void TpmiAlgKdfFromValueDoesNotValidate()
    {
        TpmiAlgKdf kdf = TpmiAlgKdf.FromValue(TpmAlgIdConstants.TPM_ALG_AES);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, kdf.Value);
    }

    /// <summary>
    /// <see cref="TpmtHa.Parse"/> rents exactly one carrier from the pool for a non-empty digest, and
    /// <see cref="TpmtHa.Dispose"/> returns it, balancing back to the pre-rental baseline (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaParseBalancesOnMeteredPoolForNonEmptyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] digestBytes = new byte[32];
        for(int i = 0; i < digestBytes.Length; i++)
        {
            digestBytes[i] = (byte)(i + 1);
        }

        byte[] wireBytes = new byte[sizeof(ushort) + digestBytes.Length];
        var writer = new TpmWriter(wireBytes);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteBytes(digestBytes);

        TpmtHa ha = ParseHa(wireBytes, trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);
        Assert.IsTrue(digestBytes.AsSpan().SequenceEqual(ha.Digest));

        ha.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// <see cref="TpmtHa.Create"/> rents exactly one carrier from the pool for a non-empty digest, and
    /// <see cref="TpmtHa.Dispose"/> returns it, balancing back to the pre-rental baseline (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaCreateBalancesOnMeteredPoolForNonEmptyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;

        byte[] digestBytes = new byte[32];
        for(int i = 0; i < digestBytes.Length; i++)
        {
            digestBytes[i] = (byte)(0xFF - i);
        }

        TpmtHa ha = TpmtHa.Create(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), digestBytes, trackingPool.Pool);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount);

        ha.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// The NULL hash-agile digest carries no digest octets, so <see cref="TpmtHa.Parse"/> rents nothing from
    /// the pool for it (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaParseOfNullHashAlgRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        TpmtHa ha = ParseHa(wireBytes, trackingPool.Pool, isNullAdmitted: true);

        Assert.IsTrue(ha.IsNull);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);

        ha.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// The bare <see cref="TpmiAlgHash"/> form of <see cref="TpmtHa.Parse"/> refuses <c>TPM_ALG_NULL</c>,
    /// since the leading <c>+</c> in Table 89 is a capability the caller opts into, not a blanket admission
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaParseBareFormRefusesNullHashAlg()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseHa(wireBytes, pool));
    }

    /// <summary>
    /// <see cref="TpmtHa.Create"/> refuses a digest whose length does not match the hash algorithm's digest
    /// size, since Table 89's digest length is implied by <c>hashAlg</c> rather than carried as an explicit
    /// size field on the wire (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaCreateRefusesDigestLengthMismatch()
    {
        byte[] shortDigest = new byte[16];
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Assert.ThrowsExactly<ArgumentException>(() => TpmtHa.Create(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), shortDigest, pool));
    }

    /// <summary>
    /// <see cref="TpmtHa.WriteTo"/> followed by <see cref="TpmtHa.Parse"/> reproduces the exact digest bytes
    /// and hash algorithm a structure was created from (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void TpmtHaWriteToThenParseRoundtripsByteIdentical()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] digestBytes = new byte[32];
        for(int i = 0; i < digestBytes.Length; i++)
        {
            digestBytes[i] = (byte)i;
        }

        using TpmtHa created = TpmtHa.Create(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), digestBytes, pool);

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        using TpmtHa parsed = ParseHa(wireBytes, pool);

        Assert.AreEqual(created.HashAlg.Value, parsed.HashAlg.Value);
        Assert.IsTrue(created.Digest.SequenceEqual(parsed.Digest));
        Assert.HasCount(writer.Written, wireBytes);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Create"/> then <see cref="TpmtSigScheme.Parse"/> round trip the hash-only
    /// <c>TPMS_SIG_SCHEME_RSASSA</c> shape (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.1.5, Table 183, over the
    /// <c>TPMS_SCHEME_HASH</c> shape of Table 173).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeRoundtripsRsassa()
    {
        TpmtSigScheme created = TpmtSigScheme.Create(TpmAlgIdConstants.TPM_ALG_RSASSA, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256));

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        TpmtSigScheme parsed = ParseSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, parsed.Scheme.Value);
        Assert.IsFalse(parsed.Details!.Value.IsEcdaa);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.Details!.Value.HashAlg.Value);
        Assert.HasCount(writer.Written, wireBytes);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Create"/> then <see cref="TpmtSigScheme.Parse"/> round trip the hash-only
    /// <c>TPMS_SIG_SCHEME_ECDSA</c> shape (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.1.5, Table 183, over the ECC
    /// <c>TPMS_SCHEME_HASH</c> shape of Table 181).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeRoundtripsEcdsa()
    {
        TpmtSigScheme created = TpmtSigScheme.Create(TpmAlgIdConstants.TPM_ALG_ECDSA, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384));

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        TpmtSigScheme parsed = ParseSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, parsed.Scheme.Value);
        Assert.IsFalse(parsed.Details!.Value.IsEcdaa);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, parsed.Details!.Value.HashAlg.Value);
        Assert.HasCount(writer.Written, wireBytes);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.CreateEcdaa"/> then <see cref="TpmtSigScheme.Parse"/> round trip the anonymous
    /// <c>TPMS_SIG_SCHEME_ECDAA</c> shape, including its commit counter (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section
    /// 11.2.1.5, Table 183, over <c>TPMS_SCHEME_ECDAA</c>, Table 174).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeRoundtripsEcdaa()
    {
        TpmtSigScheme created = TpmtSigScheme.CreateEcdaa(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), count: 7);

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        TpmtSigScheme parsed = ParseSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDAA, parsed.Scheme.Value);
        Assert.IsTrue(parsed.Details!.Value.IsEcdaa);
        Assert.AreEqual((ushort)7, parsed.Details!.Value.Count);
        Assert.HasCount(writer.Written, wireBytes);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Create"/> then <see cref="TpmtSigScheme.Parse"/> round trip the hash-only
    /// <c>TPMS_SCHEME_HMAC</c> shape, present in every TPM implementation (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section
    /// 11.2.1.5, Table 183, over Table 176).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeRoundtripsHmac()
    {
        TpmtSigScheme created = TpmtSigScheme.Create(TpmAlgIdConstants.TPM_ALG_HMAC, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256));

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        TpmtSigScheme parsed = ParseSigScheme(wireBytes);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, parsed.Scheme.Value);
        Assert.IsFalse(parsed.Details!.Value.IsEcdaa);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.Details!.Value.HashAlg.Value);
        Assert.HasCount(writer.Written, wireBytes);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Null"/> writes only its 2-octet <c>TPM_ALG_NULL</c> selector, with no
    /// <see cref="TpmuSigScheme"/> details, and <see cref="TpmtSigScheme.Parse"/> with
    /// <c>isNullAdmitted: true</c> reproduces it (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.1.5, Table 183's leading
    /// <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeRoundtripsNull()
    {
        TpmtSigScheme created = TpmtSigScheme.Null;

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        TpmtSigScheme parsed = ParseSigScheme(wireBytes, isNullAdmitted: true);

        Assert.IsTrue(parsed.IsNull);
        Assert.AreEqual(sizeof(ushort), writer.Written);
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Create"/> refuses <c>TPM_ALG_ECDAA</c> since that scheme needs a commit
    /// counter <see cref="TpmtSigScheme.CreateEcdaa"/> supplies and <see cref="TpmtSigScheme.Create"/> does not
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2, Section 11.2.1.4, Table 182).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeCreateRefusesEcdaaSelector()
    {
        Assert.ThrowsExactly<ArgumentException>(() => TpmtSigScheme.Create(TpmAlgIdConstants.TPM_ALG_ECDAA, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256)));
    }

    /// <summary>
    /// A non-signing algorithm is refused by <see cref="TpmtSigScheme.Parse"/> with <c>TPM_RC_SCHEME</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.1.5, Table 183, via <see cref="TpmiAlgSigScheme"/>).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeParseRefusesNonSigningAlgorithm()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_AES);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseSigScheme(wireBytes));
    }

    /// <summary>
    /// The bare form of <see cref="TpmtSigScheme.Parse"/> refuses <c>TPM_ALG_NULL</c> (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.1.5, Table 183's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeParseBareFormRefusesNull()
    {
        byte[] wireBytes = EncodeAlg(TpmAlgIdConstants.TPM_ALG_NULL);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseSigScheme(wireBytes));
    }

    /// <summary>
    /// A default-constructed <see cref="TpmtSigScheme"/> is not the NULL signing scheme — its <c>Scheme</c>
    /// selector defaults to <c>TPM_ALG_ERROR</c>, not <c>TPM_ALG_NULL</c> — and <see cref="TpmtSigScheme.WriteTo"/>
    /// refuses to serialize it (<c>TPM_RC_SCHEME</c>).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeDefaultIsNotNullAndWriteToThrows()
    {
        TpmtSigScheme defaulted = default;

        Assert.IsFalse(defaulted.IsNull);

        byte[] wireBytes = new byte[sizeof(ushort)];
        var writer = new TpmWriter(wireBytes);

        //TpmWriter is a ref struct, so it cannot be captured by a lambda; the throw is asserted with a
        //plain try/catch instead of Assert.ThrowsExactly.
        try
        {
            defaulted.WriteTo(ref writer);
            Assert.Fail("Expected InvalidOperationException.");
        }
        catch(InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// <see cref="TpmtSigScheme.Null"/> writes exactly the 2-octet <c>TPM_ALG_NULL</c> selector (0x0010) (<see
    /// href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, Section 11.2.1.5, Table 183's leading <c>+</c> row).
    /// </summary>
    [TestMethod]
    public void TpmtSigSchemeNullWritesTpmAlgNullSelectorBytes()
    {
        TpmtSigScheme created = TpmtSigScheme.Null;

        byte[] wireBytes = new byte[created.SerializedSize];
        var writer = new TpmWriter(wireBytes);
        created.WriteTo(ref writer);

        Assert.AreSequenceEqual(new byte[] { 0x00, 0x10 }, wireBytes);
    }
}
