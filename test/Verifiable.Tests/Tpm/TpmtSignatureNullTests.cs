using System;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire coverage for the NULL Signature (TPMT_SIGNATURE with <c>sigAlg</c> TPM_ALG_NULL, no union body): the
/// two-octet selector alone, its parse and write, disposal immunity, and that a body-bearing selector reads its
/// own member independently of the NULL arm, since the two arms never overlap on the wire.
/// </summary>
[TestClass]
internal sealed class TpmtSignatureNullTests
{
    /// <summary>A stand-in 32-octet ECDSA <c>signatureR</c>/<c>signatureS</c> component.</summary>
    private static byte[] ThirtyTwoOctetComponent { get; } =
    [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
    ];

    /// <summary>
    /// "If the handle for the signing key (signHandle) is TPM_RH_NULL, then all of the actions of the command
    /// are performed, and the attestation block is 'signed' with the NULL Signature" — the NULL Signature
    /// carries only the two-octet TPM_ALG_NULL selector, no union body.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1; Part 2, clause 11.3.6, Table 219</see>.
    /// </summary>
    [TestMethod]
    public void TpmtSignatureNullWriteToWritesExactlyTheTwoOctetNullSelectorAndReportsSizeTwo()
    {
        TpmtSignature original = TpmtSignature.Null;

        Assert.IsTrue(original.IsNull, "TpmtSignature.Null must report IsNull.");
        Assert.AreEqual(2, original.GetSerializedSize(), "The NULL Signature carries the two-octet sigAlg selector alone.");

        byte[] buffer = new byte[2];
        var writer = new TpmWriter(buffer);
        original.WriteTo(ref writer);

        Assert.AreEqual(2, writer.Written, "WriteTo must write exactly the selector, no union body.");
        byte[] expected = [0x00, 0x10];
        Assert.IsTrue(buffer.AsSpan().SequenceEqual(expected), "sigAlg TPM_ALG_NULL is 0x0010.");
    }

    /// <summary>
    /// Parsing the two-octet TPM_ALG_NULL selector yields the NULL Signature and reads no further field — unlike
    /// every other selector, it has no <c>hash</c> field either — so no pooled buffer is ever rented for it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1; Part 2, clause 11.3.6, Table 219</see>.
    /// </summary>
    [TestMethod]
    public void TpmtSignatureNullParseOfTheTwoOctetSelectorYieldsTheNullSignatureWithNoRental()
    {
        using var housePool = new MeteredHousePool();
        byte[] data = [0x00, 0x10];

        TpmtSignature parsed = ParseSignature(data, housePool.Pool);

        Assert.IsTrue(parsed.IsNull, "sigAlg 0x0010 must parse to the NULL Signature.");
        Assert.AreEqual(0L, housePool.RentedCount, "The NULL arm rents nothing: it reads no hash field and no signature bytes.");

        parsed.Dispose();
    }

    /// <summary>
    /// An ECDSA selector reads its own <c>hash</c> field and <c>signatureR</c>/<c>signatureS</c> members; the
    /// <c>TPM_ALG_NULL</c> selector is the only one that reads nothing at all, so the two arms never overlap.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.3.2, Table 214; clause 11.3.6, Table 219</see>.
    /// </summary>
    [TestMethod]
    public void TpmtSignatureParseOfAnEcdsaSelectorReadsTheHashFieldAndBothComponents()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //sigAlg ECDSA (0x0018), hash SHA-256 (0x000B), signatureR (TPM2B, 32 octets), signatureS (TPM2B, 32 octets).
        byte[] data =
        [
            0x00, 0x18,
            0x00, 0x0B,
            0x00, 0x20, .. ThirtyTwoOctetComponent,
            0x00, 0x20, .. ThirtyTwoOctetComponent
        ];
        var reader = new TpmReader(data);

        using TpmtSignature parsed = TpmtSignature.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the ECDSA member's octets.");
        Assert.IsFalse(parsed.IsNull, "An ECDSA selector must not be treated as the NULL Signature.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, parsed.SigAlg, "sigAlg must read back ECDSA.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.Signature.HashAlgorithm, "The member's hash field must read back SHA-256.");
        Assert.IsTrue(parsed.Signature.SignatureR!.AsReadOnlySpan().SequenceEqual(ThirtyTwoOctetComponent), "signatureR must read back the wire octets.");
        Assert.IsTrue(parsed.Signature.SignatureS!.AsReadOnlySpan().SequenceEqual(ThirtyTwoOctetComponent), "signatureS must read back the wire octets.");
    }

    /// <summary>
    /// <see cref="TpmtSignature.Dispose"/> is a no-op for the NULL Signature — it owns no buffer — so the shared
    /// <see cref="TpmtSignature.Null"/> instance stays usable for every holder no matter how many times any one
    /// of them disposes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void TpmtSignatureNullDisposeIsANoOpAndTheSharedInstanceStaysUsableAfterwards()
    {
        TpmtSignature.Null.Dispose();
        TpmtSignature.Null.Dispose();

        Assert.IsTrue(TpmtSignature.Null.IsNull, "The shared instance must still report IsNull after repeated disposal.");
        Assert.AreEqual(2, TpmtSignature.Null.GetSerializedSize(), "The shared instance must still be usable (no ObjectDisposedException) after repeated disposal.");
    }

    /// <summary>
    /// <see cref="TpmtSignature.Create"/> admits <c>TPM_ALG_NULL</c> and returns a NULL Signature — a fresh
    /// instance distinct from the shared <see cref="TpmtSignature.Null"/> singleton, but carrying the same
    /// dispose-immune NULL selector, per Part 3 clause 18.1's admission that <c>inScheme</c>/the signing scheme
    /// "may be TPM_ALG_NULL."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void TpmtSignatureCreateWithNullAlgorithmReturnsANullSignatureDistinctFromTheSharedSingleton()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        TpmtSignature built = TpmtSignature.Create(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, ReadOnlySpan<byte>.Empty, pool);

        Assert.IsTrue(built.IsNull, "Create(TPM_ALG_NULL, ...) must return a NULL Signature.");
        Assert.AreEqual(2, built.GetSerializedSize(), "The built NULL Signature carries the selector alone.");
        Assert.AreNotSame(TpmtSignature.Null, built, "Create must return a fresh instance, not the shared singleton reference.");

        built.Dispose();
        Assert.IsTrue(built.IsNull, "Disposing the built instance must be harmless (dispose-immune by value, not by reference).");
    }

    /// <summary>Parses a signature from <paramref name="data"/>; isolates the ref-struct reader from the calling assertion.</summary>
    /// <param name="data">The wire octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed signature.</returns>
    private static TpmtSignature ParseSignature(byte[] data, BaseMemoryPool pool)
    {
        var reader = new TpmReader(data);

        return TpmtSignature.Parse(ref reader, pool);
    }
}
