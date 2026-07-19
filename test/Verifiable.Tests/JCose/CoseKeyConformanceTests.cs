using System.Buffers;
using System.Linq;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Pure-table tests for <see cref="CoseKeyConformance"/>: the algorithm/curve pinning table
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">W3C Web Authentication Level 3,
/// section 5.8.5</see>), the compressed-point predicate, and the per-key-type required/allowed parameter
/// label sets (<see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section
/// 6.5.1</see>). No CBOR or wire parsing is exercised here — <see cref="Fido2CredentialKeyConformanceTests"/>
/// in <c>Verifiable.Tests.Fido2</c> covers the reader-path enforcement built on top of this mechanism.
/// </summary>
[TestClass]
internal sealed class CoseKeyConformanceTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>ES256 (-7) paired with its pinned P-256 (1) curve and EC2 key type is consistent.</summary>
    [TestMethod]
    public void Es256WithP256IsConsistent()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es256, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
    }


    /// <summary>ES256 (-7) paired with any curve other than P-256 (1) is inconsistent.</summary>
    [TestMethod]
    public void Es256WithP384IsInconsistent()
    {
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es256, CoseKeyTypes.Ec2, CoseKeyCurves.P384));
    }


    /// <summary>ES256 (-7) paired with a non-EC2 key type is inconsistent even when the curve value matches.</summary>
    [TestMethod]
    public void Es256WithNonEc2KeyTypeIsInconsistent()
    {
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es256, CoseKeyTypes.Okp, CoseKeyCurves.P256));
    }


    /// <summary>ES384 (-35) paired with its pinned P-384 (2) curve is consistent; any other curve is not.</summary>
    [TestMethod]
    public void Es384CurvePinningHoldsBothDirections()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es384, CoseKeyTypes.Ec2, CoseKeyCurves.P384));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es384, CoseKeyTypes.Ec2, CoseKeyCurves.P521));
    }


    /// <summary>ES512 (-36) paired with its pinned P-521 (3) curve is consistent; any other curve is not.</summary>
    [TestMethod]
    public void Es512CurvePinningHoldsBothDirections()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es512, CoseKeyTypes.Ec2, CoseKeyCurves.P521));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es512, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
    }


    /// <summary>
    /// The RFC 9864 fully-specified ESP256/ESP384/ESP512 algorithms pin the same curve as their legacy ES*
    /// counterpart.
    /// </summary>
    [TestMethod]
    public void FullySpecifiedEcdsaAlgorithmsPinTheSameCurvesAsTheirLegacyCounterparts()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp256, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp256, CoseKeyTypes.Ec2, CoseKeyCurves.P384));

        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp384, CoseKeyTypes.Ec2, CoseKeyCurves.P384));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp384, CoseKeyTypes.Ec2, CoseKeyCurves.P521));

        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp512, CoseKeyTypes.Ec2, CoseKeyCurves.P521));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Esp512, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
    }


    /// <summary>ES256K (-47) paired with its RFC 8812 §3 pinned secp256k1 (8) curve is consistent; any other curve is not.</summary>
    [TestMethod]
    public void Es256KCurvePinningHoldsBothDirections()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es256K, CoseKeyTypes.Ec2, CoseKeyCurves.Secp256k1));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Es256K, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
    }


    /// <summary>
    /// EdDSA (-8) paired with its pinned Ed25519 (6) curve and OKP key type is consistent; a mismatched curve or
    /// key type is not (closes tally clause 4354).
    /// </summary>
    [TestMethod]
    public void EdDsaCurveAndKeyTypePinningHoldsBothDirections()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.EdDsa, CoseKeyTypes.Okp, CoseKeyCurves.Ed25519));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.EdDsa, CoseKeyTypes.Okp, CoseKeyCurves.X25519));
        Assert.IsFalse(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.EdDsa, CoseKeyTypes.Ec2, CoseKeyCurves.Ed25519));
    }


    /// <summary>The RSA family leaves curve choice unconstrained: any key type/curve combination is consistent.</summary>
    [TestMethod]
    public void RsaFamilyAlgorithmIsConsistentRegardlessOfKeyTypeAndCurve()
    {
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Rs256, CoseKeyTypes.Rsa, curve: null));
        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(WellKnownCoseAlgorithms.Ps384, CoseKeyTypes.Ec2, CoseKeyCurves.P256));
    }


    /// <summary>An algorithm this table does not recognise is consistent regardless of key type/curve.</summary>
    [TestMethod]
    public void UnrecognisedAlgorithmIsConsistentRegardlessOfKeyTypeAndCurve()
    {
        const int unrecognisedAlgorithm = 123456;

        Assert.IsTrue(CoseKeyConformance.IsAlgorithmCurveConsistent(unrecognisedAlgorithm, CoseKeyTypes.Ec2, curve: null));
    }


    /// <summary>An EC2 key carrying an uncompressed <c>y</c> coordinate does not use compressed point encoding.</summary>
    [TestMethod]
    public void UncompressedYCoordinateIsNotCompressedPointEncoding()
    {
        using IMemoryOwner<byte> x = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> y = BaseMemoryPool.Shared.Rent(32);
        var key = new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, x: x.Memory, y: y.Memory);

        Assert.IsFalse(CoseKeyConformance.UsesCompressedPointEncoding(key));
    }


    /// <summary>An EC2 key carrying a <c>y</c> compression sign bit uses compressed point encoding.</summary>
    [TestMethod]
    public void CompressionSignBitIsCompressedPointEncoding()
    {
        using IMemoryOwner<byte> x = BaseMemoryPool.Shared.Rent(32);
        var key = new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, x: x.Memory, encodedYCompressionSign: true);

        Assert.IsTrue(CoseKeyConformance.UsesCompressedPointEncoding(key));
    }


    /// <summary>A <see langword="null"/> key is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void UsesCompressedPointEncodingRejectsNullKey()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CoseKeyConformance.UsesCompressedPointEncoding(null!));
    }


    /// <summary>The EC2 required and allowed label sets are identical and equal <c>{kty, alg, crv, x, y}</c>.</summary>
    [TestMethod]
    public void Ec2LabelSetsAreKtyAlgCrvXY()
    {
        int[] expected = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.Crv, CoseKeyParameters.X, CoseKeyParameters.Y];

        Assert.AreSequenceEqual(expected, CoseKeyConformance.RequiredParameterLabels(CoseKeyTypes.Ec2).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(expected, CoseKeyConformance.AllowedParameterLabels(CoseKeyTypes.Ec2).ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>The OKP required and allowed label sets are identical and equal <c>{kty, alg, crv, x}</c>.</summary>
    [TestMethod]
    public void OkpLabelSetsAreKtyAlgCrvX()
    {
        int[] expected = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.Crv, CoseKeyParameters.X];

        Assert.AreSequenceEqual(expected, CoseKeyConformance.RequiredParameterLabels(CoseKeyTypes.Okp).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(expected, CoseKeyConformance.AllowedParameterLabels(CoseKeyTypes.Okp).ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>The RSA required and allowed label sets are identical and equal <c>{kty, alg, n, e}</c>.</summary>
    [TestMethod]
    public void RsaLabelSetsAreKtyAlgNE()
    {
        int[] expected = [CoseKeyParameters.Kty, CoseKeyParameters.Alg, CoseKeyParameters.RsaN, CoseKeyParameters.RsaE];

        Assert.AreSequenceEqual(expected, CoseKeyConformance.RequiredParameterLabels(CoseKeyTypes.Rsa).ToArray(), SequenceOrder.InAnyOrder);
        Assert.AreSequenceEqual(expected, CoseKeyConformance.AllowedParameterLabels(CoseKeyTypes.Rsa).ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>A key type outside EC2/OKP/RSA is rejected with <see cref="ArgumentOutOfRangeException"/>.</summary>
    [TestMethod]
    public void UnsupportedKeyTypeIsRejectedForBothLabelSetQueries()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => CoseKeyConformance.RequiredParameterLabels(CoseKeyTypes.Symmetric));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => CoseKeyConformance.AllowedParameterLabels(CoseKeyTypes.Symmetric));
    }
}
