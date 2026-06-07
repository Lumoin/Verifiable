using System.Buffers;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests exercising <see cref="EllipticCurveUtilities"/> through the four
/// Brainpool r1 curves landed in Q.2.X. Each test uses real BouncyCastle key
/// generation so the (x, y) points are actually on-curve, then exercises the
/// utility's Compress → Decompress → CheckPointOnCurve flow.
/// </summary>
/// <remarks>
/// <para>
/// BC's <c>Q.GetEncoded(compressed: false)</c> emits 0x04 || X || Y with X
/// and Y already padded to the curve's field byte size, so the slice helpers
/// have a clean uncompressed-point to chew on.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EllipticCurveUtilitiesBrainpoolTests
{
    private static readonly SecureRandom Random = new();


    [TestMethod]
    public void BrainpoolP256r1CompressDecompressRoundTripRecoversY()
    {
        AssertCompressDecompressRoundTrip("brainpoolP256r1", EllipticCurveTypes.BrainpoolP256r1, fieldByteSize: 32);
    }


    [TestMethod]
    public void BrainpoolP320r1CompressDecompressRoundTripRecoversY()
    {
        AssertCompressDecompressRoundTrip("brainpoolP320r1", EllipticCurveTypes.BrainpoolP320r1, fieldByteSize: 40);
    }


    [TestMethod]
    public void BrainpoolP384r1CompressDecompressRoundTripRecoversY()
    {
        AssertCompressDecompressRoundTrip("brainpoolP384r1", EllipticCurveTypes.BrainpoolP384r1, fieldByteSize: 48);
    }


    [TestMethod]
    public void BrainpoolP512r1CompressDecompressRoundTripRecoversY()
    {
        AssertCompressDecompressRoundTrip("brainpoolP512r1", EllipticCurveTypes.BrainpoolP512r1, fieldByteSize: 64);
    }


    [TestMethod]
    public void BrainpoolCurvesFamilyFlagIncludesAllFourMembers()
    {
        //BrainpoolCurves mirrors NistCurves — a union flag for callers that
        //want to accept any Brainpool variant without enumerating each.
        Assert.IsTrue(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.BrainpoolP256r1));
        Assert.IsTrue(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.BrainpoolP320r1));
        Assert.IsTrue(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.BrainpoolP384r1));
        Assert.IsTrue(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.BrainpoolP512r1));

        //And does NOT include NIST or secp256k1 — keep the families disjoint.
        Assert.IsFalse(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.P256));
        Assert.IsFalse(EllipticCurveTypes.BrainpoolCurves.HasFlag(EllipticCurveTypes.Secp256k1));
    }


    [TestMethod]
    public void CheckPointOnCurveRejectsBrainpoolP256r1PointWithoutFlag()
    {
        //CheckPointOnCurve uses the curveType flag to pick parameter sets when
        //multiple curves share a byte length. A BP-256 point passed without
        //its flag must NOT be accepted as P-256 — the field primes and a
        //coefficients differ.
        (byte[] x, byte[] y) = GenerateOnCurvePoint("brainpoolP256r1", fieldByteSize: 32);

        bool acceptedWithBrainpoolFlag = EllipticCurveUtilities.CheckPointOnCurve(
            x, y, EllipticCurveTypes.BrainpoolP256r1);
        bool acceptedAsP256 = EllipticCurveUtilities.CheckPointOnCurve(
            x, y, EllipticCurveTypes.P256);

        Assert.IsTrue(acceptedWithBrainpoolFlag, "BP-256 point must be accepted under its own curve flag.");
        Assert.IsFalse(acceptedAsP256, "BP-256 point must NOT be accepted under the P-256 flag — different curve parameters.");
    }


    [TestMethod]
    public void CheckPointOnCurveAcceptsAllBrainpoolPoints()
    {
        AssertCheckPointAccepts("brainpoolP256r1", EllipticCurveTypes.BrainpoolP256r1, 32);
        AssertCheckPointAccepts("brainpoolP320r1", EllipticCurveTypes.BrainpoolP320r1, 40);
        AssertCheckPointAccepts("brainpoolP384r1", EllipticCurveTypes.BrainpoolP384r1, 48);
        AssertCheckPointAccepts("brainpoolP512r1", EllipticCurveTypes.BrainpoolP512r1, 64);
    }


    [TestMethod]
    public void IsCompressedAcceptsBrainpoolCompressedLengths()
    {
        //Q.2.X widened IsCompressed to accept the BP-320 (41) and BP-512 (65)
        //compressed lengths in addition to the existing 33 / 49 / 67 set.
        Span<byte> bp320Compressed = stackalloc byte[41];
        bp320Compressed[0] = EllipticCurveUtilities.EvenYCoordinate;
        Assert.IsTrue(EllipticCurveUtilities.IsCompressed(bp320Compressed));

        Span<byte> bp512Compressed = stackalloc byte[65];
        bp512Compressed[0] = EllipticCurveUtilities.OddYCoordinate;
        Assert.IsTrue(EllipticCurveUtilities.IsCompressed(bp512Compressed));
    }


    private static void AssertCompressDecompressRoundTrip(string brainpoolCurveName, EllipticCurveTypes curveType, int fieldByteSize)
    {
        (byte[] x, byte[] y) = GenerateOnCurvePoint(brainpoolCurveName, fieldByteSize);

        byte[] compressed = EllipticCurveUtilities.Compress(x, y);
        Assert.HasCount(1 + fieldByteSize, compressed,
            "Compressed encoding is one prefix byte plus the X coordinate.");
        Assert.IsTrue(
            compressed[0] == EllipticCurveUtilities.EvenYCoordinate || compressed[0] == EllipticCurveUtilities.OddYCoordinate,
            "Compressed prefix must be 0x02 or 0x03.");

        byte[] recoveredY = EllipticCurveUtilities.Decompress(compressed, curveType);

        Assert.HasCount(fieldByteSize, recoveredY,
            "Decompressed Y is left-padded to the curve field byte size.");
        Assert.IsTrue(recoveredY.AsSpan().SequenceEqual(y),
            "Decompressed Y must match the original Y coordinate the BC generator produced.");

        bool onCurve = EllipticCurveUtilities.CheckPointOnCurve(x, recoveredY, curveType);
        Assert.IsTrue(onCurve, $"Recovered point must satisfy the {brainpoolCurveName} curve equation.");
    }


    private static void AssertCheckPointAccepts(string brainpoolCurveName, EllipticCurveTypes curveType, int fieldByteSize)
    {
        (byte[] x, byte[] y) = GenerateOnCurvePoint(brainpoolCurveName, fieldByteSize);

        Assert.IsTrue(
            EllipticCurveUtilities.CheckPointOnCurve(x, y, curveType),
            $"BC-generated {brainpoolCurveName} point must satisfy the curve equation under its own flag.");
    }


    private static (byte[] X, byte[] Y) GenerateOnCurvePoint(string brainpoolCurveName, int fieldByteSize)
    {
        X9ECParameters curveParams = ECNamedCurveTable.GetByName(brainpoolCurveName);
        var domainParams = new ECDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);
        var keyGenParams = new ECKeyGenerationParameters(domainParams, Random);
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
        var pub = (ECPublicKeyParameters)keyPair.Public;

        //GetEncoded(compressed: false) produces 0x04 || X (fieldByteSize bytes) || Y
        //(fieldByteSize bytes); slice through EllipticCurveUtilities to exercise the
        //full slice/uncompressed-length path.
        byte[] uncompressed = pub.Q.GetEncoded(compressed: false);
        Assert.HasCount(1 + 2 * fieldByteSize, uncompressed);

        byte[] x = EllipticCurveUtilities.SliceXCoordinate(uncompressed).ToArray();
        byte[] y = EllipticCurveUtilities.SliceYCoordinate(uncompressed).ToArray();

        return (x, y);
    }
}
