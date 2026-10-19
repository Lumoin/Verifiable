using System.Buffers.Text;
using System.Security.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests the library's reconstruction of the public key a JWK states (<see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>)
/// at its EC coordinates: <c>x</c> and <c>y</c> are each the full width of the curve's coordinate (RFC 7518 sections 6.2.1.2
/// and 6.2.1.3) and name a point of the curve (NIST SP 800-186 appendix D.1.1.1), judged on the coordinates as supplied before
/// the point is compressed, and the reconstruction's refusal is typed (<see cref="JwkPublicKeyException"/>).
/// </summary>
[TestClass]
internal sealed class JwkPublicKeyReconstructionTests
{
    /// <summary>
    /// A P-256 JWK whose coordinates are of the curve's width but name no point of it - the y of a real point with its last bit
    /// flipped - states no public key, so the reconstruction refuses it rather than compressing x with the parity of the y it was
    /// given; the control, the real point, is reconstructed.
    /// </summary>
    [TestMethod]
    public void CoordinatesNamingNoPointOfTheCurveAreRefused()
    {
        var (x, y) = PointOnP256();
        var offCurveY = (byte[])y.Clone();
        offCurveY[^1] ^= 0x01;

        var (_, _, _, keyMaterial) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(Jwk(x, y), BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder);
        keyMaterial.Dispose();

        var refusal = Assert.Throws<ArgumentException>(
            () => CryptoFormatConversions.DefaultJwkToAlgorithmConverter(Jwk(x, offCurveY), BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder));

        Assert.AreEqual(JwkPublicKeyFailureKind.NotAPointOfTheCurve, Assert.IsInstanceOfType<JwkPublicKeyException>(refusal).FailureKind);
    }


    /// <summary>
    /// A P-256 point's sixty-four octets split as thirty-three and thirty-one are no coordinates of the curve's width, whatever
    /// their concatenation spells, and the reconstruction refuses them as no point of the curve.
    /// </summary>
    [TestMethod]
    public void CoordinatesNotOfTheCurvesWidthAreRefused()
    {
        var (x, y) = PointOnP256();
        byte[] point = [.. x, .. y];

        var refusal = Assert.Throws<ArgumentException>(
            () => CryptoFormatConversions.DefaultJwkToAlgorithmConverter(Jwk(point[..33], point[33..]), BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder));

        Assert.AreEqual(JwkPublicKeyFailureKind.NotAPointOfTheCurve, Assert.IsInstanceOfType<JwkPublicKeyException>(refusal).FailureKind);
    }


    /// <summary>
    /// The reconstruction's refusals of a key type or a curve it reconstructs no key of, and of a JWK naming no key type, are of
    /// the typed exception with their reasons, so a caller tells them from a fault of the decoder or the allocator it supplied.
    /// </summary>
    [TestMethod]
    public void TheReconstructionsRefusalsAreTyped()
    {
        var (x, y) = PointOnP256();
        var unnamedCurve = Jwk(x, y);
        unnamedCurve[WellKnownJwkMemberNames.Crv] = "P-999";

        var noType = Jwk(x, y);
        _ = noType.Remove(WellKnownJwkMemberNames.Kty);

        var unknownType = Jwk(x, y);
        unknownType[WellKnownJwkMemberNames.Kty] = "x-unknown";

        Assert.AreEqual(JwkPublicKeyFailureKind.UnsupportedCurveOrAlgorithm, RefusalOf(unnamedCurve).FailureKind);
        Assert.AreEqual(JwkPublicKeyFailureKind.MemberAbsent, RefusalOf(noType).FailureKind);
        Assert.AreEqual(JwkPublicKeyFailureKind.UnsupportedKeyType, RefusalOf(unknownType).FailureKind);
    }


    /// <summary>The reconstruction's refusal of a JWK.</summary>
    /// <param name="jwk">The JWK.</param>
    /// <returns>The refusal.</returns>
    private static JwkPublicKeyException RefusalOf(Dictionary<string, object> jwk) =>
        Assert.ThrowsExactly<JwkPublicKeyException>(
            () => CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, BaseMemoryPool.Shared, TestSetup.Base64UrlDecoder));


    /// <summary>The members of a P-256 JWK of the coordinates given.</summary>
    /// <param name="x">The x coordinate.</param>
    /// <param name="y">The y coordinate.</param>
    /// <returns>The members.</returns>
    private static Dictionary<string, object> Jwk(byte[] x, byte[] y) => new(StringComparer.Ordinal)
    {
        [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Ec,
        [WellKnownJwkMemberNames.Crv] = WellKnownCurveValues.P256,
        [WellKnownJwkMemberNames.X] = Base64Url.EncodeToString(x),
        [WellKnownJwkMemberNames.Y] = Base64Url.EncodeToString(y)
    };


    /// <summary>The coordinates of a fresh point of P-256.</summary>
    /// <returns>The coordinates.</returns>
    private static P256Point PointOnP256()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(includePrivateParameters: false).Q;

        return new P256Point(
            point.X ?? throw new InvalidOperationException("An exported P-256 key carries its x coordinate."),
            point.Y ?? throw new InvalidOperationException("An exported P-256 key carries its y coordinate."));
    }


    /// <summary>The coordinates of a point of P-256.</summary>
    /// <param name="X">The x coordinate.</param>
    /// <param name="Y">The y coordinate.</param>
    private sealed record P256Point(byte[] X, byte[] Y);
}
