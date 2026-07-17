using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the EC2/OKP branches of <c>CoseKeyExtensions.BuildKeyMaterial</c> (via
/// <see cref="CoseKeyExtensions.ToPublicKeyMemory"/>) the RSA-focused <see cref="CoseKeyRsaTests"/> does
/// not cover: the compressed-point success path, and the guard clauses that reject a <see cref="CoseKey"/>
/// missing the coordinates its key type requires.
/// </summary>
/// <remarks>
/// No CBOR reader is exercised here — every <see cref="CoseKey"/> under test is constructed directly from
/// its parsed parameters, mirroring <see cref="CoseKeyRsaTests"/>'s own precedent for testing this
/// conversion layer in isolation from the CBOR codec.
/// </remarks>
[TestClass]
internal sealed class CoseKeyEc2BuildKeyMaterialTests
{
    /// <summary>
    /// A compressed-form EC2 <see cref="CoseKey"/> (<c>x</c> plus <c>encodedYCompressionSign</c>, no
    /// <c>y</c>) round-trips through <see cref="CoseKeyExtensions.ToPublicKeyMemory"/> to the exact
    /// original compressed SEC1 point — the only path in the suite that builds a <see cref="CoseKey"/>
    /// from a compressed point and extracts key material from it, rather than merely exercising the
    /// compressed-point predicate or equality.
    /// </summary>
    [TestMethod]
    public void CompressedEc2CoseKeyRoundTripsToTheOriginalCompressedPoint()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            byte[] compressed = keys.PublicKey.AsReadOnlySpan().ToArray();
            bool ySign = compressed[0] == EllipticCurveUtilities.OddYCoordinate;
            byte[] x = compressed[1..];

            CoseKey coseKey = new(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, x: x, encodedYCompressionSign: ySign);

            using PublicKeyMemory extracted = coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared);

            Assert.IsTrue(
                extracted.AsReadOnlySpan().SequenceEqual(compressed),
                "The compressed-form CoseKey must extract to the exact original compressed SEC1 point.");
            Assert.AreEqual(keys.PublicKey.Tag, extracted.Tag, "Extracted key must carry the P-256 public-key tag.");
        }
        finally
        {
            keys.PublicKey.Dispose();
            keys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// An EC2 <see cref="CoseKey"/> missing the mandatory <c>x</c> coordinate (RFC 9052 §7.1) is rejected,
    /// whether or not an uncompressed <c>y</c> is present.
    /// </summary>
    [TestMethod]
    public void Ec2CoseKeyWithoutXCoordinateIsRejected()
    {
        using IMemoryOwner<byte> y = BaseMemoryPool.Shared.Rent(32);
        CoseKey coseKey = new(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, y: y.Memory);

        Assert.ThrowsExactly<InvalidOperationException>(() => coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An EC2 <see cref="CoseKey"/> carrying <c>x</c> but neither an uncompressed <c>y</c> nor a
    /// compressed <c>encodedYCompressionSign</c> is rejected: neither point-reconstruction path in
    /// <c>BuildKeyMaterial</c> can proceed.
    /// </summary>
    [TestMethod]
    public void Ec2CoseKeyWithNeitherYCoordinateNorSignBitIsRejected()
    {
        using IMemoryOwner<byte> x = BaseMemoryPool.Shared.Rent(32);
        CoseKey coseKey = new(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, x: x.Memory);

        Assert.ThrowsExactly<InvalidOperationException>(() => coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An OKP <see cref="CoseKey"/> missing the mandatory <c>x</c> public-key bytes (RFC 9052 §7.2) is
    /// rejected.
    /// </summary>
    [TestMethod]
    public void OkpCoseKeyWithoutXIsRejected()
    {
        CoseKey coseKey = new(kty: CoseKeyTypes.Okp, curve: CoseKeyCurves.Ed25519);

        Assert.ThrowsExactly<InvalidOperationException>(() => coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A <see cref="CoseKey"/> whose <c>kty</c> is neither EC2, OKP, nor RSA is rejected as unsupported —
    /// here the registered-but-unconvertible <see cref="CoseKeyTypes.Symmetric"/> type.
    /// </summary>
    [TestMethod]
    public void UnsupportedKeyTypeIsRejected()
    {
        CoseKey coseKey = new(kty: CoseKeyTypes.Symmetric);

        Assert.ThrowsExactly<NotSupportedException>(() => coseKey.ToPublicKeyMemory(BaseMemoryPool.Shared));
    }
}
