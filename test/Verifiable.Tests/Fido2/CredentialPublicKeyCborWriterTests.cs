using System.Buffers;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="CredentialPublicKeyCborWriter"/>: the production counterpart to
/// <see cref="CredentialPublicKeyCborReader"/>, spanning a hand-computed byte-exact EC2 vector and round
/// trips through the shipped reader for every <c>kty</c> branch (EC2, OKP, RSA).
/// </summary>
[TestClass]
internal sealed class CredentialPublicKeyCborWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An EC2 ES256 COSE_Key with fixed 32-byte X/Y coordinates matches a fully hand-computed CTAP2
    /// canonical CBOR byte sequence: map header (5 entries) then <c>kty</c>(1)/<c>alg</c>(3)/<c>crv</c>(-1)/
    /// <c>x</c>(-2)/<c>y</c>(-3) in ascending canonical key order — which coincides with construction order
    /// here since every label encodes to a single byte and 1 &lt; 3 &lt; 0x20 &lt; 0x21 &lt; 0x22.
    /// </summary>
    [TestMethod]
    public void WritesAnEc2KeyToHandComputedBytes()
    {
        using IMemoryOwner<byte> xOwner = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> yOwner = BaseMemoryPool.Shared.Rent(32);
        Span<byte> x = xOwner.Memory.Span[..32];
        Span<byte> y = yOwner.Memory.Span[..32];
        for(int i = 0; i < 32; i++)
        {
            x[i] = (byte)(i + 1);
            y[i] = (byte)(i + 33);
        }

        var coseKey = new CoseKey(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: xOwner.Memory[..32], y: yOwner.Memory[..32]);

        byte[] expected = Convert.FromHexString(
            "A50102032620012158200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2022582021222324" +
            "25262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40");

        TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(coseKey);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.CredentialPublicKeyKind, kind);
    }


    /// <summary>An EC2 ES256 COSE_Key round-trips through the shipped <see cref="CredentialPublicKeyCborReader"/>.</summary>
    [TestMethod]
    public void RoundTripsAnEs256Ec2KeyThroughTheShippedReader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            (byte[] x, byte[] y) = DecodeEcPoint(keyMaterial.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var expected = new CoseKey(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: x, y: y);

            TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(expected);
            CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(written.Memory);

            Assert.AreEqual(CoseKeyTypes.Ec2, result.CoseKey.Kty);
            Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.CoseKey.Alg);
            Assert.AreEqual(CoseKeyCurves.P256, result.CoseKey.Curve);
            Assert.IsTrue(result.CoseKey.X!.Value.Span.SequenceEqual(expected.X!.Value.Span));
            Assert.IsTrue(result.CoseKey.Y!.Value.Span.SequenceEqual(expected.Y!.Value.Span));
            Assert.AreEqual(written.Length, result.BytesConsumed);
        }
    }


    /// <summary>An OKP EdDSA (Ed25519) COSE_Key round-trips through the shipped <see cref="CredentialPublicKeyCborReader"/>.</summary>
    [TestMethod]
    public void RoundTripsAnEdDsaOkpKeyThroughTheShippedReader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            CoseKey expected = Fido2AttestationTestVectors.CreateEd25519CoseKey(keyMaterial.PublicKey, WellKnownCoseAlgorithms.EdDsa);

            TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(expected);
            CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(written.Memory);

            Assert.AreEqual(CoseKeyTypes.Okp, result.CoseKey.Kty);
            Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, result.CoseKey.Alg);
            Assert.AreEqual(CoseKeyCurves.Ed25519, result.CoseKey.Curve);
            Assert.IsTrue(result.CoseKey.X!.Value.Span.SequenceEqual(expected.X!.Value.Span));
            Assert.IsNull(result.CoseKey.Y);
            Assert.AreEqual(written.Length, result.BytesConsumed);
        }
    }


    /// <summary>An RSA RS256 COSE_Key round-trips through the shipped <see cref="CredentialPublicKeyCborReader"/>.</summary>
    [TestMethod]
    public void RoundTripsARs256RsaKeyThroughTheShippedReader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            (byte[] n, byte[] e) = DecodeRsaPublicKeyComponents(keyMaterial.PublicKey.AsReadOnlyMemory());
            var expected = new CoseKey(kty: CoseKeyTypes.Rsa, alg: WellKnownCoseAlgorithms.Rs256, n: n, e: e);

            TaggedMemory<byte> written = CredentialPublicKeyCborWriter.Write(expected);
            CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(written.Memory);

            Assert.AreEqual(CoseKeyTypes.Rsa, result.CoseKey.Kty);
            Assert.AreEqual(WellKnownCoseAlgorithms.Rs256, result.CoseKey.Alg);
            Assert.IsTrue(result.CoseKey.N!.Value.Span.SequenceEqual(expected.N!.Value.Span));
            Assert.IsTrue(result.CoseKey.E!.Value.Span.SequenceEqual(expected.E!.Value.Span));
            Assert.IsNull(result.CoseKey.X);
            Assert.AreEqual(written.Length, result.BytesConsumed);
        }
    }


    /// <summary>A COSE_Key carrying an unsupported <c>kty</c> (here, Symmetric) is rejected.</summary>
    [TestMethod]
    public void UnsupportedKeyTypeThrowsArgumentException()
    {
        var coseKey = new CoseKey(kty: CoseKeyTypes.Symmetric);

        Assert.ThrowsExactly<ArgumentException>(() => CredentialPublicKeyCborWriter.Write(coseKey));
    }


    /// <summary>A <see langword="null"/> <see cref="CoseKey"/> is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullCoseKeyThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CredentialPublicKeyCborWriter.Write(null!));
    }
}
