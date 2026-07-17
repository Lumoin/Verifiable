using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="AuthenticatorDataWriter"/>: the production counterpart to
/// <see cref="AuthenticatorDataReader"/>, spanning a hand-computed byte-exact vector, a vector matching
/// the independent <see cref="Fido2TestVectors"/> builders, round trips through the shipped
/// <see cref="AuthenticatorDataReader"/> and <see cref="CredentialPublicKeyCborReader"/> (with and
/// without attested credential data), and every flags/data consistency rejection.
/// </summary>
[TestClass]
internal sealed class AuthenticatorDataWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The 37-byte minimum layout (no attested credential data, no extensions) matches a fully
    /// hand-computed expected byte sequence: <c>rpIdHash</c> verbatim, followed by the flags byte, followed
    /// by the big-endian sign count.
    /// </summary>
    [TestMethod]
    public void MinimumLayoutWithNoAttestedCredentialDataOrExtensionsProducesHandComputedBytes()
    {
        byte[] rpIdHashBytes = CreateRpIdHash();
        using DigestValue rpIdHash = WrapRpIdHash(rpIdHashBytes, BaseMemoryPool.Shared);

        byte[] expected = [.. rpIdHashBytes, 0x00, 0x01, 0x02, 0x03, 0x04];

        TaggedMemory<byte> written = AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0x01020304u);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.AuthenticatorDataKind, kind);
    }


    /// <summary>
    /// A layout carrying both attested credential data and extensions matches the independent
    /// <see cref="Fido2TestVectors.BuildAuthenticatorData"/>/<see cref="Fido2TestVectors.BuildAttestedCredentialData"/>
    /// test-only builders byte-for-byte — an oracle implemented independently of
    /// <see cref="AuthenticatorDataWriter"/> itself.
    /// </summary>
    [TestMethod]
    public void AttestedCredentialDataAndExtensionsMatchTheIndependentTestVectorBuilder()
    {
        byte[] rpIdHashBytes = CreateRpIdHash();
        Guid aaguid = Guid.NewGuid();
        byte[] credentialIdBytes = [0x10, 0x20, 0x30, 0x40];
        byte[] credentialPublicKeyCbor = EncodeP256CoseKey();
        byte[] extensionsBytes = [0xA0]; //An empty CBOR map.

        byte[] expectedAttestedCredentialData = BuildAttestedCredentialData(aaguid, credentialIdBytes, credentialPublicKeyCbor);
        byte[] expected = BuildAuthenticatorData(rpIdHashBytes, flags: (byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit), signCount: 5, expectedAttestedCredentialData, extensionsBytes);

        using DigestValue rpIdHash = WrapRpIdHash(rpIdHashBytes, BaseMemoryPool.Shared);
        using CredentialId credentialId = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
        var attestedCredentialData = new AttestedCredentialDataToWrite(aaguid, credentialId, credentialPublicKeyCbor);

        TaggedMemory<byte> written = AuthenticatorDataWriter.Write(
            rpIdHash,
            new AuthenticatorDataFlags((byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit)),
            signCount: 5,
            attestedCredentialData,
            extensionsBytes);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// Attested credential data written with a real <see cref="CredentialPublicKeyCborWriter"/>-encoded
    /// ES256 COSE_Key round-trips through the shipped <see cref="AuthenticatorDataReader"/> and
    /// <see cref="CredentialPublicKeyCborReader"/>, recovering every field.
    /// </summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReaderWithAttestedCredentialData()
    {
        //The public key's content is immaterial to this round trip — only its P-256 shape (kty/curve)
        //is observed below — so the shared provider material stands in for a freshly minted key pair.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory credentialPublicKey = credentialKeyMaterial.PublicKey;
        using PrivateKeyMemory credentialPrivateKey = credentialKeyMaterial.PrivateKey;

        byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(credentialPublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
        CoseKey coseKey = new(
            kty: CoseKeyTypes.Ec2,
            alg: WellKnownCoseAlgorithms.Es256,
            curve: CoseKeyCurves.P256,
            x: EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
            y: EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray());
        TaggedMemory<byte> coseKeyCbor = CredentialPublicKeyCborWriter.Write(coseKey);

        Guid aaguid = Guid.NewGuid();
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);
        using CredentialId credentialId = CredentialId.Create([0x10, 0x20, 0x30, 0x40], BaseMemoryPool.Shared);
        var attestedCredentialData = new AttestedCredentialDataToWrite(aaguid, credentialId, coseKeyCbor.Memory);

        TaggedMemory<byte> written = AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit), signCount: 7, attestedCredentialData);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(written.Memory, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);

        Assert.IsTrue(parsed.RpIdHash.AsReadOnlySpan().SequenceEqual(rpIdHash.AsReadOnlySpan()));
        Assert.AreEqual(7u, parsed.SignCount);
        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.AreEqual(aaguid, parsed.AttestedCredentialData.Aaguid);
        Assert.IsTrue(parsed.AttestedCredentialData.CredentialId.AsReadOnlySpan().SequenceEqual(credentialId.AsReadOnlySpan()));
        Assert.AreEqual(CoseKeyTypes.Ec2, parsed.AttestedCredentialData.CredentialPublicKey.Kty);
        Assert.AreEqual(CoseKeyCurves.P256, parsed.AttestedCredentialData.CredentialPublicKey.Curve);
        Assert.AreEqual(0, parsed.Extensions.Length);
    }


    /// <summary>
    /// The minimum layout with no attested credential data and no extensions round-trips through the
    /// shipped <see cref="AuthenticatorDataReader"/>.
    /// </summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReaderWithoutAttestedCredentialDataOrExtensions()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);

        TaggedMemory<byte> written = AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(written.Memory, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);

        Assert.IsTrue(parsed.RpIdHash.AsReadOnlySpan().SequenceEqual(rpIdHash.AsReadOnlySpan()));
        Assert.AreEqual(0u, parsed.SignCount);
        Assert.IsNull(parsed.AttestedCredentialData);
        Assert.AreEqual(0, parsed.Extensions.Length);
    }


    /// <summary>The <c>AT</c> flag set without <c>attestedCredentialData</c> supplied is rejected.</summary>
    [TestMethod]
    public void AtFlagSetWithoutAttestedCredentialDataThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit), signCount: 0));
    }


    /// <summary>The <c>AT</c> flag clear with <c>attestedCredentialData</c> supplied is rejected.</summary>
    [TestMethod]
    public void AtFlagClearWithAttestedCredentialDataThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);
        using CredentialId credentialId = CredentialId.Create([0x01], BaseMemoryPool.Shared);
        var attestedCredentialData = new AttestedCredentialDataToWrite(Guid.NewGuid(), credentialId, EncodeP256CoseKey());

        Assert.ThrowsExactly<ArgumentException>(
            () => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0, attestedCredentialData));
    }


    /// <summary>The <c>ED</c> flag set without non-empty <c>extensions</c> supplied is rejected.</summary>
    [TestMethod]
    public void EdFlagSetWithoutExtensionsThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.ExtensionDataIncludedBit), signCount: 0));
    }


    /// <summary>The <c>ED</c> flag clear with non-empty <c>extensions</c> supplied is rejected.</summary>
    [TestMethod]
    public void EdFlagClearWithExtensionsThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(
            () => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0, extensions: new byte[] { 0xA0 }));
    }


    /// <summary>An <c>rpIdHash</c> that is not exactly 32 bytes is rejected.</summary>
    [TestMethod]
    public void WrongLengthRpIdHashThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(new byte[16], BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0));
    }


    /// <summary>A credential ID exceeding the section 7.1 step 25 bound of 1023 bytes is rejected.</summary>
    [TestMethod]
    public void CredentialIdOverTheBoundThrowsArgumentException()
    {
        using DigestValue rpIdHash = WrapRpIdHash(CreateRpIdHash(), BaseMemoryPool.Shared);
        using CredentialId credentialId = CredentialId.Create(new byte[CredentialId.MaxLength + 1], BaseMemoryPool.Shared);
        var attestedCredentialData = new AttestedCredentialDataToWrite(Guid.NewGuid(), credentialId, EncodeP256CoseKey());

        Assert.ThrowsExactly<ArgumentException>(
            () => AuthenticatorDataWriter.Write(rpIdHash, new AuthenticatorDataFlags(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit), signCount: 0, attestedCredentialData));
    }


    /// <summary>A <see langword="null"/> <c>rpIdHash</c> is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullRpIdHashThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => AuthenticatorDataWriter.Write(null!, new AuthenticatorDataFlags(AuthenticatorDataFlags.None), signCount: 0));
    }
}
