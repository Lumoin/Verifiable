using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the content equality added to the FIDO2 <see cref="IDisposable"/> ownership-tree
/// types <see cref="AuthenticatorData"/>, <see cref="Fido2.AttestedCredentialData"/>, and
/// <see cref="Fido2CredentialRecord"/>: two independently built instances carrying byte-identical
/// content must compare equal and report the same hash code, every differing member must break
/// equality, and <see cref="Fido2CredentialRecord"/>'s <see cref="Fido2CredentialRecord.Transports"/>
/// override must fix the reference-equality defect the compiler-synthesized record comparison
/// would otherwise have for that member.
/// </summary>
[TestClass]
internal sealed class Fido2OwnershipTypeEqualityTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Two <see cref="AuthenticatorData"/> instances independently parsed from separately-built
    /// buffers carrying the same content compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void EqualContentFromIndependentlyParsedBuffersAreEqual()
    {
        byte[] rpIdHash = CreateRpIdHash();
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x01, 0x02, 0x03];
        byte[] credentialPublicKey = EncodeP256CoseKey();
        byte[] extensions = [0xA0]; //An empty CBOR map.

        byte[] attestedCredentialDataA = BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKey);
        byte[] attestedCredentialDataB = BuildAttestedCredentialData(aaguid, (byte[])credentialId.Clone(), (byte[])credentialPublicKey.Clone());

        byte[] bufferA = BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit), signCount: 7, attestedCredentialDataA, extensions);
        byte[] bufferB = BuildAuthenticatorData((byte[])rpIdHash.Clone(), flags: (byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit), signCount: 7, attestedCredentialDataB, (byte[])extensions.Clone());

        using AuthenticatorData parsedA = AuthenticatorDataReader.Read(bufferA, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedB = AuthenticatorDataReader.Read(bufferB, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreEqual(parsedA, parsedB);
        Assert.IsTrue(parsedA == parsedB);
        Assert.IsFalse(parsedA != parsedB);
        Assert.AreEqual(parsedA.GetHashCode(), parsedB.GetHashCode());
    }


    /// <summary>A differing <c>flags</c> byte breaks <see cref="AuthenticatorData"/> equality.</summary>
    [TestMethod]
    public void DifferingFlagsBreaksAuthenticatorDataEquality()
    {
        byte[] rpIdHash = CreateRpIdHash();
        byte[] bufferA = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 1);
        byte[] bufferB = BuildAuthenticatorData((byte[])rpIdHash.Clone(), flags: AuthenticatorDataFlags.UserPresentBit, signCount: 1);

        using AuthenticatorData parsedA = AuthenticatorDataReader.Read(bufferA, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedB = AuthenticatorDataReader.Read(bufferB, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreNotEqual(parsedA, parsedB);
    }


    /// <summary>A differing <c>signCount</c> breaks <see cref="AuthenticatorData"/> equality.</summary>
    [TestMethod]
    public void DifferingSignCountBreaksAuthenticatorDataEquality()
    {
        byte[] rpIdHash = CreateRpIdHash();
        byte[] bufferA = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 1);
        byte[] bufferB = BuildAuthenticatorData((byte[])rpIdHash.Clone(), flags: AuthenticatorDataFlags.None, signCount: 2);

        using AuthenticatorData parsedA = AuthenticatorDataReader.Read(bufferA, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedB = AuthenticatorDataReader.Read(bufferB, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreNotEqual(parsedA, parsedB);
    }


    /// <summary>A differing <c>rpIdHash</c> breaks <see cref="AuthenticatorData"/> equality.</summary>
    [TestMethod]
    public void DifferingRpIdHashBreaksAuthenticatorDataEquality()
    {
        byte[] rpIdHashA = CreateRpIdHash();
        byte[] rpIdHashB = CreateRpIdHash();
        rpIdHashB[0] ^= 0xFF;

        byte[] bufferA = BuildAuthenticatorData(rpIdHashA, flags: AuthenticatorDataFlags.None, signCount: 1);
        byte[] bufferB = BuildAuthenticatorData(rpIdHashB, flags: AuthenticatorDataFlags.None, signCount: 1);

        using AuthenticatorData parsedA = AuthenticatorDataReader.Read(bufferA, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedB = AuthenticatorDataReader.Read(bufferB, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreNotEqual(parsedA, parsedB);
    }


    /// <summary>Differing <c>extensions</c> bytes break <see cref="AuthenticatorData"/> equality.</summary>
    [TestMethod]
    public void DifferingExtensionsBytesBreaksAuthenticatorDataEquality()
    {
        byte[] rpIdHash = CreateRpIdHash();
        byte[] bufferA = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.ExtensionDataIncludedBit, signCount: 1, extensions: [0xA0]);
        byte[] bufferB = BuildAuthenticatorData((byte[])rpIdHash.Clone(), flags: AuthenticatorDataFlags.ExtensionDataIncludedBit, signCount: 1, extensions: [0xA1, 0x00]);

        using AuthenticatorData parsedA = AuthenticatorDataReader.Read(bufferA, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedB = AuthenticatorDataReader.Read(bufferB, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreNotEqual(parsedA, parsedB);
    }


    /// <summary>
    /// Attested credential data present on one side only (the <c>AT</c> flag differs) breaks
    /// <see cref="AuthenticatorData"/> equality, exercising the null-aware comparison.
    /// </summary>
    [TestMethod]
    public void DifferingAttestedCredentialDataPresenceBreaksAuthenticatorDataEquality()
    {
        byte[] rpIdHash = CreateRpIdHash();
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), [0x01, 0x02], EncodeP256CoseKey());

        byte[] bufferWithout = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 1);
        byte[] bufferWith = BuildAuthenticatorData((byte[])rpIdHash.Clone(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 1, attestedCredentialData);

        using AuthenticatorData parsedWithout = AuthenticatorDataReader.Read(bufferWithout, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);
        using AuthenticatorData parsedWith = AuthenticatorDataReader.Read(bufferWith, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.AreNotEqual(parsedWithout, parsedWith);
        Assert.IsNull(parsedWithout.AttestedCredentialData);
        Assert.IsNotNull(parsedWith.AttestedCredentialData);
    }


    /// <summary>
    /// Two <see cref="Fido2.AttestedCredentialData"/> instances built independently from the same
    /// AAGUID, credential ID bytes, and key material compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the AttestedCredentialData instances, disposed via their using declarations.")]
    public void EqualAttestedCredentialDataFromIndependentInstancesAreEqual()
    {
        Guid aaguid = Guid.NewGuid();
        byte[] credentialIdBytes = [0x0A, 0x0B, 0x0C, 0x0D];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using AttestedCredentialData attestedA = new(aaguid, idA, keyA);
            using AttestedCredentialData attestedB = new(aaguid, idB, keyB);

            Assert.AreEqual(attestedA, attestedB);
            Assert.IsTrue(attestedA == attestedB);
            Assert.AreEqual(attestedA.GetHashCode(), attestedB.GetHashCode());
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A differing <see cref="Fido2.AttestedCredentialData.Aaguid"/> breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the AttestedCredentialData instances, disposed via their using declarations.")]
    public void DifferingAaguidBreaksAttestedCredentialDataEquality()
    {
        byte[] credentialIdBytes = [0x0A, 0x0B];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using AttestedCredentialData attestedA = new(Guid.NewGuid(), idA, keyA);
            using AttestedCredentialData attestedB = new(Guid.NewGuid(), idB, keyB);

            Assert.AreNotEqual(attestedA, attestedB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A differing <see cref="Fido2.AttestedCredentialData.CredentialId"/> breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the AttestedCredentialData instances, disposed via their using declarations.")]
    public void DifferingCredentialIdBreaksAttestedCredentialDataEquality()
    {
        Guid aaguid = Guid.NewGuid();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create([0x01, 0x02], BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create([0x03, 0x04], BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using AttestedCredentialData attestedA = new(aaguid, idA, keyA);
            using AttestedCredentialData attestedB = new(aaguid, idB, keyB);

            Assert.AreNotEqual(attestedA, attestedB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A differing <see cref="Fido2.AttestedCredentialData.CredentialPublicKey"/> breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the AttestedCredentialData instances, disposed via their using declarations.")]
    public void DifferingCredentialPublicKeyBreaksAttestedCredentialDataEquality()
    {
        Guid aaguid = Guid.NewGuid();
        byte[] credentialIdBytes = [0x0A, 0x0B];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterialA = TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterialB = TestKeyMaterialProvider.CreateP384KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterialA.PublicKey);
            var keyB = new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P384, x: keyMaterialB.PublicKey.AsReadOnlySpan()[1..].ToArray());

            using AttestedCredentialData attestedA = new(aaguid, idA, keyA);
            using AttestedCredentialData attestedB = new(aaguid, idB, keyB);

            Assert.AreNotEqual(attestedA, attestedB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterialA);
            MdocTestFixtures.DisposeKeyMaterial(keyMaterialB);
        }
    }


    /// <summary>
    /// Two <see cref="Fido2CredentialRecord"/> instances built with independently constructed
    /// <see cref="Fido2CredentialRecord.Transports"/> lists holding the same entries in the same
    /// order compare equal and report the same hash code — the defect the
    /// <see cref="Fido2CredentialRecord.Equals(Fido2CredentialRecord?)"/> override fixes: the
    /// compiler-synthesized record equality would compare the two <see cref="IReadOnlyList{T}"/>
    /// instances by reference and report them as unequal despite identical content.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void IdenticalRecordsWithIndependentlyBuiltTransportsListsAreEqual()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            List<string> transportsA = ["usb", "nfc"];
            List<string> transportsB = new(transportsA);
            Assert.AreNotSame(transportsA, transportsB);

            using Fido2CredentialRecord recordA = new(WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, transportsA, false, false);
            using Fido2CredentialRecord recordB = new(WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 3, true, transportsB, false, false);

            Assert.AreEqual(recordA, recordB);
            Assert.AreEqual(recordA.GetHashCode(), recordB.GetHashCode());
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A different <see cref="Fido2CredentialRecord.Transports"/> entry set breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void DifferingTransportsEntriesBreaksFido2CredentialRecordEquality()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using Fido2CredentialRecord recordA = new(WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, ["usb"], false, false);
            using Fido2CredentialRecord recordB = new(WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 3, true, ["nfc"], false, false);

            Assert.AreNotEqual(recordA, recordB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A <see cref="Fido2CredentialRecord.Transports"/> list differing only in order breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void DifferingTransportsOrderBreaksFido2CredentialRecordEquality()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using Fido2CredentialRecord recordA = new(WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, ["usb", "nfc"], false, false);
            using Fido2CredentialRecord recordB = new(WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 3, true, ["nfc", "usb"], false, false);

            Assert.AreNotEqual(recordA, recordB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>A differing scalar member (<see cref="Fido2CredentialRecord.SignCount"/>) breaks equality.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void DifferingSignCountBreaksFido2CredentialRecordEquality()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using Fido2CredentialRecord recordA = new(WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, ["usb"], false, false);
            using Fido2CredentialRecord recordB = new(WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 4, true, ["usb"], false, false);

            Assert.AreNotEqual(recordA, recordB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>
    /// A differing <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/> breaks equality — the
    /// sharpest risk of adding this member to a HAND-ROLLED equality override: unlike a
    /// compiler-synthesized record, adding a primary-constructor parameter does not automatically
    /// join it, so this guards against the override silently treating two records differing only in
    /// this member as equal.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void DifferingAuthenticatorAttachmentBreaksFido2CredentialRecordEquality()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using Fido2CredentialRecord recordA = new(
                WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, ["usb"], false, false, WellKnownAuthenticatorAttachments.Platform);
            using Fido2CredentialRecord recordB = new(
                WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 3, true, ["usb"], false, false, WellKnownAuthenticatorAttachments.CrossPlatform);

            Assert.AreNotEqual(recordA, recordB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>
    /// A present <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/> versus an absent one
    /// (otherwise identical) breaks equality — the null-vs-value edge of the same override.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId instances transfers to the Fido2CredentialRecord instances, disposed via their using declarations.")]
    public void PresentVersusAbsentAuthenticatorAttachmentBreaksFido2CredentialRecordEquality()
    {
        byte[] credentialIdBytes = [0x11, 0x22, 0x33];
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            CredentialId idA = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CredentialId idB = CredentialId.Create(credentialIdBytes, BaseMemoryPool.Shared);
            CoseKey keyA = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);
            CoseKey keyB = MdocTestFixtures.CoseKeyFromP256Public(keyMaterial.PublicKey);

            using Fido2CredentialRecord recordA = new(
                WellKnownPublicKeyCredentialTypes.PublicKey, idA, keyA, 3, true, ["usb"], false, false, WellKnownAuthenticatorAttachments.Platform);
            using Fido2CredentialRecord recordB = new(WellKnownPublicKeyCredentialTypes.PublicKey, idB, keyB, 3, true, ["usb"], false, false);

            Assert.AreNotEqual(recordA, recordB);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }
}
