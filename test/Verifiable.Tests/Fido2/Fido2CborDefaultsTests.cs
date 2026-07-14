using System.Formats.Cbor;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor.Fido2;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the shipped CBOR default readers in <c>Verifiable.Cbor.Fido2</c> —
/// <see cref="AttestationObjectCborReader"/>, <see cref="PackedAttestationStatementCborReader"/>,
/// <see cref="CredentialPublicKeyCborReader"/>, and <see cref="AuthenticatorExtensionOutputsCborReader"/> —
/// the interim System.Formats.Cbor-based composition-edge implementations of the parse delegates
/// <c>Verifiable.Fido2</c> declares but never itself implements.
/// </summary>
/// <remarks>
/// Every positive vector is minted at test time with a fresh <see cref="CborWriter"/> — never a frozen
/// external fixture. Vectors that violate CTAP2 canonical CBOR (a duplicate or out-of-order map key)
/// are minted with <see cref="CborConformanceMode.Lax"/> so the writer itself does not refuse to
/// encode the shape under test, mirroring the established
/// <see cref="Fido2TestVectors.EncodeRawCoseKey"/> idiom. The final test proves the shipped
/// <see cref="AttestationObjectCborReader"/> and <see cref="PackedAttestationStatementCborReader"/>
/// compose with <see cref="PackedAttestation.Build"/> end to end, with no test-local stub parser
/// standing in for either layer.
/// </remarks>
[TestClass]
internal sealed class Fido2CborDefaultsTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A minted <c>attestationObject</c> round-trips through <see cref="AttestationObjectCborReader.Parse"/>
    /// byte-exact, and its <c>attStmt</c>/<c>authData</c> slices genuinely alias the source buffer
    /// (wrap, don't copy) rather than each being an independent copy.
    /// </summary>
    [TestMethod]
    public void AttestationObjectRoundTripsFmtAttStmtAndAuthDataAsAliasingSlices()
    {
        byte[] attStmtCbor = EncodeEmptyMap();
        byte[] authData = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        byte[] attestationObject = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, attStmtCbor, authData);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObject);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, parts.Format);
        Assert.IsTrue(parts.AttestationStatement.Span.SequenceEqual(attStmtCbor));
        Assert.IsTrue(parts.AuthenticatorData.Span.SequenceEqual(authData));

        Assert.IsTrue(MemoryMarshal.TryGetArray(parts.AttestationStatement, out ArraySegment<byte> attStmtSegment));
        Assert.AreSame(attestationObject, attStmtSegment.Array);
        Assert.IsTrue(MemoryMarshal.TryGetArray(parts.AuthenticatorData, out ArraySegment<byte> authDataSegment));
        Assert.AreSame(attestationObject, authDataSegment.Array);
    }


    /// <summary>An <c>attestationObject</c> map carrying a fourth, unrecognised member is rejected.</summary>
    [TestMethod]
    public void AttestationObjectWithAnUnrecognisedMemberIsRejected()
    {
        byte[] bytes = EncodeTextKeyedMap(
            CborConformanceMode.Ctap2Canonical,
            ("fmt", TextValue("packed")),
            ("attStmt", EmptyMapValue),
            ("authData", writer => writer.WriteByteString([1, 2, 3])),
            ("unknownmember", TextValue("x")));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(bytes));

        Assert.Contains("unknownmember", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>attestationObject</c> map carrying the <c>fmt</c> member twice is rejected — the CTAP2
    /// canonical CBOR conformance mode rejects the duplicate key at the framework level before this
    /// reader's own logic runs, so the wrapped <see cref="Fido2FormatException"/>'s inner exception
    /// carries the framework's own diagnosis.
    /// </summary>
    [TestMethod]
    public void AttestationObjectWithADuplicateMemberIsRejected()
    {
        byte[] bytes = EncodeTextKeyedMap(
            CborConformanceMode.Lax,
            ("fmt", TextValue("packed")),
            ("fmt", TextValue("also-packed")),
            ("attStmt", EmptyMapValue),
            ("authData", writer => writer.WriteByteString([1, 2, 3])));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(bytes));

        Assert.IsInstanceOfType<CborContentException>(exception.InnerException);
        Assert.Contains("duplicate", exception.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A CBOR value whose root is not a map (here, a bare text string) is rejected.</summary>
    [TestMethod]
    public void AttestationObjectWithANonMapRootIsRejected()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteTextString("not-a-map");
        byte[] bytes = writer.Encode();

        Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(bytes));
    }


    /// <summary>An <c>attestationObject</c> buffer truncated mid-map is rejected.</summary>
    [TestMethod]
    public void AttestationObjectTruncatedMidMapIsRejected()
    {
        byte[] valid = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, EncodeEmptyMap(), [1, 2, 3, 4]);
        byte[] truncated = valid[..^2];

        Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(truncated));
    }


    /// <summary>
    /// A byte trailing an otherwise-valid <c>attestationObject</c> map is rejected — the CTAP2
    /// canonical CBOR conformance mode does not itself check for unconsumed trailing bytes, so this
    /// is this reader's own check.
    /// </summary>
    [TestMethod]
    public void AttestationObjectWithTrailingBytesIsRejected()
    {
        byte[] valid = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, EncodeEmptyMap(), [1, 2, 3, 4]);
        byte[] withTrailingByte = [.. valid, 0xFF];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(withTrailingByte));

        Assert.Contains("trailing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>An <c>attestationObject</c> map missing the required <c>authData</c> member is rejected.</summary>
    [TestMethod]
    public void AttestationObjectMissingARequiredMemberIsRejected()
    {
        byte[] bytes = EncodeTextKeyedMap(
            CborConformanceMode.Ctap2Canonical,
            ("fmt", TextValue("packed")),
            ("attStmt", EmptyMapValue));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AttestationObjectCborReader.Parse(bytes));

        Assert.Contains("authData", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see cref="PackedAttestationStatementCborReader.Parse"/> decodes a minted self-attestation
    /// statement (<c>alg</c>/<c>sig</c>, no <c>x5c</c>).
    /// </summary>
    [TestMethod]
    public void PackedStatementDefaultParsesAMintedSelfStatement()
    {
        byte[] signature = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] cbor = Fido2AttestationTestVectors.EncodePackedAttStmt(WellKnownCoseAlgorithms.Es256, signature, x5c: null);

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared);

        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, statement.Alg);
        Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
        Assert.IsNull(statement.X5c);
    }


    /// <summary>
    /// <see cref="PackedAttestationStatementCborReader.Parse"/> decodes a minted certified-attestation
    /// statement (<c>alg</c>/<c>sig</c>/<c>x5c</c>), copying each <c>x5c</c> entry into a pooled,
    /// correctly tagged <see cref="PkiCertificateMemory"/>.
    /// </summary>
    [TestMethod]
    public void PackedStatementDefaultParsesAMintedCertifiedStatement()
    {
        //Cert-factory carve-out: feeds CreateSelfSignedCa's CertificateRequest-based CA minting; the
        //signature below is a fixed placeholder, never produced by this key.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        //Cert-factory carve-out: feeds CreateLeafAttestationCertificate's CertificateRequest-based
        //leaf minting; the signature below is a fixed placeholder, never produced by this key.
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: Guid.NewGuid());

        byte[] signature = [9, 8, 7, 6, 5];
        byte[] cbor = Fido2AttestationTestVectors.EncodePackedAttStmt(WellKnownCoseAlgorithms.Es256, signature, [leafCert.RawData, rootCert.RawData]);

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(WellKnownCoseAlgorithms.Es256, statement.Alg);
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
            Assert.IsNotNull(statement.X5c);
            Assert.HasCount(2, statement.X5c);
            Assert.IsTrue(statement.X5c[0].IsX509Certificate);
            Assert.IsTrue(statement.X5c[0].AsReadOnlySpan().SequenceEqual(leafCert.RawData));
            Assert.IsTrue(statement.X5c[1].AsReadOnlySpan().SequenceEqual(rootCert.RawData));
        }
        finally
        {
            foreach(PkiCertificateMemory certificate in statement.X5c!)
            {
                certificate.Dispose();
            }
        }
    }


    /// <summary>A packed attestation statement carrying an unrecognised member is rejected.</summary>
    [TestMethod]
    public void PackedStatementDefaultRejectsAnUnrecognisedMember()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("alg");
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteTextString("sig");
        writer.WriteByteString([1, 2, 3]);
        writer.WriteTextString("foo");
        writer.WriteBoolean(true);
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => PackedAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("foo", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A packed attestation statement missing the required <c>sig</c> member is rejected.</summary>
    [TestMethod]
    public void PackedStatementDefaultRejectsAMissingRequiredMember()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("alg");
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => PackedAttestationStatementCborReader.Parse(cbor, BaseMemoryPool.Shared));

        Assert.Contains("sig", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see cref="CredentialPublicKeyCborReader.Read"/> decodes a minted ES256 EC2 COSE_Key, reporting
    /// every top-level label it encountered — including <c>kid</c> (label 2), a label it does not
    /// itself interpret — in wire order.
    /// </summary>
    [TestMethod]
    public void CredentialPublicKeyDefaultParsesAnEs256KeyAndReportsEveryLabel()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey expected = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] kid = [0xAA, 0xBB];

        byte[] cbor = Fido2TestVectors.EncodeRawCoseKey(
            (CoseKeyParameters.Kty, Fido2TestVectors.IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Kid, Fido2TestVectors.BytesValue(kid)),
            (CoseKeyParameters.Alg, Fido2TestVectors.IntValue(WellKnownCoseAlgorithms.Es256)),
            (CoseKeyParameters.Crv, Fido2TestVectors.IntValue(CoseKeyCurves.P256)),
            (CoseKeyParameters.X, Fido2TestVectors.BytesValue(expected.X!.Value.ToArray())),
            (CoseKeyParameters.Y, Fido2TestVectors.BytesValue(expected.Y!.Value.ToArray())));

        CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(cbor);

        Assert.AreEqual(CoseKeyTypes.Ec2, result.CoseKey.Kty);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.CoseKey.Alg);
        Assert.AreEqual(CoseKeyCurves.P256, result.CoseKey.Curve);
        Assert.IsTrue(result.CoseKey.X!.Value.Span.SequenceEqual(expected.X!.Value.Span));
        Assert.IsTrue(result.CoseKey.Y!.Value.Span.SequenceEqual(expected.Y!.Value.Span));
        Assert.AreEqual(cbor.Length, result.BytesConsumed);
        Assert.IsTrue(result.Labels.SequenceEqual(
        [
            CoseKeyParameters.Kty,
            CoseKeyParameters.Kid,
            CoseKeyParameters.Alg,
            CoseKeyParameters.Crv,
            CoseKeyParameters.X,
            CoseKeyParameters.Y
        ]));
    }


    /// <summary>
    /// <see cref="CredentialPublicKeyCborReader.Read"/> decodes a minted EdDSA (Ed25519) OKP COSE_Key.
    /// </summary>
    [TestMethod]
    public void CredentialPublicKeyDefaultParsesAnEdDsaKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            CoseKey expected = Fido2AttestationTestVectors.CreateEd25519CoseKey(keyMaterial.PublicKey, WellKnownCoseAlgorithms.EdDsa);
            byte[] cbor = MdocCborCoseKeyWriter.Write(expected).ToArray();

            CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(cbor);

            Assert.AreEqual(CoseKeyTypes.Okp, result.CoseKey.Kty);
            Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, result.CoseKey.Alg);
            Assert.AreEqual(CoseKeyCurves.Ed25519, result.CoseKey.Curve);
            Assert.IsTrue(result.CoseKey.X!.Value.Span.SequenceEqual(expected.X!.Value.Span));
            Assert.IsNull(result.CoseKey.Y);
            Assert.AreEqual(cbor.Length, result.BytesConsumed);
        }
    }


    /// <summary>
    /// <see cref="CredentialPublicKeyCborReader.Read"/> decodes a minted RS256 RSA COSE_Key — the
    /// wire-parse gap the mdoc-oriented COSE_Key reader this type mirrors does not close.
    /// </summary>
    [TestMethod]
    public void CredentialPublicKeyDefaultParsesARs256Key()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        CoseKey expected = Fido2AssertionOracle.BuildRsaCoseKey(credentialKeys.PublicKey, WellKnownCoseAlgorithms.Rs256);

        //BuildRsaCoseKey returns N and E as slices over the still-pooled key-material buffer, so they
        //are copied out before the material is disposed and the pool reclaims (and clears) that memory.
        byte[] expectedN = expected.N!.Value.ToArray();
        byte[] expectedE = expected.E!.Value.ToArray();
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);

        byte[] cbor = Fido2TestVectors.EncodeRawCoseKey(
            (CoseKeyParameters.Kty, Fido2TestVectors.IntValue(CoseKeyTypes.Rsa)),
            (CoseKeyParameters.Alg, Fido2TestVectors.IntValue(WellKnownCoseAlgorithms.Rs256)),
            (CoseKeyParameters.RsaN, Fido2TestVectors.BytesValue(expectedN)),
            (CoseKeyParameters.RsaE, Fido2TestVectors.BytesValue(expectedE)));

        CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(cbor);

        Assert.AreEqual(CoseKeyTypes.Rsa, result.CoseKey.Kty);
        Assert.AreEqual(WellKnownCoseAlgorithms.Rs256, result.CoseKey.Alg);
        Assert.IsTrue(result.CoseKey.N!.Value.Span.SequenceEqual(expectedN));
        Assert.IsTrue(result.CoseKey.E!.Value.Span.SequenceEqual(expectedE));
        Assert.IsNull(result.CoseKey.X);
        Assert.AreEqual(cbor.Length, result.BytesConsumed);
    }


    /// <summary>
    /// <see cref="CredentialPublicKeyCborReader.Read"/> reports only the bytes the COSE_Key encoding
    /// itself occupies, leaving a trailing extensions slice unconsumed and un-rejected — the contract
    /// <see cref="AuthenticatorDataReader"/> relies on to locate the following extensions data.
    /// </summary>
    [TestMethod]
    public void CredentialPublicKeyDefaultLeavesTrailingExtensionBytesUnconsumed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey expected = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] coseKeyCbor = MdocCborCoseKeyWriter.Write(expected).ToArray();
        byte[] trailingExtensionBytes = [0xA1, 0x63, 0x75, 0x76, 0x6D, 0xF5];
        byte[] sourceWithTrailingBytes = [.. coseKeyCbor, .. trailingExtensionBytes];

        CredentialPublicKeyReadResult result = CredentialPublicKeyCborReader.Read(sourceWithTrailingBytes);

        Assert.AreEqual(coseKeyCbor.Length, result.BytesConsumed);
    }


    /// <summary>
    /// A COSE_Key map carrying the <c>kty</c> label twice is rejected — the CTAP2 canonical CBOR
    /// conformance mode rejects the duplicate label at the framework level.
    /// </summary>
    [TestMethod]
    public void CredentialPublicKeyDefaultRejectsADuplicateLabel()
    {
        byte[] cbor = Fido2TestVectors.EncodeRawCoseKey(
            (CoseKeyParameters.Kty, Fido2TestVectors.IntValue(CoseKeyTypes.Ec2)),
            (CoseKeyParameters.Kty, Fido2TestVectors.IntValue(CoseKeyTypes.Ec2)));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => CredentialPublicKeyCborReader.Read(cbor));

        Assert.IsInstanceOfType<CborContentException>(exception.InnerException);
    }


    /// <summary>
    /// <see cref="AuthenticatorExtensionOutputsCborReader.Read"/> splits a two-extension authenticator
    /// data <c>extensions</c> map into <see cref="Fido2ExtensionOutput"/> entries in wire order, each
    /// aliasing the source buffer.
    /// </summary>
    [TestMethod]
    public void AuthenticatorExtensionOutputsDefaultSplitsATwoExtensionMapInWireOrder()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("credProtect");
        writer.WriteInt32(2);
        writer.WriteTextString("hmac-secret");
        writer.WriteBoolean(true);
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        IReadOnlyList<Fido2ExtensionOutput> outputs = AuthenticatorExtensionOutputsCborReader.Read(cbor);

        Assert.HasCount(2, outputs);
        Assert.AreEqual("credProtect", outputs[0].Identifier);
        Assert.IsTrue(outputs[0].Value.Span.SequenceEqual(new byte[] { 0x02 }));
        Assert.AreEqual("hmac-secret", outputs[1].Identifier);
        Assert.IsTrue(outputs[1].Value.Span.SequenceEqual(new byte[] { 0xF5 }));

        Assert.IsTrue(MemoryMarshal.TryGetArray(outputs[0].Value, out ArraySegment<byte> segment));
        Assert.AreSame(cbor, segment.Array);
    }


    /// <summary>A byte trailing an otherwise-valid authenticator data extensions map is rejected.</summary>
    [TestMethod]
    public void AuthenticatorExtensionOutputsDefaultRejectsTrailingBytes()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("uvm");
        writer.WriteBoolean(true);
        writer.WriteEndMap();
        byte[] valid = writer.Encode();
        byte[] withTrailingByte = [.. valid, 0xFF];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorExtensionOutputsCborReader.Read(withTrailingByte));

        Assert.Contains("trailing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// The capstone proof: an existing packed-certified-attestation registration composition, minted
    /// end to end as real wire <c>attestationObject</c> CBOR bytes (no stub parser anywhere), is
    /// decoded by <see cref="AttestationObjectCborReader.Parse"/> and
    /// <see cref="PackedAttestationStatementCborReader.Parse"/> and verifies successfully through
    /// <see cref="PackedAttestation.Build"/> — proving the shipped CBOR defaults compose with the
    /// existing verifier exactly as the test-local stub parsers they replace did.
    /// </summary>
    [TestMethod]
    public async Task ShippedCborDefaultsComposeWithPackedAttestationBuildEndToEnd()
    {
        //Cert-factory carve-out: feeds CreateSelfSignedCa's CertificateRequest-based CA minting to
        //mint the trust-anchor root.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        //Cert-factory + independent-oracle carve-out: feeds CreateLeafAttestationCertificate and
        //signs the attestation statement below (SignWithEcdsaP256).
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        Guid aaguid = Guid.NewGuid();

        using X509Certificate2 rootCert = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Attestation Root", rootKey);
        using X509Certificate2 leafCert = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCert, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguid);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, toBeSigned);

        //Mint the wire attestationObject CBOR exactly as an authenticator would: the packed attStmt
        //map (alg/sig/x5c) wrapped in the fmt/attStmt/authData attestationObject map.
        byte[] attStmtCbor = Fido2AttestationTestVectors.EncodePackedAttStmt(WellKnownCoseAlgorithms.Es256, signature, [leafCert.RawData, rootCert.RawData]);
        byte[] attestationObjectBytes = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, attStmtCbor, authDataBytes);

        //Split it through the shipped default splitter -- no test-local stub.
        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObjectBytes);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, parts.Format);
        Assert.IsTrue(parts.AuthenticatorData.Span.SequenceEqual(authDataBytes));

        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCert.RawData);

        //Compose PackedAttestation.Build with the shipped default packed-statement CBOR reader -- no
        //stub parser.
        AttestationVerifyDelegate verify = PackedAttestation.Build(
            PackedAttestationStatementCborReader.Parse,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);

        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: parts.AttestationStatement, trustAnchors: [rootPki], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<CertifiedAttestationResult>(result);
        var certified = (CertifiedAttestationResult)result;
        Assert.AreEqual(AttestationType.Unknown, certified.Type);
        Assert.HasCount(2, certified.TrustPath);

        foreach(PkiCertificateMemory certificate in certified.TrustPath)
        {
            certificate.Dispose();
        }
    }


    /// <summary>Encodes the canonical CTAP2 CBOR empty map — a placeholder <c>attStmt</c> value.</summary>
    /// <returns>The CBOR-encoded empty map.</returns>
    private static byte[] EncodeEmptyMap()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Writes the canonical CTAP2 CBOR empty map to <paramref name="writer"/>.</summary>
    /// <param name="writer">The writer to write to.</param>
    private static void EmptyMapValue(CborWriter writer)
    {
        writer.WriteStartMap(0);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Encodes a text-keyed CBOR map from raw key/value-writer pairs in <paramref name="mode"/>, so
    /// shapes that violate CTAP2 canonical CBOR — a duplicate key — can be crafted for the readers'
    /// negative-path tests by passing <see cref="CborConformanceMode.Lax"/> without the writer itself
    /// rejecting them, mirroring <see cref="Fido2TestVectors.EncodeRawCoseKey"/>.
    /// </summary>
    /// <param name="mode">The conformance mode to write with.</param>
    /// <param name="entries">The key/value-writer pairs to emit, in the given order.</param>
    /// <returns>The CBOR-encoded map bytes.</returns>
    private static byte[] EncodeTextKeyedMap(CborConformanceMode mode, params (string Key, Action<CborWriter> WriteValue)[] entries)
    {
        var writer = new CborWriter(mode);
        writer.WriteStartMap(entries.Length);
        foreach((string key, Action<CborWriter> writeValue) in entries)
        {
            writer.WriteTextString(key);
            writeValue(writer);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Builds a map-entry value writer that emits <paramref name="value"/> as a CBOR text string.</summary>
    /// <param name="value">The text to write.</param>
    /// <returns>The value writer, for use with <see cref="EncodeTextKeyedMap"/>.</returns>
    private static Action<CborWriter> TextValue(string value) => writer => writer.WriteTextString(value);
}
