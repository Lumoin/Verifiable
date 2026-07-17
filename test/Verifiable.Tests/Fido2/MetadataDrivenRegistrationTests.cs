using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor.Fido2;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The capstone flow the frontier scout flagged as untested by every studied library: a full,
/// firewalled registration ceremony whose packed attestation trust anchors come exclusively from a
/// JWS-authenticated Metadata BLOB entry — never from an unauthenticated side channel.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-attestation-trust-anchors">W3C Web
/// Authentication Level 3, section 7.1, step 23</see>: "obtain a list of acceptable trust anchors…
/// the FIDO Metadata Service provides one way to obtain such information, using the aaguid in the
/// attestedCredentialData in authData." Every certificate and every key that signs wire material in
/// this file is minted with an independent oracle (raw <see cref="ECDsa"/>, never the library's own
/// signing seam); the credential key, which signs nothing, comes from
/// <see cref="TestKeyMaterialProvider"/>. Every wire structure (the <c>attestationObject</c> CBOR,
/// the Metadata BLOB compact JWS) is decoded through the SHIPPED default readers — no test-local
/// stub parser stands in for either codec.
/// </remarks>
[TestClass]
internal sealed class MetadataDrivenRegistrationTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The correlation identifier every verification call in this fixture uses.</summary>
    private const string CorrelationId = "metadata-driven-registration-test-correlation";

    /// <summary>The fixed instant every certificate/BLOB in this file validates against.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The tenant every BLOB verification in this file uses.</summary>
    private static TenantId DefaultTenantId { get; } = new("metadata-driven-registration-tests");

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as unique.</summary>
    private static IsCredentialIdUniqueDelegate AlwaysUnique { get; } = static (_, _) => ValueTask.FromResult(true);


    /// <summary>
    /// A packed-certified registration whose trust anchors are obtained exclusively from a
    /// JWS-verified Metadata BLOB entry, matched by AAGUID, with an accepting status, succeeds end
    /// to end through <see cref="Fido2RegistrationVerifier"/>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The matched entry's disposal is subsumed by the enclosing MetadataBlob's Dispose() (a MetadataBlobPayload disposes every entry it owns), called in this method's finally block; disposing the entry a second time would be redundant, not a leak.")]
    public async Task VerifiedBlobEntryTrustAnchorsDriveASuccessfulCertifiedRegistration()
    {
        using RegistrationFixture fixture = CreateRegistrationFixture(WellKnownAuthenticatorStatuses.FidoCertified);

        //Wires the serial-number resolve/persist pair under Required so this capstone also proves the
        //jti persist-after-accept analog fires, end to end, on the ceremony's accepted path — the
        //write half of MDS-3764-1's "write the verified object to a local cache" step.
        var serialNumberStore = new FakeMetadataBlobSerialNumberStore();
        MetadataBlobResult blobResult = await VerifyBlobAsync(
            fixture.BlobBytes, fixture.MdsRootPki,
            serialNumberPolicy: MetadataBlobSerialNumberPolicy.Required,
            resolvePreviousSerialNumber: serialNumberStore.ResolveAsync,
            persistVerifiedBlob: serialNumberStore.PersistAsync);
        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(blobResult);
        MetadataBlob blob = ((VerifiedMetadataBlobResult)blobResult).Blob;
        try
        {
            Assert.HasCount(1, serialNumberStore.Persisted);
            Assert.AreEqual(DefaultTenantId, serialNumberStore.Persisted[0].TenantId);
            Assert.AreEqual(blob.Payload.No, serialNumberStore.Persisted[0].SerialNumber);

            Assert.IsTrue(MetadataBlobPayloadQueries.TryFindEntryByAaguid(blob.Payload, fixture.Aaguid, out MetadataBlobPayloadEntry? entry));
            MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry!);
            Assert.IsTrue(evaluation.Accepted);

            IReadOnlyList<PkiCertificateMemory> trustAnchors = MetadataBlobPayloadQueries.GetAttestationTrustAnchors(entry!, BaseMemoryPool.Shared);
            try
            {
                Assert.HasCount(1, trustAnchors);

                Fido2RegistrationOutcome outcome = await RunRegistrationAsync(fixture, trustAnchors);

                Assert.IsInstanceOfType<CertifiedAttestationResult>(outcome.AttestationResult);
                Assert.IsTrue(outcome.IsAcceptable);
                outcome.CredentialRecord?.Dispose();
            }
            finally
            {
                foreach(PkiCertificateMemory anchor in trustAnchors)
                {
                    anchor.Dispose();
                }
            }
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>
    /// The same flow with a REVOKED entry stops at the status gate: the BLOB itself verifies (it is
    /// not tampered), but <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/> rejects the entry, so
    /// a correct relying party never extracts its trust anchors, and a registration attempted with no
    /// anchors is rejected for lacking a trust anchor — not for a chain failure, proving the gate
    /// stops the flow before chain validation is even reached.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The matched entry's disposal is subsumed by the enclosing MetadataBlob's Dispose() (a MetadataBlobPayload disposes every entry it owns), called in this method's finally block; disposing the entry a second time would be redundant, not a leak.")]
    public async Task RevokedBlobEntryStopsAtTheStatusGateBeforeChainValidation()
    {
        using RegistrationFixture fixture = CreateRegistrationFixture(WellKnownAuthenticatorStatuses.Revoked);

        MetadataBlobResult blobResult = await VerifyBlobAsync(fixture.BlobBytes, fixture.MdsRootPki);
        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(blobResult);
        MetadataBlob blob = ((VerifiedMetadataBlobResult)blobResult).Blob;
        try
        {
            Assert.IsTrue(MetadataBlobPayloadQueries.TryFindEntryByAaguid(blob.Payload, fixture.Aaguid, out MetadataBlobPayloadEntry? entry));
            MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry!);
            Assert.IsFalse(evaluation.Accepted);

            //A correct relying party gates on Accepted and never calls GetAttestationTrustAnchors
            //here; the registration below is run with no anchors at all, the exact shape the gate
            //produces, and rejects for that reason specifically.
            Fido2RegistrationOutcome outcome = await RunRegistrationAsync(fixture, []);

            Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
            Assert.AreEqual(Fido2AttestationErrors.NoTrustAnchors.Code, ((RejectedAttestationResult)outcome.AttestationResult).Error.Code);
            Assert.IsFalse(outcome.IsAcceptable);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>
    /// A tampered BLOB never yields anchors at all: verification rejects with
    /// <see cref="Fido2MetadataErrors.InvalidBlobSignature"/>, and the exhaustive switch a correct
    /// caller writes over <see cref="MetadataBlobResult"/> has no code path from that rejection to
    /// <see cref="MetadataBlobPayloadQueries.GetAttestationTrustAnchors"/> — proven directly by
    /// failing the test if the tampered BLOB ever verifies.
    /// </summary>
    [TestMethod]
    public async Task TamperedBlobNeverYieldsTrustAnchors()
    {
        using RegistrationFixture fixture = CreateRegistrationFixture(WellKnownAuthenticatorStatuses.FidoCertified);
        byte[] tamperedBlobBytes = MetadataBlobTestVectors.TamperSignatureSegment(fixture.BlobBytes);

        MetadataBlobResult blobResult = await VerifyBlobAsync(tamperedBlobBytes, fixture.MdsRootPki);

        _ = blobResult switch
        {
            VerifiedMetadataBlobResult verified => FailBecauseTamperedBlobVerified(verified),
            RejectedMetadataBlobResult rejected => AssertRejectedForTamperedSignature(rejected),
            MetadataBlobStoreUnavailableResult unavailable => FailBecauseStoreUnavailable(unavailable),
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(MetadataBlobResult)} subtype '{blobResult.GetType().Name}'; the closed sum admits only the three sibling records.")
        };

        //A tampered Metadata BLOB must not verify — no trust anchors may ever be derived from it.
        static bool FailBecauseTamperedBlobVerified(VerifiedMetadataBlobResult verified)
        {
            verified.Blob.Dispose();
            Assert.Fail("A tampered Metadata BLOB must not verify — no trust anchors may ever be derived from it.");

            return false;
        }

        //The tamper must be detected specifically as an invalid signature, not any other rejection reason.
        static bool AssertRejectedForTamperedSignature(RejectedMetadataBlobResult rejected)
        {
            Assert.AreEqual(Fido2MetadataErrors.InvalidBlobSignature.Code, rejected.Error.Code);

            return true;
        }

        //This capstone wires no Required policy without its delegates — a StoreUnavailable result
        //would signal a fixture misconfiguration, not the tamper this test exercises.
        static bool FailBecauseStoreUnavailable(MetadataBlobStoreUnavailableResult unavailable)
        {
            Assert.Fail($"This capstone wires no Required policy without its delegates — a StoreUnavailable result ('{unavailable.Error.Code}') would signal a fixture misconfiguration, not the tamper this test exercises.");

            return false;
        }
    }


    /// <summary>
    /// Builds and runs the <see cref="MetadataBlobVerification"/> verifier over
    /// <paramref name="blobBytes"/>. Defaults to <see cref="MetadataBlobSerialNumberPolicy.NotTracked"/>
    /// and <see cref="MetadataBlobRevocationPolicy.NotChecked"/> — the postures every capstone test
    /// but the persist-observing leg needs — overridden explicitly by a caller that wires the
    /// resolve/persist pair.
    /// </summary>
    private async Task<MetadataBlobResult> VerifyBlobAsync(
        byte[] blobBytes,
        PkiCertificateMemory mdsRootPki,
        MetadataBlobSerialNumberPolicy serialNumberPolicy = MetadataBlobSerialNumberPolicy.NotTracked,
        ResolvePreviousMetadataBlobSerialNumberAsyncDelegate? resolvePreviousSerialNumber = null,
        PersistVerifiedMetadataBlobAsyncDelegate? persistVerifiedBlob = null)
    {
        VerifyMetadataBlobAsyncDelegate verify = MetadataBlobVerification.Build(
            MetadataBlobReader.Read,
            MicrosoftX509Functions.ValidateChainAsync,
            resolvePreviousSerialNumber: resolvePreviousSerialNumber,
            persistVerifiedBlob: persistVerifiedBlob);

        var request = new MetadataBlobVerificationRequest(
            blobBytes, [mdsRootPki], ValidationTime, DefaultTenantId,
            serialNumberPolicy, MetadataBlobRevocationPolicy.NotChecked, BaseMemoryPool.Shared);

        return await verify(request, TestContext.CancellationToken);
    }


    /// <summary>
    /// Runs the packed-certified registration ceremony through the real
    /// <see cref="Fido2RegistrationVerifier"/> composition, decoding the wire
    /// <c>attestationObject</c>/<c>attStmt</c> through the SHIPPED CBOR defaults.
    /// </summary>
    private async Task<Fido2RegistrationOutcome> RunRegistrationAsync(RegistrationFixture fixture, IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        AttestationObjectParts parts = AttestationObjectCborReader.Parse(fixture.AttestationObjectBytes);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedAttestation.Build(
                PackedAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateProfile,
                MicrosoftX509Functions.ReadCertificateExtensionValue)));

        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(fixture.AuthenticatorDataBytes, CredentialPublicKeyCborReader.Read, BaseMemoryPool.Shared);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(fixture.ClientDataJsonBytes),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: fixture.RpIdHash);

        return await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            parts.AttestationStatement,
            fixture.AuthenticatorDataBytes,
            fixture.ClientDataJsonBytes,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors,
            ValidationTime,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);
    }


    /// <summary>
    /// Mints the full fixture: an independent "attestation root" CA (the trust anchor the Metadata
    /// BLOB entry vouches for, never itself an MDS signing certificate), a packed §8.2.1-conformant
    /// attestation leaf issued from it, a credential key pair, the real wire <c>authData</c>/
    /// <c>clientDataJSON</c>/<c>attestationObject</c> bytes, a self-contained MDS root/signer PKI, and
    /// a signed Metadata BLOB whose single entry's <c>metadataStatement.attestationRootCertificates</c>
    /// carries the attestation root — vouched for only because the JWS-authenticated BLOB says so.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every minted certificate/key transfers to the returned RegistrationFixture, which the caller disposes.")]
    private static RegistrationFixture CreateRegistrationFixture(string status)
    {
        Guid aaguid = Guid.NewGuid();

        //Cert-factory carve-out: a CA key that only ever mints attestationRootCertificate
        //(CertificateRequest, via MetadataBlobTestVectors.CreateMdsRootCa) — it never signs wire
        //material directly, so no key-material-provider substitute could stand in for it.
        using ECDsa attestationRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Attestation Root", attestationRootKey);

        //Independent-oracle carve-out: besides minting attestationLeafCertificate, this key signs
        //the packed attStmt's toBeSigned transcript directly (SignWithEcdsaP256, below) outside the
        //library's own signing seam, so the shipped PackedAttestation verifier under test is
        //exercised against genuinely external wire material.
        ECDsa attestationLeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationLeafCertificate = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            attestationRootCertificate, attestationLeafKey, isCertificateAuthority: false,
            Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        //The credential key never signs or verifies anything in this capstone — only its P-256
        //public point is embedded in attestedCredentialData — so it is mere fixture material.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeyMaterial.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        byte[] authenticatorDataBytes = BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId);
        byte[] clientDataJsonBytes = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, ValidChallenge, ValidOrigin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJsonBytes, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(attestationLeafKey, toBeSigned);

        byte[] attStmtCbor = EncodePackedAttStmt(WellKnownCoseAlgorithms.Es256, signature, [attestationLeafCertificate.RawData]);
        byte[] attestationObjectBytes = EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, attStmtCbor, authenticatorDataBytes);

        //Cert-factory carve-out: a CA key that only ever mints mdsRootCertificate (CertificateRequest,
        //via MetadataBlobTestVectors.CreateMdsRootCa) — it never signs wire material directly.
        ECDsa mdsRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 mdsRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Root Capstone", mdsRootKey);

        //Independent-oracle carve-out: besides minting mdsSigningCertificate, this key produces the
        //Metadata BLOB's compact-JWS signature directly (SignEs256, below) outside the library's own
        //signing seam, so the shipped MetadataBlobVerification verifier under test is exercised
        //against genuinely external wire material.
        ECDsa mdsSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 mdsSigningCertificate = MetadataBlobTestVectors.CreateMdsSigningCertificate(mdsRootCertificate, mdsSigningKey);

        string metadataStatementJson = MetadataBlobTestVectors.BuildMetadataStatementJson([attestationRootCertificate.RawData]);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(
            aaguid: aaguid,
            metadataStatementJson: metadataStatementJson,
            statusReportJsons: [MetadataBlobTestVectors.BuildStatusReportJson(status, "2020-01-01")]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [mdsSigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(mdsSigningKey, data));

        PkiCertificateMemory mdsRootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(mdsRootCertificate.RawData);

        return new RegistrationFixture(
            aaguid, rpIdHash, authenticatorDataBytes, clientDataJsonBytes, attestationObjectBytes, blobBytes, mdsRootPki,
            attestationRootCertificate, attestationLeafCertificate, attestationLeafKey, credentialKeyMaterial,
            mdsRootCertificate, mdsSigningCertificate, mdsRootKey, mdsSigningKey);
    }


    /// <summary>
    /// Assembles a registration <c>authData</c> binary layout (per WebAuthn L3 section 6.1) with the
    /// <c>UP</c>/<c>UV</c>/<c>AT</c> bits set, mirroring
    /// <see cref="Fido2AttestationTestVectors.BuildAuthenticatorData"/> but taking an explicit
    /// <paramref name="credentialId"/> and <paramref name="rpIdHash"/>.
    /// </summary>
    private static byte[] BuildRegistrationAuthenticatorData(byte[] rpIdHash, Guid aaguid, CoseKey credentialPublicKey, byte[] credentialId)
    {
        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialDataBytes = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);

        return Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialDataBytes);
    }


    /// <summary>
    /// Encodes a valid <c>attestationObject</c> CBOR map (<c>fmt</c>/<c>attStmt</c>/<c>authData</c>) in
    /// the CTAP2 canonical CBOR encoding form, as a real authenticator would — mirrors the shipped
    /// CBOR defaults' own test-vector idiom.
    /// </summary>
    private static byte[] EncodeAttestationObject(string format, byte[] attStmtCbor, byte[] authData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(format);
        writer.WriteTextString("attStmt");
        writer.WriteEncodedValue(attStmtCbor);
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Encodes a valid <c>packed</c> <c>attStmt</c> CBOR map (<c>alg</c>/<c>sig</c>/<c>x5c</c>) in the
    /// CTAP2 canonical CBOR encoding form.
    /// </summary>
    private static byte[] EncodePackedAttStmt(int alg, byte[] sig, IReadOnlyList<byte[]> x5c)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("alg");
        writer.WriteInt32(alg);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5c.Count);
        foreach(byte[] certificate in x5c)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }
}


/// <summary>
/// The minted fixture <see cref="MetadataDrivenRegistrationTests"/> runs its capstone flows against:
/// an independent attestation root/leaf pair, the credential key, the real wire bytes, and a
/// self-contained MDS root/signer PKI plus the signed Metadata BLOB vouching for the attestation
/// root. Owns and disposes every certificate and key.
/// </summary>
internal sealed class RegistrationFixture: IDisposable
{
    /// <summary>Initializes a new <see cref="RegistrationFixture"/>, taking ownership of every certificate and key.</summary>
    public RegistrationFixture(
        Guid aaguid,
        byte[] rpIdHash,
        byte[] authenticatorDataBytes,
        byte[] clientDataJsonBytes,
        byte[] attestationObjectBytes,
        byte[] blobBytes,
        PkiCertificateMemory mdsRootPki,
        X509Certificate2 attestationRootCertificate,
        X509Certificate2 attestationLeafCertificate,
        ECDsa attestationLeafKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial,
        X509Certificate2 mdsRootCertificate,
        X509Certificate2 mdsSigningCertificate,
        ECDsa mdsRootKey,
        ECDsa mdsSigningKey)
    {
        Aaguid = aaguid;
        RpIdHash = rpIdHash;
        AuthenticatorDataBytes = authenticatorDataBytes;
        ClientDataJsonBytes = clientDataJsonBytes;
        AttestationObjectBytes = attestationObjectBytes;
        BlobBytes = blobBytes;
        MdsRootPki = mdsRootPki;
        AttestationRootCertificate = attestationRootCertificate;
        AttestationLeafCertificate = attestationLeafCertificate;
        AttestationLeafKey = attestationLeafKey;
        CredentialKeyMaterial = credentialKeyMaterial;
        MdsRootCertificate = mdsRootCertificate;
        MdsSigningCertificate = mdsSigningCertificate;
        MdsRootKey = mdsRootKey;
        MdsSigningKey = mdsSigningKey;
    }


    /// <summary>Gets the AAGUID embedded in <see cref="AuthenticatorDataBytes"/> and the matching Metadata BLOB entry.</summary>
    public Guid Aaguid { get; }

    /// <summary>Gets the 32-byte RP ID hash embedded in <see cref="AuthenticatorDataBytes"/>.</summary>
    public byte[] RpIdHash { get; }

    /// <summary>Gets the raw wire <c>authData</c> bytes.</summary>
    public byte[] AuthenticatorDataBytes { get; }

    /// <summary>Gets the raw wire <c>clientDataJSON</c> bytes.</summary>
    public byte[] ClientDataJsonBytes { get; }

    /// <summary>Gets the raw wire <c>attestationObject</c> CBOR bytes.</summary>
    public byte[] AttestationObjectBytes { get; }

    /// <summary>Gets the signed compact-JWS Metadata BLOB bytes.</summary>
    public byte[] BlobBytes { get; }

    /// <summary>Gets the pooled certificate carrier for <see cref="MdsRootCertificate"/>, the MDS BLOB trust anchor.</summary>
    public PkiCertificateMemory MdsRootPki { get; }

    /// <summary>Gets the independent attestation root CA certificate the Metadata BLOB entry vouches for.</summary>
    public X509Certificate2 AttestationRootCertificate { get; }

    /// <summary>Gets the packed §8.2.1-conformant attestation leaf certificate, issued by <see cref="AttestationRootCertificate"/>.</summary>
    public X509Certificate2 AttestationLeafCertificate { get; }

    /// <summary>Gets the attestation leaf's private key.</summary>
    public ECDsa AttestationLeafKey { get; }

    /// <summary>Gets the credential's own key material — mere fixture material, never used for signing or verification.</summary>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CredentialKeyMaterial { get; }

    /// <summary>Gets the MDS root CA certificate (private key attached), the Metadata BLOB trust anchor.</summary>
    public X509Certificate2 MdsRootCertificate { get; }

    /// <summary>Gets the MDS BLOB-signing leaf certificate (private key attached).</summary>
    public X509Certificate2 MdsSigningCertificate { get; }

    /// <summary>Gets the MDS root CA's private key.</summary>
    public ECDsa MdsRootKey { get; }

    /// <summary>Gets the MDS BLOB signer's private key.</summary>
    public ECDsa MdsSigningKey { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        MdsRootPki.Dispose();
        AttestationRootCertificate.Dispose();
        AttestationLeafCertificate.Dispose();
        AttestationLeafKey.Dispose();
        CredentialKeyMaterial.PublicKey.Dispose();
        CredentialKeyMaterial.PrivateKey.Dispose();
        MdsRootCertificate.Dispose();
        MdsSigningCertificate.Dispose();
        MdsRootKey.Dispose();
        MdsSigningKey.Dispose();
    }
}
