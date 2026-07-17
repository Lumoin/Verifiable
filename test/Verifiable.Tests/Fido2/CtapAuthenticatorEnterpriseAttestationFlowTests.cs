using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The waveep PKG-D real-wire capstones for enterprise attestation (CTAP 2.3 §7.1): three end-to-end
/// flows over the UNCHANGED <see cref="CtapWave2TransportHarness"/>, each reconstructing every assertion
/// from wire bytes only, mirroring <see cref="CtapAuthenticatorConfigFlowTests"/>'s/
/// <see cref="CtapAuthenticatorResetFlowTests"/>'s own real-transport composition. The lifecycle capstone
/// additionally closes the loop through the already-shipped RP-side <see cref="PackedAttestation"/>
/// verifier (waveep R14) — the ONE test in this wave that mints a REAL X.509 certificate chain via
/// <see cref="CtapWaveEpFixtures.BuildRealCertificateProvisioning"/>, rather than PKG-A/B/C's opaque
/// placeholder x5c bytes.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorEnterpriseAttestationFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The rp.id on the vendor's pre-configured list (grants under <c>enterpriseAttestation: 1</c>).</summary>
    private const string VendorListedRpId = "waveep-capstone-vendor.example";

    /// <summary>An rp.id PROVABLY absent from the vendor's pre-configured list (waveep trap 19) — grants only under <c>enterpriseAttestation: 2</c>, the platform-vetted path.</summary>
    private const string PlatformVettedRpId = "waveep-capstone-platform.example";

    /// <summary>An rp.id used for the personal (non-enterprise, parameter-absent) mc request (R15(a)).</summary>
    private const string PersonalRpId = "waveep-capstone-personal.example";

    /// <summary>An rp.id never on any fixture's pre-configured list, for the value-1 fallthrough leg.</summary>
    private const string UnlistedRpId = "waveep-capstone-unlisted.example";

    /// <summary>
    /// The <c>clientDataHash</c> bytes every <see cref="CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest"/>
    /// call in this file seeds with — captured independently for the RP-side verification request, since
    /// the mc request's own carrier is disposed once sent.
    /// </summary>
    private static byte[] ExpectedClientDataHashBytes => CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);


    /// <summary>
    /// R15(c)/the PKG-D lifecycle capstone: ONE device, ONE wire session, all three enterprise-attestation
    /// contexts interleaved, closing through the RP verifier. Sequence: <c>getInfo</c> shows <c>ep:false</c>
    /// (capable, not yet enabled) &#8594; a fresh-device TOKENLESS <c>enableEnterpriseAttestation</c> (0x01,
    /// R12/trap 17 — no PIN is ever established in this capstone) &#8594; <c>getInfo</c> now shows
    /// <c>ep:true</c> &#8594; a PERSONAL mc (no <c>enterpriseAttestation</c> parameter) returns a regular
    /// self attestation with <c>epAtt</c> absent (R15(a)) &#8594; <c>enterpriseAttestation: 1</c> for the
    /// VENDOR-pre-provisioned (seed-listed) rp.id grants <c>epAtt: true</c> &#8594; <c>enterpriseAttestation:
    /// 2</c> for a PLATFORM-vetted rp.id PROVABLY absent from the vendor list (trap 19, asserted against the
    /// same list literal the fixture was seeded with) also grants <c>epAtt: true</c> — proving the two
    /// authorization sources are genuinely independent (R15(c)). The value-1 grant's wire <c>attStmt</c> is
    /// then decoded and driven through the already-shipped RP-side <c>PackedAttestation.VerifyCertifiedAsync</c>
    /// (<see cref="AttestationVerificationRequest.AcceptsEnterpriseAttestation"/><c> = true</c>, trust
    /// anchor = the seeded chain's own root) and VERIFIES as a <see cref="CertifiedAttestationResult"/>; the
    /// SAME bytes against <c>AcceptsEnterpriseAttestation = false</c> reject with
    /// <see cref="Fido2AttestationErrors.SerialNumberExtensionNotPermitted"/> — the shipped WP-Enterprise
    /// check (waveep R14), never touched by this wave.
    /// </summary>
    [TestMethod]
    public async Task LifecycleAcrossAllThreeContextsClosesThroughRpVerifierOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        Guid aaguid = Guid.NewGuid();
        byte[] serialNumber = [0xDE, 0xAD, 0xBE, 0xEF, 0x11];
        IReadOnlyList<string> vendorPreConfiguredRpIds = [VendorListedRpId];

        (CtapEnterpriseAttestationProvisioning provisioning, X509Certificate2 rootCertificateResult) =
            CtapWaveEpFixtures.BuildRealCertificateProvisioning(pool, aaguid, serialNumber, vendorPreConfiguredRpIds);
        using X509Certificate2 rootCertificate = rootCertificateResult;
        using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCertificate.RawData);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator(
            "waveep-capstone-lifecycle", aaguid: aaguid, enterpriseAttestationProvisioning: provisioning);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoBeforeEnable = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoBeforeEnable.Options!.Ep.HasValue, "a capable authenticator must advertise ep, present, even before the first enable.");
        Assert.IsFalse(infoBeforeEnable.Options!.Ep!.Value, "ep must be present-false before enableEnterpriseAttestation is ever invoked.");

        await SendAuthenticatorConfigAsync(
            harness.Transceive, new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation),
            pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoAfterEnable = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoAfterEnable.Options!.Ep!.Value, "enableEnterpriseAttestation must flip ep to true on the wire.");

        CtapMakeCredentialRequest personalRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: PersonalRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x81));
        CtapMakeCredentialResponse personalDecoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, personalRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(personalRequest);
        Assert.IsFalse(personalDecoded.EpAtt.HasValue, "R15(a): the personal (parameter-absent) mc must never carry epAtt.");
        PackedAttestationStatement personalStatement = PackedAttestationStatementCborReader.Parse(personalDecoded.AttStmt!.Value, pool);
        Assert.IsNull(personalStatement.X5c, "R15(a): the personal (parameter-absent) mc must be a regular self attestation, no x5c.");

        CtapMakeCredentialRequest vendorRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: VendorListedRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x82), enterpriseAttestation: 1);
        CtapMakeCredentialResponse vendorDecoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, vendorRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(vendorRequest);
        Assert.IsTrue(vendorDecoded.EpAtt.HasValue && vendorDecoded.EpAtt.Value, "value 1 with a vendor-listed rp.id must grant epAtt: true on the wire.");

        Assert.IsFalse(
            CollectionContains(vendorPreConfiguredRpIds, PlatformVettedRpId),
            "trap 19: the platform-vetted rp.id used below must be PROVABLY absent from the same vendor list literal the fixture was seeded with.");
        CtapMakeCredentialRequest platformRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: PlatformVettedRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x83), enterpriseAttestation: 2);
        CtapMakeCredentialResponse platformDecoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, platformRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(platformRequest);
        Assert.IsTrue(
            platformDecoded.EpAtt.HasValue && platformDecoded.EpAtt.Value,
            "value 2 for an rp.id NOT on the vendor list must still grant epAtt: true (the independent, platform-vetted authorization source).");

        AttestationResult acceptedResult = await VerifyThroughRpAsync(vendorDecoded, rootPki, acceptsEnterpriseAttestation: true, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsInstanceOfType<CertifiedAttestationResult>(acceptedResult, "the wire-minted certified attestation must verify against the seeded root anchor.");

        AttestationResult rejectedResult = await VerifyThroughRpAsync(vendorDecoded, rootPki, acceptsEnterpriseAttestation: false, pool, cancellationToken).ConfigureAwait(false);
        var rejected = Assert.IsInstanceOfType<RejectedAttestationResult>(rejectedResult, "the SAME bytes against AcceptsEnterpriseAttestation=false must be rejected, never silently accepted.");
        Assert.AreEqual(Fido2AttestationErrors.SerialNumberExtensionNotPermitted.Code, rejected.Error.Code);
    }


    /// <summary>
    /// The vendor-facilitated wire proof (CTAP 2.3 line 3345/3350, waveep R4): on ONE capable+enabled
    /// authenticator, <c>enterpriseAttestation: 1</c> for a listed rp.id grants <c>epAtt: true</c> on the
    /// wire, while the SAME value for an UNLISTED rp.id falls through to a regular attestation with
    /// <c>epAtt</c> ABSENT — row 3339's non-vacuous MUST NOT proof, driven over the real transport rather
    /// than in-process (mirroring PKG-C's own equivalent in-process matrix).
    /// </summary>
    [TestMethod]
    public async Task VendorFacilitatedGrantIsGatedByPreConfiguredRpIdListOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        CtapEnterpriseAttestationProvisioning provisioning = CtapWaveEpFixtures.BuildProvisioning(pool, [VendorListedRpId]);
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator(
            "waveep-capstone-vendor", enterpriseAttestationProvisioning: provisioning);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await SendAuthenticatorConfigAsync(
            harness.Transceive, new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation),
            pool, cancellationToken).ConfigureAwait(false);

        CtapMakeCredentialRequest listedRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: VendorListedRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x91), enterpriseAttestation: 1);
        CtapMakeCredentialResponse listedDecoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, listedRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(listedRequest);
        Assert.IsTrue(listedDecoded.EpAtt.HasValue && listedDecoded.EpAtt.Value, "a listed rp.id under value 1 must grant epAtt: true on the wire.");

        CtapMakeCredentialRequest unlistedRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: UnlistedRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x92), enterpriseAttestation: 1);
        CtapMakeCredentialResponse unlistedDecoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, unlistedRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(unlistedRequest);
        Assert.IsFalse(unlistedDecoded.EpAtt.HasValue, "an unlisted rp.id under value 1 must fall through to a regular attestation with epAtt absent on the wire.");
    }


    /// <summary>
    /// The reset capstone (CTAP 2.3 §7.1.3, lines 8276-8278): <c>enableEnterpriseAttestation</c>, then a
    /// bare <c>authenticatorReset</c> (0x07) over the wire, then <c>getInfo</c> shows <c>ep:false</c> again
    /// (the capability survives — <c>ep</c> stays PRESENT — only the enabled bit reverts), then a subsequent
    /// mc with <c>enterpriseAttestation</c> present rejects with <c>InvalidParameter</c> (0x02), the same
    /// code as a never-enabled capable authenticator. Clones
    /// <see cref="CtapAuthenticatorExtensionsFlowTests.ResetClearsMinPinLengthRpIdsOverRealApduTransport"/>'s
    /// shape.
    /// </summary>
    [TestMethod]
    public async Task AuthenticatorResetDisablesEnterpriseAttestationOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        CtapEnterpriseAttestationProvisioning provisioning = CtapWaveEpFixtures.BuildProvisioning(pool, [VendorListedRpId]);
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator(
            "waveep-capstone-reset", enterpriseAttestationProvisioning: provisioning);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await SendAuthenticatorConfigAsync(
            harness.Transceive, new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation),
            pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoAfterEnable = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoAfterEnable.Options!.Ep!.Value, "ep must read true after enable, before the reset below.");

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using(PooledMemory resetResponse = await harness.Transceive(resetRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must succeed on the wire.");
        }

        CtapGetInfoResponse infoAfterReset = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoAfterReset.Options!.Ep.HasValue, "the underlying capability (the seeded provisioning) survives a reset — ep stays PRESENT.");
        Assert.IsFalse(infoAfterReset.Options!.Ep!.Value, "authenticatorReset must disable the enterprise attestation feature — ep reverts to present-false.");

        CtapMakeCredentialRequest postResetRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: VendorListedRpId, enterpriseAttestation: 1);
        CtapCommandException postResetException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, postResetRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(postResetRequest);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, postResetException.StatusCode, "a post-reset mc with enterpriseAttestation present must reject exactly like a never-enabled capable authenticator.");
    }


    /// <summary>
    /// Reconstructs an <see cref="AttestationVerificationRequest"/> from <paramref name="decoded"/>'s own
    /// WIRE bytes only (the raw <c>authData</c>/<c>attStmt</c> the authenticator emitted, re-parsed through
    /// the shipped <see cref="AuthenticatorDataReader"/>/<see cref="PackedAttestationStatementCborReader"/>
    /// codecs — never internal simulator state) and drives it through the already-shipped
    /// <see cref="PackedAttestation"/> verifier, real chain validation
    /// (<see cref="MicrosoftX509Functions.ValidateChainAsync"/>) included.
    /// </summary>
    /// <param name="decoded">The decoded <c>authenticatorMakeCredential</c> response carrying a certified <c>attStmt</c>.</param>
    /// <param name="rootPki">The trust anchor the certified mint's leaf certificate chains to.</param>
    /// <param name="acceptsEnterpriseAttestation">The <see cref="AttestationVerificationRequest.AcceptsEnterpriseAttestation"/> value under test.</param>
    /// <param name="pool">The memory pool every allocation in this reconstruction uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The raw verification result.</returns>
    private static async Task<AttestationResult> VerifyThroughRpAsync(
        CtapMakeCredentialResponse decoded, PkiCertificateMemory rootPki, bool acceptsEnterpriseAttestation, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(decoded.AttStmt!.Value, pool);
        try
        {
            IMemoryOwner<byte> clientDataHashOwner = pool.Rent(ExpectedClientDataHashBytes.Length);
            ExpectedClientDataHashBytes.AsSpan().CopyTo(clientDataHashOwner.Memory.Span);
            using DigestValue clientDataHash = new(clientDataHashOwner, CryptoTags.Sha256Digest);

            AttestationVerifyDelegate verify = PackedAttestation.Build(
                Fido2AttestationTestVectors.CreateStatementParser(statement),
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateProfile,
                MicrosoftX509Functions.ReadCertificateExtensionValue);

            var request = new AttestationVerificationRequest(
                authenticatorDataBytes: decoded.AuthData,
                authenticatorData: authenticatorData,
                clientDataHash: clientDataHash,
                attestationStatement: decoded.AttStmt!.Value,
                trustAnchors: [rootPki],
                validationTime: TestClock.CanonicalEpoch,
                pool: pool)
            {
                AcceptsEnterpriseAttestation = acceptsEnterpriseAttestation
            };

            return await verify(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if(statement.X5c is not null)
            {
                foreach(PkiCertificateMemory certificate in statement.X5c)
                {
                    certificate.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Sends an <c>authenticatorConfig</c> request over <paramref name="transceive"/>'s real transport,
    /// throwing <see cref="CtapCommandException"/> for a non-success status — reaching the caller's next
    /// line is itself the wire proof of <c>CTAP2_OK</c>. Mirrors
    /// <see cref="CtapAuthenticatorConfigFlowTests"/>'s own identically-shaped private helper.
    /// </summary>
    private static async Task SendAuthenticatorConfigAsync(
        Ctap2TransceiveDelegate transceive, CtapAuthenticatorConfigRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWaveConfigFixtures.BuildAuthenticatorConfigEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }
    }


    /// <summary>Reports whether <paramref name="rpIds"/> contains <paramref name="rpId"/> — trap 19's own provably-absent check, with no collection-type dependency beyond <see cref="IReadOnlyList{T}"/>.</summary>
    private static bool CollectionContains(IReadOnlyList<string> rpIds, string rpId)
    {
        for(int i = 0; i < rpIds.Count; i++)
        {
            if(string.Equals(rpIds[i], rpId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
