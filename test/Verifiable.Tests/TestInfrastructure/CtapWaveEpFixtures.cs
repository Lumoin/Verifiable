using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.Fido2;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP waveep (enterprise attestation) test suites: builds a
/// <see cref="CtapEnterpriseAttestationProvisioning"/> fixture through the project's own key-creation
/// seam, mirroring <see cref="CtapCredentialSigningBackend.CreateEs256Default"/>'s own ES256-minting
/// shape rather than reimplementing key generation, and <see cref="Fido2AttestationTestVectors.ToPkiCertificateMemory"/>
/// for the x5c entry rather than a bespoke certificate-memory wrapper.
/// </summary>
internal static class CtapWaveEpFixtures
{
    /// <summary>The key identifier every fixture-minted enterprise attestation key is registered under.</summary>
    private const string AttestationKeyIdentifier = "ctap-waveep-fixture-attestation-key";

    /// <summary>The RP ID a freshly built fixture's pre-configured list names by default.</summary>
    public const string DefaultPreConfiguredRpId = "enterprise.example";

    /// <summary>
    /// The dotted OID of the <c>id-fido-gen-ce-sernum</c> extension (WebAuthn L3 section 8.2.2,
    /// snapshot line 7506), mirroring <c>PackedAttestation.SernumExtensionOid</c>'s own literal —
    /// carried here separately since that constant is private to the RP-side (fenced) verifier.
    /// </summary>
    private const string SernumExtensionOid = "1.3.6.1.4.1.45724.1.1.2";

    /// <summary>The subject distinguished name a fixture-minted real-certificate root CA carries.</summary>
    private const string RootSubjectName = "CN=Ctap Waveep Capstone Root";


    /// <summary>
    /// Builds a <see cref="CtapEnterpriseAttestationProvisioning"/> fixture: a fresh P-256 (ES256)
    /// attestation private key minted through <see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>
    /// and bound via <see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, Tag, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>
    /// (never a bespoke keygen routine), paired with one placeholder DER-shaped x5c entry — opaque
    /// bytes to PKG-A's own state/getInfo surface, which never parses or validates certificate content.
    /// </summary>
    /// <param name="pool">The memory pool the attestation key is minted from.</param>
    /// <param name="preConfiguredRpIds">
    /// The vendor's pre-configured RP ID list, or <see langword="null"/> for a single-entry list
    /// naming <see cref="DefaultPreConfiguredRpId"/>.
    /// </param>
    /// <returns>The built provisioning fixture. The caller owns it and must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted PrivateKey and the wrapped PkiCertificateMemory transfers to the returned CtapEnterpriseAttestationProvisioning, which the caller disposes.")]
    public static CtapEnterpriseAttestationProvisioning BuildProvisioning(MemoryPool<byte> pool, IReadOnlyList<string>? preConfiguredRpIds = null)
    {
        (CtapEnterpriseAttestationProvisioning provisioning, PublicKeyMemory attestationPublicKey) = BuildProvisioningCore(pool, preConfiguredRpIds);
        attestationPublicKey.Dispose();

        return provisioning;
    }


    /// <summary>
    /// Builds the identical fixture <see cref="BuildProvisioning"/> does, but ALSO returns the seeded
    /// attestation key's public half — public material, safe to hand to a test (never the custody
    /// concern <see cref="CtapEnterpriseAttestationProvisioning.AttestationKey"/> itself is) — so a test
    /// can independently verify a certified mint's signature was produced by THIS specific key (trap 11's
    /// "sig by attestation key" proof), the one thing <see cref="BuildProvisioning"/> itself discards.
    /// </summary>
    /// <param name="pool">The memory pool the attestation key is minted from.</param>
    /// <param name="preConfiguredRpIds">The vendor's pre-configured RP ID list — see <see cref="BuildProvisioning"/>.</param>
    /// <returns>The built provisioning fixture and its attestation public key. The caller owns both and must dispose both.</returns>
    public static (CtapEnterpriseAttestationProvisioning Provisioning, PublicKeyMemory AttestationPublicKey) BuildProvisioningWithAttestationPublicKey(
        MemoryPool<byte> pool, IReadOnlyList<string>? preConfiguredRpIds = null) =>
        BuildProvisioningCore(pool, preConfiguredRpIds);


    /// <summary>
    /// The shared core <see cref="BuildProvisioning"/> and <see cref="BuildProvisioningWithAttestationPublicKey"/>
    /// both funnel through, so the two never drift: mints a fresh P-256 (ES256) attestation key pair
    /// through <see cref="CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm, Purpose, MemoryPool{byte}, string?)"/>,
    /// binds the private half via <see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, Tag, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>,
    /// and pairs it with one placeholder DER-shaped x5c entry.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted PrivateKey/PublicKeyMemory and the wrapped PkiCertificateMemory transfers to the returned tuple; both callers dispose what they don't keep.")]
    private static (CtapEnterpriseAttestationProvisioning Provisioning, PublicKeyMemory AttestationPublicKey) BuildProvisioningCore(
        MemoryPool<byte> pool, IReadOnlyList<string>? preConfiguredRpIds)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, pool);

        PrivateKey attestationKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, AttestationKeyIdentifier, keys.PrivateKey.Tag);

        byte[] placeholderCertificateBytes = new byte[32];
        for(int i = 0; i < placeholderCertificateBytes.Length; i++)
        {
            placeholderCertificateBytes[i] = (byte)(0x30 + i);
        }

        PkiCertificateMemory leafCertificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(placeholderCertificateBytes);

        var provisioning = new CtapEnterpriseAttestationProvisioning(
            attestationKey,
            [leafCertificate],
            WellKnownCoseAlgorithms.Es256,
            preConfiguredRpIds ?? [DefaultPreConfiguredRpId]);

        return (provisioning, keys.PublicKey);
    }


    /// <summary>
    /// Builds a REAL X.509-backed <see cref="CtapEnterpriseAttestationProvisioning"/> fixture, for the
    /// PKG-D real-wire capstones that close the loop through the already-shipped RP-side
    /// <c>PackedAttestation.VerifyCertifiedAsync</c> — unlike <see cref="BuildProvisioning"/>'s opaque
    /// 32-byte placeholder (sufficient for PKG-A/B/C's own state/getInfo/mint-shape tests, which never
    /// parse <c>x5c</c>), this fixture mints a section 8.2.1-conformant leaf certificate, via
    /// <see cref="Fido2AttestationTestVectors.CreateSelfSignedCa"/>/<see cref="Fido2AttestationTestVectors.CreateLeafAttestationCertificate"/>,
    /// carrying the <c>id-fido-gen-ce-aaguid</c> extension (matching <paramref name="aaguid"/>) and the
    /// <c>id-fido-gen-ce-sernum</c> extension (WebAuthn L3 section 8.2.2, snapshot line 7506: a single,
    /// non-critical OCTET STRING — never the AAGUID extension's double wrap, waveep trap 10). The
    /// returned provisioning's <see cref="CtapEnterpriseAttestationProvisioning.AttestationKey"/> signs
    /// with the SAME mathematical private key the leaf certificate's own SubjectPublicKeyInfo carries —
    /// built the same way <see cref="Verifiable.Microsoft.MicrosoftKeyMaterialCreator"/>'s own P-256
    /// key-creation delegate shapes a <see cref="PrivateKeyMemory"/> (the raw <c>D</c> scalar, tagged
    /// <see cref="CryptoTags.P256PrivateKey"/>) — so a certified mint this provisioning backs verifies,
    /// end to end, against the leaf certificate's embedded public key.
    /// </summary>
    /// <param name="pool">The memory pool the attestation private key and leaf certificate carrier are minted from.</param>
    /// <param name="aaguid">
    /// The AAGUID to embed in the leaf's <c>id-fido-gen-ce-aaguid</c> extension — MUST equal the
    /// authenticator simulator's own <see cref="CtapAuthenticatorSimulator.Aaguid"/> (threaded to its
    /// constructor's <c>aaguid</c> parameter BEFORE construction) or the RP-side AAGUID cross-check in
    /// <c>PackedAttestation.VerifyCertifiedAsync</c> fails.
    /// </param>
    /// <param name="serialNumber">The device serial number the <c>id-fido-gen-ce-sernum</c> extension carries.</param>
    /// <param name="preConfiguredRpIds">The vendor's pre-configured RP ID list, or <see langword="null"/> for a single-entry list naming <see cref="DefaultPreConfiguredRpId"/>.</param>
    /// <returns>
    /// The built provisioning fixture (x5c carrying the leaf certificate only) and the self-signed root
    /// CA certificate a caller supplies as the RP-side verification's own trust anchor. The caller owns
    /// both and must dispose both (the provisioning via the simulator it seeds, per
    /// <see cref="CtapEnterpriseAttestationProvisioning.Dispose"/>; the root certificate directly).
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted PrivateKey and the wrapped PkiCertificateMemory transfers to the returned CtapEnterpriseAttestationProvisioning; ownership of the root certificate transfers to the returned tuple. Both callers dispose what they don't keep.")]
    public static (CtapEnterpriseAttestationProvisioning Provisioning, X509Certificate2 RootCertificate) BuildRealCertificateProvisioning(
        MemoryPool<byte> pool, Guid aaguid, byte[] serialNumber, IReadOnlyList<string>? preConfiguredRpIds = null)
    {
        // Certificate-factory carve-out: these ECDsa keys are the raw material CreateSelfSignedCa
        // and CreateLeafAttestationCertificate embed and sign the X.509 certificates below with.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        X509Certificate2 rootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa(RootSubjectName, rootKey);

        IReadOnlyList<X509Extension> sernumExtension = [new X509Extension(SernumExtensionOid, EncodeSernumExtensionValue(serialNumber), critical: false)];
        using X509Certificate2 leafCertificate = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            rootCertificate, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit,
            aaguidExtensionValue: aaguid, additionalExtensions: sernumExtension);

        // Bridges the leaf certificate's own private key into a PrivateKeyMemory (the same D scalar
        // the leaf's SubjectPublicKeyInfo carries) rather than minting a fresh, mismatched attestation key.
        ECParameters leafParameters = leafKey.ExportParameters(includePrivateParameters: true);
        IMemoryOwner<byte> privateKeyOwner = pool.Rent(leafParameters.D!.Length);
        leafParameters.D.CopyTo(privateKeyOwner.Memory.Span);
        var privateKeyMemory = new PrivateKeyMemory(privateKeyOwner, CryptoTags.P256PrivateKey);
        CryptographicOperations.ZeroMemory(leafParameters.D);

        PrivateKey attestationKey = CryptographicKeyFactory.CreatePrivateKey(privateKeyMemory, AttestationKeyIdentifier, privateKeyMemory.Tag);
        PkiCertificateMemory leafCertificateMemory = Fido2AttestationTestVectors.ToPkiCertificateMemory(leafCertificate.RawData);

        var provisioning = new CtapEnterpriseAttestationProvisioning(
            attestationKey,
            [leafCertificateMemory],
            WellKnownCoseAlgorithms.Es256,
            preConfiguredRpIds ?? [DefaultPreConfiguredRpId]);

        return (provisioning, rootCertificate);
    }


    /// <summary>
    /// DER-encodes a device serial number as the single OCTET STRING value the WebAuthn L3 section 8.2.2
    /// <c>id-fido-gen-ce-sernum</c> extension carries (snapshot line 7506: "the corresponding value is
    /// encoded as an OCTET STRING") — one layer, never <see cref="Fido2AttestationTestVectors.EncodeAaguidExtensionValue"/>'s
    /// "wrapped in two OCTET STRINGS" AAGUID shape (waveep trap 10).
    /// </summary>
    /// <param name="serialNumber">The device serial number bytes to encode.</param>
    /// <returns>The DER bytes of an OCTET STRING containing <paramref name="serialNumber"/>.</returns>
    internal static byte[] EncodeSernumExtensionValue(byte[] serialNumber)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(serialNumber);

        return writer.Encode();
    }


    /// <summary>
    /// Builds a simulator seeded enterprise-attestation-CAPABLE, via <see cref="BuildProvisioning"/> and
    /// <see cref="CtapWave2AuthenticatorFixtures.CreateSimulator"/> — the one composition every waveep
    /// PKG-B/C/D test needing a capable authenticator shares, rather than each reimplementing the
    /// provisioning-then-construct pair. Ownership of the built provisioning record transfers to the
    /// returned simulator (<see cref="CtapAuthenticatorSimulator.Dispose"/> disposes it) — the caller
    /// must NOT dispose it separately.
    /// </summary>
    /// <param name="runId">The simulator's run identifier, threaded to <see cref="CtapWave2AuthenticatorFixtures.CreateSimulator"/>.</param>
    /// <param name="pool">The memory pool the seeded attestation key and certificate chain are minted from.</param>
    /// <param name="preConfiguredRpIds">The vendor's pre-configured RP ID list — see <see cref="BuildProvisioning"/>.</param>
    /// <param name="timeProvider">The simulator's time source, threaded to <see cref="CtapWave2AuthenticatorFixtures.CreateSimulator"/>.</param>
    /// <returns>The built, enterprise-attestation-capable simulator. The caller owns it and must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built CtapEnterpriseAttestationProvisioning transfers to CtapWave2AuthenticatorFixtures.CreateSimulator's own enterpriseAttestationProvisioning parameter, and from there to the returned CtapAuthenticatorSimulator, whose Dispose disposes it; the analyzer cannot see this transfer through the nested method calls.")]
    public static CtapAuthenticatorSimulator CreateCapableSimulator(
        string runId, MemoryPool<byte> pool, IReadOnlyList<string>? preConfiguredRpIds = null, TimeProvider? timeProvider = null) =>
        CtapWave2AuthenticatorFixtures.CreateSimulator(
            runId, timeProvider: timeProvider, enterpriseAttestationProvisioning: BuildProvisioning(pool, preConfiguredRpIds));


    /// <summary>
    /// Builds a capable simulator (<see cref="CreateCapableSimulator"/>) and immediately drives a
    /// fresh-device tokenless <c>enableEnterpriseAttestation</c> (CTAP 2.3 §6.11.1 line 7999, the no-PIN-
    /// set skip-auth path) so the returned simulator is BOTH capable AND enabled — the composition every
    /// mc Step 9 POSITIVE-path test needs, reached only by driving the real command (mirroring
    /// <c>CtapAuthenticatorConfigTests.FreshDeviceTokenlessEnableEnterpriseAttestationSucceeds</c>'s own
    /// proof that this path succeeds).
    /// </summary>
    /// <param name="runId">The simulator's run identifier.</param>
    /// <param name="pool">The memory pool the seeded attestation key/chain and every request/response use.</param>
    /// <param name="preConfiguredRpIds">The vendor's pre-configured RP ID list — see <see cref="BuildProvisioning"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The built, capable-and-enabled simulator. The caller owns it and must dispose it.</returns>
    /// <exception cref="Fido2FormatException">The fixture's own enable call did not answer <c>CTAP2_OK</c>.</exception>
    public static async Task<CtapAuthenticatorSimulator> CreateCapableEnabledSimulatorAsync(
        string runId, MemoryPool<byte> pool, IReadOnlyList<string>? preConfiguredRpIds, CancellationToken cancellationToken)
    {
        CtapAuthenticatorSimulator simulator = CreateCapableSimulator(runId, pool, preConfiguredRpIds);
        try
        {
            var request = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation);
            using PooledMemory response = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);
            if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
            {
                throw new Fido2FormatException($"Fixture enable-enterprise-attestation failed with CTAP2 status 0x{response.AsReadOnlySpan()[0]:X2}.");
            }
        }
        catch
        {
            simulator.Dispose();
            throw;
        }

        return simulator;
    }
}
