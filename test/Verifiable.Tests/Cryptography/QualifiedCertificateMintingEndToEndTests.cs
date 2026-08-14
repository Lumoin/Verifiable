using System;
using System.Security;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.QualifiedCertificateMintingFixtures;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The end-to-end spine for <see cref="QualifiedCertificateMinting"/> and
/// <see cref="QualifiedTrustedListComposition"/>: a minted root Certification Authority and the qualified
/// certificate it issues, wired into the minimal <see cref="TrustedList"/> graph
/// <see cref="QualifiedTrustedListComposition.ComposeQualifiedTrustedList"/> builds, determined through
/// <see cref="TrustedListQualification.DetermineEuQualifiedCertificateAsync"/> with a REAL RFC 5280 §6.1
/// certification-path match — not the byte-equality stand-in the procedure conformance vectors use — built
/// on <see cref="MicrosoftX509Functions.ValidateChainAsync"/> per <see cref="MatchCertificateToTrustServiceAsyncDelegate"/>'s
/// own remarks.
/// </summary>
[TestClass]
internal sealed class QualifiedCertificateMintingEndToEndTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The root's validity start.</summary>
    private static DateTimeOffset RootNotBefore { get; } = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The root's validity end.</summary>
    private static DateTimeOffset RootNotAfter { get; } = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The leaf's validity start, inside the root's own validity.</summary>
    private static DateTimeOffset LeafNotBefore { get; } = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The leaf's validity end.</summary>
    private static DateTimeOffset LeafNotAfter { get; } = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The evaluation instant the determination runs at — inside the leaf's validity, after <see cref="LeafNotBefore"/>.</summary>
    private static DateTimeOffset EvaluationTime { get; } = new(2025, 7, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// A qualified electronic-signature certificate minted directly under a self-signed root, checked against
    /// the composed trusted list, determines <see cref="EuQualifiedCertificateIndication.QualifiedForESignature"/>
    /// per <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
    /// ETSI TS 119 615 V1.4.1 clause 4.4</see>, with the PRO-4.3.4-03 check (ii) match resolved by REAL X.509
    /// certification-path validation over the wire-shaped DER bytes the minter produced — the root recognises
    /// the leaf because <see cref="MicrosoftX509Functions.ValidateChainAsync"/> builds and validates the path
    /// from the leaf to the root as sole trust anchor, not because the bytes are compared for equality.
    /// </summary>
    [TestMethod]
    public async Task MintedElectronicSignatureCertificateQualifiesThroughRealChainValidationMatch()
    {
        const string ProviderCountryCode = "FI";
        const string ProviderOrganizationName = "Verifiable Root Provider";
        const string PolicyOid = "0.4.0.194112.1.2";

        (PublicKeyMemory rootPublicKey, PrivateKeyMemory rootPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName(ProviderCountryCode, ProviderOrganizationName, "Verifiable Test Root CA"), RootNotBefore, RootNotAfter,
            rootPublicKey, rootPrivateKey, pathLengthConstraint: 1, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        rootPublicKey.Dispose();

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            root, CreateSubjectName(ProviderCountryCode, "Verifiable QC Provider", "Alice Esign"), LeafNotBefore, LeafNotAfter,
            leafPublicKey, rootPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: true,
            certificatePolicyOids: [PolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        rootPrivateKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        using TrustedList trustedList = QualifiedTrustedListComposition.ComposeQualifiedTrustedList(
            root, EuQualifiedCertificateType.ElectronicSignature, [new LocalizedText("en", ProviderOrganizationName)],
            ProviderCountryCode, LeafNotBefore, BaseMemoryPool.Shared);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, leaf, facts, EvaluationTime, CreateRealChainValidationMatch(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, "The determination must not fail when the leaf validates to the trusted root.");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESignature, result.Indications, "The minted electronic-signature dimension must be confirmed Qualified.");
    }


    /// <summary>
    /// The same wire-coupled pass as <see cref="MintedElectronicSignatureCertificateQualifiesThroughRealChainValidationMatch"/>,
    /// for the electronic-seal dimension: a qualified electronic-seal certificate, checked against a trusted
    /// list <see cref="QualifiedTrustedListComposition.ComposeQualifiedTrustedList"/> composed for
    /// <see cref="EuQualifiedCertificateType.ElectronicSeal"/>, determines
    /// <see cref="EuQualifiedCertificateIndication.QualifiedForESeal"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
    /// ETSI TS 119 615 V1.4.1 clause 4.4</see>. This pins <see cref="QualifiedTrustedListComposition.DefaultIdentifyingCondition"/>'s
    /// <c>KeyUsage{nonRepudiation}</c> criterion as load-bearing for BOTH dimensions: the composed graph's
    /// <see cref="QualificationElement.Condition"/> is the same one the esign pass above already matches, and
    /// <see cref="QualifiedCertificateMinting.MintQualifiedCertificateAsync"/> writes that same critical
    /// <c>KeyUsage</c> bit independent of the declared <see cref="EuQualifiedCertificateType"/>, so an
    /// eseal-dimension leaf must match it too.
    /// </summary>
    [TestMethod]
    public async Task MintedElectronicSealCertificateQualifiesThroughRealChainValidationMatch()
    {
        const string ProviderCountryCode = "FI";
        const string ProviderOrganizationName = "Verifiable Root Provider";
        const string PolicyOid = "0.4.0.194112.1.3";

        (PublicKeyMemory rootPublicKey, PrivateKeyMemory rootPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName(ProviderCountryCode, ProviderOrganizationName, "Verifiable Test Root CA"), RootNotBefore, RootNotAfter,
            rootPublicKey, rootPrivateKey, pathLengthConstraint: 1, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        rootPublicKey.Dispose();

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            root, CreateSubjectName(ProviderCountryCode, "Verifiable QC Provider", "Acme Seal"), LeafNotBefore, LeafNotAfter,
            leafPublicKey, rootPrivateKey, EuQualifiedCertificateType.ElectronicSeal, requiresQualifiedSignatureCreationDevice: true,
            certificatePolicyOids: [PolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        rootPrivateKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        using TrustedList trustedList = QualifiedTrustedListComposition.ComposeQualifiedTrustedList(
            root, EuQualifiedCertificateType.ElectronicSeal, [new LocalizedText("en", ProviderOrganizationName)],
            ProviderCountryCode, LeafNotBefore, BaseMemoryPool.Shared);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, leaf, facts, EvaluationTime, CreateRealChainValidationMatch(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, "The determination must not fail when the leaf validates to the trusted root.");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESeal, result.Indications, "The minted electronic-seal dimension must be confirmed Qualified.");
    }


    /// <summary>
    /// A qualified electronic-signature certificate minted from a COMPRESSED P-256 subject public key — the
    /// project's own <see cref="MicrosoftKeyMaterialCreator.CreateP256Keys"/> output, tagged
    /// <see cref="EncodingScheme.EcCompressed"/>, taken verbatim with no test-side normalization — still
    /// yields a <c>subjectPublicKeyInfo</c> that decodes and validates: <see cref="MicrosoftX509Functions.ValidateChainAsync"/>
    /// builds and validates a real RFC 5280 §6.1 certification path from the leaf to its issuing root, which
    /// requires both the platform X.509 parser to decode the written SPKI and the ECDSA signature to verify
    /// against the decompressed point — proving <see cref="QualifiedCertificateMinting"/>'s elliptic-curve
    /// <c>subjectPublicKeyInfo</c> branch decompresses a compressed SEC1 point it is handed rather than
    /// writing it verbatim.
    /// </summary>
    [TestMethod]
    public async Task MintedCertificateFromCompressedPublicKeyValidatesThroughRealChain()
    {
        const string ProviderCountryCode = "FI";
        const string ProviderOrganizationName = "Verifiable Root Provider";
        const string PolicyOid = "0.4.0.194112.1.2";

        (PublicKeyMemory rootPublicKey, PrivateKeyMemory rootPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName(ProviderCountryCode, ProviderOrganizationName, "Verifiable Test Root CA"), RootNotBefore, RootNotAfter,
            rootPublicKey, rootPrivateKey, pathLengthConstraint: 1, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        rootPublicKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> compressedLeafKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        Assert.AreEqual(EncodingScheme.EcCompressed, compressedLeafKeys.PublicKey.Tag.Get<EncodingScheme>(), "This test's premise: the library's own P-256 creator hands out the compressed SEC1 form.");

        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            root, CreateSubjectName(ProviderCountryCode, "Verifiable QC Provider", "Alice Esign"), LeafNotBefore, LeafNotAfter,
            compressedLeafKeys.PublicKey, rootPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: true,
            certificatePolicyOids: [PolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        compressedLeafKeys.PublicKey.Dispose();
        rootPrivateKey.Dispose();
        compressedLeafKeys.PrivateKey.Dispose();

        using PublicKeyMemory validatedLeafKey = await MicrosoftX509Functions.ValidateChainAsync(
            [leaf], [root], EvaluationTime, BaseMemoryPool.Shared, checkRevocation: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(validatedLeafKey);
    }


    /// <summary>
    /// Composes a <see cref="MatchCertificateToTrustServiceAsyncDelegate"/> the way that delegate's own
    /// remarks describe: each <see cref="X509CertificateIdentity"/> entry of a service's digital identity is
    /// tried, in turn, as the sole RFC 5280 §6.1 trust anchor for the certificate under determination through
    /// <see cref="MicrosoftX509Functions.ValidateChainAsync"/>, falling back to a direct byte comparison for
    /// the path-length-zero case (the certificate under determination IS the trust anchor's own certificate).
    /// </summary>
    private static MatchCertificateToTrustServiceAsyncDelegate CreateRealChainValidationMatch() =>
        async (certificate, serviceDigitalIdentity, validationTime, pool, cancellationToken) =>
        {
            foreach(ServiceDigitalIdentityEntry entry in serviceDigitalIdentity.Entries)
            {
                if(entry is not X509CertificateIdentity certificateEntry)
                {
                    continue;
                }

                if(certificate.AsReadOnlySpan().SequenceEqual(certificateEntry.Certificate.AsReadOnlySpan()))
                {
                    return true;
                }

                try
                {
                    using PublicKeyMemory _ = await MicrosoftX509Functions.ValidateChainAsync(
                        [certificate], [certificateEntry.Certificate], validationTime, pool, checkRevocation: null, cancellationToken).ConfigureAwait(false);

                    return true;
                }
                catch(SecurityException)
                {
                    //This entry did not recognise the certificate; the next one, if any, gets a chance.
                }
            }

            return false;
        };
}
