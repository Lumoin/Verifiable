using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The two worlds the informative validation examples of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 Annex A</see> describe.
/// </summary>
internal enum AnnexAValidationExample
{
    /// <summary>
    /// Clause A.3 example 1, "Revoked certificate": a signing certificate revoked after the signature and its
    /// signature time-stamp were produced. Clause A.3.2 expects basic validation to be
    /// <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> and clause A.3.3 expects validation with time to be
    /// <c>TOTAL-PASSED</c>.
    /// </summary>
    RevokedCertificate = 0,

    /// <summary>
    /// Clause A.3.4 example 2, "Revoked CA certificate": the certification authority that issued the signing
    /// certificate is revoked, the authority that produced the signature time-stamp has expired by validation
    /// time, and an archive time-stamp was produced while everything was still sound. Clauses A.3.5 and A.3.6
    /// expect <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c> and clause A.3.7 expects <c>TOTAL-PASSED</c>.
    /// </summary>
    RevokedCertificationAuthority = 1
}


/// <summary>
/// One complete, internally consistent world for a validation example of ETSI EN 319 102-1 Annex A: real
/// certificates, real dated revocation material, a real CAdES Signed Data Object with real RFC 3161 time-stamp
/// tokens, and the constraint sets, inputs and seams one validation run of clause 5 takes. A scenario test
/// states its intent in one call and asserts against the named instants of the example's own timeline.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here is a stand-in. Certificates come from <see cref="X509ChainTestRing"/>'s platform certificate
/// requests, revocation lists and OCSP responses from the independent oracles of
/// <see cref="X509ChainTestRingRevocation"/>, time-stamp tokens from the independent time-stamp protocol oracle
/// of <see cref="X509ChainTestRingTimestamping"/>, and the signature from the framework's own CMS signer through
/// <see cref="CAdESSignatureTestFactory"/>. Every revocation status a run consumes was read back out of the
/// minted DER by a shipped library method, so no description can disagree with the bytes it describes.
/// </para>
/// <para>
/// Every instant is an offset from <see cref="TestClock.CanonicalEpoch"/>, which is the validation time itself
/// — <c>t5</c> of example 1 and <c>t9</c> of example 2 — so a run is deterministic and no clock is ever read.
/// </para>
/// <para>
/// <strong>Freshness.</strong> The X.509 validation constraints deliberately state no maximum accepted
/// revocation freshness, so clause 5.2.5.4 step 1)'s fallback applies and each revocation list carries its own
/// freshness in its <c>nextUpdate</c> interval. That is what lets one world hold both the archived list clause
/// A.3.7 assumes fresh at the control-time it slides to and the list about the time-stamping authority the same
/// clause assumes stale — a single constraint value could not express both.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The scenario owns every carrier, certificate and key it minted and releases them
/// in reverse order on disposal. Everything it exposes is a reference into that ledger; a validation run must
/// not dispose anything it reaches through this object.
/// </para>
/// </remarks>
internal sealed class AnnexAValidationScenario: IDisposable
{
    /// <summary>The content every signature in these worlds covers.</summary>
    private static ReadOnlyMemory<byte> ExampleContent { get; } = new("the Annex A validation example content"u8.ToArray());

    /// <summary>The carriers, certificates and keys this scenario minted, released in reverse order.</summary>
    private readonly List<IDisposable> owned = [];

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>The example this world realizes.</summary>
    public AnnexAValidationExample Example { get; private set; }

    /// <summary>The validation time: <c>t5</c> of clause A.3.1 in example 1, <c>t9</c> of clause A.3.4 in example 2. Always <see cref="TestClock.CanonicalEpoch"/>.</summary>
    public DateTimeOffset ValidationTime { get; private set; }

    /// <summary>The instant the certification authority that issued the signing certificate was itself issued — <c>t0</c> of clause A.3.4; the same instant in example 1, which names no such event.</summary>
    public DateTimeOffset CertificationAuthorityIssued { get; private set; }

    /// <summary>The instant the signing certificate was issued — <c>t1</c> of both examples.</summary>
    public DateTimeOffset SigningCertificateIssued { get; private set; }

    /// <summary>The instant the signature was created — <c>t2</c> of both examples, and the claimed signing time the signature states.</summary>
    public DateTimeOffset SignatureCreated { get; private set; }

    /// <summary>The generation time of the signature time-stamp — <c>t3</c> of both examples.</summary>
    public DateTimeOffset SignatureTimestampCreated { get; private set; }

    /// <summary>The instant the certification authority that issued the signing certificate issued the revocation list about it — <c>t4</c> of clause A.3.4. In example 1 the same instant is <c>t4</c>, when the signing certificate itself is revoked.</summary>
    public DateTimeOffset SigningCertificateRevocationListIssued { get; private set; }

    /// <summary>The instant the signing certificate was revoked — <c>t4</c> of example 1; <see langword="null"/> in example 2, where the signing certificate is never revoked.</summary>
    public DateTimeOffset? SigningCertificateRevoked { get; private set; }

    /// <summary>The generation time of the archive time-stamp — <c>t5</c> of clause A.3.4; <see langword="null"/> in example 1, which has no such time-stamp.</summary>
    public DateTimeOffset? ArchiveTimestampCreated { get; private set; }

    /// <summary>The instant the revocation list about the signature time-stamp's authority was issued — <c>t6</c> of clause A.3.4; <see langword="null"/> in example 1.</summary>
    public DateTimeOffset? SignatureTimestampAuthorityRevocationListIssued { get; private set; }

    /// <summary>The instant the certificate of the signature time-stamp's authority expires — <c>t7</c> of clause A.3.4; <see langword="null"/> in example 1, where that certificate is still valid at validation time.</summary>
    public DateTimeOffset? SignatureTimestampAuthorityExpiry { get; private set; }

    /// <summary>The instant the certification authority certificate was revoked — <c>t8</c> of clause A.3.4; <see langword="null"/> in example 1.</summary>
    public DateTimeOffset? CertificationAuthorityRevoked { get; private set; }


    /// <summary>The self-signed root, the one trust anchor of both worlds.</summary>
    public X509ChainTestRingNode Root { get; private set; } = null!;

    /// <summary>The certification authority that issued the signing certificate — the certificate example 2 revokes at <c>t8</c>.</summary>
    public X509ChainTestRingNode SigningCertificationAuthority { get; private set; } = null!;

    /// <summary>The end entity whose key signs — the signing certificate example 1 revokes at <c>t4</c>.</summary>
    public X509ChainTestRingNode Signer { get; private set; } = null!;

    /// <summary>The certification authority of the time-stamping leg. Clause A.3.4 assumes the time-stamping authority was issued by an authority other than the one that issued the signing certificate, which is what this node is.</summary>
    public X509ChainTestRingNode TimeStampingCertificationAuthority { get; private set; } = null!;

    /// <summary>The authority that produced the signature time-stamp at <c>t3</c>.</summary>
    public X509ChainTestRingNode SignatureTimestampAuthority { get; private set; } = null!;

    /// <summary>The authority that produced the archive time-stamp at <c>t5</c>; <see langword="null"/> in example 1.</summary>
    public X509ChainTestRingNode? ArchiveTimestampAuthority { get; private set; }


    /// <summary>The Signed Data Object under validation: a CAdES-B-T signature in example 1, the same signature carrying an archive time-stamp as well in example 2.</summary>
    public CmsSignedData SignedDataObject { get; private set; } = null!;

    /// <summary>The content the signature encapsulates and covers.</summary>
    public SignedContentMemory SignedContent { get; private set; } = null!;

    /// <summary>The <c>SignerInfo.signature</c> octets — what the signature time-stamp's message imprint is taken over and what proofs of existence about the signature are keyed on.</summary>
    public SignedContentMemory SignatureValue { get; private set; } = null!;

    /// <summary>The signing certificate's chain, signing certificate first, then its certification authority, then the root.</summary>
    public IReadOnlyList<PkiCertificateMemory> Chain { get; private set; } = [];

    /// <summary>The trust anchors: the root alone, for signatures and time-stamps alike.</summary>
    public IReadOnlyList<PkiCertificateMemory> TrustAnchorCertificates { get; private set; } = [];

    /// <summary>Every certificate revocation list this world minted, in issuance order.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; private set; } = [];

    /// <summary>An OCSP response stating the same status about the signing certificate that its revocation list does, for a test that drives the same world through the other revocation material.</summary>
    public PkiCertificateMemory SigningCertificateOcspResponse { get; private set; } = null!;

    /// <summary>The revocation status information the same OCSP response carries, read back through the shipped OCSP reader.</summary>
    public RevocationStatusInformation SigningCertificateOcspStatus { get; private set; } = null!;

    /// <summary>The certificates and revocation lists the Driving Application supplies in addition to what the signature carries.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; private set; } = [];

    /// <summary>The revocation status information the Driving Application's own checkers established about every certificate of every chain in this world.</summary>
    public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformation { get; private set; } = [];

    /// <summary>The X.509 validation constraints: the root as the one trust anchor, the shell validity model, and no maximum accepted revocation freshness (see the type's remarks).</summary>
    public X509ValidationConstraints X509Constraints { get; private set; } = null!;

    /// <summary>The cryptographic constraints, asserting every algorithm this world's material uses reliable without a stated expiry.</summary>
    public CryptographicConstraints CryptographicConstraints { get; private set; } = null!;

    /// <summary>The validation constraints a run applies to the signature.</summary>
    public SignatureValidationConstraints Constraints { get; private set; } = null!;

    /// <summary>The validation constraints a run applies to a time-stamp token; the same trust anchors, stated separately so a scenario test can narrow one without the other.</summary>
    public SignatureValidationConstraints TimestampConstraints { get; private set; } = null!;

    /// <summary>The inputs one validation run takes.</summary>
    public SignatureValidationInputs Inputs { get; private set; } = null!;

    /// <summary>The seams one validation run composes: the shipped CAdES binding, the offline chain completer, the platform path validator and an offline revocation checker over this world's own lists.</summary>
    public SignatureValidationSeams Seams { get; private set; } = null!;


    /// <summary>
    /// Builds the world of clause A.3 example 1, "Revoked certificate": a certificate issued at <c>t1</c>, a
    /// signature at <c>t2</c>, a signature time-stamp at <c>t3</c>, the certificate revoked at <c>t4</c>, and
    /// validation attempted at <c>t5</c>. Every other certificate in the world is still valid and unrevoked at
    /// <c>t5</c>, as clause A.3.1 assumes.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The scenario, which the caller disposes.</returns>
    public static ValueTask<AnnexAValidationScenario> CreateRevokedCertificateWorldAsync(CancellationToken cancellationToken = default) =>
        CreateAsync(AnnexAValidationExample.RevokedCertificate, cancellationToken);


    /// <summary>
    /// Builds the world of clause A.3.4 example 2, "Revoked CA certificate": the certification authority issued
    /// at <c>t0</c>, the signing certificate at <c>t1</c>, the signature at <c>t2</c>, a signature time-stamp at
    /// <c>t3</c>, the signing authority's revocation list at <c>t4</c>, an archive time-stamp at <c>t5</c>, the
    /// revocation list about the signature time-stamp's authority at <c>t6</c>, that authority's certificate
    /// expiring at <c>t7</c>, the certification authority revoked at <c>t8</c>, and validation attempted at
    /// <c>t9</c>.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The scenario, which the caller disposes.</returns>
    public static ValueTask<AnnexAValidationScenario> CreateRevokedCertificationAuthorityWorldAsync(CancellationToken cancellationToken = default) =>
        CreateAsync(AnnexAValidationExample.RevokedCertificationAuthority, cancellationToken);


    /// <summary>
    /// Builds one of the two worlds.
    /// </summary>
    /// <param name="example">The example to realize.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The scenario, which the caller disposes.</returns>
    public static async ValueTask<AnnexAValidationScenario> CreateAsync(
        AnnexAValidationExample example,
        CancellationToken cancellationToken = default)
    {
        var scenario = new AnnexAValidationScenario();
        try
        {
            await scenario.BuildAsync(example, cancellationToken).ConfigureAwait(false);

            return scenario;
        }
        catch
        {
            scenario.Dispose();

            throw;
        }
    }


    /// <summary>
    /// The revocation list the certification authority that issued the signing certificate published at
    /// <c>t4</c> — the one clause A.3.7's Table A.3.7-3 records a proof of existence for at that instant.
    /// <see langword="null"/> in example 1, whose single list about the signing certificate is the current one.
    /// </summary>
    public PkiCertificateMemory? ArchivedSigningCertificateRevocationList { get; private set; }

    /// <summary>
    /// The proofs of existence the Driving Application asserts about the archived revocation material of this
    /// world — Table 27's "set of POEs" input, which NOTE 3 of clause 5.6.3.4 says is used without additional
    /// processing, and which <see cref="Inputs"/> already carries. Only the revocation list clause A.3.7 has the
    /// validation time sliding process select at a past control-time needs one: every certificate and every
    /// time-stamp token of the world is proven by the archive time-stamp itself, and everything the Driving
    /// Application supplied is proven at the current time by the long-term process's own initialization. Empty
    /// in example 1, which runs no long-term process.
    /// </summary>
    public ProofOfExistenceSet DrivingApplicationProofs { get; private set; } = ProofOfExistenceSet.Empty;


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        for(int i = owned.Count - 1; i >= 0; --i)
        {
            owned[i].Dispose();
        }

        owned.Clear();
    }


    /// <summary>
    /// Mints every artefact of the world and assembles the constraints, inputs and seams.
    /// </summary>
    /// <param name="example">The example to realize.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private async ValueTask BuildAsync(AnnexAValidationExample example, CancellationToken cancellationToken)
    {
        Example = example;

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        ValidationTime = timeProvider.GetUtcNow();

        bool isRevokedAuthorityWorld = example == AnnexAValidationExample.RevokedCertificationAuthority;
        SetTimeline(isRevokedAuthorityWorld);

        MintCertificates(timeProvider, isRevokedAuthorityWorld);
        await MintSignedDataObjectAsync(isRevokedAuthorityWorld, cancellationToken).ConfigureAwait(false);
        await MintRevocationMaterialAsync(isRevokedAuthorityWorld, cancellationToken).ConfigureAwait(false);
        await AssembleInputsAsync(cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Places every named instant of the example's timeline at an offset from the validation time.
    /// </summary>
    /// <param name="isRevokedAuthorityWorld">Whether the timeline is the ten-event one of clause A.3.4.</param>
    private void SetTimeline(bool isRevokedAuthorityWorld)
    {
        if(isRevokedAuthorityWorld)
        {
            CertificationAuthorityIssued = ValidationTime.AddDays(-340);            //t0.
            SigningCertificateIssued = ValidationTime.AddDays(-330);                //t1.
            SignatureCreated = ValidationTime.AddDays(-320).AddHours(-1);           //t2.
            SignatureTimestampCreated = ValidationTime.AddDays(-320);               //t3.
            SigningCertificateRevocationListIssued = ValidationTime.AddDays(-300);  //t4.
            ArchiveTimestampCreated = ValidationTime.AddDays(-200);                 //t5.
            SignatureTimestampAuthorityRevocationListIssued = ValidationTime.AddDays(-150);  //t6.
            SignatureTimestampAuthorityExpiry = ValidationTime.AddDays(-120);       //t7.
            CertificationAuthorityRevoked = ValidationTime.AddDays(-30);            //t8.
            SigningCertificateRevoked = null;

            return;
        }

        CertificationAuthorityIssued = ValidationTime.AddDays(-240);
        SigningCertificateIssued = ValidationTime.AddDays(-210);                    //t1.
        SignatureCreated = ValidationTime.AddDays(-200).AddHours(-1);               //t2.
        SignatureTimestampCreated = ValidationTime.AddDays(-200);                   //t3.
        SigningCertificateRevoked = ValidationTime.AddDays(-30);                    //t4.
        SigningCertificateRevocationListIssued = ValidationTime.AddDays(-1);
        ArchiveTimestampCreated = null;
        SignatureTimestampAuthorityRevocationListIssued = null;
        SignatureTimestampAuthorityExpiry = null;
        CertificationAuthorityRevoked = null;
    }


    /// <summary>
    /// Mints the certificates of both legs: the signing leg (root, its certification authority, the signer) and
    /// the time-stamping leg (a separate certification authority under the same root, one authority per
    /// time-stamp the world produces).
    /// </summary>
    /// <param name="timeProvider">The deterministic clock the ring's own defaults would read; every validity window here is explicit.</param>
    /// <param name="isRevokedAuthorityWorld">Whether the world is the one of clause A.3.4.</param>
    private void MintCertificates(TimeProvider timeProvider, bool isRevokedAuthorityWorld)
    {
        Root = Own(X509ChainTestRing.CreateRootCa(
            timeProvider,
            subjectCn: "Verifiable Annex A Root CA",
            pathLengthConstraint: 1,
            notBefore: CertificationAuthorityIssued.AddDays(-10),
            notAfter: ValidationTime.AddYears(10)));

        SigningCertificationAuthority = Own(X509ChainTestRing.CreateIntermediate(
            Root,
            timeProvider,
            subjectCn: "Verifiable Annex A Signing CA",
            pathLengthConstraint: 0,
            notBefore: CertificationAuthorityIssued,
            notAfter: ValidationTime.AddYears(2)));

        Signer = Own(X509ChainTestRing.CreateLeaf(
            SigningCertificationAuthority,
            dnsName: isRevokedAuthorityWorld ? "revoked-authority.annex-a.example.test" : "revoked-certificate.annex-a.example.test",
            timeProvider,
            notBefore: SigningCertificateIssued,
            notAfter: ValidationTime.AddYears(1)));

        TimeStampingCertificationAuthority = Own(X509ChainTestRing.CreateIntermediate(
            Root,
            timeProvider,
            subjectCn: "Verifiable Annex A Time-Stamping CA",
            pathLengthConstraint: 0,
            notBefore: CertificationAuthorityIssued,
            notAfter: ValidationTime.AddYears(2)));

        SignatureTimestampAuthority = Own(X509ChainTestRing.CreateTimeStampingAuthority(
            TimeStampingCertificationAuthority,
            timeProvider,
            subjectCn: "Verifiable Annex A Signature Time-Stamping Authority",
            notBefore: SigningCertificateIssued.AddDays(-10),
            notAfter: SignatureTimestampAuthorityExpiry ?? ValidationTime.AddYears(1)));

        if(isRevokedAuthorityWorld)
        {
            ArchiveTimestampAuthority = Own(X509ChainTestRing.CreateTimeStampingAuthority(
                TimeStampingCertificationAuthority,
                timeProvider,
                subjectCn: "Verifiable Annex A Archive Time-Stamping Authority",
                notBefore: SigningCertificateIssued.AddDays(-10),
                notAfter: ValidationTime.AddYears(1)));
        }
    }


    /// <summary>
    /// Mints the Signed Data Object: a CAdES-B-B signature at <c>t2</c>, carrying the certification authority
    /// certificates so that the archive time-stamp proves their existence, then a signature time-stamp at
    /// <c>t3</c> and, in the world of clause A.3.4, an archive time-stamp at <c>t5</c>.
    /// </summary>
    /// <param name="isRevokedAuthorityWorld">Whether the world is the one of clause A.3.4.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private async ValueTask MintSignedDataObjectAsync(bool isRevokedAuthorityWorld, CancellationToken cancellationToken)
    {
        SignedContent = Own(SignedContentMemory.FromBytes(ExampleContent.Span, BaseMemoryPool.Shared));

        using CmsSignedData baseline = CAdESSignatureTestFactory.SignBaseline(ExampleContent, Signer, SignatureCreated);

        //The certification authority certificates travel inside the signature so that the archive time-stamp of
        //clause A.3.4 protects them, which is what gives the validation time sliding process of clause 5.6.2.2 a
        //proof of their existence at a past control-time. A signature that carried only its signer's certificate
        //would leave that proof to the Driving Application.
        using CmsSignedData withCertificates = CAdESSignatureTestFactory.EmbedCertificates(
            baseline, [SigningCertificationAuthority, TimeStampingCertificationAuthority], BaseMemoryPool.Shared);

        CmsSignedData timestamped = await CAdESSignatureTestFactory.AttachSignatureTimestampAsync(
            withCertificates,
            SignatureTimestampAuthority,
            [SignatureTimestampAuthority, TimeStampingCertificationAuthority],
            SignatureTimestampCreated,
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        if(!isRevokedAuthorityWorld)
        {
            SignedDataObject = Own(timestamped);
        }
        else
        {
            using(timestamped)
            {
                SignedDataObject = Own(await CAdESSignatureTestFactory.AttachArchiveTimestampAsync(
                    timestamped,
                    ArchiveTimestampAuthority!,
                    [ArchiveTimestampAuthority!, TimeStampingCertificationAuthority],
                    ArchiveTimestampCreated!.Value,
                    BaseMemoryPool.Shared,
                    cancellationToken).ConfigureAwait(false));
            }
        }

        SignatureValue = Own(CAdESSignatureTestFactory.ReadSignatureValue(SignedDataObject, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Mints the revocation lists and the OCSP response of the world and describes each of them as the neutral
    /// revocation status information the validation algorithm consumes.
    /// </summary>
    /// <param name="isRevokedAuthorityWorld">Whether the world is the one of clause A.3.4.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private async ValueTask MintRevocationMaterialAsync(bool isRevokedAuthorityWorld, CancellationToken cancellationToken)
    {
        PkiCertificateMemory rootCarrier = Own(OcspTestFixtures.ToCertificateCarrier(Root.Certificate));
        PkiCertificateMemory signingAuthorityCarrier = Own(OcspTestFixtures.ToCertificateCarrier(SigningCertificationAuthority.Certificate));
        PkiCertificateMemory signerCarrier = Own(OcspTestFixtures.ToCertificateCarrier(Signer.Certificate));
        PkiCertificateMemory timeStampingAuthorityCarrier = Own(OcspTestFixtures.ToCertificateCarrier(TimeStampingCertificationAuthority.Certificate));
        PkiCertificateMemory signatureTimestampAuthorityCarrier = Own(OcspTestFixtures.ToCertificateCarrier(SignatureTimestampAuthority.Certificate));

        Chain = [signerCarrier, signingAuthorityCarrier, rootCarrier];
        TrustAnchorCertificates = [rootCarrier];

        DateTimeOffset currentListsIssued = ValidationTime.AddDays(-1);
        DateTimeOffset currentListsExpire = ValidationTime.AddDays(29);

        //The root's own list is what states the revocation of a certification authority: the authority's
        //certificate was issued by the root, so only the root can revoke it. In example 2 it is issued a day
        //after t8 so that it can state that revocation.
        DateTimeOffset rootListIssued = CertificationAuthorityRevoked is DateTimeOffset revoked ? revoked.AddDays(1) : currentListsIssued;
        PkiCertificateMemory rootList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
            Root,
            rootListIssued,
            rootListIssued.AddDays(30),
            CertificationAuthorityRevoked is DateTimeOffset authorityRevoked
                ? [new X509ChainTestRingRevocation.RevokedCertificateEntry(SigningCertificationAuthority, authorityRevoked)]
                : []));

        //The list the certification authority that issued the signing certificate publishes. In example 1 it is
        //current and lists the signing certificate as revoked at t4; in example 2 it is clean and current, and a
        //second, archived list issued at t4 is what the long-term process reaches back to.
        PkiCertificateMemory signingAuthorityList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
            SigningCertificationAuthority,
            currentListsIssued,
            currentListsExpire,
            SigningCertificateRevoked is DateTimeOffset signerRevoked
                ? [new X509ChainTestRingRevocation.RevokedCertificateEntry(Signer, signerRevoked)]
                : []));

        List<PkiCertificateMemory> lists = [rootList, signingAuthorityList];
        List<RevocationStatusInformation> statuses =
        [
            await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                rootList, signingAuthorityCarrier, rootCarrier, ValidationTime, rootListIssued, rootListIssued.AddDays(30),
                CertificationAuthorityRevoked, CertificationAuthorityRevoked is null ? null : X509ChainTestRingRevocation.KeyCompromiseReason,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
            await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                rootList, timeStampingAuthorityCarrier, rootCarrier, ValidationTime, rootListIssued, rootListIssued.AddDays(30),
                revocationTime: null, revocationReason: null, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
            await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                signingAuthorityList, signerCarrier, signingAuthorityCarrier, ValidationTime, currentListsIssued, currentListsExpire,
                SigningCertificateRevoked, SigningCertificateRevoked is null ? null : X509ChainTestRingRevocation.KeyCompromiseReason,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false)
        ];

        if(isRevokedAuthorityWorld)
        {
            //Clause A.3.4's t4: the list the signing certificate's authority published then, whose freshness
            //window is wide enough that clause A.3.7's validation time sliding still considers it fresh at the
            //control-time it slides to.
            DateTimeOffset archivedIssued = SigningCertificateRevocationListIssued;
            DateTimeOffset archivedExpires = archivedIssued.AddDays(400);
            ArchivedSigningCertificateRevocationList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
                SigningCertificationAuthority, archivedIssued, archivedExpires, []));
            lists.Add(ArchivedSigningCertificateRevocationList);
            statuses.Add(await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                ArchivedSigningCertificateRevocationList, signerCarrier, signingAuthorityCarrier, ValidationTime,
                archivedIssued, archivedExpires, revocationTime: null, revocationReason: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false));

            //Clause A.3.4's t6: the list about the certificate of the authority that produced the signature
            //time-stamp, with a short freshness window so that clause A.3.7's "the revocation object is assumed
            //not to be fresh" holds at validation time and control-time slides back to its issuance.
            DateTimeOffset timeStampingListIssued = SignatureTimestampAuthorityRevocationListIssued!.Value;
            DateTimeOffset timeStampingListExpires = timeStampingListIssued.AddDays(30);
            PkiCertificateMemory timeStampingList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
                TimeStampingCertificationAuthority, timeStampingListIssued, timeStampingListExpires, []));
            lists.Add(timeStampingList);
            statuses.Add(await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                timeStampingList, signatureTimestampAuthorityCarrier, timeStampingAuthorityCarrier,
                timeStampingListIssued.AddDays(1), timeStampingListIssued, timeStampingListExpires,
                revocationTime: null, revocationReason: null, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false));

            PkiCertificateMemory archiveAuthorityCarrier = Own(OcspTestFixtures.ToCertificateCarrier(ArchiveTimestampAuthority!.Certificate));
            PkiCertificateMemory currentTimeStampingList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
                TimeStampingCertificationAuthority, currentListsIssued, currentListsExpire, []));
            lists.Add(currentTimeStampingList);
            statuses.Add(await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                currentTimeStampingList, archiveAuthorityCarrier, timeStampingAuthorityCarrier, ValidationTime,
                currentListsIssued, currentListsExpire, revocationTime: null, revocationReason: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false));
        }
        else
        {
            PkiCertificateMemory timeStampingList = Own(X509ChainTestRingRevocation.MintCertificateRevocationList(
                TimeStampingCertificationAuthority, currentListsIssued, currentListsExpire, []));
            lists.Add(timeStampingList);
            statuses.Add(await X509ChainTestRingRevocation.DescribeRevocationListStatusAsync(
                timeStampingList, signatureTimestampAuthorityCarrier, timeStampingAuthorityCarrier, ValidationTime,
                currentListsIssued, currentListsExpire, revocationTime: null, revocationReason: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false));
        }

        CertificateRevocationLists = lists;
        RevocationStatusInformation = statuses;

        //The same status about the signing certificate as an OCSP response, so that a test can drive this world
        //through the other revocation material RFC 6960 defines without minting a second world.
        using OcspRequestContent ocspRequest = await X509ChainTestRingRevocation.CreateOcspRequestAsync(
            Signer, SigningCertificationAuthority, BaseMemoryPool.Shared, includeNonce: true, cancellationToken).ConfigureAwait(false);
        SigningCertificateOcspResponse = Own(X509ChainTestRingRevocation.MintOcspResponse(
            Signer,
            SigningCertificationAuthority,
            SigningCertificateRevoked is null ? OcspCertificateStatus.Good : OcspCertificateStatus.Revoked,
            currentListsIssued,
            currentListsExpire,
            SigningCertificateRevoked,
            SigningCertificateRevoked is null ? null : X509ChainTestRingRevocation.KeyCompromiseReason,
            ocspRequest.RequestNonce));
        SigningCertificateOcspStatus = await X509ChainTestRingRevocation.DescribeOcspStatusAsync(
            SigningCertificateOcspResponse, ocspRequest, signerCarrier, signingAuthorityCarrier, ValidationTime,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        List<PkiCertificateMemory> validationData = [signingAuthorityCarrier, timeStampingAuthorityCarrier, rootCarrier];
        validationData.AddRange(lists);
        CertificateValidationData = validationData;
    }


    /// <summary>
    /// Assembles the constraint sets, the Driving Application's proofs of existence, the inputs and the seams
    /// from the minted material.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    private async ValueTask AssembleInputsAsync(CancellationToken cancellationToken)
    {
        X509Constraints = new X509ValidationConstraints
        {
            TrustAnchors = BuildTrustAnchors(TrustAnchorCertificates),
            ValidityModel = CertificateValidityModel.Shell
        };

        CryptographicConstraints = new CryptographicConstraints
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(
                    new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                    MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                    TrustedUntil: null),
                new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };

        Constraints = new SignatureValidationConstraints
        {
            Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
            X509 = X509Constraints,
            Cryptographic = CryptographicConstraints,

            //Nothing is declared about time-stamp coverage: the archive time-stamp of this world carries the
            //ats-hash-index-v3 of ETSI EN 319 122-1 clause 5.5.2 and its imprint is the clause 5.5.3
            //concatenation, both of which the shipped CAdES binding recomputes, so the proof-of-existence
            //extraction building block verifies the token's messageImprint against octets it derived itself.
            //SignatureElementsConstraints.None leaves AcceptsUnverifiableTimestampCoverage at its false default.
            SignatureElements = SignatureElementsConstraints.None
        };

        TimestampConstraints = Constraints;

        var completer = new CertificateChainCompleter(CertificateValidationData);
        var revocationChecker = new CrlRevocationChecker(CertificateRevocationLists);
        Seams = new SignatureValidationSeams
        {
            Format = CAdESSignatureFacts.Seam,
            CompleteCertificateChain = completer.CompleteAsync,
            ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
            CheckRevocation = revocationChecker.CheckAsync
        };

        DrivingApplicationProofs = await BuildDrivingApplicationProofsAsync(cancellationToken).ConfigureAwait(false);

        Inputs = new SignatureValidationInputs
        {
            SignedDataObject = SignedDataObject,
            Constraints = Constraints,
            CertificateValidationData = CertificateValidationData,
            RevocationStatusInformation = RevocationStatusInformation,
            ProofsOfExistence = DrivingApplicationProofs,
            TimestampConstraints = TimestampConstraints
        };


        //Wraps trust anchor certificates as the constraint records clause 5.1.4.2 names, none of them with a
        //sunset date. A one-off helper kept local to the call it serves.
        static List<TrustAnchorConstraint> BuildTrustAnchors(IReadOnlyList<PkiCertificateMemory> anchors)
        {
            List<TrustAnchorConstraint> constraints = [];
            for(int i = 0; i < anchors.Count; ++i)
            {
                constraints.Add(new TrustAnchorConstraint(anchors[i], SunsetDate: null));
            }

            return constraints;
        }
    }


    /// <summary>
    /// Builds the Driving Application's own proofs of existence about this world's archived revocation material.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The proofs, empty when the world has no archived material.</returns>
    private async ValueTask<ProofOfExistenceSet> BuildDrivingApplicationProofsAsync(CancellationToken cancellationToken)
    {
        if(ArchiveTimestampCreated is not DateTimeOffset archiveInstant || ArchivedSigningCertificateRevocationList is null)
        {
            return ProofOfExistenceSet.Empty;
        }

        //The identities the proofs are keyed on are digests taken through the registered digest seam, and the
        //ledger they are tracked in lives as long as this scenario does.
        var identityResources = Own(new SignatureValidationResources());

        return ProofOfExistenceSet.Create(
        [
            new ProofOfExistence
            {
                ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                    ArchivedSigningCertificateRevocationList.AsReadOnlyMemory(), ValidationObjectKind.RevocationData,
                    reference: null, identityResources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                Instant = archiveInstant,
                Scope = ProofOfExistenceScope.Object,
                Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
            }
        ]);
    }


    /// <summary>
    /// Takes ownership of one artefact.
    /// </summary>
    /// <typeparam name="T">The artefact's type.</typeparam>
    /// <param name="artefact">The artefact.</param>
    /// <returns>The same artefact.</returns>
    private T Own<T>(T artefact) where T: IDisposable
    {
        owned.Add(artefact);

        return artefact;
    }
}
