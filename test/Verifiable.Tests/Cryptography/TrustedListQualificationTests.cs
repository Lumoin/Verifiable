using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance vectors for the ETSI TS 119 615 V1.4.1 clause 4 qualification procedures in
/// <see cref="TrustedListQualification"/>. The expected outcomes are transcribed from the specification
/// text and tables — never from the implementation: the Tables 1-3 vectors below are a literal cell-by-cell
/// transcription of the specification's determination grids, so the implementation's closed-form reduction
/// is verified against the specification's own enumeration, and the flow scenarios each cite the PRO
/// requirement they realise.
/// </summary>
[TestClass]
internal sealed class TrustedListQualificationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The DER-stand-in bytes of the certificate under qualification; the byte-equality match seam treats them opaquely.</summary>
    private static byte[] CertificateUnderTestBytes { get; } = [0x30, 0x82, 0x01, 0x01, 0x11, 0x22, 0x33];

    /// <summary>DER-stand-in bytes of a certificate no service digital identity carries.</summary>
    private static byte[] UnrelatedCertificateBytes { get; } = [0x30, 0x82, 0x02, 0x02, 0x44, 0x55, 0x66];

    /// <summary>The certificate policy identifier the procedure tests' criteria trees assert, present in the default facts.</summary>
    private const string MatchingPolicyOid = "1.2.246.517.1.1";

    /// <summary>An evaluation instant safely inside the Regulation regime.</summary>
    private static DateTimeOffset RegulationEvaluationTime { get; } = new(2024, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>An evaluation instant safely inside the Directive regime.</summary>
    private static DateTimeOffset DirectiveEvaluationTime { get; } = new(2015, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The PRO-4.3.4-03 check (ii) seam realised as byte equality against the identity's certificate
    /// entries — the "public key and subject name are identical" limb of the check, sufficient for these
    /// procedure vectors because the certificates are opaque stand-ins.
    /// </summary>
    private static MatchCertificateToTrustServiceAsyncDelegate ByteEqualityMatch { get; } = (certificate, serviceDigitalIdentity, validationTime, pool, cancellationToken) =>
    {
        foreach(ServiceDigitalIdentityEntry entry in serviceDigitalIdentity.Entries)
        {
            if(entry is X509CertificateIdentity certificateEntry
                && certificateEntry.Certificate.AsReadOnlySpan().SequenceEqual(certificate.AsReadOnlySpan()))
            {
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    };


    /// <summary>
    /// The literal transcriptions of the specification's Tables 1, 2 and 3 (QC-For-eSig, QC-For-eSeal and
    /// QC-For-WebSiteAuthentication determination). Each yielded case is one cell: the table (1-3), the
    /// certificate's QcCompliance flag, its QcType set, the qualifier column (1-5), and the expected
    /// indication letter (<c>'Q'</c> qualified, <c>'N'</c> not qualified, <c>'I'</c> indeterminate). Row
    /// order follows the specification's rows 1-15, with row 1's two certificate shapes (QcCompliance
    /// alone, and QcCompliance with QcType 1) enumerated separately.
    /// </summary>
    /// <returns>The 240 cell vectors.</returns>
    public static IEnumerable<object[]> DeterminationTableCells()
    {
        //Each row: the certificate shape (QcCompliance flag + QcType set) and the five column letters.
        (bool HasCompliance, int[] Types, string Cells)[][] tables =
        [
            //Table 1: QC-For-eSig determination.
            [
                (true, [], "QNQQQ"),
                (true, [1], "QNQQQ"),
                (true, [2], "NNNQQ"),
                (true, [3], "NNNQQ"),
                (true, [1, 2], "INIQQ"),
                (true, [1, 3], "INIQQ"),
                (true, [2, 3], "NNNQQ"),
                (true, [1, 2, 3], "INIQQ"),
                (false, [], "NNINQ"),
                (false, [1], "NNQNQ"),
                (false, [2], "NNNNQ"),
                (false, [3], "NNNNQ"),
                (false, [1, 2], "NNINQ"),
                (false, [1, 3], "NNINQ"),
                (false, [2, 3], "NNNNQ"),
                (false, [1, 2, 3], "NNINQ"),
            ],
            //Table 2: QC-For-eSeal determination.
            [
                (true, [], "NNNQQ"),
                (true, [1], "NNNQQ"),
                (true, [2], "QNQQQ"),
                (true, [3], "NNNQQ"),
                (true, [1, 2], "INIQQ"),
                (true, [1, 3], "NNNQQ"),
                (true, [2, 3], "INIQQ"),
                (true, [1, 2, 3], "INIQQ"),
                (false, [], "NNINQ"),
                (false, [1], "NNNNQ"),
                (false, [2], "NNQNQ"),
                (false, [3], "NNNNQ"),
                (false, [1, 2], "NNINQ"),
                (false, [1, 3], "NNNNQ"),
                (false, [2, 3], "NNINQ"),
                (false, [1, 2, 3], "NNINQ"),
            ],
            //Table 3: QC-For-WebSiteAuthentication determination.
            [
                (true, [], "NNNQQ"),
                (true, [1], "NNNQQ"),
                (true, [2], "NNNQQ"),
                (true, [3], "QNQQQ"),
                (true, [1, 2], "NNNQQ"),
                (true, [1, 3], "INIQQ"),
                (true, [2, 3], "INIQQ"),
                (true, [1, 2, 3], "INIQQ"),
                (false, [], "NNINQ"),
                (false, [1], "NNNNQ"),
                (false, [2], "NNNNQ"),
                (false, [3], "NNQNQ"),
                (false, [1, 2], "NNNNQ"),
                (false, [1, 3], "NNINQ"),
                (false, [2, 3], "NNINQ"),
                (false, [1, 2, 3], "NNINQ"),
            ],
        ];

        for(int tableIndex = 0; tableIndex < tables.Length; ++tableIndex)
        {
            foreach((bool hasCompliance, int[] types, string cells) in tables[tableIndex])
            {
                for(int column = 1; column <= 5; ++column)
                {
                    yield return [tableIndex + 1, hasCompliance, types, column, cells[column - 1]];
                }
            }
        }
    }


    /// <summary>
    /// PRO-4.4.4-15 / -23 / -31: every cell of the specification's Tables 1, 2 and 3, driven through the
    /// full clause 4.4 determination with a single matched service asserting only the table's
    /// additional-service-information type.
    /// </summary>
    /// <param name="table">The specification table (1 = eSig, 2 = eSeal, 3 = website authentication).</param>
    /// <param name="hasQcCompliance">The row selector's QcCompliance flag.</param>
    /// <param name="qcTypes">The row selector's QcType values (1-3).</param>
    /// <param name="column">The column selector (1 = no qualifier, 2 = NotQualified, 3 = QCStatement, 4 = the type qualifier, 5 = QCStatement with the type qualifier).</param>
    /// <param name="expectedCell">The expected indication letter transcribed from the specification.</param>
    [TestMethod]
    [DynamicData(nameof(DeterminationTableCells))]
    public async Task QualifiedCertificateDeterminationMatchesEverySpecificationTableCell(int table, bool hasQcCompliance, int[] qcTypes, int column, char expectedCell)
    {
        (TrustServiceAdditionalInformationType informationType, ServiceQualifier typeQualifier) = table switch
        {
            1 => (TrustServiceAdditionalInformationType.ForElectronicSignatures, ServiceQualifier.ForElectronicSignature),
            2 => (TrustServiceAdditionalInformationType.ForElectronicSeals, ServiceQualifier.ForElectronicSeal),
            _ => (TrustServiceAdditionalInformationType.ForWebSiteAuthentication, ServiceQualifier.ForWebSiteAuthentication)
        };

        List<ServiceQualifier> qualifiers = column switch
        {
            2 => [ServiceQualifier.NotQualified],
            3 => [ServiceQualifier.QualifiedCertificateStatement],
            4 => [typeQualifier],
            5 => [ServiceQualifier.QualifiedCertificateStatement, typeQualifier],
            _ => []
        };

        List<QualificationElement> qualifications = qualifiers.Count == 0
            ? []
            : [CreateMatchingQualificationElement(qualifiers)];
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [informationType],
            qualifications);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: hasQcCompliance,
            qcTypes: [.. qcTypes.Select(type => (EuQualifiedCertificateType)type)]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EuQualifiedCertificateIndication expected = (table, expectedCell) switch
        {
            (1, 'Q') => EuQualifiedCertificateIndication.QualifiedForESignature,
            (1, 'N') => EuQualifiedCertificateIndication.NotQualifiedForESignature,
            (1, _) => EuQualifiedCertificateIndication.IndeterminateForESignature,
            (2, 'Q') => EuQualifiedCertificateIndication.QualifiedForESeal,
            (2, 'N') => EuQualifiedCertificateIndication.NotQualifiedForESeal,
            (2, _) => EuQualifiedCertificateIndication.IndeterminateForESeal,
            (_, 'Q') => EuQualifiedCertificateIndication.QualifiedForWebsiteAuthentication,
            (_, 'N') => EuQualifiedCertificateIndication.NotQualifiedForWebsiteAuthentication,
            (_, _) => EuQualifiedCertificateIndication.IndeterminateForWebsiteAuthentication
        };

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, $"Table {table} cell (compliance={hasQcCompliance}, types=[{string.Join(',', qcTypes)}], column={column}) must not fail the process.");
        Assert.Contains(expected, result.Indications, $"Table {table} cell (compliance={hasQcCompliance}, types=[{string.Join(',', qcTypes)}], column={column}) must determine {expected}.");

        //PRO-4.4.4-15 (d) / -23 (d) / -31 (d): the row8/column3 cell additionally raises the
        //not-enough-information warning.
        if(!hasQcCompliance && qcTypes.Length == 0 && column == 3)
        {
            TrustedListQualificationSubStatus expectedWarning = table switch
            {
                1 => TrustedListQualificationSubStatus.WarningType1NotEnoughInformationOnQcType,
                2 => TrustedListQualificationSubStatus.WarningType2NotEnoughInformationOnQcType,
                _ => TrustedListQualificationSubStatus.WarningType3NotEnoughInformationOnQcType
            };
            Assert.Contains(expectedWarning, result.SubStatuses, $"Table {table} row8/column3 must raise the not-enough-information warning.");
        }
    }


    /// <summary>
    /// PRO-4.4.4-32 / Table 4: a certificate the trusted list qualifies for two different types at once
    /// (electronic signatures via the certificate's own statements, electronic seals via a QCForESeal
    /// qualifier) fails the determination with the pairwise error.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task QualifiedForTwoTypesAtOnceFailsThePairwiseStatusCheck()
    {
        //Two services of one provider, each asserting exactly one dimension: the eSignature dimension
        //qualifies through the certificate's own statements (Table 1 row1/column1) and the eSeal dimension
        //through the second service's QCForESeal qualifier (Table 2 row1/column4). A single service carrying
        //both information types would instead route the QCForESeal qualifier into the eSignature dimension
        //as a PRO-4.4.4-12 foreign-type inconsistency, never reaching the Table 4 error.
        DateTimeOffset statusStart = new(2017, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using TrustedList trustedList = CreateTrustedList([CreateProvider(
        [
            CreateService(TrustServiceStatus.Granted, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSignatures], [], CertificateUnderTestBytes, []),
            CreateService(TrustServiceStatus.Granted, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSeals], [CreateMatchingQualificationElement([ServiceQualifier.ForElectronicSeal])], CertificateUnderTestBytes, [])
        ])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "Two positive determinations of different types are a Table 4 error and must fail the process.");
        Assert.Contains(
            subStatus => subStatus.Value.StartsWith("ERROR_QC_status_check_", StringComparison.Ordinal),
            result.SubStatuses,
            "The pairwise error sub-status must name the conflicting combination.");
    }


    /// <summary>
    /// PRO-4.4.4-12: a qualifier of a foreign type applying to the certificate on a dimension's own states
    /// (here QCForESeal on a for-eSignatures state) leaves that dimension indeterminate with the
    /// inconsistency warning rather than qualified.
    /// </summary>
    [TestMethod]
    public async Task ForeignTypeQualifierOnDimensionStateLeavesDimensionIndeterminate()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [CreateMatchingQualificationElement([ServiceQualifier.ForElectronicSeal])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(EuQualifiedCertificateIndication.IndeterminateForESignature, result.Indications, "A foreign-type qualifier must leave the dimension indeterminate (PRO-4.4.4-12).");
        Assert.Contains(TrustedListQualificationSubStatus.WarningType1QualifierInconsistency, result.SubStatuses, "The inconsistency warning must be raised (PRO-4.4.4-12).");
    }


    /// <summary>
    /// PRO-4.4.4-05: a certificate no listed service recognises is simply not qualified, with the
    /// no-confirmation sub-status — a passed process, not a failed one.
    /// </summary>
    [TestMethod]
    public async Task UnrecognisedCertificateDeterminesNotQualified()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(UnrelatedCertificateBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status, "No confirmation is a passed process (PRO-4.4.4-05).");
        Assert.Contains(EuQualifiedCertificateIndication.NotQualified, result.Indications, "The determination must be Not_Qualified (PRO-4.4.4-05).");
        Assert.Contains(TrustedListQualificationSubStatus.NoConfirmationFound, result.SubStatuses, "The no-confirmation sub-status must be reported (PRO-4.4.4-05).");
    }


    /// <summary>
    /// PRO-4.4.4-10 / withdrawn: a for-eSignatures state whose status is withdrawn at the evaluation time
    /// determines not qualified for that dimension.
    /// </summary>
    [TestMethod]
    public async Task WithdrawnServiceDeterminesNotQualifiedForItsDimension()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Withdrawn,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(EuQualifiedCertificateIndication.NotQualifiedForESignature, result.Indications, "A withdrawn for-eSignatures state must determine Not_Qualified_For_eSig (PRO-4.4.4-10).");
    }


    /// <summary>
    /// PRO-4.4.4-10A: a Regulation-regime state with a Directive-era status (under supervision) is a
    /// trusted-list non-compliance leaving the dimension indeterminate.
    /// </summary>
    [TestMethod]
    public async Task NonRegulationStatusUnderRegulationRegimeLeavesDimensionIndeterminate()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.UnderSupervision,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(EuQualifiedCertificateIndication.IndeterminateForESignature, result.Indications, "A non-Regulation status must leave the dimension indeterminate (PRO-4.4.4-10A).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorServiceStatusNoncompliance, result.SubStatuses, "The non-compliance sub-status must be reported (PRO-4.4.4-10A).");
    }


    /// <summary>
    /// PRO-4.4.4-06: a certificate whose issuer organization matches none of the matched provider's names
    /// fails the determination as indeterminate with the name-inconsistency sub-status.
    /// </summary>
    [TestMethod]
    public async Task IssuerNameNotIdentifyingProviderFailsDetermination()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            issuerOrganizationNames: ["Some Other Organization"]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "A provider-name inconsistency must fail the process (PRO-4.4.4-06).");
        Assert.Contains(EuQualifiedCertificateIndication.Indeterminate, result.Indications, "The determination must be INDETERMINATE (PRO-4.4.4-06).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorTrustServiceProviderNameInconsistency, result.SubStatuses, "The name-inconsistency sub-status must be reported (PRO-4.4.4-06).");
    }


    /// <summary>
    /// PRO-4.4.4-34/-36: a service granted at the evaluation time but withdrawn at the certificate's
    /// NotBefore instant produces differing indication sets between the two runs, which fails the
    /// determination.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task DifferingIndicationsBetweenEvaluationAndNotBeforeFailDetermination()
    {
        //Withdrawn until 2021, granted from 2021: at NotBefore (2020) the certificate reads withdrawn, at
        //the evaluation time (2024) granted.
        TrustService service = CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [],
            CertificateUnderTestBytes,
            [CreateHistoryEntry(TrustServiceStatus.Withdrawn, new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero), [TrustServiceAdditionalInformationType.ForElectronicSignatures], [])]);
        using TrustedList trustedList = CreateTrustedList([CreateProvider([service])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "Differing indication sets between Date-time and NotBefore must fail the process (PRO-4.4.4-36).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorIndicationsDifferBetweenEvaluationTimeAndNotBefore, result.SubStatuses, "The comparison error sub-status must be reported (PRO-4.4.4-36).");
    }


    /// <summary>
    /// PRO-4.4.4-33 with Table 5: under the Directive regime an under-supervision service and a
    /// QcCompliance certificate determine qualified for electronic signatures, and the seal and website
    /// dimensions read their fixed Directive-era not-qualified values.
    /// </summary>
    [TestMethod]
    public async Task DirectiveRegimeDeterminesFromTableFive()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.UnderSupervision,
            new DateTimeOffset(2013, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [],
            notBefore: new DateTimeOffset(2014, 1, 1, 0, 0, 0, TimeSpan.Zero));

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, DirectiveEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, "The Directive-regime determination must pass (PRO-4.4.4-33).");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESignature, result.Indications, "QcCompliance under Table 5 column0/row1 determines QC_For_eSig.");
        Assert.Contains(EuQualifiedCertificateIndication.NotQualifiedForESeal, result.Indications, "The Directive knew no seal qualification (PRO-4.4.4-33 (a)).");
        Assert.Contains(EuQualifiedCertificateIndication.NotQualifiedForWebsiteAuthentication, result.Indications, "The Directive knew no website-authentication qualification (PRO-4.4.4-33 (b)).");
    }


    /// <summary>
    /// PRO-4.4.4-33 (f) (1): a ceased supervision under the Directive regime short-circuits to not
    /// qualified for electronic signatures.
    /// </summary>
    [TestMethod]
    public async Task CeasedSupervisionUnderDirectiveRegimeDeterminesNotQualified()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.SupervisionCeased,
            new DateTimeOffset(2013, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [],
            notBefore: new DateTimeOffset(2012, 1, 1, 0, 0, 0, TimeSpan.Zero));

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, DirectiveEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status, "The short-circuit is a passed process (PRO-4.4.4-33 (f) (3)).");
        Assert.Contains(EuQualifiedCertificateIndication.NotQualifiedForESignature, result.Indications, "Ceased supervision must determine Not_Qualified_For_eSig (PRO-4.4.4-33 (f) (1)).");
    }


    /// <summary>
    /// PRO-4.4.4-01: the certificate's issuer country and the list's scheme territory must agree; a
    /// contradiction is a composition error surfaced as <see cref="ArgumentException"/>, not a
    /// determination outcome.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TerritoryMismatchThrowsArgumentException()
    {
        using TrustedList trustedList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [])])], schemeTerritory: "SE");
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: []);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
                trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>PRO-4.4.4-01 (a)/(b): the Directive-era country conversions the territory resolution applies.</summary>
    [TestMethod]
    [DataRow("GB", "UK")]
    [DataRow("GR", "EL")]
    [DataRow("fi", "FI")]
    [DataRow("DE", "DE")]
    public void TerritoryResolutionConvertsCountryCodes(string countryCode, string expectedTerritory)
    {
        Assert.AreEqual(expectedTerritory, TrustedListQualification.ResolveTrustedListTerritory(countryCode));
    }


    /// <summary>
    /// PRO-4.3.4-03 (b): an evaluation instant before the current status selects the covering history
    /// instance, and the state reports itself as historical.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task EvaluationBeforeCurrentStatusSelectsHistoryInstance()
    {
        TrustService service = CreateService(
            TrustServiceStatus.Withdrawn,
            new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [],
            CertificateUnderTestBytes,
            [CreateHistoryEntry(TrustServiceStatus.Granted, new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero), [TrustServiceAdditionalInformationType.ForElectronicSignatures], [])]);
        using TrustedList trustedList = CreateTrustedList([CreateProvider([service])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);

        ListedServicesMatchResult result = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            trustedList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero), ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status);
        Assert.HasCount(1, result.Matches);
        Assert.IsTrue(result.Matches[0].StateAtTime.IsFromHistory, "The 2020 evaluation must select the 2017 history instance, not the 2023 current status (PRO-4.3.4-03 (b)).");
        Assert.IsTrue(result.Matches[0].StateAtTime.Status.IsGranted, "The selected historical state was granted.");
    }


    /// <summary>
    /// PRO-4.3.4-03A: history instances out of descending status-starting-time order stop the matching
    /// with an error.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task DisorderedHistoryFailsMatching()
    {
        TrustService service = CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [],
            CertificateUnderTestBytes,
            [
                CreateHistoryEntry(TrustServiceStatus.UnderSupervision, new DateTimeOffset(2015, 1, 1, 0, 0, 0, TimeSpan.Zero), [], []),
                CreateHistoryEntry(TrustServiceStatus.Granted, new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero), [], [])
            ]);
        using TrustedList trustedList = CreateTrustedList([CreateProvider([service])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);

        ListedServicesMatchResult result = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            trustedList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "Ascending history order must stop the process with an error (PRO-4.3.4-03A).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorServiceHistoryOrder, result.SubStatuses);
    }


    /// <summary>
    /// PRO-4.3.4-05/-06: two matched for-eSignatures services with identical statuses raise the
    /// duplication warning; with differing statuses, the duplication error.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task DuplicatedServicesRaiseDuplicationIndications()
    {
        DateTimeOffset statusStart = new(2017, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using TrustedList identicalStatusList = CreateTrustedList([CreateProvider(
        [
            CreateService(TrustServiceStatus.Granted, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSignatures], [], CertificateUnderTestBytes, []),
            CreateService(TrustServiceStatus.Granted, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSignatures], [], CertificateUnderTestBytes, [])
        ])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);

        ListedServicesMatchResult identicalResult = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            identicalStatusList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(TrustedListQualificationSubStatus.WarningType1Duplication, identicalResult.SubStatuses, "Identical duplicated statuses raise the warning (PRO-4.3.4-05).");

        using TrustedList differingStatusList = CreateTrustedList([CreateProvider(
        [
            CreateService(TrustServiceStatus.Granted, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSignatures], [], CertificateUnderTestBytes, []),
            CreateService(TrustServiceStatus.Withdrawn, statusStart, [TrustServiceAdditionalInformationType.ForElectronicSignatures], [], CertificateUnderTestBytes, [])
        ])]);

        ListedServicesMatchResult differingResult = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            differingStatusList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(TrustedListQualificationSubStatus.ErrorType1Duplication, differingResult.SubStatuses, "Differing duplicated statuses raise the error (PRO-4.3.4-06).");
    }


    /// <summary>
    /// PRO-4.3.4-11: matches spread across providers with different names fail the matching with the
    /// provider-conflict error.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task MatchesAcrossDifferentProvidersFailWithProviderConflict()
    {
        DateTimeOffset statusStart = new(2017, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using TrustedList trustedList = CreateTrustedList(
        [
            CreateProvider([CreateService(TrustServiceStatus.Granted, statusStart, [], [], CertificateUnderTestBytes, [])]),
            CreateProvider([CreateService(TrustServiceStatus.Granted, statusStart, [], [], CertificateUnderTestBytes, [])], providerName: "Another Provider Ab")
        ]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);

        ListedServicesMatchResult result = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            trustedList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "Matches across differently-named providers must fail (PRO-4.3.4-11).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorTrustServiceProviderConflict, result.SubStatuses);
    }


    /// <summary>
    /// PRO-4.5.4-04 with Table 7: the QSCD determination follows the trusted list's qualifier when one
    /// applies and the certificate's QcSSCD statement when the list defers to it.
    /// </summary>
    [TestMethod]
    [DataRow("WithQscd", false, QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice)]
    [DataRow("ManagedOnBehalf", false, QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice)]
    [DataRow("NoQscd", true, QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice)]
    [DataRow("AsInCert", true, QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice)]
    [DataRow("AsInCert", false, QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice)]
    [DataRow("None", true, QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice)]
    [DataRow("None", false, QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice)]
    public async Task QscdDeterminationFollowsTableSeven(string qualifierCase, bool hasQcSscd, QualifiedSignatureCreationDeviceIndication expected)
    {
        List<ServiceQualifier> qualifiers = qualifierCase switch
        {
            "WithQscd" => [ServiceQualifier.WithQscd],
            "ManagedOnBehalf" => [ServiceQualifier.QscdManagedOnBehalf],
            "NoQscd" => [ServiceQualifier.NoQscd],
            "AsInCert" => [ServiceQualifier.QscdStatusAsInCertificate],
            _ => []
        };
        List<QualificationElement> qualifications = qualifiers.Count == 0 ? [] : [CreateMatchingQualificationElement(qualifiers)];
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            qualifications);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            hasQcSscdStatement: hasQcSscd);

        QualifiedSignatureCreationDeviceDeterminationResult result = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, $"Case {qualifierCase} must not fail the process.");
        Assert.AreEqual(expected, result.Indication, $"Table 7 case {qualifierCase} with QcSSCD={hasQcSscd} must determine {expected} (PRO-4.5.4-04 (e)).");
    }


    /// <summary>
    /// PRO-4.5.4-04 (b): an unknown qualifier in a critical Qualifications extension fails the QSCD
    /// determination; the same qualifier in a non-critical extension only warns.
    /// </summary>
    [TestMethod]
    public async Task UnknownQualifierRespectsExtensionCriticality()
    {
        var unknownQualifier = new ServiceQualifier("http://uri.example.test/unregistered-qualifier");

        using TrustedList criticalList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [CreateMatchingQualificationElement([unknownQualifier], isCritical: true)]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature], hasQcSscdStatement: true);

        QualifiedSignatureCreationDeviceDeterminationResult criticalResult = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            criticalList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, criticalResult.Status, "An unknown qualifier in a critical extension must fail (PRO-4.5.4-04 (b) (1)).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorUnknownCriticalQualifiers, criticalResult.SubStatuses);

        using TrustedList nonCriticalList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [CreateMatchingQualificationElement([unknownQualifier], isCritical: false)]);

        QualifiedSignatureCreationDeviceDeterminationResult nonCriticalResult = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            nonCriticalList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, nonCriticalResult.Status, "An unknown qualifier in a non-critical extension must not fail (PRO-4.5.4-04 (b) (2)).");
        Assert.Contains(TrustedListQualificationSubStatus.WarningUnknownQualifiers, nonCriticalResult.SubStatuses);
    }


    /// <summary>
    /// PRO-4.5.4-04 (c): the TLv5 SSCD terminology appearing without its Regulation counterpart is an
    /// inconsistency that leaves the device status indeterminate with a warning.
    /// </summary>
    [TestMethod]
    public async Task LegacySscdQualifierWithoutQscdCounterpartIsIndeterminate()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            [CreateMatchingQualificationElement([ServiceQualifier.WithSscd])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        QualifiedSignatureCreationDeviceDeterminationResult result = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.PassedWithWarning, result.Status, "The inconsistency passes with a warning (PRO-4.5.4-04 (c)).");
        Assert.AreEqual(QualifiedSignatureCreationDeviceIndication.Indeterminate, result.Indication);
        Assert.Contains(TrustedListQualificationSubStatus.WarningQscdQualifierInconsistency, result.SubStatuses);
    }


    /// <summary>
    /// PRO-4.5.4-05: a certificate qualified for neither electronic signatures nor seals gets an
    /// indeterminate device status from a passed process.
    /// </summary>
    [TestMethod]
    public async Task QscdDeterminationIsIndeterminateWithoutSignatureOrSealQualification()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForWebSiteAuthentication],
            []);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.WebsiteAuthentication]);

        QualifiedSignatureCreationDeviceDeterminationResult result = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status);
        Assert.AreEqual(QualifiedSignatureCreationDeviceIndication.Indeterminate, result.Indication, "Neither QC_For_eSig nor QC_For_eSeal determined means QSCD_INDETERMINATE (PRO-4.5.4-05).");
    }


    /// <summary>
    /// PRO-4.6.4-09: a granted time-stamp service whose provider the certificate's subject identifies
    /// determines the token issuer as qualified; a withdrawn one as not qualified.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TokenIssuerQualificationFollowsServiceStatus()
    {
        using TrustedList grantedList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: false, qcTypes: []);

        TrustServiceTokenIssuerQualificationResult grantedResult = await TrustedListQualification.DetermineTrustServiceTokenIssuerQualificationAsync(
            grantedList, certificate, facts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustServiceTokenIssuerIndication.Qualified, grantedResult.Indication, "A granted service determines Qualified (PRO-4.6.4-09 (a)).");
        Assert.IsNotEmpty(grantedResult.ProviderNames, "The provider name output must be populated (PRO-4.6.4-09 (a) (3)).");

        using TrustedList withdrawnList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Withdrawn,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)])]);

        TrustServiceTokenIssuerQualificationResult withdrawnResult = await TrustedListQualification.DetermineTrustServiceTokenIssuerQualificationAsync(
            withdrawnList, certificate, facts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustServiceTokenIssuerIndication.NotQualified, withdrawnResult.Indication, "A non-granted service determines Not_Qualified (PRO-4.6.4-09 (b)).");
    }


    /// <summary>PRO-4.6.4-01: before the Regulation applied no token issuer was EU qualified.</summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TokenIssuerQualificationBeforeRegulationIsNotQualified()
    {
        using TrustedList trustedList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2013, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: false, qcTypes: []);

        TrustServiceTokenIssuerQualificationResult result = await TrustedListQualification.DetermineTrustServiceTokenIssuerQualificationAsync(
            trustedList, certificate, facts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, DirectiveEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status);
        Assert.AreEqual(TrustServiceTokenIssuerIndication.NotQualified, result.Indication, "No service was EU qualified before the Regulation (PRO-4.6.4-01).");
    }


    /// <summary>
    /// PRO-4.6.4-08: a token issuer certificate whose subject organization matches none of the provider's
    /// names fails as indeterminate.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TokenIssuerSubjectNameMismatchFailsAsIndeterminate()
    {
        using TrustedList trustedList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: false,
            qcTypes: [],
            subjectOrganizationNames: ["A Wholly Different Body"]);

        TrustServiceTokenIssuerQualificationResult result = await TrustedListQualification.DetermineTrustServiceTokenIssuerQualificationAsync(
            trustedList, certificate, facts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "A subject-name mismatch must fail (PRO-4.6.4-08).");
        Assert.AreEqual(TrustServiceTokenIssuerIndication.Indeterminate, result.Indication);
        Assert.Contains(TrustedListQualificationSubStatus.ErrorTokenIssuerNameInconsistency, result.SubStatuses);
    }


    /// <summary>
    /// PRO-4.7.4-06: a time-stamp service granted at the token's generation time but withdrawn at the
    /// evaluation time produces disagreeing indications, which fails the time stamp determination.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TimeStampDeterminationFailsWhenGenerationAndEvaluationDisagree()
    {
        TrustService service = CreateService(
            TrustServiceStatus.Withdrawn,
            new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [CreateHistoryEntry(TrustServiceStatus.Granted, new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero), [], [], TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority);
        using TrustedList trustedList = CreateTrustedList([CreateProvider([service])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: false, qcTypes: []);

        TrustServiceTokenIssuerQualificationResult result = await TrustedListQualification.DetermineEuQualifiedTimeStampAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero), ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.Status, "Disagreeing generation-time and evaluation-time indications must fail (PRO-4.7.4-06).");
        Assert.Contains(TrustedListQualificationSubStatus.ErrorTimeStampIndicationsDifferBetweenEvaluationAndGenerationTime, result.SubStatuses);
    }


    /// <summary>
    /// PRO-4.7.4-06: a time-stamp service granted at both instants agrees and reports the evaluation-time
    /// determination.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every disposable model node transfers to the returned TrustedList, which the test disposes via its using declaration.")]
    public async Task TimeStampDeterminationPassesWhenBothInstantsAgree()
    {
        using TrustedList trustedList = CreateTrustedList([CreateProvider([CreateService(
            TrustServiceStatus.Granted,
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [],
            [],
            CertificateUnderTestBytes,
            [],
            TrustServiceTypeIdentifier.QualifiedTimeStampAuthority)])]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: false, qcTypes: []);

        TrustServiceTokenIssuerQualificationResult result = await TrustedListQualification.DetermineEuQualifiedTimeStampAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero), ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Passed, result.Status);
        Assert.AreEqual(TrustServiceTokenIssuerIndication.Qualified, result.Indication, "Agreement at both instants reports the evaluation-time determination (PRO-4.7.4-03).");
    }


    /// <summary>
    /// TS 119 612 clause 5.5.9.2.2.1: a KeyUsage assertion requires the extension to be present and every
    /// asserted bit to match.
    /// </summary>
    [TestMethod]
    public void KeyUsageCriterionRequiresExtensionAndExactBits()
    {
        var condition = new CriteriaListCondition(QualifierAssertion.All, null,
            [new KeyUsageCondition([new KeyUsageBitAssertion(KeyUsageBitName.NonRepudiation, true), new KeyUsageBitAssertion(KeyUsageBitName.KeyCertSign, false)])]);

        QualifiedCertificateFacts matching = CreateFacts(hasQcCompliance: true, qcTypes: [], setKeyUsageBits: [KeyUsageBitName.NonRepudiation]);
        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(condition, matching));

        QualifiedCertificateFacts wrongBit = CreateFacts(hasQcCompliance: true, qcTypes: [], setKeyUsageBits: [KeyUsageBitName.NonRepudiation, KeyUsageBitName.KeyCertSign]);
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(condition, wrongBit), "A bit asserted false but set in the certificate must not match.");

        QualifiedCertificateFacts noExtension = CreateFacts(hasQcCompliance: true, qcTypes: [], hasKeyUsageExtension: false);
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(condition, noExtension), "An absent KeyUsage extension must not match (clause 5.5.9.2.2.1).");
    }


    /// <summary>
    /// TS 119 612 clause 5.5.9.2.2.2: a PolicySet assertion requires the CertificatePolicies extension to
    /// be present and every listed identifier to be present in it.
    /// </summary>
    [TestMethod]
    public void PolicySetCriterionRequiresAllIdentifiers()
    {
        var condition = new CriteriaListCondition(QualifierAssertion.All, null,
            [new PolicySetCondition([MatchingPolicyOid, "2.999.1"])]);

        QualifiedCertificateFacts bothPresent = CreateFacts(hasQcCompliance: true, qcTypes: [], certificatePolicyOids: [MatchingPolicyOid, "2.999.1", "2.999.2"]);
        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(condition, bothPresent));

        QualifiedCertificateFacts onePresent = CreateFacts(hasQcCompliance: true, qcTypes: [], certificatePolicyOids: [MatchingPolicyOid]);
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(condition, onePresent), "ALL listed identifiers must be present (clause 5.5.9.2.2.2).");

        QualifiedCertificateFacts noExtension = CreateFacts(hasQcCompliance: true, qcTypes: [], hasCertificatePoliciesExtension: false);
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(condition, noExtension), "An absent CertificatePolicies extension must not match (clause 5.5.9.2.2.2).");
    }


    /// <summary>
    /// TS 119 612 clause 5.5.9.2.2.0: the three matching criteria indicators, including three-valued
    /// propagation of an unrecognised criterion — under <c>none</c> an unknown leaf must poison the result
    /// to indeterminate rather than letting the tree pass.
    /// </summary>
    [TestMethod]
    public void AssertCombinationsFollowClauseSemanticsAndUnknownsPropagate()
    {
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: []);
        var matchingLeaf = new PolicySetCondition([MatchingPolicyOid]);
        var missingLeaf = new PolicySetCondition(["2.999.404"]);
        var unknownLeaf = new OtherQualifierCondition("VendorSpecificCriterion");

        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.All, null, [matchingLeaf, matchingLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.All, null, [matchingLeaf, missingLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.AtLeastOne, null, [missingLeaf, matchingLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.AtLeastOne, null, [missingLeaf, missingLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.None, null, [missingLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.None, null, [matchingLeaf, missingLeaf]), facts));

        //The load-bearing three-valued cases: an unknown leaf can neither satisfy nor refute.
        Assert.AreEqual(CriteriaMatchResult.Indeterminate, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.None, null, [missingLeaf, unknownLeaf]), facts),
            "An unknown criterion under 'none' must poison the result — treating it as unmatched would grant qualifiers on unevaluated evidence.");
        Assert.AreEqual(CriteriaMatchResult.Indeterminate, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.All, null, [matchingLeaf, unknownLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.Indeterminate, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.AtLeastOne, null, [missingLeaf, unknownLeaf]), facts));

        //Definite outcomes still dominate unknowns where the specification's semantics allow.
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.All, null, [missingLeaf, unknownLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.AtLeastOne, null, [matchingLeaf, unknownLeaf]), facts));
        Assert.AreEqual(CriteriaMatchResult.NotMatched, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.None, null, [matchingLeaf, unknownLeaf]), facts));

        //A non-conformant empty criteria list cannot be soundly evaluated.
        Assert.AreEqual(CriteriaMatchResult.Indeterminate, TrustedListCriteriaEvaluation.Evaluate(new CriteriaListCondition(QualifierAssertion.All, null, []), facts));
    }


    /// <summary>
    /// The criteria walk is iterative: a tree nested a few thousand levels deep evaluates without a stack
    /// overflow (the document is attacker-reachable, so depth must not translate to call-stack depth).
    /// </summary>
    [TestMethod]
    public void DeeplyNestedCriteriaTreeEvaluatesIteratively()
    {
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: []);
        QualifierCondition tree = new PolicySetCondition([MatchingPolicyOid]);
        for(int i = 0; i < 4096; ++i)
        {
            tree = new CriteriaListCondition(QualifierAssertion.All, null, [tree]);
        }

        Assert.AreEqual(CriteriaMatchResult.Matched, TrustedListCriteriaEvaluation.Evaluate(tree, facts));
    }


    /// <summary>
    /// Bridges the qualification machinery to the real DSS trusted-list corpus: every criteria tree of
    /// every qualification element in every valid fixture evaluates to a defined three-valued outcome
    /// without throwing, against both a richly-populated and an empty certificate-facts shape — the corpus
    /// is attacker-reachable input and evaluation must be total over it. Skips inconclusive when the local
    /// reference clone is absent, exactly as the parser fixture tests do.
    /// </summary>
    [TestMethod]
    public async Task EveryCriteriaTreeInTheDssCorpusEvaluatesTotally()
    {
        string? resourcesDirectory = TryFindDssTrustedListResourcesDirectory();
        if(resourcesDirectory is null)
        {
            Assert.Inconclusive("The local ETSI/eIDAS reference clone (tempdocs/etsi-ades-reference/dss) was not found; the DSS TL/LOTL corpus is optional local reference material.");
            return;
        }

        QualifiedCertificateFacts richFacts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            certificatePolicyOids: [MatchingPolicyOid, WellKnownOids.QcpPublic, WellKnownOids.QcpPublicWithSscd],
            setKeyUsageBits: [KeyUsageBitName.NonRepudiation, KeyUsageBitName.DigitalSignature]);
        QualifiedCertificateFacts emptyFacts = CreateFacts(
            hasQcCompliance: false,
            qcTypes: [],
            hasKeyUsageExtension: false,
            hasCertificatePoliciesExtension: false,
            certificatePolicyOids: []);

        int evaluatedTrees = 0;
        int criticalElements = 0;
        foreach(string filePath in Directory.EnumerateFiles(resourcesDirectory, "*.xml", SearchOption.AllDirectories))
        {
            byte[] bytes = await File.ReadAllBytesAsync(filePath, TestContext.CancellationToken).ConfigureAwait(false);
            using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);
            using TrustedListParseResult parseResult = await TrustedListXmlParser.ParseAsync(document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            if(!parseResult.IsValid)
            {
                continue;
            }

            foreach(TrustServiceProvider provider in parseResult.Document!.TrustServiceProviders)
            {
                foreach(TrustService service in provider.Services)
                {
                    foreach(QualificationElement element in service.Qualifications.Concat(service.History.SelectMany(entry => entry.Qualifications)))
                    {
                        //A defined tri-state for both shapes; Evaluate throwing would fail the test.
                        CriteriaMatchResult richOutcome = TrustedListCriteriaEvaluation.Evaluate(element.Condition, richFacts);
                        CriteriaMatchResult emptyOutcome = TrustedListCriteriaEvaluation.Evaluate(element.Condition, emptyFacts);
                        Assert.IsTrue(Enum.IsDefined(richOutcome) && Enum.IsDefined(emptyOutcome));
                        ++evaluatedTrees;
                        if(element.IsCritical)
                        {
                            ++criticalElements;
                        }
                    }
                }
            }
        }

        Assert.IsGreaterThan(0, evaluatedTrees, "The corpus is expected to carry qualification elements; none were found, so this bridge test no longer exercises anything.");
        TestContext.WriteLine($"Evaluated {evaluatedTrees} criteria trees from the corpus; {criticalElements} carried in critical Qualifications extensions.");
    }


    /// <summary>Creates the default certificate facts the vectors vary from.</summary>
    private static QualifiedCertificateFacts CreateFacts(
        bool hasQcCompliance,
        IReadOnlyList<EuQualifiedCertificateType> qcTypes,
        IReadOnlyList<string>? issuerOrganizationNames = null,
        IReadOnlyList<string>? subjectOrganizationNames = null,
        DateTimeOffset? notBefore = null,
        bool hasQcSscdStatement = false,
        bool hasKeyUsageExtension = true,
        IReadOnlyList<KeyUsageBitName>? setKeyUsageBits = null,
        bool hasCertificatePoliciesExtension = true,
        IReadOnlyList<string>? certificatePolicyOids = null) => new()
    {
        IssuerCountryCode = "FI",
        IssuerOrganizationNames = issuerOrganizationNames ?? ["Example Provider Oy"],
        IssuerCommonNames = ["Example Provider Root CA"],
        SubjectCountryCode = "FI",
        SubjectOrganizationNames = subjectOrganizationNames ?? ["Example Provider Oy"],
        NotBefore = notBefore ?? new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
        HasQcCompliance = hasQcCompliance,
        QcTypes = qcTypes,
        HasQcSscdStatement = hasQcSscdStatement,
        HasCertificatePoliciesExtension = hasCertificatePoliciesExtension,
        CertificatePolicyOids = certificatePolicyOids ?? [MatchingPolicyOid],
        HasKeyUsageExtension = hasKeyUsageExtension,
        SetKeyUsageBits = setKeyUsageBits ?? [KeyUsageBitName.NonRepudiation],
        HasExtendedKeyUsageExtension = false,
        ExtendedKeyUsageOids = [],
        SubjectAttributeTypeOids = [WellKnownOids.CountryName, WellKnownOids.OrganizationName, WellKnownOids.CommonName]
    };


    /// <summary>Creates a qualification element whose criteria (a PolicySet on <see cref="MatchingPolicyOid"/>) identify the default facts.</summary>
    private static QualificationElement CreateMatchingQualificationElement(IReadOnlyList<ServiceQualifier> qualifiers, bool isCritical = false) => new()
    {
        Qualifiers = qualifiers,
        Condition = new CriteriaListCondition(QualifierAssertion.All, null, [new PolicySetCondition([MatchingPolicyOid])]),
        IsCritical = isCritical
    };


    /// <summary>Creates a trusted list with one provider carrying one CA/QC service in the given shape.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created service transfers to the returned TrustedList, which the caller disposes.")]
    private static TrustedList CreateSingleServiceTrustedList(
        TrustServiceStatus status,
        DateTimeOffset statusStartingTime,
        IReadOnlyList<TrustServiceAdditionalInformationType> additionalServiceInformation,
        IReadOnlyList<QualificationElement> qualifications) =>
        CreateTrustedList([CreateProvider([CreateService(status, statusStartingTime, additionalServiceInformation, qualifications, CertificateUnderTestBytes, [])])]);


    /// <summary>Creates a trusted list carrying the given providers under a minimal, well-formed scheme.</summary>
    private static TrustedList CreateTrustedList(IReadOnlyList<TrustServiceProvider> providers, string schemeTerritory = "FI") => new()
    {
        SchemeInformation = new TrustedListSchemeInformation
        {
            TslVersionIdentifier = 6,
            TslSequenceNumber = 1,
            TslType = TrustedListKind.Generic,
            SchemeOperatorNames = [new LocalizedText("en", "Example Supervisory Body")],
            SchemeOperatorPostalAddresses = [],
            SchemeOperatorElectronicAddresses = [],
            SchemeNames = [new LocalizedText("en", "FI: Example Trusted List")],
            SchemeInformationUris = [],
            StatusDeterminationApproach = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
            SchemeTerritory = schemeTerritory,
            HistoricalInformationPeriodYears = 65535,
            ListIssueDateTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)
        },
        TrustServiceProviders = providers
    };


    /// <summary>Creates a provider with the given services and name.</summary>
    private static TrustServiceProvider CreateProvider(IReadOnlyList<TrustService> services, string providerName = "Example Provider Oy") => new()
    {
        Names = [new LocalizedText("en", providerName)],
        TradeNames = [new LocalizedText("en", $"{providerName} Trade")],
        PostalAddresses = [],
        ElectronicAddresses = [],
        InformationUris = [],
        Services = services
    };


    /// <summary>Creates a service recognising the given certificate bytes, in the given state.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the certificate carrier transfers to the returned service's digital identity, disposed through the owning TrustedList.")]
    private static TrustService CreateService(
        TrustServiceStatus status,
        DateTimeOffset statusStartingTime,
        IReadOnlyList<TrustServiceAdditionalInformationType> additionalServiceInformation,
        IReadOnlyList<QualificationElement> qualifications,
        byte[] certificateBytes,
        IReadOnlyList<TrustServiceHistoryEntry> history,
        TrustServiceTypeIdentifier? serviceTypeIdentifier = null) => new()
    {
        ServiceTypeIdentifier = serviceTypeIdentifier ?? TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
        ServiceNames = [new LocalizedText("en", "Example CA")],
        DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CreateCertificateMemory(certificateBytes))] },
        Status = status,
        StatusStartingTime = statusStartingTime,
        AdditionalServiceInformation = additionalServiceInformation,
        Qualifications = qualifications,
        History = history
    };


    /// <summary>Creates a history instance recognising the certificate under test, in the given prior state.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the certificate carrier transfers to the returned history instance's digital identity, disposed through the owning TrustedList.")]
    private static TrustServiceHistoryEntry CreateHistoryEntry(
        TrustServiceStatus previousStatus,
        DateTimeOffset statusStartingTime,
        IReadOnlyList<TrustServiceAdditionalInformationType> additionalServiceInformation,
        IReadOnlyList<QualificationElement> qualifications,
        TrustServiceTypeIdentifier? serviceTypeIdentifier = null) => new()
    {
        ServiceTypeIdentifier = serviceTypeIdentifier ?? TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
        ServiceNames = [new LocalizedText("en", "Example CA")],
        DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CreateCertificateMemory(CertificateUnderTestBytes))] },
        PreviousStatus = previousStatus,
        StatusStartingTime = statusStartingTime,
        AdditionalServiceInformation = additionalServiceInformation,
        Qualifications = qualifications
    };


    /// <summary>Rents a <see cref="PkiCertificateMemory"/> carrier over the given DER-stand-in bytes.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory CreateCertificateMemory(byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Locates the DSS trusted-list resources directory of the optional local reference clone, exactly as the parser fixture tests do.</summary>
    private static string? TryFindDssTrustedListResourcesDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string candidate = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference", "dss", "dss-tsl-validation", "src", "test", "resources");

        return Directory.Exists(candidate) ? candidate : null;
    }
}
