using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the signature validation conclusion model, validation constraints and proof-of-existence
/// data model of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clauses 5.1.3 and 5.1.4</see> and clause 5.6.2.3, together with the wire values
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4</see> assigns them.
/// </summary>
/// <remarks>
/// The vectors are transcribed from the specification tables — Table 5's main indications, Table 6's
/// sub-indications, Table 7's retry conditions, and Table 2 of TS 119 102-2 clause 4.3.4.3 — so a change to a
/// mapped value fails against the specification rather than against a restatement of the implementation.
/// Digests are minted through the registered digest seam and disposed by the test that owns them; the identity
/// records hold non-owning references to them.
/// </remarks>
[TestClass]
internal sealed class SignatureValidationModelTests
{
    /// <summary>The test context, providing the cancellation token every asynchronous call is threaded with.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The SHA-256 digest length in bytes, the length every identity in these tests is minted at.</summary>
    private static int Sha256DigestByteLength => 32;


    /// <summary>
    /// Every sub-indication Table 6 of EN 319 102-1 clause 5.1.3 defines, paired with the URI Table 2 of
    /// TS 119 102-2 clause 4.3.4.3 assigns it. The last two rows are the sub-indications EN 319 102-1 V1.4.1
    /// adds after Table 2 was written; their expected URIs follow the same prefixing rule every other row of
    /// Table 2 follows.
    /// </summary>
    /// <returns>The sub-indication vectors.</returns>
    public static IEnumerable<object[]> SubIndicationWireValues()
    {
        (SignatureValidationSubIndication SubIndication, string Token)[] vectors =
        [
            (SignatureValidationSubIndication.FormatFailure, "FORMAT_FAILURE"),
            (SignatureValidationSubIndication.HashFailure, "HASH_FAILURE"),
            (SignatureValidationSubIndication.SignatureCryptographicFailure, "SIG_CRYPTO_FAILURE"),
            (SignatureValidationSubIndication.Revoked, "REVOKED"),
            (SignatureValidationSubIndication.Expired, "EXPIRED"),
            (SignatureValidationSubIndication.NotYetValid, "NOT_YET_VALID"),
            (SignatureValidationSubIndication.SignatureConstraintsFailure, "SIG_CONSTRAINTS_FAILURE"),
            (SignatureValidationSubIndication.ChainConstraintsFailure, "CHAIN_CONSTRAINTS_FAILURE"),
            (SignatureValidationSubIndication.CertificateChainGeneralFailure, "CERTIFICATE_CHAIN_GENERAL_FAILURE"),
            (SignatureValidationSubIndication.CryptographicConstraintsFailure, "CRYPTO_CONSTRAINTS_FAILURE"),
            (SignatureValidationSubIndication.PolicyProcessingError, "POLICY_PROCESSING_ERROR"),
            (SignatureValidationSubIndication.SignaturePolicyNotAvailable, "SIGNATURE_POLICY_NOT_AVAILABLE"),
            (SignatureValidationSubIndication.TimestampOrderFailure, "TIMESTAMP_ORDER_FAILURE"),
            (SignatureValidationSubIndication.NoSigningCertificateFound, "NO_SIGNING_CERTIFICATE_FOUND"),
            (SignatureValidationSubIndication.NoCertificateChainFound, "NO_CERTIFICATE_CHAIN_FOUND"),
            (SignatureValidationSubIndication.RevokedNoProofOfExistence, "REVOKED_NO_POE"),
            (SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, "REVOKED_CA_NO_POE"),
            (SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence, "OUT_OF_BOUNDS_NO_POE"),
            (SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence, "REVOCATION_OUT_OF_BOUNDS_NO_POE"),
            (SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence, "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
            (SignatureValidationSubIndication.NoProofOfExistence, "NO_POE"),
            (SignatureValidationSubIndication.TryLater, "TRY_LATER"),
            (SignatureValidationSubIndication.SignedDataNotFound, "SIGNED_DATA_NOT_FOUND"),
            (SignatureValidationSubIndication.Custom, "CUSTOM"),
            (SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence, "NO_CERTIFICATE_CHAIN_FOUND_NO_POE"),
            (SignatureValidationSubIndication.OutOfBoundsNotRevoked, "OUT_OF_BOUNDS_NOT_REVOKED")
        ];

        foreach((SignatureValidationSubIndication subIndication, string token) in vectors)
        {
            yield return [subIndication, token];
        }
    }


    /// <summary>
    /// Table 6: each sub-indication carries the specification's own token, and Table 2 of TS 119 102-2 clause
    /// 4.3.4.3 builds its URI by appending that token to the sub-indication namespace, which reads back to the
    /// same value.
    /// </summary>
    /// <param name="subIndication">The sub-indication under test.</param>
    /// <param name="expectedToken">The token the specification spells the sub-indication with.</param>
    [TestMethod]
    [DynamicData(nameof(SubIndicationWireValues))]
    public void SubIndicationCarriesItsSpecifiedTokenAndUriRoundTrips(SignatureValidationSubIndication subIndication, string expectedToken)
    {
        Assert.AreEqual(expectedToken, subIndication.Value, "The sub-indication has to carry the specification's own token.");

        string wireValue = SignatureValidationSubIndicationMapping.ToWireValue(subIndication);

        Assert.AreEqual($"urn:etsi:019102:subindication:{expectedToken}", wireValue, "Table 2 builds the URI by appending the token to the sub-indication namespace.");
        Assert.IsTrue(SignatureValidationWellKnown.IsSubIndication(wireValue), "A sub-indication URI has to be recognised as one.");
        Assert.IsTrue(SignatureValidationSubIndicationMapping.TryFromWireValue(wireValue, out SignatureValidationSubIndication readBack), "A sub-indication URI has to read back.");
        Assert.AreEqual(subIndication, readBack, "Reading a sub-indication URI back yields the same sub-indication.");
    }


    /// <summary>
    /// Table 7 of clause 5.1.3 lists the sub-indications for which the Driving Application may rerun the
    /// validation process, and the six of those whose condition is that additional proofs of existence have
    /// been made available. A sub-indication outside Table 7 — including a caller-minted custom one — advertises
    /// no retry.
    /// </summary>
    [TestMethod]
    public void RetryConditionsAreReportedForExactlyTheSubIndicationsTable7Lists()
    {
        SignatureValidationSubIndication[] retryable =
        [
            SignatureValidationSubIndication.ChainConstraintsFailure,
            SignatureValidationSubIndication.CertificateChainGeneralFailure,
            SignatureValidationSubIndication.PolicyProcessingError,
            SignatureValidationSubIndication.SignaturePolicyNotAvailable,
            SignatureValidationSubIndication.NoSigningCertificateFound,
            SignatureValidationSubIndication.NoCertificateChainFound,
            SignatureValidationSubIndication.RevokedNoProofOfExistence,
            SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence,
            SignatureValidationSubIndication.OutOfBoundsNotRevoked,
            SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence,
            SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
            SignatureValidationSubIndication.NoProofOfExistence,
            SignatureValidationSubIndication.TryLater
        ];

        foreach(SignatureValidationSubIndication subIndication in retryable)
        {
            Assert.IsTrue(subIndication.IsRetryable, $"Table 7 lists {subIndication.Value} as retryable.");
        }

        SignatureValidationSubIndication[] notRetryable =
        [
            SignatureValidationSubIndication.FormatFailure,
            SignatureValidationSubIndication.HashFailure,
            SignatureValidationSubIndication.SignatureCryptographicFailure,
            SignatureValidationSubIndication.Revoked,
            SignatureValidationSubIndication.Expired,
            SignatureValidationSubIndication.NotYetValid,
            SignatureValidationSubIndication.SignatureConstraintsFailure,
            SignatureValidationSubIndication.CryptographicConstraintsFailure,
            SignatureValidationSubIndication.TimestampOrderFailure,
            SignatureValidationSubIndication.NoCertificateChainFoundNoProofOfExistence,
            SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence,
            SignatureValidationSubIndication.SignedDataNotFound,
            SignatureValidationSubIndication.Custom,
            new SignatureValidationSubIndication("A_CALLER_MINTED_DIAGNOSTIC")
        ];

        foreach(SignatureValidationSubIndication subIndication in notRetryable)
        {
            Assert.IsFalse(subIndication.IsRetryable, $"Table 7 does not list {subIndication.Value} as retryable.");
        }

        SignatureValidationSubIndication[] needingProofsOfExistence =
        [
            SignatureValidationSubIndication.RevokedNoProofOfExistence,
            SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence,
            SignatureValidationSubIndication.OutOfBoundsNotRevoked,
            SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence,
            SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
            SignatureValidationSubIndication.NoProofOfExistence
        ];

        foreach(SignatureValidationSubIndication subIndication in needingProofsOfExistence)
        {
            Assert.IsTrue(subIndication.RequiresAdditionalProofsOfExistenceToRetry, $"Table 7 conditions retrying {subIndication.Value} on additional proofs of existence.");
        }

        Assert.IsFalse(SignatureValidationSubIndication.TryLater.RequiresAdditionalProofsOfExistenceToRetry, "Table 7 conditions retrying TRY_LATER on fresher revocation status information, not on proofs of existence.");
        Assert.IsFalse(SignatureValidationSubIndication.NoCertificateChainFound.RequiresAdditionalProofsOfExistenceToRetry, "Table 7 conditions retrying NO_CERTIFICATE_CHAIN_FOUND on CA certificates becoming available, not on proofs of existence.");
    }


    /// <summary>
    /// Clause 5.1.3's <c>INDETERMINATE</c> semantics — "the available information is insufficient to ascertain
    /// the signature to be <c>TOTAL-PASSED</c> or <c>TOTAL-FAILED</c>" — is what an unset indication has to
    /// read as, in both the process-level and the block-level vocabulary.
    /// </summary>
    /// <remarks>
    /// Each value is read out of a runtime zero-initialized array element rather than written as
    /// <c>default(T)</c>, so what the assertion exercises is the value a field the runtime cleared actually
    /// holds, not a constant the compiler folds away.
    /// </remarks>
    [TestMethod]
    public void UnsetIndicationsReadAsIndeterminate()
    {
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, ZeroInitialized<SignatureValidationIndication>(), "An unset process indication must never be a passing one.");
        Assert.AreEqual(BuildingBlockIndication.Indeterminate, ZeroInitialized<BuildingBlockIndication>(), "An unset block indication must never be a passing one.");
        Assert.AreEqual(AlgorithmReliabilityVerdict.Unknown, ZeroInitialized<AlgorithmReliabilityVerdict>(), "An unset reliability verdict must never assert reliability.");
        Assert.AreEqual(ProofOfExistenceScope.Unknown, ZeroInitialized<ProofOfExistenceScope>(), "An unset proof scope must prove nothing.");
        Assert.AreEqual(ProofOfExistenceOrigin.Unknown, ZeroInitialized<ProofOfExistenceOrigin>(), "An unset proof origin must attribute the proof to nothing.");
        Assert.AreEqual(ValidationObjectKind.Unknown, ZeroInitialized<ValidationObjectKind>(), "An unset object kind must name no object.");
        Assert.AreEqual(CertificateChainReportKind.LastBuilt, ZeroInitialized<CertificateChainReportKind>(), "An unset chain report kind must make the weaker of the two claims.");
        Assert.AreEqual(CertificateValidityModel.Shell, ZeroInitialized<CertificateValidityModel>(), "The shell model is the RFC 5280 clause 6.1 model clause 5.2.6.4 names first.");

        /// <summary>Reads the value a runtime-cleared field of the enumeration type holds.</summary>
        static T ZeroInitialized<T>() where T: struct, Enum
        {
            T[] cleared = new T[1];

            return cleared[0];
        }
    }


    /// <summary>
    /// Clause 5.1.3's three promotion rules: a selected validation process returning <c>PASSED</c> makes the
    /// overall result <c>TOTAL-PASSED</c>, <c>FAILED</c> makes it <c>TOTAL-FAILED</c>, and <c>INDETERMINATE</c>
    /// makes it <c>INDETERMINATE</c>. An out-of-range value promotes to <c>INDETERMINATE</c>, never to a
    /// passing one.
    /// </summary>
    [TestMethod]
    public void BlockIndicationsPromoteToProcessIndicationsPerClause513()
    {
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, BuildingBlockIndicationMapping.ToProcessIndication(BuildingBlockIndication.Passed), "PASSED promotes to TOTAL-PASSED.");
        Assert.AreEqual(SignatureValidationIndication.TotalFailed, BuildingBlockIndicationMapping.ToProcessIndication(BuildingBlockIndication.Failed), "FAILED promotes to TOTAL-FAILED.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, BuildingBlockIndicationMapping.ToProcessIndication(BuildingBlockIndication.Indeterminate), "INDETERMINATE promotes to INDETERMINATE.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, BuildingBlockIndicationMapping.ToProcessIndication((BuildingBlockIndication)99), "An unrecognised block indication must not promote to a passing result.");
    }


    /// <summary>
    /// Clause 4.3.4.2 of TS 119 102-2 assigns two different URI sets to the same main indication element: the
    /// <c>total-*</c> set in the validation report of a signature, and the <c>passed</c> / <c>failed</c> set in
    /// an individual validation constraint report element, with <c>INDETERMINATE</c> shared between them.
    /// </summary>
    [TestMethod]
    public void MainIndicationUrisDifferBetweenTheProcessAndBlockContexts()
    {
        Assert.AreEqual("urn:etsi:019102:mainindication:total-passed", SignatureValidationIndicationMapping.ToWireValue(SignatureValidationIndication.TotalPassed), "Clause 4.3.4.2 names the TOTAL-PASSED URI.");
        Assert.AreEqual("urn:etsi:019102:mainindication:total-failed", SignatureValidationIndicationMapping.ToWireValue(SignatureValidationIndication.TotalFailed), "Clause 4.3.4.2 names the TOTAL-FAILED URI.");
        Assert.AreEqual("urn:etsi:019102:mainindication:indeterminate", SignatureValidationIndicationMapping.ToWireValue(SignatureValidationIndication.Indeterminate), "Clause 4.3.4.2 names the INDETERMINATE URI.");
        Assert.AreEqual("urn:etsi:019102:mainindication:passed", BuildingBlockIndicationMapping.ToWireValue(BuildingBlockIndication.Passed), "Clause 4.3.4.2 names the PASSED URI.");
        Assert.AreEqual("urn:etsi:019102:mainindication:failed", BuildingBlockIndicationMapping.ToWireValue(BuildingBlockIndication.Failed), "Clause 4.3.4.2 names the FAILED URI.");
        Assert.AreEqual("urn:etsi:019102:mainindication:indeterminate", BuildingBlockIndicationMapping.ToWireValue(BuildingBlockIndication.Indeterminate), "The INDETERMINATE URI is shared between the two contexts.");

        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationIndeterminate, SignatureValidationIndicationMapping.ToWireValue((SignatureValidationIndication)99), "An unrecognised process indication must not map to a passing URI.");
        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationIndeterminate, BuildingBlockIndicationMapping.ToWireValue((BuildingBlockIndication)99), "An unrecognised block indication must not map to a passing URI.");

        Assert.IsTrue(SignatureValidationWellKnown.IsProcessMainIndication(SignatureValidationWellKnown.MainIndicationTotalPassed), "The TOTAL-PASSED URI belongs to the process context.");
        Assert.IsFalse(SignatureValidationWellKnown.IsBuildingBlockMainIndication(SignatureValidationWellKnown.MainIndicationTotalPassed), "The TOTAL-PASSED URI does not belong to the block context.");
        Assert.IsTrue(SignatureValidationWellKnown.IsMainIndication(SignatureValidationWellKnown.MainIndicationFailed), "The FAILED URI is a main indication URI.");
        Assert.IsFalse(SignatureValidationWellKnown.IsSubIndication(SignatureValidationWellKnown.SubIndicationPrefix), "The bare sub-indication namespace names no sub-indication.");

        Assert.IsTrue(SignatureValidationProcessIdentifier.Basic.IsBasic, "The clause 5.3 process identifies itself.");
        Assert.IsTrue(SignatureValidationWellKnown.IsSpecifiedValidationProcess(SignatureValidationProcessIdentifier.LongTermValidationMaterial.Value), "Clause 4.3.11.1 names the clause 5.5 process URI.");
        Assert.IsTrue(SignatureValidationWellKnown.IsSpecifiedValidationProcess(SignatureValidationProcessIdentifier.LongTermAvailability.Value), "Clause 4.3.11.1 names the clause 5.6 process URI.");
    }


    /// <summary>
    /// A block conclusion built by the passing factories carries no sub-indication, and the failing factories
    /// carry exactly the one they were given, so a process propagating "the indication and sub-indication
    /// returned by" a block has one value to read.
    /// </summary>
    [TestMethod]
    public void BuildingBlockConclusionFactoriesCarryTheGivenVocabulary()
    {
        Assert.AreEqual(BuildingBlockIndication.Passed, BuildingBlockConclusion.Passed.Indication, "The passed conclusion is PASSED.");
        Assert.IsEmpty(BuildingBlockConclusion.Passed.SubIndications, "A passing conclusion carries no sub-indication.");
        Assert.IsEmpty(BuildingBlockConclusion.Passed.ReportData, "The bare passed conclusion carries no report data.");

        BuildingBlockConclusion indeterminate = BuildingBlockConclusion.Indeterminate(
            SignatureValidationSubIndication.RevokedNoProofOfExistence,
            [new CustomDiagnosticReportData("the revocation instant is unknown")]);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, indeterminate.Indication, "The factory sets INDETERMINATE.");
        Assert.AreSequenceEqual([SignatureValidationSubIndication.RevokedNoProofOfExistence], indeterminate.SubIndications, "The factory carries exactly the sub-indication it was given.");
        Assert.HasCount(1, indeterminate.ReportData, "The factory carries the report data it was given.");

        BuildingBlockConclusion failed = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.HashFailure, [new HashFailureReportData(["#object-1"])]);

        Assert.AreEqual(BuildingBlockIndication.Failed, failed.Indication, "The factory sets FAILED.");
        Assert.AreSequenceEqual([SignatureValidationSubIndication.HashFailure], failed.SubIndications, "The factory carries exactly the sub-indication it was given.");
    }


    /// <summary>
    /// Clause 5.1.4.3: an algorithm the cryptographic constraints do not list is never reliable, one whose key
    /// size is below the table's floor is not reliable at any instant, and one the table dates is reliable up
    /// to and including its trusted-until instant and not after it.
    /// </summary>
    [TestMethod]
    public void AlgorithmReliabilityFollowsTheDatedTableAndFailsClosedForUnlistedAlgorithms()
    {
        DateTimeOffset sha256TrustedUntil = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset rsaTrustedUntil = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        AlgorithmIdentifier rsa = new("1.2.840.113549.1.1.11") { Name = "sha256WithRSAEncryption" };

        CryptographicConstraints constraints = new()
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, sha256TrustedUntil),
                new AlgorithmReliabilityEntry(rsa, MinimumKeySizeBits: 2048, rsaTrustedUntil),
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha512, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };

        AlgorithmUse unlisted = new(AlgorithmIdentifier.Sha1, KeySizeBits: null, "the signature value");
        AlgorithmReliabilityAssessment unlistedAssessment = constraints.Assess(unlisted, sha256TrustedUntil);

        Assert.AreEqual(AlgorithmReliabilityVerdict.Unknown, unlistedAssessment.Verdict, "An unlisted algorithm is not asserted reliable by anything.");
        Assert.IsFalse(unlistedAssessment.IsReliable, "Clause 5.1.4.1 forbids treating an unchecked constraint as satisfied.");
        Assert.IsNull(unlistedAssessment.TrustedUntil, "An unlisted algorithm has no trusted-until instant to report.");

        AlgorithmUse shortKey = new(rsa, KeySizeBits: 1024, "the signing certificate");

        Assert.AreEqual(AlgorithmReliabilityVerdict.KeySizeBelowMinimum, constraints.Assess(shortKey, rsaTrustedUntil.AddYears(-5)).Verdict, "A key below the table's floor is not reliable however early the instant.");

        AlgorithmUse longKey = new(rsa, KeySizeBits: 3072, "the signing certificate");

        Assert.AreEqual(AlgorithmReliabilityVerdict.Reliable, constraints.Assess(longKey, rsaTrustedUntil).Verdict, "The trusted-until instant is itself still reliable.");
        Assert.AreEqual(AlgorithmReliabilityVerdict.NoLongerReliable, constraints.Assess(longKey, rsaTrustedUntil.AddTicks(1)).Verdict, "One tick past the trusted-until instant is no longer reliable.");
        Assert.AreEqual(rsaTrustedUntil, constraints.Assess(longKey, rsaTrustedUntil.AddTicks(1)).TrustedUntil, "Table 6 requires reporting the time up to which the algorithm was considered secure.");

        AlgorithmUse noExpiry = new(AlgorithmIdentifier.Sha512, KeySizeBits: null, "an archive time-stamp");

        Assert.AreEqual(AlgorithmReliabilityVerdict.Reliable, constraints.Assess(noExpiry, sha256TrustedUntil.AddYears(50)).Verdict, "A row asserting no expiry is reliable at any instant.");

        IReadOnlyList<AlgorithmReliabilityAssessment> unreliable = constraints.FindUnreliable([longKey, unlisted, noExpiry], rsaTrustedUntil.AddTicks(1));

        Assert.HasCount(2, unreliable, "Both the expired algorithm and the unlisted one are reported.");
        Assert.AreEqual("the signing certificate", unreliable[0].Use.MaterialIdentifier, "The offending material is reported in the order the uses were given.");

        Assert.AreEqual(rsaTrustedUntil, constraints.LatestInstantAllReliable([longKey, noExpiry]), "Clause 5.6.2.2 step 2)d) slides control-time to the earliest of the listed trusted-until instants.");
        Assert.IsNull(constraints.LatestInstantAllReliable([longKey, unlisted]), "No instant can be asserted for a set containing an unlisted algorithm.");
        Assert.IsNull(constraints.LatestInstantAllReliable([shortKey]), "No instant can be asserted for a key below the table's floor.");

        Assert.IsTrue(constraints.IsHashTrustedUntilAtLeast(AlgorithmIdentifier.Sha256, sha256TrustedUntil), "Clause 5.6.2.3 step 4 gates on the hash being trusted until at least the instant.");
        Assert.IsFalse(constraints.IsHashTrustedUntilAtLeast(AlgorithmIdentifier.Sha256, sha256TrustedUntil.AddTicks(1)), "A hash is not trusted past its trusted-until instant.");
        Assert.IsFalse(constraints.IsHashTrustedUntilAtLeast(AlgorithmIdentifier.Sha1, sha256TrustedUntil), "An unlisted hash gates nothing open.");
        Assert.IsFalse(CryptographicConstraints.Empty.IsHashTrustedUntilAtLeast(AlgorithmIdentifier.Sha256, sha256TrustedUntil), "An empty table asserts nothing reliable.");
    }


    /// <summary>
    /// An algorithm identity is the object identifier alone: a report label does not make two identities
    /// differ, and two different identifiers never match.
    /// </summary>
    [TestMethod]
    public void AlgorithmIdentityIsTheObjectIdentifierAlone()
    {
        Assert.AreEqual(AlgorithmIdentifier.Sha256, new AlgorithmIdentifier(WellKnownOids.Sha256), "A label takes no part in identity.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256.GetHashCode(), new AlgorithmIdentifier(WellKnownOids.Sha256).GetHashCode(), "Equal identities hash equally.");
        Assert.AreNotEqual(AlgorithmIdentifier.Sha256, AlgorithmIdentifier.Sha384, "Different object identifiers are different algorithms.");

        Assert.IsTrue(AlgorithmIdentifier.TryFromTag(CryptoTags.Sha256Digest, out AlgorithmIdentifier fromTag), "The registered digest seam's SHA-256 tag names a known algorithm.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256, fromTag, "The tag maps to the SHA-256 object identifier.");
        Assert.IsFalse(AlgorithmIdentifier.TryFromTag(CryptoTags.P256PublicKey, out _), "A tag carrying no hash algorithm names no digest algorithm.");
    }


    /// <summary>
    /// Clause 5.6.2.2 step 2)a), clause 5.6.2.3 and clause 5.6.2.4 step 3): the set answers whether an object,
    /// or a digest of it under a stated hash function, is proven to have existed at or before an instant, and
    /// what the earliest such instant is. A proof of a digest never answers a question about the object itself.
    /// </summary>
    [TestMethod]
    public async Task ProofOfExistenceSetAnswersTheMembershipQueriesOfClause562()
    {
        using DigestValue signatureValueDigest = await ComputeSha256Async("the signature value", TestContext.CancellationToken).ConfigureAwait(false);
        using DigestValue certificateDigest = await ComputeSha256Async("the signing certificate", TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity signatureValue = new()
        {
            Kind = ValidationObjectKind.SignatureValue,
            Digest = signatureValueDigest,
            DigestAlgorithm = AlgorithmIdentifier.Sha256
        };
        ValidationObjectIdentity certificate = new()
        {
            Kind = ValidationObjectKind.Certificate,
            Digest = certificateDigest,
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            Reference = "CN=Signer, serial 01"
        };

        DateTimeOffset early = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset late = new(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);

        ProofOfExistence lateSignatureProof = new()
        {
            ObjectIdentity = signatureValue,
            Instant = late,
            Scope = ProofOfExistenceScope.Object,
            Origin = ProofOfExistenceOrigin.TimestampToken
        };
        ProofOfExistence earlySignatureProof = lateSignatureProof with { Instant = early };
        ProofOfExistence certificateDigestProof = new()
        {
            ObjectIdentity = certificate,
            Instant = early,
            Scope = ProofOfExistenceScope.DigestOfObject,
            Origin = ProofOfExistenceOrigin.TimestampToken,
            ReferenceDigestAlgorithm = AlgorithmIdentifier.Sha256
        };

        Assert.IsEmpty(ProofOfExistenceSet.Empty.Proofs, "Clause 5.6.2.3 step 3) initialises the set of POE with an empty set.");
        Assert.IsFalse(ProofOfExistenceSet.Empty.ExistsAtOrBefore(signatureValue, late), "An empty set proves nothing.");

        ProofOfExistenceSet set = ProofOfExistenceSet.Empty
            .With(lateSignatureProof)
            .With(earlySignatureProof)
            .With(certificateDigestProof);

        Assert.HasCount(3, set.Proofs, "Three distinct proofs were added.");
        Assert.AreSame(set, set.With(lateSignatureProof), "Adding a proof already present leaves the set unchanged.");

        Assert.IsTrue(set.ExistsAtOrBefore(signatureValue, early), "The signature value is proven to have existed at the early instant.");
        Assert.IsFalse(set.ExistsAtOrBefore(signatureValue, early.AddTicks(-1)), "Nothing proves the signature value existed before the earliest proof.");
        Assert.AreEqual(early, set.EarliestInstantFor(signatureValue), "Best-signature-time is the lowest instant at which a proof for the signature value exists.");

        Assert.IsFalse(set.ExistsAtOrBefore(certificate, late), "A proof of a digest is not a proof of the object itself.");
        Assert.IsNull(set.EarliestInstantFor(certificate), "A proof of a digest contributes no instant to the object's own earliest proof.");
        Assert.IsTrue(set.DigestExistsAtOrBefore(certificate, AlgorithmIdentifier.Sha256, early), "The digest of the certificate is proven to have existed at the early instant.");
        Assert.IsFalse(set.DigestExistsAtOrBefore(certificate, AlgorithmIdentifier.Sha384, early), "A proof for a digest under one hash function says nothing about another.");
        Assert.AreEqual(early, set.EarliestDigestInstantFor(certificate, AlgorithmIdentifier.Sha256), "The earliest digest proof is the date T1 of the indirect derivation.");

        Assert.HasCount(2, set.For(signatureValue), "Both proofs about the signature value are reported.");
        Assert.HasCount(1, set.For(certificate), "The one proof about the certificate is reported.");

        ProofOfExistenceSet union = set.Union(ProofOfExistenceSet.Create([earlySignatureProof, certificateDigestProof]));

        Assert.AreSame(set, union, "Unioning a set with proofs it already holds leaves it unchanged.");
        Assert.HasCount(3, ProofOfExistenceSet.Create([lateSignatureProof, lateSignatureProof, earlySignatureProof, certificateDigestProof]).Proofs, "Creating a set discards duplicates.");
    }


    /// <summary>
    /// An object's identity is its kind, its digest algorithm, its reference and its digest bytes together:
    /// the same bytes read under a different algorithm, or carried by a differently referenced object, name a
    /// different object.
    /// </summary>
    [TestMethod]
    public async Task ValidationObjectIdentityDistinguishesAlgorithmKindAndReference()
    {
        using DigestValue digest = await ComputeSha256Async("an object", TestContext.CancellationToken).ConfigureAwait(false);
        using DigestValue otherDigest = await ComputeSha256Async("another object", TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity identity = new()
        {
            Kind = ValidationObjectKind.Certificate,
            Digest = digest,
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            Reference = "CN=Signer"
        };

        Assert.AreEqual(identity, identity with { }, "An identity equals a copy of itself.");
        Assert.AreEqual(identity.GetHashCode(), (identity with { }).GetHashCode(), "Equal identities hash equally.");
        Assert.AreNotEqual(identity, identity with { DigestAlgorithm = AlgorithmIdentifier.Sha384 }, "The digest algorithm is part of the identity, since a digest's own equality is byte-level only.");
        Assert.AreNotEqual(identity, identity with { Kind = ValidationObjectKind.RevocationData }, "The kind is part of the identity.");
        Assert.AreNotEqual(identity, identity with { Reference = "CN=Other" }, "The reference is part of the identity.");
        Assert.AreNotEqual(identity, identity with { Digest = otherDigest }, "The digest bytes are part of the identity.");
    }


    /// <summary>
    /// Clause 5.1.4.2: the X.509 validation constraints associate an optional sunset date with each trust
    /// anchor, and an anchor the constraints do not list is not one the chain may terminate at.
    /// </summary>
    [TestMethod]
    public void TrustAnchorSunsetDatesAreLookedUpByTheAnchorsOwnBytes()
    {
        using PkiCertificateMemory anchor = CreateCertificateCarrier([0x30, 0x03, 0x02, 0x01, 0x01]);
        using PkiCertificateMemory sameAnchor = CreateCertificateCarrier([0x30, 0x03, 0x02, 0x01, 0x01]);
        using PkiCertificateMemory otherAnchor = CreateCertificateCarrier([0x30, 0x03, 0x02, 0x01, 0x02]);

        DateTimeOffset sunset = new(2029, 6, 1, 0, 0, 0, TimeSpan.Zero);
        X509ValidationConstraints constraints = new()
        {
            TrustAnchors = [new TrustAnchorConstraint(anchor, sunset), new TrustAnchorConstraint(otherAnchor, SunsetDate: null)]
        };

        Assert.IsTrue(constraints.TryGetTrustAnchorSunsetDate(sameAnchor, out DateTimeOffset? found), "An anchor is looked up by its own bytes.");
        Assert.AreEqual(sunset, found, "Clause 5.2.6.4 step 3) reads the sunset date associated with the anchor the chain was built from.");
        Assert.IsTrue(constraints.TryGetTrustAnchorSunsetDate(otherAnchor, out DateTimeOffset? none), "A listed anchor is found even without a sunset date.");
        Assert.IsNull(none, "An anchor the constraints set no sunset date for reports none.");

        using PkiCertificateMemory unlisted = CreateCertificateCarrier([0x30, 0x03, 0x02, 0x01, 0x03]);

        Assert.IsFalse(constraints.TryGetTrustAnchorSunsetDate(unlisted, out _), "An unlisted anchor is not a trust anchor.");

        Assert.AreEqual(CertificateValidityModel.Shell, constraints.ValidityModel, "The shell model is the default.");
        Assert.IsNull(constraints.MaximumAcceptedRevocationFreshness, "No maximum accepted freshness selects the nextUpdate fallback of clause 5.2.5.4 step 1.");
        Assert.IsFalse(constraints.ExemptCertificatesWithOcspNoCheckExtension,
            "EXAMPLE 2 of clause 5.2.6.4 says a relying party MAY honour id-pkix-ocsp-nocheck, and the extension is non-critical and self-asserted, so the default that skips nothing the algorithm prescribes is to keep checking.");
        Assert.IsFalse(constraints.ExemptCertificatesWithExtendedValidationAssuranceExtension, "The relying party's own choice under EN 319 412-1 defaults to still checking.");
    }


    /// <summary>
    /// Clause 5.1.4.4: every default of the signature elements constraints is the branch the specification
    /// itself takes when no constraint is stated, so an untouched constraint set drives the algorithm exactly
    /// as an absent one does.
    /// </summary>
    [TestMethod]
    public void SignatureElementsConstraintDefaultsMatchTheSpecificationsOwnAbsentConstraintBranches()
    {
        SignatureElementsConstraints constraints = new();

        Assert.IsEmpty(constraints.MandatedSignedAttributeOids, "No attribute is mandated by default.");
        Assert.IsEmpty(constraints.ForbiddenSignedAttributeOids, "No attribute is forbidden by default.");
        Assert.IsNull(constraints.TimestampDelay, "Clause 5.5.4 step 5) only runs when the constraints specify a time-stamp delay.");
        Assert.IsFalse(constraints.RequireSigningCertificateReferencesForFullPath, "Clause 5.2.8.4.2.1 conditions the full-path check on the signature policy mandating it.");
        Assert.IsFalse(constraints.RequireSignatureTimestampValidity, "Clause 5.5.4 step 3)b) removes a failing token from the set unless a constraint mandates its validity.");
        Assert.IsFalse(constraints.RequireContentTimestampValidity, "Clause 5.2.8.4.2.5 conditions the check on specific constraints for time-stamps on Signed Data Objects.");
        Assert.IsFalse(constraints.RequireCountersignatureValidity, "Clause 5.2.8.4.2.6 forbids failing the signature for a countersignature when no constraint is stated.");
    }


    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam, which is the only way this suite obtains
    /// a digest.
    /// </summary>
    /// <param name="text">The text whose UTF-8 bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The digest, which the caller owns and disposes.</returns>
    private static async ValueTask<DigestValue> ComputeSha256Async(string text, CancellationToken cancellationToken)
    {
        byte[] input = Encoding.UTF8.GetBytes(text);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(input),
            Sha256DigestByteLength,
            CryptoTags.Sha256Digest,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Wraps DER bytes in the certificate carrier the constraint records hold references to.
    /// </summary>
    /// <param name="derBytes">The DER bytes to wrap.</param>
    /// <returns>The carrier, which the caller owns and disposes.</returns>
    private static PkiCertificateMemory CreateCertificateCarrier(ReadOnlySpan<byte> derBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
