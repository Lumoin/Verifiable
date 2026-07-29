using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.X509;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The cross-implementation leg of the signature validation algorithm of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5</see>: CAdES artifacts signed by a third party are driven through the
/// shipped engine and the conclusions it reaches are asserted exactly.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where the artifacts come from.</strong> They are read at run time from a local reference-artifact
/// clone under <c>tempdocs/etsi-ades-reference/</c>. Nothing is copied into this repository, and when the clone
/// is absent — a fresh checkout without that optional local material — every test here reports
/// <see cref="Assert.Inconclusive(string)"/> instead of failing, exactly as <c>TrustedListFixtureTests</c> does
/// for the trusted-list corpus.
/// </para>
/// <para>
/// <strong>The selection rule.</strong> Every file under the clone's CAdES validation-resources directory whose
/// extension is <c>.p7m</c>, <c>.p7s</c> or <c>.pkcs7</c>, enumerated recursively and ordered ordinally. The rule
/// is mechanical and exhaustive: the corpus contains valid signatures, deliberately malformed ones, detached
/// ones, and ones using algorithms this library does not implement, and every one of them is driven through the
/// engine. Nothing is picked for a favourable outcome, and the sweep pins the whole distribution, so an artifact
/// silently changing bucket is a failure rather than a shrug.
/// </para>
/// <para>
/// <strong>What can be asserted, and why.</strong> The Driving Application here has no trust context for any of
/// these artifacts: no trust anchor, no revocation material, no signature policy. Under clause 5.1.3 that makes
/// <c>TOTAL-PASSED</c> unreachable by construction, so the sweep asserts fail-closed staging (no artifact passes,
/// every artifact lands in a documented bucket, none makes the algorithm throw) and the named tests assert the
/// precise sub-indication each artifact's own shape mandates. Where an artifact carries its whole chain up to a
/// self-signed certificate the test can then trust deliberately, a stronger assertion is made: the engine gets
/// through format checking, signing-certificate identification, chain building, certification path validation
/// and cryptographic verification on genuine third-party material and stops exactly at the one input the
/// artifact does not carry.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ReferenceArtifactSignatureValidationTests
{
    /// <summary>
    /// How many artifacts the selection rule yields at the clone revision this class was written against. Pinned
    /// so that a corpus change is reported rather than silently changing what the sweep proves.
    /// </summary>
    private const int ExpectedArtifactCount = 110;


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The distribution the whole corpus produces when validated with no trust context at all: which conclusion
    /// of clause 5.1.3 each artifact reaches, and how many reach it. Every bucket is a documented consequence of
    /// the artifact's own shape; the two <c>TOTAL-FAILED</c> buckets carry an entry in the flag list of this
    /// class's build-log section.
    /// </summary>
    private static FrozenDictionary<string, int> ExpectedDistributionWithoutTrustContext { get; } =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            //The signature parsed, its signing certificate was identified and its signature value verified; the
            //Driving Application simply has no trust anchor, so step 2)a) of clause 5.2.6.4 ends the chain
            //building. This is the fail-closed staging outcome the leg exists to prove.
            ["INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND"] = 53,

            //Detached signatures. The shipped CMS verification seam verifies encapsulated content only and the
            //Driving Application supplied no Signer's Document, which is clause 5.2.7.4 step 1)'s own outcome.
            ["INDETERMINATE/SIGNED_DATA_NOT_FOUND"] = 18,

            //Signed Data Objects the shipped binding refuses: 13 encoded under the Basic Encoding Rules rather
            //than the Distinguished Encoding Rules, 2 carrying duplicated signed attributes (trailing data the
            //hostile-input discipline rejects), and 2 whose outermost ASN.1 tag is not a SEQUENCE.
            ["TOTAL-FAILED/FORMAT_FAILURE"] = 17,

            //One genuinely tampered artifact whose content does not match its own message-digest attribute, and
            //nine naming a digest algorithm this library cannot compute (see the known-deviation test).
            ["TOTAL-FAILED/HASH_FAILURE"] = 10,

            //Signatures declaring a signature creation policy the caller's mapping does not cover, with the
            //secure default of clause 5.2.4.4's local-configuration decision.
            ["INDETERMINATE/POLICY_PROCESSING_ERROR"] = 6,

            //Signatures whose signing-certificate reference names no certificate the signature carries, or names
            //it under a digest algorithm this library cannot compute.
            ["INDETERMINATE/NO_SIGNING_CERTIFICATE_FOUND"] = 3,

            //Signature values two independent CMS backends both refuse.
            ["TOTAL-FAILED/SIG_CRYPTO_FAILURE"] = 3
        }.ToFrozenDictionary(StringComparer.Ordinal);


    /// <summary>
    /// The artifacts whose signature an independent CMS backend verifies but which the shipped engine reports
    /// <c>TOTAL-FAILED</c>/<c>HASH_FAILURE</c> for, because the digest algorithm their <c>SignerInfo</c> names
    /// is one this library cannot compute (SHA-1, and the SHA-3 family). See
    /// <see cref="ArtifactsNamingAnUncomputableDigestAlgorithmAreReportedTotalFailedAlthoughTheirSignaturesVerify"/>.
    /// </summary>
    private static IReadOnlyList<string> ArtifactsWithAnUncomputableDigestAlgorithm { get; } =
    [
        "Signature-C-X-1.p7m",
        "Signature-CBp-B-1.p7m",
        "CAdES-BpB-att-SHA3_224-SHA3_224withRSA.p7m",
        "CAdES-BpB-att-SHA3_256-SHA3_256withRSA.p7m",
        "CAdES-BpB-att-SHA3_512-SHA3_512withRSA.p7m"
    ];


    /// <summary>
    /// The whole corpus, validated with no trust context: no artifact reaches <c>TOTAL-PASSED</c>, no artifact
    /// makes a process entry point throw, and the distribution of conclusions is exactly the documented one.
    /// </summary>
    [TestMethod]
    public async Task TheWholeCorpusStagesFailClosedAndProducesExactlyTheDocumentedDistribution()
    {
        IReadOnlyList<string>? artifacts = TryEnumerateArtifacts();
        if(artifacts is null)
        {
            return;
        }

        Assert.HasCount(ExpectedArtifactCount, artifacts,
            "The selection rule is expected to yield exactly the pinned number of artifacts; the local reference-artifact corpus changed.");

        Dictionary<string, int> distribution = new(StringComparer.Ordinal);
        List<string> passed = [];
        for(int i = 0; i < artifacts.Count; ++i)
        {
            byte[] bytes = await ReadArtifactAsync(artifacts[i]).ConfigureAwait(false);
            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
            if(conclusion.Indication == SignatureValidationIndication.TotalPassed)
            {
                passed.Add(artifacts[i]);
            }

            string bucket = Describe(conclusion);
            distribution[bucket] = distribution.TryGetValue(bucket, out int count) ? count + 1 : 1;
        }

        Assert.IsEmpty(passed,
            "Clause 5.1.3 makes TOTAL-PASSED unreachable without a trust anchor, so any artifact reaching it would be a fail-open defect: " + string.Join(", ", passed));

        foreach(KeyValuePair<string, int> expected in ExpectedDistributionWithoutTrustContext)
        {
            Assert.IsTrue(distribution.TryGetValue(expected.Key, out int actual) && actual == expected.Value,
                $"The bucket '{expected.Key}' is expected to hold {expected.Value} artifacts but holds {(distribution.TryGetValue(expected.Key, out int found) ? found : 0)}.");
        }

        Assert.HasCount(ExpectedDistributionWithoutTrustContext.Count, distribution,
            "Every conclusion the corpus produces has to be one of the documented buckets: " + string.Join(", ", distribution.Keys));
    }


    /// <summary>
    /// The regression anchor for the fail-closed rule that no exception escapes a process entry point for
    /// attacker-reachable input: the whole corpus is run twice — once with no trust context, and once with every
    /// self-signed certificate the artifact itself carries deliberately trusted, at an instant inside the signing
    /// certificate's own validity window — and neither sweep lets an exception out.
    /// </summary>
    /// <remarks>
    /// The second sweep is what found the defect this class shipped a fix for: the platform certification path
    /// validation seam raises <c>CryptographicException</c>, not <c>SecurityException</c>, from a chain build it
    /// cannot complete, and the X.509 certificate validation building block caught only the latter. One artifact
    /// of this corpus reaches that branch.
    /// </remarks>
    [TestMethod]
    public async Task NoArtifactMakesAValidationProcessThrowWithOrWithoutItsOwnTrustContext()
    {
        IReadOnlyList<string>? artifacts = TryEnumerateArtifacts();
        if(artifacts is null)
        {
            return;
        }

        List<string> escaped = [];
        int reachedRevocation = 0;
        for(int i = 0; i < artifacts.Count; ++i)
        {
            byte[] bytes = await ReadArtifactAsync(artifacts[i]).ConfigureAwait(false);
            try
            {
                _ = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
                SignatureValidationConclusion? trusted = await ValidateAgainstOwnAnchorsAsync(bytes).ConfigureAwait(false);
                if(trusted is not null
                    && trusted.SubIndications.Count > 0
                    && trusted.SubIndications[0].Equals(SignatureValidationSubIndication.TryLater))
                {
                    ++reachedRevocation;
                }
            }
            catch(Exception exception)
            {
                escaped.Add($"{artifacts[i]}: {exception.GetType().Name}");
            }
        }

        Assert.IsEmpty(escaped,
            "No process entry point of clause 5 may let an exception escape for attacker-reachable input: " + string.Join(", ", escaped));
        Assert.IsGreaterThan(0, reachedRevocation,
            "At least one artifact has to get all the way to the revocation check under its own trust anchor, or the sweep proves nothing about the depth reached.");
    }


    /// <summary>
    /// An enveloping artifact — one that encapsulates the content it signs — has its signature value verified by
    /// the shipped cryptographic verification of clause 5.2.7 and then stops at exactly one thing: the Driving
    /// Application knows no trust anchor. Table 6 mandates no associated report data for that sub-indication and
    /// none is invented.
    /// </summary>
    [TestMethod]
    public async Task AnEnvelopingArtifactVerifiesCryptographicallyAndStopsAtTheMissingTrustAnchor()
    {
        string[] enveloping = ["cades-bes-signeddata-enveloping.p7m", "cades-enveloping.pkcs7"];
        for(int i = 0; i < enveloping.Length; ++i)
        {
            byte[]? bytes = await TryReadArtifactAsync(enveloping[i]).ConfigureAwait(false);
            if(bytes is null)
            {
                return;
            }

            SignatureCryptographicOutcome cryptographic = await VerifyCryptographyAsync(bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureCryptographicOutcome.Verified, cryptographic,
                $"The signature value of '{enveloping[i]}' verifies under its own signing certificate through the shipped cryptographic verification building block.");

            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication, $"'{enveloping[i]}' cannot be decided without a trust anchor.");
            Assert.AreEqual(SignatureValidationSubIndication.NoCertificateChainFound, conclusion.SubIndications[0],
                "Step 2)a) of clause 5.2.6.4 returns NO_CERTIFICATE_CHAIN_FOUND when no prospective chain reaches a trust anchor.");
            Assert.IsEmpty(conclusion.ReportData, "Table 6 mandates no associated validation report data for NO_CERTIFICATE_CHAIN_FOUND.");
            Assert.IsEmpty(conclusion.ValidatedCertificateChain, "No chain was validated, so Table 5's TOTAL-PASSED output is absent.");
        }
    }


    /// <summary>
    /// A detached artifact whose Signer's Document the Driving Application did not supply reports the outcome of
    /// step 1) of clause 5.2.7.4 — the signed data items could not be obtained — naming the signed data item that
    /// is missing.
    /// </summary>
    [TestMethod]
    public async Task ADetachedArtifactReportsSignedDataNotFoundNamingTheMissingSignedDataItem()
    {
        string[] detached = ["cades-bes-signeddata-detached.p7s", "cades-detached.pkcs7"];
        for(int i = 0; i < detached.Length; ++i)
        {
            byte[]? bytes = await TryReadArtifactAsync(detached[i]).ConfigureAwait(false);
            if(bytes is null)
            {
                return;
            }

            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication, $"'{detached[i]}' is indeterminate, not invalid: the signed data was never obtained.");
            Assert.AreEqual(SignatureValidationSubIndication.SignedDataNotFound, conclusion.SubIndications[0],
                "Table 15 of clause 5.2.7.3 names SIGNED_DATA_NOT_FOUND for signed data that cannot be obtained.");

            Assert.HasCount(1, conclusion.ReportData, "Table 6 asks for the identifiers of the signed data that caused the failure.");
            Assert.IsInstanceOfType<SignedDataNotFoundReportData>(conclusion.ReportData[0], "The reported evidence has the shape Table 6 asks for.");
            Assert.IsNotEmpty(((SignedDataNotFoundReportData)conclusion.ReportData[0]).SignedDataIdentifiers,
                "The identifier of the signed data item the binding could not obtain is reported.");
        }
    }


    /// <summary>
    /// A deliberately tampered enveloping artifact — its encapsulated content no longer matches its own
    /// <c>message-digest</c> signed attribute — is reported <c>TOTAL-FAILED</c>/<c>HASH_FAILURE</c>, which an
    /// independent CMS backend agrees with.
    /// </summary>
    [TestMethod]
    public async Task ATamperedEnvelopingArtifactIsRejectedAsAHashFailure()
    {
        byte[]? bytes = await TryReadArtifactAsync("cades-enveloping-broken.pkcs7").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
        Assert.AreEqual(SignatureValidationIndication.TotalFailed, conclusion.Indication,
            "Clause 5.1.2 step 6) promotes a FAILED cryptographic verification to TOTAL-FAILED: the signature genuinely does not cover this content.");
        Assert.AreEqual(SignatureValidationSubIndication.HashFailure, conclusion.SubIndications[0],
            "Table 15 of clause 5.2.7.3 names HASH_FAILURE for the integrity of the signed data items.");
        Assert.HasCount(1, conclusion.ReportData, "Table 6 mandates the identifiers of the elements that caused the failure.");
        Assert.IsInstanceOfType<HashFailureReportData>(conclusion.ReportData[0], "The reported evidence has the shape Table 6 mandates.");
        Assert.IsNotEmpty(((HashFailureReportData)conclusion.ReportData[0]).FailingObjectIdentifiers, "The failing element is named.");

        Assert.IsFalse(await IndependentBackendVerifiesAsync(bytes).ConfigureAwait(false),
            "An independent CMS backend has to reject the same artifact, or the rejection would be this library's own artefact rather than a property of the signature.");
    }


    /// <summary>
    /// Artifacts carrying duplicated signed attributes are rejected by the format checking building block of
    /// clause 5.2.2 before any cryptography runs — the hostile-input discipline that refuses trailing data inside
    /// a structure whose last expected value has already been read.
    /// </summary>
    [TestMethod]
    public async Task ArtifactsWithDuplicatedSignedAttributesAreRejectedByFormatCheckingBeforeAnyCryptographyRuns()
    {
        string[] duplicated = ["cades-duplicated-signed-attrs.p7m", "cades-double-signing-certificate.p7m"];
        for(int i = 0; i < duplicated.Length; ++i)
        {
            byte[]? bytes = await TryReadArtifactAsync(duplicated[i]).ConfigureAwait(false);
            if(bytes is null)
            {
                return;
            }

            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.TotalFailed, conclusion.Indication,
                $"'{duplicated[i]}' is not a Signed Data Object the binding can process at all, which clause 5.2.2.4 makes FAILED.");
            Assert.AreEqual(SignatureValidationSubIndication.FormatFailure, conclusion.SubIndications[0], "Table 8 of clause 5.2.2.3 names FORMAT_FAILURE.");
            Assert.HasCount(1, conclusion.ReportData, "Table 6 mandates any information available on why parsing failed.");
            Assert.IsInstanceOfType<FormatFailureReportData>(conclusion.ReportData[0], "The reported evidence has the shape Table 6 mandates.");
            Assert.IsNotEmpty(((FormatFailureReportData)conclusion.ReportData[0]).Reason, "The parse failure carries a reason.");
        }
    }


    /// <summary>
    /// The same signature in two encodings: the shipped binding processes the one encoded under the Distinguished
    /// Encoding Rules and refuses the one encoded under the Basic Encoding Rules.
    /// </summary>
    /// <remarks>
    /// RFC 5652 §5.1 permits a CMS <c>SignedData</c> to be BER-encoded and only mandates DER for the
    /// <c>SignedAttributes</c> digest input, so refusing a BER-encoded Signed Data Object outright is a
    /// deliberate strictness of this library rather than a conformance requirement. Thirteen artifacts of this
    /// corpus fall into that bucket; the pair asserted here isolates the encoding as the only difference.
    /// </remarks>
    [TestMethod]
    public async Task AnArtifactEncodedUnderBasicEncodingRulesIsRefusedWhileItsDistinguishedEncodingTwinIsProcessed()
    {
        byte[]? basicEncoding = await TryReadArtifactAsync("evidence-record/C-B-B-basic.p7m").ConfigureAwait(false);
        byte[]? distinguishedEncoding = await TryReadArtifactAsync("evidence-record/C-B-B-basic-der.p7m").ConfigureAwait(false);
        if(basicEncoding is null || distinguishedEncoding is null)
        {
            return;
        }

        SignatureValidationConclusion basicEncodingConclusion = await ValidateWithoutTrustContextAsync(basicEncoding).ConfigureAwait(false);
        SignatureValidationConclusion distinguishedEncodingConclusion = await ValidateWithoutTrustContextAsync(distinguishedEncoding).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationSubIndication.FormatFailure, basicEncodingConclusion.SubIndications[0],
            "The Basic Encoding Rules variant is refused by the format checking building block.");
        Assert.AreEqual(SignatureValidationSubIndication.NoCertificateChainFound, distinguishedEncodingConclusion.SubIndications[0],
            "The Distinguished Encoding Rules variant is processed all the way to the missing trust anchor.");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, await VerifyCryptographyAsync(distinguishedEncoding).ConfigureAwait(false),
            "The signature the two artifacts share verifies, so the encoding is the only reason the other one is refused.");
    }


    /// <summary>
    /// An artifact declaring a signature creation policy the Driving Application's mapping does not cover
    /// terminates the validation under the secure default of clause 5.2.4.4, and continues under default
    /// constraints when the local configuration says so — the branch that clause explicitly makes a policy
    /// decision.
    /// </summary>
    [TestMethod]
    public async Task AnArtifactDeclaringAnUnmappedSignaturePolicyTerminatesUnlessTheLocalConfigurationSaysOtherwise()
    {
        byte[]? bytes = await TryReadArtifactAsync("cades-extended-epes.pkcs7").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        SignatureValidationConclusion terminated = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, terminated.Indication, "A policy that cannot be processed leaves the status indeterminate.");
        Assert.AreEqual(SignatureValidationSubIndication.PolicyProcessingError, terminated.SubIndications[0],
            "Clause 5.2.4.4's local-configuration default terminates the validation for a creation policy outside the mapping.");
        Assert.IsInstanceOfType<PolicyProcessingErrorReportData>(terminated.ReportData[0], "Table 6 mandates additional information on the problem.");

        SignatureValidationConclusion continued = await ValidateWithoutTrustContextAsync(
            bytes, UnmappedSignaturePolicyHandling.ApplyDefaultConstraints).ConfigureAwait(false);
        Assert.AreEqual(SignatureValidationSubIndication.NoCertificateChainFound, continued.SubIndications[0],
            "With the other branch of clause 5.2.4.4 selected, the same artifact is validated under the default constraints and stops at the missing trust anchor.");
    }


    /// <summary>
    /// An artifact that carries its whole certificate chain up to a self-signed certificate, validated against
    /// that certificate as a deliberately configured trust anchor and at an instant inside its own signing
    /// certificate's validity window, gets through format checking, signing-certificate identification, chain
    /// building, certification path validation and cryptographic verification, and stops at exactly one thing:
    /// nothing establishes the revocation status of its certificates.
    /// </summary>
    /// <remarks>
    /// The trust anchor is asserted by this test, not derived from the artifact's own claim to be trustworthy —
    /// which is what a Driving Application configured with that root would do. The validation instant is read out
    /// of the artifact's own signing certificate rather than fixed, because these artifacts predate any instant
    /// this suite anchors on.
    /// </remarks>
    [TestMethod]
    public async Task AnArtifactValidatedAgainstItsOwnEmbeddedTrustAnchorStopsOnlyAtTheMissingRevocationStatusInformation()
    {
        byte[]? bytes = await TryReadArtifactAsync("evidence-record/C-B-B-basic-der.p7m").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        SignatureValidationConclusion? conclusion = await ValidateAgainstOwnAnchorsAsync(bytes).ConfigureAwait(false);
        Assert.IsNotNull(conclusion, "The artifact carries a self-signed certificate that can be configured as a trust anchor.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion!.Indication,
            "Nothing about this signature is known to be wrong; one input is missing, which is what INDETERMINATE means.");
        Assert.AreEqual(SignatureValidationSubIndication.TryLater, conclusion!.SubIndications[0],
            "Step 4) of clause 5.2.6.4 reports TRY_LATER when no revocation status information establishes a certificate's status.");
        Assert.IsInstanceOfType<TryLaterReportData>(conclusion!.ReportData[0],
            "Table 6 mandates the point of time where the necessary revocation status information is expected to become available.");
        Assert.HasCount(3, ((TryLaterReportData)conclusion!.ReportData[0]).CertificateChain,
            "Table 13 adds the chain the block worked on: the signing certificate, the certification authority that issued it, and the self-signed certificate the test configured as the trust anchor.");
    }


    /// <summary>
    /// The known deviation this leg found: an artifact whose <c>SignerInfo</c> names a digest algorithm this
    /// library cannot compute is reported <c>TOTAL-FAILED</c>/<c>HASH_FAILURE</c> even though an independent CMS
    /// backend verifies its signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test asserts the shipped behaviour so that a fix breaks it deliberately rather than silently. The
    /// behaviour is wrong: clause 5.1.3 makes <c>TOTAL-FAILED</c> the statement that the signature is not valid,
    /// while the only thing established here is that this library cannot compute the digest the signature uses,
    /// which clause 5.1.3 and the fail-closed rule make an <c>INDETERMINATE</c> outcome. The independent backend
    /// verifying the same artifact is the proof that the signature is not in fact invalid.
    /// </para>
    /// <para>
    /// The cause is that the resolvable digest algorithms are SHA-256, SHA-384 and SHA-512 only, so a SHA-1 or
    /// SHA-3 <c>SignerInfo</c> falls into the <c>HASH_FAILURE</c> branch of the message-digest check rather than
    /// into an "algorithm not supported" branch, of which Table 15 of clause 5.2.7.3 has none.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task ArtifactsNamingAnUncomputableDigestAlgorithmAreReportedTotalFailedAlthoughTheirSignaturesVerify()
    {
        for(int i = 0; i < ArtifactsWithAnUncomputableDigestAlgorithm.Count; ++i)
        {
            string artifact = ArtifactsWithAnUncomputableDigestAlgorithm[i];
            byte[]? bytes = await TryReadArtifactAsync(artifact).ConfigureAwait(false);
            if(bytes is null)
            {
                return;
            }

            Assert.IsTrue(await IndependentBackendVerifiesAsync(bytes).ConfigureAwait(false),
                $"An independent CMS backend verifies '{artifact}', so its signature is not invalid.");

            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.TotalFailed, conclusion.Indication,
                $"'{artifact}' is reported TOTAL-FAILED today; this assertion pins a known deviation, see the remarks.");
            Assert.AreEqual(SignatureValidationSubIndication.HashFailure, conclusion.SubIndications[0],
                "The message-digest check of clause 5.2.7.4 step 2) reports HASH_FAILURE for a digest algorithm it cannot compute.");
        }
    }


    /// <summary>
    /// Runs the validation process for Basic Signatures of clause 5.3 over an artifact with no trust anchor, no
    /// revocation material and no signature policy mapping.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <param name="unmappedPolicyHandling">What clause 5.2.4.4 does with a creation policy the mapping does not cover.</param>
    /// <returns>The conclusion of clause 5.1.3.</returns>
    private async ValueTask<SignatureValidationConclusion> ValidateWithoutTrustContextAsync(
        byte[] artifactBytes,
        UnmappedSignaturePolicyHandling unmappedPolicyHandling = UnmappedSignaturePolicyHandling.TerminateValidation)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        var completer = new CertificateChainCompleter([]);

        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = signedData,
            Constraints = BuildConstraints([]),
            UnmappedSignaturePolicyHandling = unmappedPolicyHandling
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, BuildSeams(completer), SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return outcome.Conclusion;
    }


    /// <summary>
    /// Runs the validation process for Basic Signatures over an artifact with every self-signed certificate the
    /// artifact itself carries configured as a trust anchor, at the midpoint of the signing certificate's own
    /// validity window.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The conclusion, or <see langword="null"/> when the artifact carries no self-signed certificate or no readable signing certificate.</returns>
    private async ValueTask<SignatureValidationConclusion?> ValidateAgainstOwnAnchorsAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        if(facts.Status != SignatureFactsStatus.Extracted || facts.SigningCertificate is null)
        {
            return null;
        }

        var parser = new X509CertificateParser();
        List<TrustAnchorConstraint> anchors = [];
        for(int i = 0; i < facts.EmbeddedCertificates.Count; ++i)
        {
            BcX509Certificate candidate = parser.ReadCertificate(facts.EmbeddedCertificates[i].AsReadOnlySpan().ToArray());
            if(candidate.SubjectDN.Equivalent(candidate.IssuerDN))
            {
                anchors.Add(new TrustAnchorConstraint(facts.EmbeddedCertificates[i], SunsetDate: null));
            }
        }

        if(anchors.Count == 0)
        {
            return null;
        }

        BcX509Certificate signer = parser.ReadCertificate(facts.SigningCertificate.AsReadOnlySpan().ToArray());
        DateTimeOffset notBefore = new(signer.NotBefore, TimeSpan.Zero);
        DateTimeOffset notAfter = new(signer.NotAfter, TimeSpan.Zero);
        DateTimeOffset validationTime = notBefore + ((notAfter - notBefore) / 2);

        var completer = new CertificateChainCompleter(facts.EmbeddedCertificates);
        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = signedData,
            Constraints = BuildConstraints(anchors),
            UnmappedSignaturePolicyHandling = UnmappedSignaturePolicyHandling.ApplyDefaultConstraints
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, BuildSeams(completer), SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, validationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return outcome.Conclusion;
    }


    /// <summary>
    /// Runs the cryptographic verification building block of clause 5.2.7 over an artifact, so a test can state
    /// that a signature value genuinely verified rather than infer it from the process's later steps.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The outcome in the vocabulary of Table 15.</returns>
    private async ValueTask<SignatureCryptographicOutcome> VerifyCryptographyAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status, "The artifact has to parse before its cryptography can be judged.");
        Assert.IsNotNull(facts.SigningCertificate, "The artifact has to name a signing certificate it carries.");

        SignatureCryptographicVerification verification = await CAdESSignatureFacts.VerifyCryptographyAsync(
            new SignatureCryptographicVerificationContext { Signature = facts, SigningCertificate = facts.SigningCertificate! },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return verification.Outcome;
    }


    /// <summary>
    /// Verifies an artifact's CMS signature with a backend independent of the one the engine's default
    /// composition uses, so a rejection or an acceptance can be attributed to the signature rather than to one
    /// implementation.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns><see langword="true"/> when the independent backend verifies the signature.</returns>
    private async ValueTask<bool> IndependentBackendVerifiesAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        try
        {
            using CmsVerifiedContent verified = await BouncyCastleCmsFunctions.VerifyCmsSignedDataAsync(
                signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            return true;
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            return false;
        }
    }


    /// <summary>
    /// Builds the validation constraints every run of this class uses: the supplied trust anchors under the shell
    /// validity model, no revocation freshness constraint, no signature elements constraint.
    /// </summary>
    /// <param name="anchors">The trust anchors, empty for a run with no trust context.</param>
    /// <returns>The constraints.</returns>
    /// <remarks>
    /// The cryptographic constraints are empty because no run of this class reaches step 6) of clause 5.2.6.4:
    /// every run ends at chain building or at the revocation check of step 4), both of which precede it. An empty
    /// reliability table would otherwise make every algorithm unreliable, which is the fail-closed default the
    /// model stage chose.
    /// </remarks>
    private static SignatureValidationConstraints BuildConstraints(IReadOnlyList<TrustAnchorConstraint> anchors) => new()
    {
        Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
        X509 = new X509ValidationConstraints { TrustAnchors = anchors, ValidityModel = CertificateValidityModel.Shell },
        Cryptographic = CryptographicConstraints.Empty,
        SignatureElements = new SignatureElementsConstraints()
    };


    /// <summary>
    /// Builds the seams every run of this class composes: the shipped CAdES binding, the supplied offline chain
    /// completer, the platform certification path validator and no revocation seam at all.
    /// </summary>
    /// <param name="completer">The chain completion seam over whatever certificates the run may use.</param>
    /// <returns>The seams.</returns>
    private static SignatureValidationSeams BuildSeams(CertificateChainCompleter completer) => new()
    {
        Format = CAdESSignatureFacts.Seam,
        CompleteCertificateChain = completer.CompleteAsync,
        ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync
    };


    /// <summary>Renders a conclusion as the bucket key the distribution is expressed in.</summary>
    /// <param name="conclusion">The conclusion.</param>
    /// <returns>The main indication and the first sub-indication, in the specification's own vocabulary.</returns>
    private static string Describe(SignatureValidationConclusion conclusion)
    {
        string indication = conclusion.Indication switch
        {
            SignatureValidationIndication.TotalPassed => "TOTAL-PASSED",
            SignatureValidationIndication.TotalFailed => "TOTAL-FAILED",
            _ => "INDETERMINATE"
        };

        return conclusion.SubIndications.Count > 0 ? $"{indication}/{conclusion.SubIndications[0].Value}" : indication;
    }


    /// <summary>
    /// Enumerates every artifact the selection rule yields, or reports <see cref="Assert.Inconclusive(string)"/>
    /// and returns <see langword="null"/> when the local reference-artifact clone is absent.
    /// </summary>
    /// <returns>The artifacts as clone-relative paths with forward slashes, ordered ordinally.</returns>
    private static IReadOnlyList<string>? TryEnumerateArtifacts()
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        return
        [
            .. Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                .Where(IsSignedCadesArtifact)
                .Select(path => Path.GetRelativePath(directory, path).Replace('\\', '/'))
                .OrderBy(path => path, StringComparer.Ordinal)
        ];
    }


    /// <summary>Reports whether a path names a signed CAdES artifact under the selection rule.</summary>
    /// <param name="path">The candidate path.</param>
    /// <returns><see langword="true"/> when its extension is one the rule names.</returns>
    private static bool IsSignedCadesArtifact(string path) =>
        path.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".pkcs7", StringComparison.OrdinalIgnoreCase);


    /// <summary>Reads one artifact by its clone-relative path, which the caller has already established exists.</summary>
    /// <param name="relativePath">The clone-relative path with forward slashes.</param>
    /// <returns>The artifact's octets.</returns>
    private async ValueTask<byte[]> ReadArtifactAsync(string relativePath)
    {
        string directory = TryFindArtifactDirectory()!;

        return await File.ReadAllBytesAsync(
            Path.Combine(directory, relativePath.Replace('/', Path.DirectorySeparatorChar)),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads one named artifact, or reports <see cref="Assert.Inconclusive(string)"/> and returns
    /// <see langword="null"/> when the local reference-artifact clone is absent.
    /// </summary>
    /// <param name="relativePath">The clone-relative path with forward slashes.</param>
    /// <returns>The artifact's octets, or <see langword="null"/>.</returns>
    private async ValueTask<byte[]?> TryReadArtifactAsync(string relativePath)
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        if(TryResolveArtifact(directory, relativePath) is not string path)
        {
            Assert.Inconclusive($"The artifact '{relativePath}' is not present in the local reference-artifact corpus.");

            return null;
        }

        return await File.ReadAllBytesAsync(path, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>What every test reports when the optional local reference-artifact clone is not present.</summary>
    private static string MissingCloneMessage =>
        "The local reference-artifact clone (tempdocs/etsi-ades-reference) was not found; the signed CAdES corpus is optional local reference material, not a repository asset.";


    /// <summary>
    /// Walks up from the test assembly's output directory to the repository root and resolves the CAdES
    /// validation-resources directory of the local reference-artifact clone relative to it — the same marker-file
    /// search <c>TrustedListFixtureTests</c> uses for the trusted-list corpus.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    private static string? TryFindArtifactDirectory()
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

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");
        if(!Directory.Exists(referenceMaterial))
        {
            return null;
        }

        //The clone's own directory names are not spelled here. The CAdES validation resources are found by the
        //layout every module of that corpus shares — a "validation" directory under "src/test/resources" — and
        //the first such directory in ordinal order that actually holds signed CAdES artifacts is the one used, so
        //the resolution is deterministic without naming anything outside this repository.
        string tail = Path.Combine("src", "test", "resources", "validation");

        return Directory.EnumerateDirectories(referenceMaterial, "validation", SearchOption.AllDirectories)
            .Where(directory => directory.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            .Where(directory => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Any(IsSignedCadesArtifact))
            .OrderBy(directory => directory, StringComparer.Ordinal)
            .FirstOrDefault();
    }


    /// <summary>
    /// Resolves one artifact by the file name it carries in the corpus, wherever in the corpus it sits, so that a
    /// test names the artifact and never the directory layout of the material it comes from.
    /// </summary>
    /// <param name="directory">The corpus root.</param>
    /// <param name="artifact">The artifact's file name, or a corpus-relative path with forward slashes.</param>
    /// <returns>The artifact's full path, or <see langword="null"/> when the corpus does not hold it.</returns>
    private static string? TryResolveArtifact(string directory, string artifact)
    {
        string direct = Path.Combine(directory, artifact.Replace('/', Path.DirectorySeparatorChar));
        if(File.Exists(direct))
        {
            return direct;
        }

        string fileName = Path.GetFileName(artifact);

        return Directory.EnumerateFiles(directory, fileName, SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .FirstOrDefault();
    }
}
