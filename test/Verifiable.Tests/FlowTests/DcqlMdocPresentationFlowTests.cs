using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end DCQL presentation flow tests for mdoc credentials — mirror of
/// <see cref="DcqlPresentationFlowTests"/> (SD-JWT VC) and
/// <see cref="DcqlCwtPresentationFlowTests"/> (SD-CWT) on the mdoc track.
/// </summary>
/// <remarks>
/// <para>
/// Each test runs the full issue → request → evaluate → trim → present →
/// verify loop with real keys and real CBOR. The flow:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Issuer</strong> signs a full mdoc PID (all M.1 + M.3 surface).
/// </description></item>
/// <item><description>
/// <strong>Verifier</strong> sends a DCQL query against the
/// <c>mso_mdoc</c> format with one or more namespace + element_identifier
/// patterns.
/// </description></item>
/// <item><description>
/// <strong>Wallet</strong> evaluates via <see cref="DcqlEvaluator"/> +
/// <see cref="MdocDcqlAdapter"/>, lifts matched patterns to selected
/// paths via <see cref="DcqlPathResolver"/>, trims the issuer-signed shape
/// via <see cref="MdocIssuerSignedTrimmer.Trim"/>.
/// </description></item>
/// <item><description>
/// <strong>Wallet</strong> device-signs over the SessionTranscript
/// (M.3b + M.7a) — same OID4VP-shape transcript the SD-JWT VC test
/// would use, just with a different credential format under it.
/// </description></item>
/// <item><description>
/// <strong>Verifier</strong> validates the issuer MSO signature (M.3),
/// runs digest binding on the TRIMMED items (M.4), and verifies the
/// device signature (M.3b).
/// </description></item>
/// </list>
/// <para>
/// The selective-disclosure subset round-trip is the headline. The MSO
/// commits to all the issuer's items, but the wallet presents only the
/// subset the verifier asked for; M.4's validator iterates the presented
/// items and validates each against the MSO commitment — items the wallet
/// omitted never reach the validator and don't need to be present for the
/// trimmed presentation to verify.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DcqlMdocPresentationFlowTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-mdoc-01";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task PidMdocPresentationFlowProducesValidVpTokenWithSubsetDisclosure()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            //=== Issuer signs full PID with five claims ===
            using MdocDocument issued = await IssueFullPidAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            IReadOnlyList<MdocIssuerSignedItem> fullItems = issued.IssuerSigned.NameSpaces[PidNamespace];
            Assert.HasCount(5, fullItems);

            //=== Verifier builds a DCQL query for given_name + family_name ===
            var dcqlQuery = new DcqlQuery
            {
                Credentials =
                [
                    new CredentialQuery
                    {
                        Id = EudiPid.DefaultCredentialQueryId,
                        Format = MdocDcqlAdapter.FormatIdentifier,
                        Claims =
                        [
                            new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.FamilyName) },
                            new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.GivenName) }
                        ]
                    }
                ]
            };

            //=== Wallet evaluates the query against its mdoc holding ===
            PreparedDcqlQuery prepared = DcqlPreparer.Prepare(dcqlQuery);

            List<DcqlMatch<MdocDocument>> matches = DcqlEvaluator.Evaluate(
                prepared,
                credentials: [issued],
                metadataExtractor: MdocDcqlAdapter.MetadataExtractor,
                claimExtractor: MdocDcqlAdapter.ClaimExtractor).ToList();

            Assert.HasCount(1, matches);
            Assert.AreEqual(EudiPid.DefaultCredentialQueryId, matches[0].CredentialQueryId);
            Assert.HasCount(2, matches[0].MatchedPatterns);

            //Lift matched patterns into concrete CredentialPath values for trimming.
            HashSet<CredentialPath> selectedPaths = DcqlPathResolver.ResolveAll(
                matches[0].MatchedPatterns, availablePaths: null);

            Assert.HasCount(2, selectedPaths);
            Assert.Contains(MdocIssuerSignedTrimmer.PathFor(PidNamespace, EudiPid.Mdoc.FamilyName), selectedPaths);
            Assert.Contains(MdocIssuerSignedTrimmer.PathFor(PidNamespace, EudiPid.Mdoc.GivenName), selectedPaths);

            //=== Wallet derives the presentation projection ===
            MdocPresentationDocument trimmed = issued.Derive(selectedPaths);

            IReadOnlyList<MdocIssuerSignedItem> trimmedItems = trimmed.IssuerSigned.NameSpaces[PidNamespace];
            Assert.HasCount(2, trimmedItems);
            Assert.IsTrue(trimmedItems.All(item =>
                item.ElementIdentifier == EudiPid.Mdoc.FamilyName || item.ElementIdentifier == EudiPid.Mdoc.GivenName));

            //=== Wallet builds OID4VP SessionTranscript + device-signs ===
            using IMemoryOwner<byte> mdocGeneratedNonce =
                Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, SensitiveMemoryPool<byte>.Shared);
            ReadOnlyMemory<byte> nonceMemory =
                mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
            ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span);

            //Device-sign the trimmed presentation against the SessionTranscript.
            //DeviceSignAsync folds (sign + attach) into one call and returns a
            //fresh MdocPresentationDocument carrying the device-signed half.
            MdocPresentationDocument presented = await trimmed.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                sessionTranscript,
                deviceKeys.PrivateKey,
                SensitiveMemoryPool<byte>.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using MdocDeviceResponse deviceResponse = new(
                version: MdocWellKnownKeys.Version10,
                documents: [presented],
                status: MdocWellKnownKeys.StatusOk);

            string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(
                deviceResponse, TestSetup.Base64UrlEncoder);
            Assert.IsFalse(string.IsNullOrEmpty(vpTokenValue));

            //=== Verifier side ===

            //Issuer signature (M.3).
            bool isIssuerVerified = await issued.VerifyIssuerAuthAsync(
                issuerKeys.PublicKey, SensitiveMemoryPool<byte>.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isIssuerVerified, "Issuer MSO signature must verify against the same key used at issuance.");

            //Digest binding on the TRIMMED set (M.4). The headline assertion:
            //the MSO commits to all five items, the wallet presents only two,
            //M.4's validator iterates the two presented items and finds each
            //in the MSO's valueDigests map.
            MdocDigestBindingResult bindingResult = presented.VerifyDigestBinding();
            Assert.IsTrue(bindingResult.IsValid,
                $"Digest binding on the trimmed presentation must hold. Got: {bindingResult}.");
            Assert.HasCount(2, bindingResult.ItemResults);
            Assert.IsTrue(bindingResult.ItemResults.All(r => r.IsValid));

            //Device signature against reconstructed transcript (M.3b).
            bool isDeviceVerified = await presented.VerifyDeviceSignedAsync(
                sessionTranscript,
                deviceKeys.PublicKey, SensitiveMemoryPool<byte>.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isDeviceVerified, "Device signature must verify.");

            //None of the un-requested items appear in the presentation.
            HashSet<string> presentedIdentifiers = trimmedItems
                .Select(i => i.ElementIdentifier)
                .ToHashSet(StringComparer.Ordinal);
            Assert.DoesNotContain(EudiPid.Mdoc.BirthDate, presentedIdentifiers);
            Assert.DoesNotContain(EudiPid.Mdoc.AgeOver18, presentedIdentifiers);
            Assert.DoesNotContain(EudiPid.Mdoc.IssuingCountry, presentedIdentifiers);
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task DcqlQueryRequestingMissingClaimDoesNotMatchMdocCredential()
    {
        //Mirror of the SD-JWT side's "required claim missing" case: the
        //verifier asks for `nationalities` which the sample PID doesn't
        //carry, and the DCQL evaluator returns zero matches.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument issued = await IssueFullPidAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            var dcqlQuery = new DcqlQuery
            {
                Credentials =
                [
                    new CredentialQuery
                    {
                        Id = EudiPid.DefaultCredentialQueryId,
                        Format = MdocDcqlAdapter.FormatIdentifier,
                        Claims =
                        [
                            new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.Nationalities) }
                        ]
                    }
                ]
            };

            List<DcqlMatch<MdocDocument>> matches = DcqlEvaluator.Evaluate(
                DcqlPreparer.Prepare(dcqlQuery),
                credentials: [issued],
                metadataExtractor: MdocDcqlAdapter.MetadataExtractor,
                claimExtractor: MdocDcqlAdapter.ClaimExtractor).ToList();

            Assert.HasCount(0, matches);
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task TrimmedPresentationOverDomesticPidNamespaceVerifies()
    {
        //EUDI domestic PID namespace (eu.europa.ec.eudi.pid.de.1) per
        //EudiPid.DomesticNamespace — the DCQL → mdoc bridge handles
        //alternative namespace strings identically.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        string domesticNamespace = EudiPid.DomesticNamespace("de");

        try
        {
            MdocLogicalDocument logical = MdocIssuance.BuildDocument(
                docType: PidDocType,
                claims:
                [
                    new() { NameSpace = domesticNamespace, ElementIdentifier = "id_card_number", EncodedElementValue = CborText("DE-12345") },
                    new() { NameSpace = domesticNamespace, ElementIdentifier = "tax_id", EncodedElementValue = CborText("DE-67890") }
                ],
                generateRandom: () => MdocTestFixtures.ItemRandomSalt());

            using MdocDocument issued = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                SensitiveMemoryPool<byte>.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Ask for one of the two domestic claims.
            HashSet<CredentialPath> selectedPaths =
            [
                MdocIssuerSignedTrimmer.PathFor(domesticNamespace, "id_card_number")
            ];

            MdocPresentationDocument trimmed = issued.Derive(selectedPaths);

            Assert.HasCount(1, trimmed.IssuerSigned.NameSpaces[domesticNamespace]);
            Assert.AreEqual("id_card_number", trimmed.IssuerSigned.NameSpaces[domesticNamespace][0].ElementIdentifier);

            //Trimmed presentation must still verify against the MSO.
            MdocDigestBindingResult binding = trimmed.VerifyDigestBinding();
            Assert.IsTrue(binding.IsValid,
                $"Trimmed domestic-namespace presentation must validate; got {binding}.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    private async ValueTask<MdocDocument> IssueFullPidAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys)
    {
        MdocLogicalDocument logical = MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.FamilyName, EncodedElementValue = CborText("Mustermann") },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.GivenName, EncodedElementValue = CborText("Erika") },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.BirthDate, EncodedElementValue = CborText("1971-09-01") },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.AgeOver18, EncodedElementValue = CborBoolTrue() },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.IssuingCountry, EncodedElementValue = CborText("DE") }
            ],
            generateRandom: () => MdocTestFixtures.ItemRandomSalt());

        return await logical.SignAsync(
            new MdocIssuerSigningConfig
            {
                DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                Validity = SampleValidity(),
                DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
            },
            issuerKeys.PrivateKey,
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));
}
