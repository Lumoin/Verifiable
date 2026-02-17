using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end tests for the DCQL presentation flow with real cryptographic signing
/// and verification: issuer signs SD-JWT VC -> verifier sends DCQL query -> wallet
/// evaluates via <see cref="DisclosureComputation{TCredential}"/> -> wallet selects
/// disclosures -> verifier validates signature.
/// </summary>
/// <remarks>
/// <para>
/// Every test in this class uses real key material and cryptographic operations.
/// The flow is:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Issuer</strong> creates disclosures and calls
/// <see cref="SdJwtIssuance.IssueAsync"/> which serializes each disclosure via
/// <see cref="SerializeDisclosureDelegate{TDisclosure}"/>, computes digests via
/// <see cref="ComputeDisclosureDigestDelegate"/>, assembles the payload, signs via
/// <see cref="JwtSigningExtensions.SignAsync"/>, and returns an <see cref="SdToken{TEnvelope}"/> (where TEnvelope is <see cref="string"/>).
/// </description></item>
/// <item><description>
/// <strong>Verifier</strong> constructs a DCQL query specifying required credentials
/// and claims using <see cref="DcqlQueryBuilder"/>.
/// </description></item>
/// <item><description>
/// <strong>Wallet</strong> evaluates the query against its credential holdings,
/// producing <see cref="DisclosureMatch{TCredential}"/> instances, and runs them
/// through <see cref="DisclosureComputation{TCredential}"/>.
/// </description></item>
/// <item><description>
/// <strong>Wallet</strong> selects disclosures from the <see cref="SdToken{TEnvelope}"/>
/// based on the disclosure plan and constructs the VP Token response.
/// </description></item>
/// <item><description>
/// <strong>Verifier</strong> validates the issuer JWT signature on the presented token
/// and can independently recompute disclosure digests using the same
/// <see cref="ComputeDisclosureDigestDelegate"/>.
/// </description></item>
/// </list>
/// <para>
/// See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP v1.0 Section 8.1</see>,
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP v1.0 Section 6 (DCQL)</see>,
/// and <see href="https://www.rfc-editor.org/rfc/rfc9901.html">RFC 9901 (SD-JWT)</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DcqlPresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    private static JwtHeaderSerializer HeaderSerializer => header =>
        JsonSerializer.SerializeToUtf8Bytes(header);

    private static JwtPayloadSerializer PayloadSerializer => payload =>
        JsonSerializer.SerializeToUtf8Bytes(payload);


    /// <summary>
    /// Full DCQL presentation flow with P-256: issuer signs -> verifier requests
    /// given_name and family_name -> disclosure engine computes minimum set ->
    /// wallet selects disclosures -> verifier validates signature.
    /// </summary>
    [TestMethod]
    public async Task PidSdJwtPresentationFlowProducesValidVpToken()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Verifier builds a DCQL query requesting PID given_name and family_name.
        var query = await new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [EudiPid.SdJwtVct],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName]),
                 ClaimsQuery.ForPath([EudiPid.SdJwt.FamilyName])])
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);

        //Wallet evaluates the DCQL query against holdings.
        var requestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        var match = new DisclosureMatch<SdToken<string>>
        {
            Credential = issuedToken,
            QueryRequirementId = EudiPid.DefaultCredentialQueryId,
            RequiredPaths = requestedPaths,
            MatchedPaths = requestedPaths,
            AllAvailablePaths = CreateAllAvailablePaths(),
            MandatoryPaths = CreateMandatoryPaths(),
            Format = DcqlCredentialFormats.SdJwt
        };

        //Disclosure engine computes optimal disclosure via lattice.
        var computation = new DisclosureComputation<SdToken<string>>();
        var plan = await computation.ComputeAsync(
            [match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied, "The disclosure plan must be satisfied.");
        Assert.HasCount(1, plan.Decisions);

        var decision = plan.Decisions[0];
        Assert.IsTrue(decision.SatisfiesRequirements, "The decision must satisfy verifier requirements.");

        //Verify minimum disclosure: mandatory + requested, nothing extra.
        Assert.Contains(
            CredentialPath.FromJsonPointer("/iss"), decision.SelectedPaths);
        Assert.Contains(
            CredentialPath.FromJsonPointer("/vct"), decision.SelectedPaths);
        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"), decision.SelectedPaths);
        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}"), decision.SelectedPaths);

        //Email, phone, and birthdate must NOT be disclosed.
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Email}"), decision.SelectedPaths);
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.PhoneNumber}"), decision.SelectedPaths);
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}"), decision.SelectedPaths);

        //Wallet selects disclosures from the SD-JWT token based on the plan.
        var selectedClaimNames = decision.SelectedPaths
            .Select(p => p.ToString().TrimStart('/'))
            .ToHashSet(StringComparer.Ordinal);

        SdToken<string> presentationToken = issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selectedClaimNames.Contains(d.ClaimName));

        Assert.IsTrue(presentationToken.Disclosures.All(
            d => selectedClaimNames.Contains(d.ClaimName!)),
            "All disclosures in the presentation must be in the selected set.");

        //Construct VP Token response per OID4VP v1.0 Section 8.1.
        var vpToken = new Dictionary<string, object>
        {
            [EudiPid.DefaultCredentialQueryId] = presentationToken
        };

        Assert.IsTrue(vpToken.ContainsKey(EudiPid.DefaultCredentialQueryId));
        Assert.IsInstanceOfType<SdToken<string>>(vpToken[EudiPid.DefaultCredentialQueryId]);

        //Verifier validates the presented issuer JWT signature.
        bool presentationValid = await Jws.VerifyAsync(
            presentationToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(presentationValid, "Presented issuer JWT signature must be cryptographically valid.");

        //Verify the decision record captured all phases.
        Assert.IsNotNull(plan.DecisionRecord);
        Assert.IsTrue(plan.DecisionRecord.Satisfied);
        Assert.HasCount(1, plan.DecisionRecord.LatticeComputations);
        Assert.HasCount(1, plan.DecisionRecord.FinalDecisions);
    }


    /// <summary>
    /// Verifier requests email but user excludes it, resulting in a conflict.
    /// The issuer JWT signature remains valid on the restricted presentation.
    /// </summary>
    [TestMethod]
    public async Task UserExclusionCreatesConflictInDisclosurePlan()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var query = await new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [EudiPid.SdJwtVct],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName]),
                 ClaimsQuery.ForPath([EudiPid.SdJwt.Email])])
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var emailPath = CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Email}");

        var match = new DisclosureMatch<SdToken<string>>
        {
            Credential = issuedToken,
            QueryRequirementId = EudiPid.DefaultCredentialQueryId,
            RequiredPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                emailPath
            },
            MatchedPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                emailPath
            },
            AllAvailablePaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}"),
                emailPath
            },
            Format = DcqlCredentialFormats.SdJwt
        };

        //User excludes email.
        var userExclusions = new Dictionary<string, IReadOnlySet<CredentialPath>>
        {
            [EudiPid.DefaultCredentialQueryId] = new HashSet<CredentialPath> { emailPath }
        };

        var computation = new DisclosureComputation<SdToken<string>>();
        var plan = await computation.ComputeAsync(
            [match],
            userExclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied, "Plan is satisfied even with conflict, the credential was still processed.");
        Assert.HasCount(1, plan.Decisions);

        var decision = plan.Decisions[0];
        Assert.IsFalse(decision.SatisfiesRequirements, "Verifier requirements are not fully met due to user exclusion.");
        Assert.IsNotNull(decision.ConflictingPaths, "Conflicting paths must be reported.");
        Assert.Contains(emailPath, decision.ConflictingPaths!);

        //Issuer JWT signature is still valid even with reduced disclosures.
        bool signatureValid = await Jws.VerifyAsync(
            issuedToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(signatureValid, "Issuer JWT signature must remain valid regardless of disclosure decisions.");
    }


    /// <summary>
    /// Multi-credential DCQL query requesting PID (SD-JWT) and mDL (mso_mdoc).
    /// The PID credential is a real signed SD-JWT; the mDL uses a placeholder since
    /// mso_mdoc signing infrastructure is out of scope for these tests.
    /// </summary>
    [TestMethod]
    public async Task MultiCredentialQueryProducesMultiEntryVpToken()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedPidToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var query = await new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [EudiPid.SdJwtVct],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName]),
                 ClaimsQuery.ForPath([EudiPid.SdJwt.FamilyName])])
            .WithMdocCredential("mdl", EudiMdl.Doctype,
                [ClaimsQuery.ForMdocPath(true, EudiMdl.Namespace, EudiMdl.Attributes.FamilyName),
                 ClaimsQuery.ForMdocPath(true, EudiMdl.Namespace, EudiMdl.Attributes.DrivingPrivileges)])
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(2, query.Credentials);

        //Wallet holds both credentials. PID is the real signed token.
        string pidSerialized = SdJwtSerializer.SerializeToken(issuedPidToken, Encoder);

        var pidMatch = new DisclosureMatch<string>
        {
            Credential = pidSerialized,
            QueryRequirementId = EudiPid.DefaultCredentialQueryId,
            RequiredPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
            },
            MatchedPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
            },
            AllAvailablePaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}"),
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}")
            },
            Format = DcqlCredentialFormats.SdJwt
        };

        var mdlMatch = new DisclosureMatch<string>
        {
            Credential = "mdl-device-response-placeholder",
            QueryRequirementId = "mdl",
            RequiredPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.FamilyName}"),
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.DrivingPrivileges}")
            },
            MatchedPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.FamilyName}"),
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.DrivingPrivileges}")
            },
            AllAvailablePaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.FamilyName}"),
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.GivenName}"),
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.DrivingPrivileges}"),
                CredentialPath.FromJsonPointer($"/{EudiMdl.Namespace}/{EudiMdl.Attributes.Portrait}")
            },
            Format = DcqlCredentialFormats.MsoMdoc
        };

        var computation = new DisclosureComputation<string>();
        var plan = await computation.ComputeAsync(
            [pidMatch, mdlMatch],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied, "Both credential queries must be satisfied.");
        Assert.HasCount(2, plan.Decisions);
        Assert.IsTrue(plan.Decisions[0].SatisfiesRequirements);
        Assert.IsTrue(plan.Decisions[1].SatisfiesRequirements);

        //Construct VP Token with both entries.
        var vpToken = new Dictionary<string, string>
        {
            [plan.Decisions[0].QueryRequirementId] = plan.Decisions[0].Credential,
            [plan.Decisions[1].QueryRequirementId] = plan.Decisions[1].Credential
        };

        Assert.HasCount(2, vpToken);
        Assert.IsTrue(vpToken.ContainsKey(EudiPid.DefaultCredentialQueryId));
        Assert.IsTrue(vpToken.ContainsKey("mdl"));

        //Verify the PID issuer signature is still valid from the serialized form.
        SdToken<string> parsedPid = SdJwtSerializer.ParseToken(vpToken[EudiPid.DefaultCredentialQueryId], Decoder, Pool);
        bool pidSignatureValid = await Jws.VerifyAsync(
            parsedPid.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(pidSignatureValid, "PID issuer JWT signature must be valid in the VP Token.");

        Assert.HasCount(2, plan.DecisionRecord.Evaluations);
        Assert.HasCount(2, plan.DecisionRecord.LatticeComputations);
    }


    /// <summary>
    /// Domestic VCT builder integrates correctly with DCQL query using Finnish PID.
    /// </summary>
    [TestMethod]
    public async Task DomesticPidVctIntegratesWithDcqlQuery()
    {
        string finnishVct = EudiPid.DomesticVct("fi");
        Assert.AreEqual("urn:eudi:pid:fi:1", finnishVct);

        var query = await new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [finnishVct],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])])
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.IsNotNull(query.Credentials[0].Meta);
        Assert.HasCount(1, query.Credentials[0].Meta!.VctValues!);
        Assert.AreEqual(finnishVct, query.Credentials[0].Meta!.VctValues![0]);

        //Verify VCT parsing round-trips.
        Assert.IsTrue(EudiPid.TryParseDomesticVct(finnishVct, out string? country));
        Assert.AreEqual("fi", country);
        Assert.IsTrue(EudiPid.IsPidVct(finnishVct));
        Assert.IsTrue(EudiPid.IsPidVct(EudiPid.SdJwtVct));
        Assert.IsFalse(EudiPid.IsPidVct("urn:other:type:1"));
    }


    /// <summary>
    /// Policy assessor removes a requested claim, resulting in partial satisfaction.
    /// The issuer JWT signature remains intact after policy narrowing.
    /// </summary>
    [TestMethod]
    public async Task PolicyAssessorNarrowsDisclosureInPresentationFlow()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var givenNamePath = CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}");
        var familyNamePath = CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}");

        //Organizational policy only allows given_name disclosure, not family_name.
        var organizationPolicy = new PolicyAssessorDelegate<SdToken<string>>((context, ct) =>
        {
            var approved = new HashSet<CredentialPath>(context.ProposedPaths);
            approved.Remove(familyNamePath);

            return Task.FromResult(new PolicyAssessmentOutcome
            {
                Approved = true,
                ApprovedPaths = approved,
                AssessorName = "OrganizationPolicy",
                Reason = "Family name disclosure restricted by organizational policy."
            });
        });

        var computation = new DisclosureComputation<SdToken<string>>([organizationPolicy]);

        var match = new DisclosureMatch<SdToken<string>>
        {
            Credential = issuedToken,
            QueryRequirementId = EudiPid.DefaultCredentialQueryId,
            RequiredPaths = new HashSet<CredentialPath> { givenNamePath, familyNamePath },
            MatchedPaths = new HashSet<CredentialPath> { givenNamePath, familyNamePath },
            AllAvailablePaths = new HashSet<CredentialPath>
            {
                givenNamePath,
                familyNamePath,
                CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}")
            },
            Format = DcqlCredentialFormats.SdJwt
        };

        var plan = await computation.ComputeAsync(
            [match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.HasCount(1, plan.Decisions);

        var decision = plan.Decisions[0];

        //Policy narrowed the disclosure, so verifier requirements are not fully met.
        Assert.IsFalse(decision.SatisfiesRequirements);
        Assert.Contains(givenNamePath, decision.SelectedPaths);
        Assert.DoesNotContain(familyNamePath, decision.SelectedPaths);

        Assert.IsNotNull(plan.DecisionRecord.PolicyAssessments);
        Assert.HasCount(1, plan.DecisionRecord.PolicyAssessments!);
        Assert.AreEqual("OrganizationPolicy", plan.DecisionRecord.PolicyAssessments[0].AssessorName);

        //Issuer JWT signature is still valid after policy narrowing.
        bool signatureValid = await Jws.VerifyAsync(
            issuedToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(signatureValid, "Issuer JWT signature must remain valid after policy narrowing.");
    }


    /// <summary>
    /// Issued SD-JWT serializes to wire format and round-trips back, preserving
    /// all disclosures, the issuer JWT, and a valid signature.
    /// </summary>
    [TestMethod]
    public async Task IssuedSdJwtRoundTripsViaSerialization()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string wireFormat = SdJwtSerializer.SerializeToken(issuedToken, Encoder);
        Assert.EndsWith("~", wireFormat, "SD-JWT without key binding must end with tilde.");
        Assert.Contains("~", wireFormat);

        SdToken<string> parsed = SdJwtSerializer.ParseToken(wireFormat, Decoder, Pool);

        Assert.AreEqual(issuedToken.IssuerSigned, parsed.IssuerSigned);
        Assert.HasCount(issuedToken.Disclosures.Count, parsed.Disclosures);
        Assert.IsFalse(parsed.HasKeyBinding);

        for(int i = 0; i < issuedToken.Disclosures.Count; i++)
        {
            Assert.AreEqual(issuedToken.Disclosures[i].ClaimName, parsed.Disclosures[i].ClaimName);
        }

        bool signatureValid = await Jws.VerifyAsync(
            parsed.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(signatureValid, "Signature must remain valid after serialization round-trip.");
    }


    /// <summary>
    /// Verifier independently recomputes disclosure digests using the same
    /// <see cref="ComputeDisclosureDigestDelegate"/> and confirms they match
    /// the <c>_sd</c> array in the issuer's JWT payload. This is what a real
    /// verifier does to confirm that presented disclosures belong to the signed token.
    /// </summary>
    [TestMethod]
    public async Task VerifierRecomputesDisclosureDigestsIndependently()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Verifier receives the token, verifies signature first.
        bool signatureValid = await Jws.VerifyAsync(
            issuedToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(signatureValid, "Issuer JWT signature must be valid before checking digests.");

        //Verifier extracts the _sd array from the payload.
        string[] parts = issuedToken.IssuerSigned.Split('.');
        using IMemoryOwner<byte> payloadBytes = Decoder(parts[1], Pool);
        using JsonDocument payloadDoc = JsonDocument.Parse(payloadBytes.Memory);
        JsonElement sdArray = payloadDoc.RootElement.GetProperty(SdConstants.SdClaimName);

        List<string> payloadDigests = sdArray.EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.HasCount(issuedToken.Disclosures.Count, payloadDigests);

        //Verifier recomputes each disclosure digest using the same two-phase pipeline:
        //serialize the disclosure, then compute its digest. The ComputeDisclosureDigestDelegate
        //is reused independently of issuance — the verifier only needs the encoded string.
        foreach(SdDisclosure disclosure in issuedToken.Disclosures)
        {
            string encoded = SerializeDisclosure(disclosure, Encoder);
            string recomputedDigest = ComputeDigest(encoded, Encoder);
            Assert.Contains(recomputedDigest, payloadDigests,
                $"Recomputed digest for '{disclosure.ClaimName}' must appear in the payload _sd array.");
        }

        //Verify _sd_alg matches the expected algorithm.
        string sdAlg = payloadDoc.RootElement.GetProperty(SdConstants.SdAlgorithmClaimName).GetString()!;
        Assert.AreEqual(WellKnownHashAlgorithms.Sha256Iana, sdAlg);
    }


    /// <summary>
    /// Ed25519 issuance integrates with the same DCQL disclosure flow,
    /// verifying algorithm-agnostic dispatch through the registry.
    /// </summary>
    [TestMethod]
    public async Task Ed25519IssuanceIntegratesWithDcqlDisclosureFlow()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<string> issuedToken = await IssueSignedPidTokenAsync(privateKey, TestContext.CancellationToken)
            .ConfigureAwait(false);

        bool signatureValid = await Jws.VerifyAsync(
            issuedToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(signatureValid, "Ed25519 issuer JWT signature must be valid.");

        var query = await new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [EudiPid.SdJwtVct],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.Birthdate])])
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var requestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}")
        };

        var match = new DisclosureMatch<SdToken<string>>
        {
            Credential = issuedToken,
            QueryRequirementId = EudiPid.DefaultCredentialQueryId,
            RequiredPaths = requestedPaths,
            MatchedPaths = requestedPaths,
            AllAvailablePaths = CreateAllAvailablePaths(),
            MandatoryPaths = CreateMandatoryPaths(),
            Format = DcqlCredentialFormats.SdJwt
        };

        var computation = new DisclosureComputation<SdToken<string>>();
        var plan = await computation.ComputeAsync(
            [match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.IsTrue(plan.Decisions[0].SatisfiesRequirements);
        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}"), plan.Decisions[0].SelectedPaths);

        var selectedClaimNames = plan.Decisions[0].SelectedPaths
            .Select(p => p.ToString().TrimStart('/'))
            .ToHashSet(StringComparer.Ordinal);

        SdToken<string> presentationToken = issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selectedClaimNames.Contains(d.ClaimName));

        bool presentationValid = await Jws.VerifyAsync(
            presentationToken.IssuerSigned, Decoder, (ReadOnlySpan<byte> _) => (object?)null, Pool,
            publicKey).ConfigureAwait(false);
        Assert.IsTrue(presentationValid, "Ed25519 signature must be valid on the presented token.");
    }


    /// <summary>
    /// Issues a signed EU Digital Identity PID token with selective disclosure
    /// using <see cref="SdJwtIssuance.IssueAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Serializes a PID document to JSON with both mandatory and disclosable claims,
    /// then issues via the delegate-free convenience API. The caller's
    /// <c>using Verifiable.Json.Sd</c> determines the format.
    /// </para>
    /// </remarks>
    private static async ValueTask<SdToken<string>> IssueSignedPidTokenAsync(
        PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        string pidJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            [WellKnownJwtClaims.Iss] = IssuerId,
            [WellKnownJwtClaims.Vct] = EudiPid.SdJwtVct,
            [WellKnownJwtClaims.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            [EudiPid.SdJwt.GivenName] = "Erika",
            [EudiPid.SdJwt.FamilyName] = "Mustermann",
            [EudiPid.SdJwt.Birthdate] = "1964-08-12",
            [EudiPid.SdJwt.Email] = "erika@example.de",
            [EudiPid.SdJwt.PhoneNumber] = "+49-170-1234567"
        });

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Email}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.PhoneNumber}")
        };

        int byteCount = Encoding.UTF8.GetByteCount(pidJson);
        using IMemoryOwner<byte> rental = Pool.Rent(byteCount);
        int written = Encoding.UTF8.GetBytes(pidJson, rental.Memory.Span);

        SdTokenResult result = await SdJwtIssuance.IssueAsync(
            rental.Memory[..written], disclosablePaths,
            SaltGenerator.Create,
            privateKey, IssuerKeyId,
            Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        return new SdToken<string>(compactJws, result.Disclosures.ToList());
    }


    /// <summary>
    /// Serializes a disclosure to its Base64Url-encoded JSON form.
    /// Wires <see cref="SdJwtSerializer.SerializeDisclosure"/> to the
    /// <see cref="SerializeDisclosureDelegate{TDisclosure}"/> signature.
    /// </summary>
    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }


    /// <summary>
    /// Computes the digest of an already-encoded disclosure string.
    /// Wires <see cref="SdJwtPathExtraction.ComputeDisclosureDigest"/> to the
    /// <see cref="ComputeDisclosureDigestDelegate"/> signature.
    /// </summary>
    private static string ComputeDigest(string encodedDisclosure, EncodeDelegate encoder)
    {
        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encodedDisclosure, WellKnownHashAlgorithms.Sha256Iana, encoder);
    }


    /// <summary>
    /// Creates the set of all available paths for a standard PID token.
    /// </summary>
    private static HashSet<CredentialPath> CreateAllAvailablePaths()
    {
        return
        [
            CredentialPath.FromJsonPointer("/iss"),
            CredentialPath.FromJsonPointer("/vct"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Birthdate}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.Email}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.PhoneNumber}")
        ];
    }


    /// <summary>
    /// Creates the mandatory paths for SD-JWT VC (iss and vct are always disclosed).
    /// </summary>
    private static HashSet<CredentialPath> CreateMandatoryPaths()
    {
        return
        [
            CredentialPath.FromJsonPointer("/iss"),
            CredentialPath.FromJsonPointer("/vct")
        ];
    }
}