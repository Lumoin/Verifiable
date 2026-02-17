using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Formats.Cbor;
using System.Globalization;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end tests for the DCQL presentation flow with SD-CWT credentials:
/// issuer signs SD-CWT → verifier sends DCQL query → wallet evaluates via
/// <see cref="DisclosureComputation{TCredential}"/> → wallet selects disclosures
/// via <see cref="SdToken{TEnvelope}.SelectDisclosures(Func{SdDisclosure, bool})"/> →
/// verifier validates COSE_Sign1 signature.
/// </summary>
/// <remarks>
/// <para>
/// Every test in this class uses real key material and cryptographic operations.
/// The flow parallels <see cref="DcqlPresentationFlowTests"/> (SD-JWT) for the
/// CBOR/COSE side.
/// </para>
/// <para>
/// The test credential uses application-defined CWT integer claim keys in the
/// private-use range. These are not EUDI PID claim keys — the EUDI ARF specifies
/// ISO mdoc (CBOR) and SD-JWT (JSON), not SD-CWT.
/// </para>
/// <para>
/// The COSE_Sign1 signature covers only the protected header and payload, so
/// <see cref="SdToken{TEnvelope}.SelectDisclosures(Func{SdDisclosure, bool})"/>
/// produces a new token whose <see cref="SdToken{TEnvelope}.IssuerSigned"/>
/// remains cryptographically valid.
/// </para>
/// <para>
/// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see> and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">
/// OID4VP §6 (DCQL)</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DcqlCwtPresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string CredentialQueryId = "employee_cwt";

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    //Application-defined CWT claim keys for a test employee credential.
    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyBirthdate = 102;
    private const int ClaimKeyEmail = 103;
    private const int ClaimKeyPhoneNumber = 104;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string BirthdatePath = "/102";
    private const string EmailPath = "/103";
    private const string PhoneNumberPath = "/104";


    /// <summary>
    /// Full DCQL presentation flow with SD-CWT: issuer signs → verifier requests
    /// given_name and family_name → disclosure engine computes minimum set →
    /// wallet selects disclosures → verifier validates COSE_Sign1 signature on
    /// the presented token.
    /// </summary>
    [TestMethod]
    public async Task SdCwtPresentationFlowProducesValidVpToken()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //Verifier builds a DCQL query requesting given_name and family_name.
        var query = await new DcqlQueryBuilder()
            .WithCredential(new CredentialQuery
            {
                Id = CredentialQueryId,
                Format = DcqlCredentialFormats.SdCwt,
                Claims =
                [
                    ClaimsQuery.ForPath([ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]),
                    ClaimsQuery.ForPath([ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)])
                ]
            })
            .BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);

        //Wallet evaluates the DCQL query against holdings.
        var requestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath)
        };

        var match = new DisclosureMatch<SdToken<ReadOnlyMemory<byte>>>
        {
            Credential = issuedToken,
            QueryRequirementId = CredentialQueryId,
            RequiredPaths = requestedPaths,
            MatchedPaths = requestedPaths,
            AllAvailablePaths = CreateAllAvailablePaths(),
            MandatoryPaths = CreateMandatoryPaths(),
            Format = DcqlCredentialFormats.SdCwt
        };

        //Disclosure engine computes optimal disclosure via lattice.
        var computation = new DisclosureComputation<SdToken<ReadOnlyMemory<byte>>>();
        var plan = await computation.ComputeAsync(
            [match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied, "The disclosure plan must be satisfied.");
        Assert.HasCount(1, plan.Decisions);

        var decision = plan.Decisions[0];
        Assert.IsTrue(decision.SatisfiesRequirements, "The decision must satisfy verifier requirements.");

        //Verify minimum disclosure: mandatory + requested, nothing extra.
        Assert.Contains(
            CredentialPath.FromJsonPointer("/1"), decision.SelectedPaths);
        Assert.Contains(
            CredentialPath.FromJsonPointer(GivenNamePath), decision.SelectedPaths);
        Assert.Contains(
            CredentialPath.FromJsonPointer(FamilyNamePath), decision.SelectedPaths);

        //Email, phone, and birthdate must NOT be disclosed.
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer(EmailPath), decision.SelectedPaths);
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer(PhoneNumberPath), decision.SelectedPaths);
        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer(BirthdatePath), decision.SelectedPaths);

        //Wallet selects disclosures from the SD-CWT token based on the plan.
        var selectedClaimNames = decision.SelectedPaths
            .Select(p => p.ToString().TrimStart('/'))
            .ToHashSet(StringComparer.Ordinal);

        SdToken<ReadOnlyMemory<byte>> presentationToken = issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selectedClaimNames.Contains(d.ClaimName));

        Assert.IsTrue(presentationToken.Disclosures.All(
            d => selectedClaimNames.Contains(d.ClaimName!)),
            "All disclosures in the presentation must be in the selected set.");

        //Construct VP Token response per OID4VP v1.0 Section 8.1.
        var vpToken = new Dictionary<string, object>
        {
            [CredentialQueryId] = presentationToken
        };

        Assert.IsTrue(vpToken.ContainsKey(CredentialQueryId));
        Assert.IsInstanceOfType<SdToken<ReadOnlyMemory<byte>>>(vpToken[CredentialQueryId]);

        //Verifier validates the COSE_Sign1 issuer signature on the presented token.
        //The signature covers protected header + payload, not the unprotected header
        //where disclosures reside, so SelectDisclosures does not invalidate it.
        CoseSign1Message coseMessage = CoseSerialization.ParseCoseSign1(
            presentationToken.IssuerSigned);

        bool signatureValid = await Verifiable.JCose.Cose.VerifyAsync(
            coseMessage, CoseSerialization.BuildSigStructure, publicKey).ConfigureAwait(false);

        Assert.IsTrue(signatureValid, "Presented COSE_Sign1 issuer signature must be cryptographically valid.");

        //Verify the decision record captured all phases.
        Assert.IsNotNull(plan.DecisionRecord);
        Assert.IsTrue(plan.DecisionRecord.Satisfied);
        Assert.HasCount(1, plan.DecisionRecord.LatticeComputations);
        Assert.HasCount(1, plan.DecisionRecord.FinalDecisions);
    }


    /// <summary>
    /// Verifier requests email but user excludes it, resulting in a conflict.
    /// The COSE_Sign1 signature remains valid regardless of disclosure decisions.
    /// </summary>
    [TestMethod]
    public async Task UserExclusionCreatesConflictInCwtDisclosurePlan()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        var emailPath = CredentialPath.FromJsonPointer(EmailPath);

        var match = new DisclosureMatch<SdToken<ReadOnlyMemory<byte>>>
        {
            Credential = issuedToken,
            QueryRequirementId = CredentialQueryId,
            RequiredPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer(GivenNamePath),
                emailPath
            },
            MatchedPaths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer(GivenNamePath),
                emailPath
            },
            AllAvailablePaths = CreateAllAvailablePaths(),
            MandatoryPaths = CreateMandatoryPaths(),
            Format = DcqlCredentialFormats.SdCwt
        };

        //User exclusions are passed to ComputeAsync, not on the match.
        var userExclusions = new Dictionary<string, IReadOnlySet<CredentialPath>>
        {
            [CredentialQueryId] = new HashSet<CredentialPath> { emailPath }
        };

        var computation = new DisclosureComputation<SdToken<ReadOnlyMemory<byte>>>();
        var plan = await computation.ComputeAsync(
            [match],
            userExclusions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied,
            "Plan is satisfied even with conflict, the credential was still processed.");
        Assert.HasCount(1, plan.Decisions);

        //The decision should reflect the conflict.
        var decision = plan.Decisions[0];
        Assert.DoesNotContain(emailPath, decision.SelectedPaths);

        //Even with an exclusion conflict, the token itself is still cryptographically sound.
        CoseSign1Message coseMessage = CoseSerialization.ParseCoseSign1(
            issuedToken.IssuerSigned);

        bool signatureValid = await Verifiable.JCose.Cose.VerifyAsync(
            coseMessage, CoseSerialization.BuildSigStructure, publicKey).ConfigureAwait(false);

        Assert.IsTrue(signatureValid,
            "COSE_Sign1 signature must be valid regardless of disclosure decisions.");
    }


    /// <summary>
    /// P-256 issuance integrates with the same DCQL disclosure flow,
    /// verifying algorithm-agnostic dispatch through the registry.
    /// </summary>
    [TestMethod]
    public async Task P256IssuanceIntegratesWithDcqlCwtFlow()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //Verify the COSE_Sign1 signature with P-256.
        CoseSign1Message coseMessage = CoseSerialization.ParseCoseSign1(
            issuedToken.IssuerSigned);

        bool signatureValid = await Verifiable.JCose.Cose.VerifyAsync(
            coseMessage, CoseSerialization.BuildSigStructure, publicKey).ConfigureAwait(false);

        Assert.IsTrue(signatureValid, "P-256 COSE_Sign1 signature must be valid.");

        //Run through DCQL disclosure computation.
        var requestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(BirthdatePath)
        };

        var match = new DisclosureMatch<SdToken<ReadOnlyMemory<byte>>>
        {
            Credential = issuedToken,
            QueryRequirementId = CredentialQueryId,
            RequiredPaths = requestedPaths,
            MatchedPaths = requestedPaths,
            AllAvailablePaths = CreateAllAvailablePaths(),
            MandatoryPaths = CreateMandatoryPaths(),
            Format = DcqlCredentialFormats.SdCwt
        };

        var computation = new DisclosureComputation<SdToken<ReadOnlyMemory<byte>>>();
        var plan = await computation.ComputeAsync(
            [match],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(plan.Satisfied);
        Assert.IsTrue(plan.Decisions[0].SatisfiesRequirements);
        Assert.Contains(
            CredentialPath.FromJsonPointer(BirthdatePath), plan.Decisions[0].SelectedPaths);

        //Wallet selects and verifier validates the presented subset.
        var selectedClaimNames = plan.Decisions[0].SelectedPaths
            .Select(p => p.ToString().TrimStart('/'))
            .ToHashSet(StringComparer.Ordinal);

        SdToken<ReadOnlyMemory<byte>> presentationToken = issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selectedClaimNames.Contains(d.ClaimName));

        CoseSign1Message presentedCose = CoseSerialization.ParseCoseSign1(
            presentationToken.IssuerSigned);

        bool presentationValid = await Verifiable.JCose.Cose.VerifyAsync(
            presentedCose, CoseSerialization.BuildSigStructure, publicKey).ConfigureAwait(false);

        Assert.IsTrue(presentationValid, "P-256 signature must be valid on the presented token.");
    }


    /// <summary>
    /// Issues a signed SD-CWT token with selective disclosure using
    /// <see cref="SdCwtIssuance.IssueAsync"/>.
    /// </summary>
    private static async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaims.Iss] = IssuerId,
            [WellKnownCwtClaims.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            [ClaimKeyGivenName] = "Erika",
            [ClaimKeyFamilyName] = "Mustermann",
            [ClaimKeyBirthdate] = "1964-08-12",
            [ClaimKeyEmail] = "erika@example.de",
            [ClaimKeyPhoneNumber] = "+49-170-1234567"
        };

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath),
            CredentialPath.FromJsonPointer(BirthdatePath),
            CredentialPath.FromJsonPointer(EmailPath),
            CredentialPath.FromJsonPointer(PhoneNumberPath)
        };

        byte[] cborBytes = SerializeCwtClaimMap(claims);

        SdTokenResult result = await SdCwtIssuance.IssueAsync(
            cborBytes, disclosablePaths,
            SaltGenerator.Create,
            privateKey, IssuerKeyId, Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return new SdToken<ReadOnlyMemory<byte>>(result.SignedToken, result.Disclosures.ToList());
    }


    /// <summary>
    /// Serializes a CWT claim map using <see cref="CborValueConverter"/>.
    /// </summary>
    private static byte[] SerializeCwtClaimMap(Dictionary<int, object> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CborValueConverter.WriteValue(writer, claims);
        return writer.Encode();
    }


    private static HashSet<CredentialPath> CreateAllAvailablePaths()
    {
        return
        [
            CredentialPath.FromJsonPointer("/1"),
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath),
            CredentialPath.FromJsonPointer(BirthdatePath),
            CredentialPath.FromJsonPointer(EmailPath),
            CredentialPath.FromJsonPointer(PhoneNumberPath)
        ];
    }


    private static HashSet<CredentialPath> CreateMandatoryPaths()
    {
        return
        [
            CredentialPath.FromJsonPointer("/1")
        ];
    }
}