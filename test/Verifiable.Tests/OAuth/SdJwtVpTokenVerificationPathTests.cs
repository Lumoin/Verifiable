using System.Buffers;
using System.Buffers.Text;
using System.Collections.Immutable;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifier-side tests for <see cref="SdJwtVpTokenVerification"/> and its SD-CWT twin
/// <see cref="KbCwtVerification"/> over a credential that carries the same claim name at two
/// depths: <c>family_name</c> at the top level and <c>family_name</c> under <c>employer</c>.
/// </summary>
/// <remarks>
/// <para>
/// The credential shape is the one
/// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see> names outright —
/// "including when the same claim name occurs at different places in the structure of the SD-JWT" —
/// so the disclosure a presentation carries is identified by its position, never by its leaf name.
/// Each test drives the credential over the wire (compact SD-JWT plus KB-JWT, or the SD-CWT Key
/// Binding Token bytes) and reads the verifier's own path-keyed result, then feeds that result to
/// the DCQL assessment seam the reference relying-party wiring uses
/// (<see cref="DisclosedClaimsDcqlAdapter"/> behind an <see cref="Oid4VpDisclosureAssessmentContext"/>).
/// </para>
/// <para>
/// Fixtures are minted through the library's own issuance
/// (<see cref="SdJwtIssuanceExtensions"/> / <see cref="SdCwtIssuanceExtensions"/>,
/// <see cref="TestSalts"/>, the <see cref="TestSetup"/> encoders) and every expectation is the path
/// the spec's own rules give the claim, written out by hand.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdJwtVpTokenVerificationPathTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The clock every issuance, key binding and verification in this class reads.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The pool the test side passes explicitly to every issuance, selection and verification call.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>A type the credential neither declares as its <c>vct</c> nor lists in <c>aka_vcts</c>.</summary>
    private const string UnrelatedCredentialType = "https://credentials.example.com/mdl_credential";

    /// <summary>The DCQL credential query identifier the presentation travels under.</summary>
    private const string IdentityCredentialQueryId = "identity";

    /// <summary>The relying party's client identifier, which is also the key-binding audience.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The relying party's base URI, under which its endpoints are registered.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The nonce the relying party issues and the holder binds its proof of possession to.</summary>
    private const string KeyBindingNonce = "n-vp-nested-01";

    /// <summary>The audience the SD-CWT Key Binding Token is bound to.</summary>
    private const string SdCwtVerifierAudience = "https://verifier.example.com/response";

    /// <summary>
    /// A well-formed <c>status</c> claim value, in the Token Status List Section 6.2 shape, written
    /// twice into one payload to compose the repeated-member fixture. Each occurrence is on its own a
    /// claim the verifier would accept, so the refusal the test asserts can only be the repetition's.
    /// </summary>
    private const string RepeatedStatusMemberJson =
        """{"status_list":{"idx":7,"uri":"https://issuer.example.com/statuslists/1"}}""";

    /// <summary>
    /// The trust evidence a relying party's own resolution stands for here: the credential's chain
    /// carries the AuthorityKeyIdentifier <see cref="DcqlFixtures.AkiExampleValue"/> spells, the
    /// <c>aki</c> evidence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// Section 6.1.1.1</see> compares a query value against.
    /// </summary>
    private static TrustedAuthorityEvidence ExampleAuthorityKeyIdentifierEvidence { get; } = new()
    {
        AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier>
        {
            new(Base64Url.DecodeFromChars(DcqlFixtures.AkiExampleValue))
        }
    };

    /// <summary>The capabilities the relying party is registered with for the presentation flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below." A presentation
    /// that selected only the disclosure under <c>employer</c> reaches the verifier as exactly that
    /// disclosure, and the verifier reports it at <c>/employer/family_name</c> —
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>'s "the same
    /// claim name occurs at different places in the structure of the SD-JWT" is why the leaf name
    /// alone cannot say which of the two was released. The rule reaches only what the wallet
    /// chooses to send, so the claims the credential carries unconditionally ride along without
    /// counting against it — the verifier reports them apart, in
    /// <see cref="VpCredentialClaims.UnconditionallyDisclosed"/>.
    /// </summary>
    [TestMethod]
    public async Task NestedFamilyNamePresentationDisclosesTheNestedPathOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<CredentialPath, object?> disclosed = parsed.Credential.Disclosed;

        Assert.IsTrue(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer)),
            "Section 6.4: the disclosure the wallet selected must surface at the path it occupies, '/employer/family_name'.");
        Assert.AreEqual(NestedSdJwtVcFixtures.HolderBoundEmployerFamilyName, disclosed[CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer)],
            "The value at '/employer/family_name' must be the nested disclosure's own value.");
        Assert.IsFalse(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer)),
            "Section 6.4 MUST NOT: the top-level family_name was not selected and must not appear in the disclosed set.");
        var selectivelyDisclosed = new HashSet<CredentialPath>(disclosed.Keys);
        selectivelyDisclosed.ExceptWith(parsed.Credential.UnconditionallyDisclosed);

        Assert.HasCount(1, selectivelyDisclosed,
            "Section 6.4 constrains selectively disclosable claims: selecting one disclosure with no disclosable ancestor must release exactly one of them.");
    }


    /// <summary>
    /// The mirror of the nested case, proving the two disclosures are distinguishable in both
    /// directions: a presentation that selected the top-level disclosure reports
    /// <c>/family_name</c> and nothing under <c>employer</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below."
    /// </summary>
    [TestMethod]
    public async Task TopLevelFamilyNamePresentationDisclosesTheTopLevelPathOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<CredentialPath, object?> disclosed = parsed.Credential.Disclosed;

        Assert.IsTrue(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer)),
            "Section 6.4: the selected top-level disclosure must surface at '/family_name'.");
        Assert.AreEqual(NestedSdJwtVcFixtures.SubjectFamilyName, disclosed[CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer)],
            "The value at '/family_name' must be the top-level disclosure's own value.");
        Assert.IsFalse(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer)),
            "Section 6.4 MUST NOT: the employer's family_name was not selected and must not appear in the disclosed set.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see> designates all three, and places them among the claims that
    /// "MUST NOT be included in the Disclosures": "vct: REQUIRED. The type of the Verifiable
    /// Digital Credential ... as defined in Section 2.2.2.1"; "aka_vcts: OPTIONAL. An array of
    /// additional types of the Verifiable Digital Credential, as defined in Section 2.2.2.2";
    /// "iss: OPTIONAL. ... this claim explicitly indicates the Issuer of the Verifiable Digital
    /// Credential when it is not conveyed by other means". The verifier reads all three from the
    /// credential's own claims, which is the evidence a DCQL type or trusted-authority constraint
    /// is answered against.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheCredentialTypeAdditionalTypesAndIssuer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(NestedSdJwtVcFixtures.Vct, parsed.Credential.CredentialType,
            "Section 2.2.2.3: the credential's vct is the type evidence the verifier surfaces.");
        Assert.Contains(NestedSdJwtVcFixtures.HolderBoundAdditionalVct, parsed.Credential.AdditionalTypes,
            "Section 2.2.2.3: every value of aka_vcts is an additional type the credential declares.");
        Assert.HasCount(1, parsed.Credential.AdditionalTypes,
            "The credential declares exactly the one additional type its aka_vcts array carries.");
        Assert.AreEqual(NestedSdJwtVcFixtures.Issuer, parsed.Credential.Issuer,
            "Section 2.2.2.3: iss is the issuer evidence the verifier surfaces.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "vct: REQUIRED. The type of the Verifiable Digital
    /// Credential ... as defined in Section 2.2.2.1". A <c>dc+sd-jwt</c> presentation whose
    /// credential carries no <c>vct</c> declares
    /// no type, and the SD-JWT VC verification profile's credential-type rule records a failure
    /// rather than treating the credential as an untyped SD-JWT.
    /// </summary>
    [TestMethod]
    public async Task PresentationWithoutCredentialTypeFailsTheCredentialTypeCheck()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, credentialType: null, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.CredentialType,
            "A credential carrying no vct declares no type, so the verifier surfaces none.");

        ValidationContext validationContext = new()
        {
            Context = new ExchangeContext(),
            Now = TimeProvider.GetUtcNow(),
            CredentialTypePresent = parsed.Credential.CredentialType is not null
        };

        List<Claim> claims = await ValidationChecks.CheckCredentialTypePresent(
            validationContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims, "The credential-type rule records exactly one claim.");
        Assert.AreEqual(ValidationClaimIds.CredentialTypePresent, claims[0].Id,
            "The recorded claim must be the credential-type-present axis.");
        Assert.AreEqual(ClaimOutcome.Failure, claims[0].Outcome,
            "Section 2.2.2.3 makes vct REQUIRED, so a dc+sd-jwt credential without one must fail verification.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1</see>: "To address a particular claim within an
    /// object, append the key (claim name) to the array." A two-segment path pointer
    /// <c>["employer", "family_name"]</c> addresses the disclosure inside <c>employer</c>, and the
    /// relying party's assessment of the nested presentation matches it.
    /// </summary>
    [TestMethod]
    public async Task NestedClaimPathMatchesTheNestedPresentation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        DcqlEvaluationResult result = Assess(parsed, BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct));

        Assert.IsTrue(result.Matches,
            $"Section 7.1: ['employer','family_name'] addresses the disclosed claim, so the credential matches. Reason: {result.FailureReason}");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." A presentation that released only the top-level
    /// <c>family_name</c> holds nothing at <c>["employer", "family_name"]</c>, so the same query
    /// does not match it — the namesake at another depth is a different claim.
    /// </summary>
    [TestMethod]
    public async Task NestedClaimPathDoesNotMatchTheTopLevelPresentation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        DcqlEvaluationResult result = Assess(parsed, BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct));

        Assert.IsFalse(result.Matches,
            "Section 6.4.2: a presentation holding only '/family_name' does not satisfy a query for '/employer/family_name'.");
        Assert.AreEqual(
            DcqlFailureReasons.MissingRequiredClaims([DcqlClaimPattern.FromKeys("employer", "family_name")]),
            result.FailureReason,
            "The named reason must be the missing required claim, not a silent non-match.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." A query whose <c>vct_values</c> names a type the
    /// credential neither declares as its <c>vct</c> nor lists in <c>aka_vcts</c> does not match,
    /// and the reason names the type the credential did declare.
    /// </summary>
    [TestMethod]
    public async Task QueryNamingAnotherCredentialTypeDoesNotMatch()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        DcqlEvaluationResult result = Assess(parsed, BuildNestedFamilyNameQuery(UnrelatedCredentialType));

        Assert.IsFalse(result.Matches,
            "Section 6.4.2: a credential of another type does not match a query constraining the type.");
        Assert.AreEqual(DcqlFailureReasons.CredentialTypeNotAccepted(NestedSdJwtVcFixtures.Vct), result.FailureReason,
            "The named reason must state which declared type was refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." A credential that declares no type at all cannot be
    /// shown to satisfy a <c>vct_values</c> constraint, so the assessment fails closed with the
    /// reason naming the absent evidence rather than skipping the check.
    /// </summary>
    [TestMethod]
    public async Task QueryConstrainingTheTypeFailsClosedWhenTheCredentialDeclaresNone()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, credentialType: null, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        DcqlEvaluationResult result = Assess(parsed, BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct));

        Assert.IsFalse(result.Matches,
            "Section 6.4.2: an unknown type cannot satisfy a type constraint, so the credential must not match.");
        Assert.AreEqual(DcqlFailureReasons.CredentialTypeUnknown, result.FailureReason,
            "The named reason must state that the query constrains the type and the credential declares none.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "The Wallet MAY return Credentials that
    /// inherit from any of the specified types, following the inheritance logic defined in
    /// [I-D.ietf-oauth-sd-jwt-vc]." The credential's own <c>aka_vcts</c> is that inheritance as far
    /// as the credential's claims carry it, so a query naming the additional type matches.
    /// </summary>
    [TestMethod]
    public async Task QueryNamingAnAdditionalDeclaredTypeMatches()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        DcqlEvaluationResult result = Assess(parsed, BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.HolderBoundAdditionalVct));

        Assert.IsTrue(result.Matches,
            $"Appendix B.3.5: a type the credential declares in aka_vcts satisfies the constraint. Reason: {result.FailureReason}");
    }


    /// <summary>
    /// The SD-CWT twin of the nested-path case.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>: "The Issuer
    /// MUST ensure that a new salt value is chosen for each claim, including when the same claim
    /// name occurs at different places in the structure of the SD-JWT." The SD-CWT Key Binding
    /// Token verifier reports each disclosed claim at the position it occupies in the issuer-signed
    /// CWT claims map, so the nested label and its top-level namesake stay distinct.
    /// </summary>
    [TestMethod]
    public async Task NestedSdCwtPresentationDisclosesTheNestedPathOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublicKey = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> storedCredential = await NestedSdJwtVcFixtures.MintHolderBoundSdCwtCredentialAsync(
            issuerPrivateKey, holderPublicKey, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = storedCredential.SelectDisclosures(
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.CwtNestedFamilyNamePointer) },
            Pool).Token;

        using EncodedCoseSign1 keyBindingToken = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivateKey,
            verifierAud: SdCwtVerifierAudience,
            verifierCnonce: KeyBindingNonce,
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SdCwtKbtVerificationResult result = await VerifySdCwtPresentationAsync(
            keyBindingToken.AsReadOnlyMemory(), issuerPublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.HolderSignatureValid, "The Key Binding Token holder signature must verify.");
        Assert.IsTrue(result.CredentialSignatureValid,
            "The embedded SD-CWT issuer signature and digest binding must hold.");

        IReadOnlyDictionary<CredentialPath, object?> disclosed = result.DisclosedClaims;

        Assert.IsTrue(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.CwtNestedFamilyNamePointer)),
            "Section 9.3: the nested disclosure must surface at the path it occupies, '/500/101'.");
        Assert.AreEqual(NestedSdJwtVcFixtures.HolderBoundEmployerFamilyName, disclosed[CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.CwtNestedFamilyNamePointer)],
            "The value at '/500/101' must be the nested disclosure's own value.");
        Assert.IsFalse(disclosed.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.CwtTopLevelFamilyNamePointer)),
            "The top-level namesake was not selected and must not appear in the disclosed set.");
    }


    /// <summary>
    /// The whole presentation exchange over the wire: the verifier pushes an authorization request
    /// asking for <c>["employer", "family_name"]</c>, the wallet answers it from the same credential
    /// that carries both namesakes, and the verified flow state carries the nested path.
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below."
    /// </summary>
    [TestMethod]
    public async Task FullPresentationFlowSurfacesTheNestedPathOnly()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(NestedSdJwtVcFixtures.Issuer, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string>(StringComparer.Ordinal) { [IdentityCredentialQueryId] = serializedSdJwt },
            holderPrivateKey,
            TimeProvider);

        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(
            new DcqlQuery { Credentials = [BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct)] });

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce(KeyBindingNonce),
            preparedQuery,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        string walletFlowId = $"wallet-nested-{Guid.NewGuid():N}";
        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        PresentationVerifiedState verified = await app.HandleDirectPostAsync(
            verifierKeys,
            parHandle,
            compactJwe,
            redirectUri: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<CredentialPath, string> claims =
            verified.Credentials[new CredentialQueryId(IdentityCredentialQueryId)].Extracted;

        Assert.AreEqual(NestedSdJwtVcFixtures.HolderBoundEmployerFamilyName, claims[CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer)],
            "Section 6.4: the claim the verifier asked for must arrive at '/employer/family_name'.");
        Assert.IsFalse(claims.ContainsKey(CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.TopLevelFamilyNamePointer)),
            "Section 6.4 MUST NOT: the top-level namesake was never selected and must not reach the verifier.");
    }


    /// <summary>
    /// Wallet side: parses the stored SD-JWT, releases exactly the disclosures at
    /// <paramref name="selectedPaths"/> (plus any disclosable ancestor the lattice closure adds),
    /// signs the Key Binding JWT over the resulting presentation and returns the wire value.
    /// </summary>
    /// <param name="serializedSdJwt">The stored credential in SD-JWT compact serialization.</param>
    /// <param name="holderPrivateKey">The holder key whose public half rides in <c>cnf</c>.</param>
    /// <param name="selectedPaths">The paths to disclose.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The vp_token value: issuer JWT, selected disclosures and the KB-JWT.</returns>
    private async ValueTask<string> ProducePresentationAsync(
        string serializedSdJwt,
        PrivateKeyMemory holderPrivateKey,
        IReadOnlySet<CredentialPath> selectedPaths,
        CancellationToken cancellationToken)
    {
        using SdToken<string> storedToken = SdJwtSerializer.ParseToken(
            serializedSdJwt, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);

        using SdToken<string> presentationToken = storedToken.SelectDisclosures(selectedPaths, Pool).Token;

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(presentationToken, TestSetup.Base64UrlEncoder);
        byte[] hashInputBytes = Encoding.UTF8.GetBytes(hashInput);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            hashInputBytes,
            holderPrivateKey,
            KeyBindingNonce,
            VerifierClientId,
            TimeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
            static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
            Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKeyBinding = presentationToken.WithKeyBinding(compactKbJwt, Pool);

        return SdJwtSerializer.SerializeToken(tokenWithKeyBinding, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Verifier side: runs the OID4VP SD-JWT VP-token verification over the wire value with the
    /// library's own parse, hash-input, digest and encoding seams and a trust framework that
    /// resolves <paramref name="issuerPublicKey"/> for the credential's <c>iss</c>.
    /// </summary>
    /// <param name="vpToken">The vp_token value the wallet produced.</param>
    /// <param name="issuerPublicKey">The issuer key the trust framework resolves.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified presentation.</returns>
    private static async ValueTask<VpTokenParsed> VerifyPresentationAsync(
        string vpToken,
        PublicKeyMemory issuerPublicKey,
        CancellationToken cancellationToken)
    {
        return await SdJwtVpTokenVerification.VerifyAsync(
            vpToken,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: _ => issuerPublicKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifier side for the SD-CWT twin: runs the Key Binding Token verification over the wire
    /// bytes with the <c>Verifiable.Cbor</c> seams and a resolver returning
    /// <paramref name="issuerPublicKey"/>.
    /// </summary>
    /// <param name="keyBindingTokenBytes">The Key Binding Token as it travels.</param>
    /// <param name="issuerPublicKey">The issuer key the trust framework resolves.</param>
    /// <returns>The verified Key Binding Token result, disclosed claims keyed by path.</returns>
    private async ValueTask<SdCwtKbtVerificationResult> VerifySdCwtPresentationAsync(
        ReadOnlyMemory<byte> keyBindingTokenBytes,
        PublicKeyMemory issuerPublicKey)
    {
        return await KbCwtVerification.VerifyAsync(
            keyBindingTokenBytes,
            parseCoseSign1: CoseSerialization.ParseCoseSign1,
            extractKcwt: SdCwtVpParsing.ExtractKcwt,
            parseSdCwt: bytes => SdCwtVpParsing.ParseEmbeddedSdCwt(
                bytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder),
            extractHolderKey: SdCwtVpParsing.ExtractHolderKey,
            readKbtClaims: SdCwtVpParsing.ReadKbtClaims,
            extractIssuer: SdCwtVpParsing.ExtractIssuer,
            extractCredentialType: SdCwtVpParsing.ExtractCredentialType,
            extractStatus: SdCwtVpParsing.ExtractStatus,
            resolveIssuerKey: _ => issuerPublicKey,
            verifyCredential: async (token, key, pool, ct) =>
            {
                SdVerificationResult result = await token.VerifyAsync(
                    key, pool,
                    CoseSerialization.ParseCoseSign1, SdCwtPathExtraction.ExtractPaths,
                    CoseSerialization.BuildSigStructure, TestSetup.Base64UrlEncoder,
                    cancellationToken: ct).ConfigureAwait(false);

                return result.IsValid;
            },
            buildSigStructure: CoseSerialization.BuildSigStructure,
            saltReuseSeam: null,
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "vct: REQUIRED. The type of the Verifiable Digital
    /// Credential". The refusal is the verifier's own, reached over the wire: a presentation whose
    /// credential declares no type does not satisfy the typed DCQL query, so the verifier refuses it and the
    /// <c>direct_post</c> endpoint answers RFC 6749 §4.1.2.1's <c>invalid_request</c> (HTTP 400) —
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0
    /// §8.2</see> defines only the success answer. Deleting the rule from the profile or the executor's
    /// wiring makes this test fail rather than leaving it green.
    /// </summary>
    [TestMethod]
    public async Task FullPresentationFlowRefusesACredentialDeclaringNoType()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, credentialType: null, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(NestedSdJwtVcFixtures.Issuer, issuerKey);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string>(StringComparer.Ordinal) { [IdentityCredentialQueryId] = serializedSdJwt },
            holderPrivateKey,
            TimeProvider);

        PreparedDcqlQuery preparedQuery = DcqlPreparer.Prepare(
            new DcqlQuery { Credentials = [BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct)] });

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce(KeyBindingNonce),
            preparedQuery,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        string walletFlowId = $"wallet-untyped-{Guid.NewGuid():N}";
        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId,
            requestUri,
            compactJar,
            verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        InvalidOperationException refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await app.HandleDirectPostAsync(
                verifierKeys,
                parHandle,
                compactJwe,
                redirectUri: null,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains(
            "status 400",
            refusal.Message,
            StringComparison.Ordinal,
            "Section 2.2.2.3 makes vct REQUIRED; a credential declaring no type does not satisfy the typed query, so the verifier refuses the presentation over the wire with RFC 6749 §4.1.2.1's HTTP 400 — never 500.");
        Assert.Contains(
            OAuthErrors.InvalidRequest,
            refusal.Message,
            StringComparison.Ordinal,
            "A presentation that does not satisfy the Authorization Request is refused as RFC 6749 §4.1.2.1 invalid_request.");
        Assert.IsFalse(
            refusal.Message.Contains("VerifierFlowFailedState", StringComparison.Ordinal),
            "The wire refusal answers a typed RFC 6749 §4.1.2.1 error, not the verifier's internal state name.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.3</see>: "path: REQUIRED The value MUST be a
    /// non-empty array representing a claims path pointer that specifies the path to a claim within
    /// the Credential". A claim the Issuer did not make selectively disclosable is a claim within
    /// the Credential like any other, so a relying party naming it resolves it in the presentation
    /// — the verifier and the holder answer the same query over the same addressable structure.
    /// </summary>
    [TestMethod]
    public async Task AnRelyingPartyQueryNamingAnUnconditionallyDisclosedClaimMatchesThePresentation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            TestContext.CancellationToken).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        CredentialQuery query = new()
        {
            Id = IdentityCredentialQueryId,
            Format = DcqlCredentialFormats.SdJwt,
            Meta = new CredentialQueryMeta { VctValues = [NestedSdJwtVcFixtures.Vct] },
            Claims =
            [
                new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(WellKnownJwtClaimNames.Vct) }
            ]
        };

        DcqlEvaluationResult assessment = Assess(parsed, query);

        Assert.IsTrue(
            assessment.Matches,
            $"Section 6.3: the presentation carries vct, so a pointer naming it resolves. Reason given: {assessment.FailureReason}");
    }


    /// <summary>
    /// The credential query the relying party asks with: an SD-JWT VC credential of one of
    /// <paramref name="acceptedTypes"/> holding the claim at the two-segment path
    /// <c>["employer", "family_name"]</c>.
    /// </summary>
    /// <param name="acceptedTypes">The <c>meta.vct_values</c> the query accepts.</param>
    /// <returns>A fresh credential query.</returns>
    private static CredentialQuery BuildNestedFamilyNameQuery(params string[] acceptedTypes) => new()
    {
        Id = IdentityCredentialQueryId,
        Format = DcqlCredentialFormats.SdJwt,
        Meta = new CredentialQueryMeta { VctValues = acceptedTypes },
        Claims =
        [
            new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("employer", "family_name") }
        ]
    };


    /// <summary>
    /// The relying party's assessment of a verified presentation, wired exactly as the reference
    /// verifier wiring is: the disclosed path/value map behind
    /// <see cref="DisclosedClaimsDcqlAdapter"/>, with the credential's own type, additional types
    /// and trust evidence as what the type and trusted-authority constraints are answered against.
    /// </summary>
    /// <param name="parsed">The verified presentation.</param>
    /// <param name="credentialQuery">The credential query to assess against.</param>
    /// <returns>The evaluation verdict together with its named failure reason.</returns>
    private static DcqlEvaluationResult Assess(VpTokenParsed parsed, CredentialQuery credentialQuery)
    {
        Oid4VpDisclosureAssessmentContext assessmentContext = new()
        {
            CredentialQuery = credentialQuery,
            Credential = parsed.Credential
        };

        DcqlMetadataExtractor<IReadOnlyDictionary<CredentialPath, object?>> metadataExtractor =
            DisclosedClaimsDcqlAdapter.CreateMetadataExtractor(
                assessmentContext.CredentialQuery.Format!,
                credentialType: assessmentContext.Credential.CredentialType,
                additionalTypes: assessmentContext.Credential.AdditionalTypes,
                trustedAuthorityEvidence: assessmentContext.Credential.TrustedAuthorityEvidence);

        return DcqlEvaluator.EvaluateSingle(
            assessmentContext.CredentialQuery,
            assessmentContext.Credential.Disclosed,
            metadataExtractor(assessmentContext.Credential.Disclosed),
            DisclosedClaimsDcqlAdapter.ClaimExtractor);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID
    /// for Verifiable Presentations 1.0, Section 8.1</see>: "vp_token: REQUIRED. This is a JSON-encoded
    /// object containing entries where the key is the id value used for a Credential Query in the DCQL
    /// query and the value is an array of one or more Presentations that match the respective Credential
    /// Query." The verified presentation names the very identifier the wire keyed it by, so a relying
    /// party reading one credential's facts never has to guess which query it answered.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationIsKeyedByTheCredentialQueryItAnswered()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(new CredentialQueryId(IdentityCredentialQueryId), parsed.CredentialQueryId,
            "Section 8.1: the presentation is keyed by the Credential Query id it answered.");
        Assert.AreEqual(IdentityCredentialQueryId, parsed.CredentialQueryId.Value,
            "The identifier's value is the same string the DCQL credential query carries.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "The following registered JWT claims are used within the SD-JWT
    /// component of the SD-JWT VC and MUST NOT be included in the Disclosures, i.e., cannot be
    /// selectively disclosed" — among them <c>iss</c> and <c>vct</c>. Those claims reach the Verifier
    /// whatever the holder selects, so they belong in the addressable structure a query is resolved over
    /// while staying apart from the released Disclosures that
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">
    /// Section 6.4</see> governs.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationSeparatesTheAlwaysDisclosedClaimsFromTheSelectedDisclosure()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        CredentialPath nestedFamilyNamePath =
            CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer);

        Assert.AreEqual(NestedSdJwtVcFixtures.HolderBoundEmployerFamilyName, parsed.Credential.Extracted[nestedFamilyNamePath],
            "Section 6.4: the released Disclosure surfaces at its own position with its own value.");
        Assert.HasCount(1, parsed.Credential.Extracted,
            "Section 6.4: exactly the one Disclosure the holder selected was released.");

        Assert.IsTrue(parsed.Credential.Disclosed.ContainsKey(nestedFamilyNamePath),
            "The released Disclosure is part of what the presentation puts in front of the Verifier.");
        Assert.IsTrue(parsed.Credential.Disclosed.ContainsKey(NestedSdJwtVcFixtures.VctPath),
            "Section 2.2.2.3: vct cannot be selectively disclosed, so the presentation plainly carries it.");
        Assert.IsTrue(parsed.Credential.Disclosed.ContainsKey(NestedSdJwtVcFixtures.IssuerPath),
            "Section 2.2.2.3: iss cannot be selectively disclosed, so the presentation plainly carries it.");

        Assert.Contains(NestedSdJwtVcFixtures.VctPath, parsed.Credential.UnconditionallyDisclosed,
            "Section 2.2.2.3: vct MUST NOT be included in the Disclosures, so it is unconditionally disclosed.");
        Assert.Contains(NestedSdJwtVcFixtures.IssuerPath, parsed.Credential.UnconditionallyDisclosed,
            "Section 2.2.2.3: iss MUST NOT be included in the Disclosures, so it is unconditionally disclosed.");
        Assert.DoesNotContain(nestedFamilyNamePath, parsed.Credential.UnconditionallyDisclosed,
            "Section 6.4: a claim the holder chose to release is a selected Disclosure, never an unconditional one.");
        Assert.DoesNotContain(NestedSdJwtVcFixtures.TopLevelFamilyNamePath, parsed.Credential.UnconditionallyDisclosed,
            "Section 6.4: the unselected namesake is neither disclosed nor unconditionally disclosed.");

        foreach(CredentialPath unconditional in parsed.Credential.UnconditionallyDisclosed)
        {
            Assert.IsTrue(parsed.Credential.Disclosed.ContainsKey(unconditional),
                "Every unconditionally disclosed claim is part of the structure a query is resolved over.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check for
    /// the existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens and
    /// Section 6.3 for COSE-based Referenced Tokens." Existence is what is checked first, so a credential
    /// whose issuer stated no status at all is reported as carrying none rather than as carrying one that
    /// cannot be read.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoStatusClaimWhenTheCredentialStatesNone()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.Status,
            "Section 8.3 step 1: a credential carrying no status claim is reported as having none.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least one
    /// reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">
    /// Token Status List, Section 6.1</see>. A <c>status</c> member that IS present and carries an empty
    /// object states a status claim naming nothing, which is a malformed presentation — the existence
    /// check of Section 8.3 step 1 is answered by the member, never by whether its content happens to be
    /// empty, so this shape is never mistaken for a credential that was not status-checked.
    /// </summary>
    [TestMethod]
    public async Task AStatusClaimWhoseValueIsAnEmptyObjectIsRefusedAsMalformed()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string malformed = SdJwtVpFixture.AppendTopLevelClaimToIssuerPayload(
            vpToken, WellKnownJwtClaimNames.Status, "{}");

        FormatException exception = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await VerifyPresentationAsync(malformed, issuerKey, TestContext.CancellationToken)
                .ConfigureAwait(false),
            "Section 6.1: a present status claim carrying no mechanism is a malformed presentation.").ConfigureAwait(false);

        Assert.Contains("status", exception.Message,
            "The refusal must name the claim it read.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least one
    /// reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">
    /// Token Status List, Section 6.1</see>. A <c>status</c> member whose value is a string is not the
    /// JSON Object the claim MUST specify, so it names no mechanism and is refused for the same reason an
    /// empty object is, rather than being read as an absent claim.
    /// </summary>
    [TestMethod]
    public async Task AStatusClaimWhoseValueIsNotAnObjectIsRefusedAsMalformed()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string malformed = SdJwtVpFixture.AppendTopLevelClaimToIssuerPayload(
            vpToken, WellKnownJwtClaimNames.Status, "\"revoked\"");

        FormatException exception = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await VerifyPresentationAsync(malformed, issuerKey, TestContext.CancellationToken)
                .ConfigureAwait(false),
            "Section 6.1: a status claim that is not a JSON Object names no mechanism.").ConfigureAwait(false);

        Assert.Contains("status", exception.Message,
            "The refusal must name the claim it read.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259, Section 4</see>: "The names
    /// within an object SHOULD be unique." and "When the names within an object are not unique, the
    /// behavior of software that receives such an object is unpredictable." An issuer-signed payload
    /// repeating a top-level claim name shows a span-scanning reader the first occurrence and a
    /// serializer-based reader the last, so one verifier can validate one value while another acts on a
    /// different one. The payload is refused before any claim is read.
    /// </summary>
    [TestMethod]
    public async Task AnIssuerPayloadRepeatingATopLevelClaimIsRefusedAsMalformed()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string withStatus = SdJwtVpFixture.AppendTopLevelClaimToIssuerPayload(
            vpToken, WellKnownJwtClaimNames.Status, RepeatedStatusMemberJson);
        string repeated = SdJwtVpFixture.AppendTopLevelClaimToIssuerPayload(
            withStatus, WellKnownJwtClaimNames.Status, RepeatedStatusMemberJson);

        FormatException exception = await Assert.ThrowsExactlyAsync<FormatException>(
            async () => await VerifyPresentationAsync(repeated, issuerKey, TestContext.CancellationToken)
                .ConfigureAwait(false),
            "A repeated top-level claim name is refused rather than resolved to one of its occurrences.").ConfigureAwait(false);

        Assert.Contains("duplicate", exception.Message,
            "The refusal must name the repeated top-level claim name as its reason.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see>: "If the Issuer of the Referenced Token is the same entity
    /// as the Status Issuer, then the same key that is embedded into the Referenced Token may be used for
    /// the Status List Token." Reaching that recommendation needs the key the Referenced Token's own
    /// issuer signature verified under, so the verified presentation carries it — the very key the trust
    /// framework answered with, byte for byte.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheIssuerKeyTheCredentialSignatureVerifiedUnder()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.CredentialSignatureValid,
            "The credential's issuer signature must verify before its key is published.");
        Assert.IsNotNull(parsed.CredentialIssuerKey,
            "Section 11.3: the key the Referenced Token verified under must be reachable from the presentation.");
        Assert.IsTrue(
            parsed.CredentialIssuerKey.AsReadOnlySpan().SequenceEqual(issuerKey.AsReadOnlySpan()),
            "Section 11.3: the published key must be the key the trust framework resolved, byte for byte.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see> makes the same-key recommendation conditional on the
    /// Referenced Token's own issuer key being known. A trust framework that resolves no key for the
    /// credential's <c>iss</c> leaves the issuer signature unverified, and nothing is published as that
    /// credential's issuer key — a composition over it fails closed rather than borrowing a key that
    /// verified nothing.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoIssuerKeyWhenTheTrustFrameworkResolvesNone()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationWithoutIssuerTrustAsync(
            vpToken, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(parsed.CredentialSignatureValid,
            "An unresolved issuer key leaves the credential's own signature unverified.");
        Assert.IsNull(parsed.CredentialIssuerKey,
            "Section 11.3: no key verified the credential, so none is published as the Referenced Token's issuer key.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Trusted Authorities Query is an
    /// object representing information that helps to identify an authority or the trust framework that
    /// certifies Issuers. A Credential is identified as a match to a Trusted Authorities Query if it
    /// matches with one of the provided values in one of the provided types." The evidence the relying
    /// party's own resolution produces for the credential's chain and verified <c>iss</c> is what that
    /// matching is answered against, so the verified presentation carries it.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheResolvedTrustEvidenceWhenTheSeamIsWired()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        string? issuerSeenByTheResolver = null;
        VpTokenParsed parsed = await VerifyPresentationWithTrustEvidenceAsync(
            vpToken,
            issuerKey,
            (chain, issuerIdentifier, pool, cancellationToken) =>
            {
                issuerSeenByTheResolver = issuerIdentifier;

                return ValueTask.FromResult<TrustedAuthorityEvidence?>(ExampleAuthorityKeyIdentifierEvidence);
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(NestedSdJwtVcFixtures.Issuer, issuerSeenByTheResolver,
            "Section 6.1.1: the evidence is resolved for the credential's own verified issuer.");
        Assert.AreSame(ExampleAuthorityKeyIdentifierEvidence, parsed.Credential.TrustedAuthorityEvidence,
            "Section 6.1.1: the resolved evidence is what a trusted_authorities constraint is matched against.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
    /// respective constraints expressed within credentials MUST NOT be returned, i.e., they are treated
    /// as if they would not exist in the Wallet." A verifier that wires no trust-evidence resolution
    /// surfaces no evidence at all, which is what makes a <c>trusted_authorities</c> constraint fail
    /// closed rather than be skipped.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoTrustEvidenceWhenNoResolverIsWired()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.TrustedAuthorityEvidence,
            "Section 6.4.2: no evidence is surfaced when none is resolved, so the constraint has nothing to match.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">OpenID
    /// for Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below." The verifier's
    /// assessment drop-out decides that from the credential's own record — the disclosed claims, the
    /// unconditionally disclosed subset the rule does not govern, and the declared types the query's
    /// constraints are answered against — all reached through the one
    /// <see cref="Oid4VpDisclosureAssessmentContext.Credential"/> the parse produced.
    /// </summary>
    [TestMethod]
    public async Task DisclosureAssessmentSeamReadsTheVerifiedCredentialRecord()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        Oid4VpDisclosureAssessmentContext assessmentContext = new()
        {
            CredentialQuery = BuildNestedFamilyNameQuery(NestedSdJwtVcFixtures.Vct),
            Credential = parsed.Credential
        };

        Assert.AreSame(parsed.Credential, assessmentContext.Credential,
            "The seam is handed the one record the parse produced, not a reconstruction of it.");

        AssessVpDisclosureDelegate assess = AssessThroughTheSeamAsync;
        Oid4VpDisclosureAssessment assessment = await assess(
            assessmentContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(assessment.Satisfied,
            "The disclosed claims the record carries satisfy the credential query the presentation answered.");
        Assert.IsFalse(assessment.OverDisclosed,
            "Section 6.4: the credential released exactly the one selectively disclosable claim the query asked for.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified as a
    /// match to a Trusted Authorities Query if it matches with one of the provided values in one of the
    /// provided types." The assessment seam answers that constraint from
    /// <see cref="VpCredentialClaims.TrustedAuthorityEvidence"/> on the credential's record, so a
    /// presentation whose resolved evidence carries the named AuthorityKeyIdentifier matches.
    /// </summary>
    [TestMethod]
    public async Task TrustedAuthoritiesQueryMatchesThroughTheEvidenceOnTheCredentialRecord()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationWithTrustEvidenceAsync(
            vpToken,
            issuerKey,
            static (chain, issuerIdentifier, pool, cancellationToken) =>
                ValueTask.FromResult<TrustedAuthorityEvidence?>(ExampleAuthorityKeyIdentifierEvidence),
            TestContext.CancellationToken).ConfigureAwait(false);

        AssessVpDisclosureDelegate assess = AssessThroughTheSeamAsync;
        Oid4VpDisclosureAssessment assessment = await assess(
            new Oid4VpDisclosureAssessmentContext
            {
                CredentialQuery = BuildTrustedAuthorityConstrainedQuery(DcqlFixtures.AkiExampleValue),
                Credential = parsed.Credential
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(assessment.Satisfied,
            "Section 6.1.1: the credential's evidence carries the named AuthorityKeyIdentifier, so the query matches.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
    /// respective constraints expressed within credentials MUST NOT be returned, i.e., they are treated
    /// as if they would not exist in the Wallet." A record carrying no trust evidence cannot be shown to
    /// match a <c>trusted_authorities</c> constraint, so the assessment fails closed on the same
    /// presentation the wired case accepts.
    /// </summary>
    [TestMethod]
    public async Task TrustedAuthoritiesQueryFailsClosedWhenTheCredentialRecordCarriesNoEvidence()
    {
        (string vpToken, PublicKeyMemory issuerPublicKey) =
            await MintAndPresentNestedFamilyNameAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory issuerKey = issuerPublicKey;

        VpTokenParsed parsed = await VerifyPresentationAsync(
            vpToken, issuerKey, TestContext.CancellationToken).ConfigureAwait(false);

        AssessVpDisclosureDelegate assess = AssessThroughTheSeamAsync;
        Oid4VpDisclosureAssessment assessment = await assess(
            new Oid4VpDisclosureAssessmentContext
            {
                CredentialQuery = BuildTrustedAuthorityConstrainedQuery(DcqlFixtures.AkiExampleValue),
                Credential = parsed.Credential
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(assessment.Satisfied,
            "Section 6.4.2: a credential with no trust evidence cannot satisfy a trusted_authorities constraint.");
    }


    /// <summary>
    /// Mints the holder-bound nested credential, has the holder release exactly the Disclosure at
    /// <c>/employer/family_name</c>, and returns the wire presentation together with the issuer public
    /// key the trust framework is to resolve. The holder key material lives only for the presentation;
    /// the returned issuer key is the caller's to dispose.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The vp_token value and the issuer public key.</returns>
    private async ValueTask<(string VpToken, PublicKeyMemory IssuerPublicKey)> MintAndPresentNestedFamilyNameAsync(
        CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivateKey = holderKeys.PrivateKey;

        (string serializedSdJwt, PublicKeyMemory issuerPublicKey) = await NestedSdJwtVcFixtures.MintHolderBoundCredentialAsync(
            holderPublicKey, NestedSdJwtVcFixtures.Vct, cancellationToken).ConfigureAwait(false);

        string vpToken = await ProducePresentationAsync(
            serializedSdJwt,
            holderPrivateKey,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer(NestedSdJwtVcFixtures.NestedFamilyNamePointer) },
            cancellationToken).ConfigureAwait(false);

        return (vpToken, issuerPublicKey);
    }


    /// <summary>
    /// <see cref="VerifyPresentationAsync"/> with the OID4VP 1.0 Section 6.1.1 trust-evidence resolution
    /// wired — the seam a relying party composes its own X.509, Trusted List and federation arms behind.
    /// </summary>
    /// <param name="vpToken">The vp_token value the wallet produced.</param>
    /// <param name="issuerPublicKey">The issuer key the trust framework resolves.</param>
    /// <param name="resolveTrustedAuthorityEvidence">The evidence resolution to wire.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified presentation.</returns>
    private static async ValueTask<VpTokenParsed> VerifyPresentationWithTrustEvidenceAsync(
        string vpToken,
        PublicKeyMemory issuerPublicKey,
        ResolveTrustedAuthorityEvidenceDelegate resolveTrustedAuthorityEvidence,
        CancellationToken cancellationToken)
    {
        return await SdJwtVpTokenVerification.VerifyAsync(
            vpToken,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: _ => issuerPublicKey,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            cancellationToken: cancellationToken,
            resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence).ConfigureAwait(false);
    }


    /// <summary>
    /// <see cref="VerifyPresentationAsync"/> against a trust framework that knows no key for the
    /// credential's <c>iss</c>: the issuer signature stays unverified and no issuer key is published.
    /// </summary>
    /// <param name="vpToken">The vp_token value the wallet produced.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed presentation, its credential signature unverified.</returns>
    private static async ValueTask<VpTokenParsed> VerifyPresentationWithoutIssuerTrustAsync(
        string vpToken,
        CancellationToken cancellationToken)
    {
        return await SdJwtVpTokenVerification.VerifyAsync(
            vpToken,
            new CredentialQueryId(IdentityCredentialQueryId),
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag),
            computeHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(t, TestSetup.Base64UrlEncoder),
            resolveIssuerKey: static _ => null,
            computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            decoder: TestSetup.Base64UrlDecoder,
            encoder: TestSetup.Base64UrlEncoder,
            pool: Pool,
            saltReuseSeam: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The relying party's <see cref="AssessVpDisclosureDelegate"/> implementation, reading every fact it
    /// needs off <see cref="Oid4VpDisclosureAssessmentContext.Credential"/>: the disclosed path/value map
    /// and the declared types behind <see cref="DisclosedClaimsDcqlAdapter"/> for satisfaction, the
    /// resolved trust evidence for a <c>trusted_authorities</c> constraint, and the unconditionally
    /// disclosed subset so
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">
    /// Section 6.4</see>'s rule — which governs only what the holder chose to send — never counts a claim
    /// the credential could not withhold against it.
    /// </summary>
    /// <param name="context">The credential query and the verified credential's record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The satisfaction and over-disclosure verdict.</returns>
    private static ValueTask<Oid4VpDisclosureAssessment> AssessThroughTheSeamAsync(
        Oid4VpDisclosureAssessmentContext context,
        CancellationToken cancellationToken)
    {
        DcqlMetadataExtractor<IReadOnlyDictionary<CredentialPath, object?>> metadataExtractor =
            DisclosedClaimsDcqlAdapter.CreateMetadataExtractor(
                context.CredentialQuery.Format!,
                credentialType: context.Credential.CredentialType,
                additionalTypes: context.Credential.AdditionalTypes,
                trustedAuthorityEvidence: context.Credential.TrustedAuthorityEvidence);

        DcqlEvaluationResult evaluation = DcqlEvaluator.EvaluateSingle(
            context.CredentialQuery,
            context.Credential.Disclosed,
            metadataExtractor(context.Credential.Disclosed),
            DisclosedClaimsDcqlAdapter.ClaimExtractor);

        var selectivelyDisclosed = new HashSet<CredentialPath>(context.Credential.Disclosed.Keys);
        selectivelyDisclosed.ExceptWith(context.Credential.UnconditionallyDisclosed);

        return ValueTask.FromResult(new Oid4VpDisclosureAssessment
        {
            Satisfied = evaluation.Matches,
            OverDisclosed = selectivelyDisclosed.Count > (context.CredentialQuery.Claims?.Count ?? 0)
        });
    }


    /// <summary>
    /// <see cref="BuildNestedFamilyNameQuery"/> with an OID4VP 1.0 Section 6.1.1.1 <c>aki</c>
    /// trusted-authority constraint added: the credential's evidence must carry the named
    /// AuthorityKeyIdentifier.
    /// </summary>
    /// <param name="authorityKeyIdentifier">The base64url AuthorityKeyIdentifier the query pins.</param>
    /// <returns>A fresh credential query.</returns>
    private static CredentialQuery BuildTrustedAuthorityConstrainedQuery(string authorityKeyIdentifier) => new()
    {
        Id = IdentityCredentialQueryId,
        Format = DcqlCredentialFormats.SdJwt,
        Meta = new CredentialQueryMeta { VctValues = [NestedSdJwtVcFixtures.Vct] },
        TrustedAuthorities =
        [
            new TrustedAuthoritiesQuery
            {
                Type = DcqlTrustedAuthorityTypes.Aki,
                Values = [authorityKeyIdentifier]
            }
        ],
        Claims =
        [
            new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("employer", "family_name") }
        ]
    };
}
