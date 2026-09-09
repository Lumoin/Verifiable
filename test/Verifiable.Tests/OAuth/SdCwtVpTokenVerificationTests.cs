using System.Buffers;
using System.Buffers.Text;
using System.Globalization;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled tests for <see cref="SdCwtVpTokenVerification"/> — the OID4VP
/// server-side SD-CWT VP-token verifier. A toy wallet issues an SD-CWT (with the
/// holder COSE_Key in <c>cnf</c>), selects disclosures, and signs an SD-CWT Key
/// Binding Token; the verifier reconstructs everything strictly from the base64url
/// vp_token value (no shared in-memory wallet objects, salts, or holder key) and runs
/// the full holder-signature + issuer-signature + digest-binding verification through
/// the OAuth-layer composition, producing a <see cref="VpTokenParsed"/>.
/// </summary>
[TestClass]
internal sealed class SdCwtVpTokenVerificationTests
{
    public required TestContext TestContext { get; set; }

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string EmployeeCwtCredentialQueryId = "employee_cwt";
    private const string VerifierAud = "https://verifier.example.com/response";
    private const string Cnonce = "n-vptoken-cwt-01";

    /// <summary>The Status List Token URI the status-bearing credential of this class references.</summary>
    private const string StatusListTokenUri = "https://issuer.example.com/statuslists/1";

    /// <summary>The Status List index the status-bearing credential of this class references.</summary>
    private const int StatusCredentialIndex = 9;

    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";

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


    [TestMethod]
    public async Task VerifiesHolderAndIssuerAndExtractsClaimsFromWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await SdCwtVpTokenVerification.VerifyAsync(
            vpTokenValue, new CredentialQueryId(EmployeeCwtCredentialQueryId), SdCwtVpFixture.BuildSeams(issuerPublic),
            TestSetup.Base64UrlDecoder, saltReuseSeam: null, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.KbJwtSignatureValid, "The KBT holder signature must verify.");
        Assert.IsTrue(parsed.CredentialSignatureValid,
            "The embedded SD-CWT issuer signature and digest binding must hold.");
        Assert.AreEqual(VerifierAud, parsed.KbJwtAud, "The KBT aud must surface as the key-binding aud.");
        Assert.AreEqual(Cnonce, parsed.KbJwtNonce, "The KBT cnonce must surface as the key-binding nonce.");
        Assert.AreEqual(
            TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            parsed.KbJwtIat?.ToUnixTimeSeconds(),
            "The KBT iat must surface as the key-binding iat.");

        //SD-CWT carries no sd_hash and no SessionTranscript; those N/A axes are not-a-failure.
        Assert.IsTrue(parsed.SdHashValid, "sd_hash is N/A for SD-CWT and must not register as a failure.");
        Assert.IsTrue(parsed.SessionTranscriptValid, "SessionTranscript is N/A for SD-CWT and must not register as a failure.");

        IReadOnlyDictionary<CredentialPath, string> claims = parsed.Credential.Extracted;
        Assert.AreEqual("Erika", claims[CredentialPath.FromJsonPointer(GivenNamePath)]);
        Assert.AreEqual("Mustermann", claims[CredentialPath.FromJsonPointer(FamilyNamePath)]);
        Assert.IsFalse(claims.ContainsKey(CredentialPath.FromJsonPointer(EmailPath)),
            "The withheld email claim must not appear in the disclosed set.");
    }


    [TestMethod]
    public async Task UntrustedIssuerKeyFailsCredentialSignatureOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        issuerKeys.PublicKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongIssuerPublic = wrongKeys.PublicKey;
        using PrivateKeyMemory wrongIssuerPrivate = wrongKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        //The trust framework resolves a key that did not sign the credential — the embedded
        //SD-CWT issuer signature fails, but the holder signature is independent and holds.
        VpTokenParsed parsed = await SdCwtVpTokenVerification.VerifyAsync(
            vpTokenValue, new CredentialQueryId(EmployeeCwtCredentialQueryId), SdCwtVpFixture.BuildSeams(wrongIssuerPublic),
            TestSetup.Base64UrlDecoder, saltReuseSeam: null, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.KbJwtSignatureValid,
            "The holder signature is independent of the issuer key and must still verify.");
        Assert.IsFalse(parsed.CredentialSignatureValid,
            "An issuer key that did not sign the credential must fail the credential signature.");
    }


    /// <summary>
    /// Wallet side: issue an SD-CWT (cnf = holder COSE_Key), select given_name +
    /// family_name, sign the KBT, and base64url-encode it as the vp_token value.
    /// </summary>
    private async ValueTask<string> ProduceVpTokenAsync(
        PrivateKeyMemory issuerPrivate,
        PublicKeyMemory holderPublic,
        PrivateKeyMemory holderPrivate)
    {
        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, holderPublic, TestContext.CancellationToken).ConfigureAwait(false);

        return await PresentGivenAndFamilyAsync(issuedToken, holderPrivate).ConfigureAwait(false);
    }


    /// <summary>
    /// Wallet side, over an already-issued credential: select <c>given_name</c> + <c>family_name</c>,
    /// sign the Key Binding Token, and base64url-encode it as the vp_token value.
    /// </summary>
    /// <param name="issuedToken">The stored credential the holder presents from.</param>
    /// <param name="holderPrivate">The holder key whose public half rides in <c>cnf</c>.</param>
    /// <returns>The vp_token value.</returns>
    private async ValueTask<string> PresentGivenAndFamilyAsync(
        SdToken<ReadOnlyMemory<byte>> issuedToken,
        PrivateKeyMemory holderPrivate)
    {
        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: Cnonce,
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return TestSetup.Base64UrlEncoder(kbt.AsReadOnlyMemory().Span);
    }


    private async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        PrivateKeyMemory privateKey, PublicKeyMemory holderPublic, CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = IssuerId,
            [WellKnownCwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            [WellKnownCwtClaimNames.Cnf] = SdCwtWireFixtures.BuildCnfWithHolderKey(holderPublic, CnfCoseKeyMember),
            [ClaimKeyGivenName] = "Erika",
            [ClaimKeyFamilyName] = "Mustermann",
            [ClaimKeyEmail] = "erika@example.de"
        };

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath),
            CredentialPath.FromJsonPointer(EmailPath)
        };

        return await claims.IssueSdCwtTokenAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths,
            TestSalts.DefaultGenerator(),
            privateKey, IssuerKeyId, Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    private static SdToken<ReadOnlyMemory<byte>> SelectGivenAndFamily(SdToken<ReadOnlyMemory<byte>> issuedToken)
    {
        HashSet<string> selected = new(StringComparer.Ordinal)
        {
            ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture),
            ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)
        };

        return issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selected.Contains(d.ClaimName), Pool);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID
    /// for Verifiable Presentations 1.0, Section 8.1</see>: "vp_token: REQUIRED. This is a JSON-encoded
    /// object containing entries where the key is the id value used for a Credential Query in the DCQL
    /// query and the value is an array of one or more Presentations that match the respective Credential
    /// Query." The verified presentation names the very identifier the wire keyed it by.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationIsKeyedByTheCredentialQueryItAnswered()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        Assert.AreEqual(new CredentialQueryId(EmployeeCwtCredentialQueryId), parsed.CredentialQueryId,
            "Section 8.1: the presentation is keyed by the Credential Query id it answered.");
        Assert.AreEqual(EmployeeCwtCredentialQueryId, parsed.CredentialQueryId.Value,
            "The identifier's value is the same string the DCQL credential query carries.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4">OpenID
    /// for Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below." The rule reaches
    /// only the Disclosures the holder chose; the claims
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see> says "MUST NOT be included in the Disclosures, i.e., cannot be
    /// selectively disclosed" — <c>iss</c> and <c>vct</c> among them — reach the Verifier regardless, so
    /// the verified presentation reports the two apart.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationSeparatesTheAlwaysDisclosedClaimsFromTheSelectedOnes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        CredentialPath givenNamePath = CredentialPath.FromJsonPointer(GivenNamePath);
        CredentialPath familyNamePath = CredentialPath.FromJsonPointer(FamilyNamePath);
        CredentialPath issuerPath = SdCwtVpFixture.IssuerPath;
        CredentialPath credentialTypePath = SdCwtVpFixture.CredentialTypePath;

        Assert.AreEqual("Erika", parsed.Credential.Disclosed[givenNamePath],
            "Section 6.4: the selected given_name Disclosure surfaces at its own position.");
        Assert.AreEqual("Mustermann", parsed.Credential.Disclosed[familyNamePath],
            "Section 6.4: the selected family_name Disclosure surfaces at its own position.");
        Assert.IsFalse(parsed.Credential.Disclosed.ContainsKey(CredentialPath.FromJsonPointer(EmailPath)),
            "Section 6.4 MUST NOT: the withheld email Disclosure was not selected and must not be sent.");

        Assert.Contains(issuerPath, parsed.Credential.UnconditionallyDisclosed,
            "Section 2.2.2.3: iss cannot be selectively disclosed, so it is reported as unconditionally disclosed.");
        Assert.Contains(credentialTypePath, parsed.Credential.UnconditionallyDisclosed,
            "Section 2.2.2.3: vct cannot be selectively disclosed, so it is reported as unconditionally disclosed.");
        Assert.DoesNotContain(givenNamePath, parsed.Credential.UnconditionallyDisclosed,
            "Section 6.4: a claim the holder chose to release is a selected Disclosure, never an unconditional one.");
        Assert.DoesNotContain(familyNamePath, parsed.Credential.UnconditionallyDisclosed,
            "Section 6.4: a claim the holder chose to release is a selected Disclosure, never an unconditional one.");

        Assert.AreEqual(SdCwtVpFixture.IssuerId, parsed.Credential.Extracted[issuerPath],
            "The string projection spans everything the presentation carries, unconditional claims included.");

        foreach(CredentialPath unconditional in parsed.Credential.UnconditionallyDisclosed)
        {
            Assert.IsTrue(parsed.Credential.Disclosed.ContainsKey(unconditional),
                "Every unconditionally disclosed claim is part of the structure a query is resolved over.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "vct: REQUIRED. The type of the Verifiable Digital Credential
    /// ... as defined in Section 2.2.2.1" and "iss: OPTIONAL. As defined in Section 4.1.1 of [RFC7519]
    /// this claim explicitly indicates the Issuer of the Verifiable Digital Credential when it is not
    /// conveyed by other means". Both are the evidence a DCQL type or trusted-authority constraint is
    /// answered against, so the verified presentation reports them; an SD-CWT declares no additional
    /// types, its <c>aka_vcts</c> counterpart having no CWT claim key.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheCredentialTypeAndIssuer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        Assert.AreEqual(EudiPid.SdJwtVct, parsed.Credential.CredentialType,
            "Section 2.2.2.3: the credential's vct is the type evidence the verifier surfaces.");
        Assert.AreEqual(SdCwtVpFixture.IssuerId, parsed.Credential.Issuer,
            "Section 2.2.2.3: iss is the issuer evidence the verifier surfaces.");
        Assert.IsEmpty(parsed.Credential.AdditionalTypes,
            "An SD-CWT declares no additional types, so none are surfaced.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check for
    /// the existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens and
    /// Section 6.3 for COSE-based Referenced Tokens." Existence is what is checked first, so an SD-CWT
    /// whose issuer stated no status at all is reported as carrying none rather than as carrying one that
    /// cannot be read.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoStatusClaimWhenTheCredentialStatesNone()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.Status,
            "Section 8.3 step 1: a credential carrying no status claim is reported as having none.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see>: "If the Issuer of the Referenced Token is the same entity
    /// as the Status Issuer, then the same key that is embedded into the Referenced Token may be used for
    /// the Status List Token." Reaching that recommendation needs the key the Referenced Token's own
    /// issuer signature verified under, so the verified presentation carries it — the very key the seams'
    /// trust framework answered with, byte for byte.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesTheIssuerKeyTheCredentialSignatureVerifiedUnder()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        Assert.IsTrue(parsed.CredentialSignatureValid,
            "The credential's issuer signature must verify before its key is published.");
        Assert.IsNotNull(parsed.CredentialIssuerKey,
            "Section 11.3: the key the Referenced Token verified under must be reachable from the presentation.");
        Assert.IsTrue(
            parsed.CredentialIssuerKey.AsReadOnlySpan().SequenceEqual(issuerPublic.AsReadOnlySpan()),
            "Section 11.3: the published key must be the key the trust framework resolved, byte for byte.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">
    /// Token Status List, Section 11.3</see> makes the same-key recommendation conditional on the
    /// Referenced Token's own issuer key being known. Seams whose trust framework resolves no key for the
    /// credential's <c>iss</c> leave the issuer signature unverified, and nothing is published as that
    /// credential's issuer key — a composition over it fails closed rather than borrowing a key that
    /// verified nothing.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoIssuerKeyWhenTheTrustFrameworkResolvesNone()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerPublic) with
        {
            ResolveIssuerKey = static _ => null
        };

        VpTokenParsed parsed = await VerifyAsync(vpTokenValue, seams).ConfigureAwait(false);

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
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        string? issuerSeenByTheResolver = null;
        SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerPublic) with
        {
            ResolveTrustedAuthorityEvidence = (chain, issuerIdentifier, pool, cancellationToken) =>
            {
                issuerSeenByTheResolver = issuerIdentifier;

                return ValueTask.FromResult<TrustedAuthorityEvidence?>(ExampleAuthorityKeyIdentifierEvidence);
            }
        };

        VpTokenParsed parsed = await VerifyAsync(vpTokenValue, seams).ConfigureAwait(false);

        Assert.AreEqual(SdCwtVpFixture.IssuerId, issuerSeenByTheResolver,
            "Section 6.1.1: the evidence is resolved for the credential's own verified issuer.");
        Assert.AreSame(ExampleAuthorityKeyIdentifierEvidence, parsed.Credential.TrustedAuthorityEvidence,
            "Section 6.1.1: the resolved evidence is what a trusted_authorities constraint is matched against.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
    /// respective constraints expressed within credentials MUST NOT be returned, i.e., they are treated
    /// as if they would not exist in the Wallet." Seams that wire no trust-evidence resolution surface no
    /// evidence at all, which is what makes a <c>trusted_authorities</c> constraint fail closed rather
    /// than be skipped.
    /// </summary>
    [TestMethod]
    public async Task ParsedPresentationCarriesNoTrustEvidenceWhenNoResolverIsWired()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        string vpTokenValue = await ProduceTypedVpTokenAsync(
            issuerPrivate, holderPublic, holderPrivate).ConfigureAwait(false);

        VpTokenParsed parsed = await VerifyAsync(
            vpTokenValue, SdCwtVpFixture.BuildSeams(issuerPublic)).ConfigureAwait(false);

        Assert.IsNull(parsed.Credential.TrustedAuthorityEvidence,
            "Section 6.4.2: no evidence is surfaced when none is resolved, so the constraint has nothing to match.");
    }


    /// <summary>
    /// Wallet side for the typed credential: issues the shared SD-CWT PID
    /// (<see cref="SdCwtVpFixture.IssueSdCwtTokenAsync"/> — <c>iss</c>, <c>vct</c>, the holder's
    /// <c>cnf</c> COSE_Key and the three business claims), then selects <c>given_name</c> +
    /// <c>family_name</c> and signs the Key Binding Token over them.
    /// </summary>
    /// <param name="issuerPrivate">The issuer's signing key.</param>
    /// <param name="holderPublic">The holder key carried in <c>cnf</c>.</param>
    /// <param name="holderPrivate">The holder key the Key Binding Token is signed with.</param>
    /// <returns>The vp_token value.</returns>
    private async ValueTask<string> ProduceTypedVpTokenAsync(
        PrivateKeyMemory issuerPrivate,
        PublicKeyMemory holderPublic,
        PrivateKeyMemory holderPrivate)
    {
        using SdToken<ReadOnlyMemory<byte>> issuedToken = await SdCwtVpFixture.IssueSdCwtTokenAsync(
            TimeProvider, issuerPrivate, holderPublic, TestContext.CancellationToken).ConfigureAwait(false);

        return await PresentGivenAndFamilyAsync(issuedToken, holderPrivate).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1 is answered off the embedded SD-CWT the Key Binding
    /// verification already parsed, and Section 11.3's same-key recommendation off the issuer key that
    /// same verification already resolved and checked the credential signature under. Both therefore
    /// reach the seat as the Key Binding result's own members: what the seat publishes is what that
    /// verification held, not a second reading of the same bytes.
    /// </summary>
    [TestMethod]
    public async Task TheSeatPublishesTheStatusAndIssuerKeyTheKeyBindingVerificationHeld()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await SdCwtVpFixture.IssueSdCwtTokenAsync(
            TimeProvider,
            issuerPrivate,
            holderPublic,
            SdCwtWireFixtures.BuildStatusWithStatusList(StatusCredentialIndex, StatusListTokenUri),
            TestContext.CancellationToken).ConfigureAwait(false);

        string vpTokenValue = await PresentGivenAndFamilyAsync(issuedToken, holderPrivate).ConfigureAwait(false);

        SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerPublic);
        VpTokenParsed parsed = await VerifyAsync(vpTokenValue, seams).ConfigureAwait(false);

        using IMemoryOwner<byte> keyBindingTokenBytes = TestSetup.Base64UrlDecoder(vpTokenValue, Pool);
        SdCwtKbtVerificationResult result = await KbCwtVerification.VerifyAsync(
            keyBindingTokenBytes.Memory,
            seams.ParseCoseSign1,
            seams.ExtractKcwt,
            seams.ParseSdCwt,
            seams.ExtractHolderKey,
            seams.ReadKbtClaims,
            seams.ExtractIssuer,
            seams.ExtractCredentialType,
            seams.ExtractStatus,
            seams.ResolveIssuerKey,
            seams.VerifyCredential,
            seams.BuildSigStructure,
            saltReuseSeam: null,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.Status,
            "Section 8.3 step 1: the Key Binding verification reads the status claim off the embedded token it parsed.");
        Assert.AreEqual(result.Status, parsed.Credential.Status,
            "The seat publishes the status claim that verification decoded, not one of its own.");

        Assert.IsNotNull(result.IssuerVerificationKey,
            "Section 11.3: the key the credential signature verified under is what the verification held.");
        Assert.IsNotNull(parsed.CredentialIssuerKey,
            "Section 11.3: the seat publishes that key for the status-list key resolution to reach.");
        Assert.IsTrue(
            result.IssuerVerificationKey.AsReadOnlySpan().SequenceEqual(parsed.CredentialIssuerKey.AsReadOnlySpan()),
            "The published key is the key the verification resolved, byte for byte.");
    }


    /// <summary>
    /// Verifier side: runs the OID4VP SD-CWT VP-token verification over the wire value with
    /// <paramref name="seams"/>, under the credential query identifier this class presents against.
    /// </summary>
    /// <param name="vpTokenValue">The vp_token value the wallet produced.</param>
    /// <param name="seams">The CBOR/COSE and trust seams the verifier is wired with.</param>
    /// <returns>The parsed and crypto-verified presentation.</returns>
    private async ValueTask<VpTokenParsed> VerifyAsync(string vpTokenValue, SdCwtVpVerificationSeams seams)
    {
        return await SdCwtVpTokenVerification.VerifyAsync(
            vpTokenValue,
            new CredentialQueryId(EmployeeCwtCredentialQueryId),
            seams,
            TestSetup.Base64UrlDecoder,
            saltReuseSeam: null,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
