using System.Buffers;
using System.Globalization;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The SD-CWT (<c>dc+sd-cwt</c>) credential format expressed as a
/// <see cref="FormatFixture"/> for the scheme × format matrix: it builds a host
/// wired with the <see cref="SdCwtVpVerificationSeams"/> the executor dispatches
/// <c>dc+sd-cwt</c> through, issues an SD-CWT (holder COSE_Key in <c>cnf</c>,
/// issuer key resolved out of band via the seams), and wires the presentation
/// drop-out that selects the minimal disclosure set and signs the Key Binding
/// Token. The single source of the SD-CWT flow setup shared by the matrix and
/// <see cref="Oid4VpSdCwtFlowIntegrationTests"/>.
/// </summary>
internal static class SdCwtVpFixture
{
    /// <summary>The issuer identifier the SD-CWT is issued under (its <c>iss</c> / CWT claim 1).</summary>
    public const string IssuerId = "https://issuer.example.com";

    /// <summary>The DCQL credential query identifier the SD-CWT presentation answers.</summary>
    public const string EmployeeCwtCredentialQueryId = "employee_cwt";

    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The position of the CWT <c>iss</c> claim (<see cref="WellKnownCwtClaimNames.Iss"/>) in the issuer-signed claims map.</summary>
    public static CredentialPath IssuerPath => CredentialPath.FromJsonPointer($"/{WellKnownCwtClaimNames.Iss}");

    /// <summary>The position of the CWT <c>vct</c> claim (<see cref="WellKnownCwtClaimNames.Vct"/>) in the issuer-signed claims map.</summary>
    public static CredentialPath CredentialTypePath => CredentialPath.FromJsonPointer($"/{WellKnownCwtClaimNames.Vct}");


    /// <summary>The SD-CWT matrix-format row: name plus the per-run <see cref="FormatRun"/> factory.</summary>
    public static FormatFixture Format => new("dc+sd-cwt", StartAsync);


    private static async ValueTask<FormatRun> StartAsync(FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        SdCwtVpVerificationSeams seams = BuildSeams(issuerKeys.PublicKey);
        TestHostShell app = new(tp, sdCwtSeams: seams);

        //The wallet holds the issued SD-CWT (holder COSE_Key in cnf); the holder
        //key matches. Neither leaves the wallet — only the wire JWE crosses.
        SdToken<ReadOnlyMemory<byte>> issued = await IssueSdCwtTokenAsync(
            tp, issuerKeys.PrivateKey, holderKeys.PublicKey, cancellationToken).ConfigureAwait(false);

        return new FormatRun
        {
            App = app,
            Query = BuildSdCwtPreparedQuery(),
            Produce = BuildSdCwtProduceDelegate(issued, holderKeys.PrivateKey),
            AssertClaims = AssertClaims,
            //The seams' ResolveIssuerKey returns issuerKeys.PublicKey directly, so it
            //must outlive verification; the holder key drives the KBT. The host owns
            //neither — both halves of both pairs are disposed here.
            Owned =
            [
                issued,
                issuerKeys.PublicKey, issuerKeys.PrivateKey,
                holderKeys.PublicKey, holderKeys.PrivateKey
            ]
        };
    }


    private static void AssertClaims(PresentationVerifiedState verified)
    {
        Assert.IsTrue(verified.Credentials.TryGetValue(new CredentialQueryId(EmployeeCwtCredentialQueryId),
            out VpCredentialClaims? credential),
            "Verified credentials must be keyed by the DCQL credential query id.");
        IReadOnlyDictionary<CredentialPath, string> claims = credential!.Extracted;
        Assert.AreEqual("Erika", claims[CredentialPath.FromJsonPointer(GivenNamePath)],
            "The disclosed given_name must round-trip through the full flow.");
        Assert.AreEqual("Mustermann", claims[CredentialPath.FromJsonPointer(FamilyNamePath)],
            "The disclosed family_name must round-trip through the full flow.");
        Assert.IsFalse(claims.ContainsKey(CredentialPath.FromJsonPointer(EmailPath)),
            "The withheld email claim must not appear in the verified set.");
    }


    public static PreparedDcqlQuery BuildSdCwtPreparedQuery()
    {
        var dcqlQuery = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = EmployeeCwtCredentialQueryId,
                    Format = DcqlCredentialFormats.SdCwt,
                    Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                    Claims =
                    [
                        ClaimsQuery.ForPath([ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]),
                        ClaimsQuery.ForPath([ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)])
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(dcqlQuery);
    }


    /// <summary>
    /// A typed query whose <c>vct_values</c> names a credential type the issued SD-CWT does not declare, so a
    /// holder releasing the queried claims still fails the DCQL type match (OID4VP 1.0 §6.1.1). The verifier
    /// refuses the presentation, exercising the <c>direct_post</c> refusal answered as RFC 6749 §4.1.2.1
    /// <c>invalid_request</c> (HTTP 400).
    /// </summary>
    public static PreparedDcqlQuery BuildSdCwtTypeMismatchPreparedQuery()
    {
        var dcqlQuery = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = EmployeeCwtCredentialQueryId,
                    Format = DcqlCredentialFormats.SdCwt,
                    Meta = new CredentialQueryMeta { VctValues = ["https://credentials.example.com/unmatched_type"] },
                    Claims =
                    [
                        ClaimsQuery.ForPath([ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]),
                        ClaimsQuery.ForPath([ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)])
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(dcqlQuery);
    }


    /// <summary>
    /// <see cref="BuildSdCwtPreparedQuery"/> with a DCQL <c>trusted_authorities</c> constraint
    /// (OID4VP 1.0 §6.1.1.3, type <c>openid_federation</c>) pinning the acceptable issuer
    /// entity identifiers — the credential's verified <c>iss</c> must be one of
    /// <paramref name="trustedIssuers"/>. Drives the verifier's fail-closed trusted_authorities
    /// enforcement for the SD-CWT format.
    /// </summary>
    public static PreparedDcqlQuery BuildSdCwtTrustedAuthoritiesPreparedQuery(params string[] trustedIssuers)
    {
        var dcqlQuery = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = EmployeeCwtCredentialQueryId,
                    Format = DcqlCredentialFormats.SdCwt,
                    Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                    TrustedAuthorities =
                    [
                        new TrustedAuthoritiesQuery
                        {
                            Type = DcqlTrustedAuthorityTypes.OpenIdFederation,
                            Values = trustedIssuers
                        }
                    ],
                    Claims =
                    [
                        ClaimsQuery.ForPath([ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]),
                        ClaimsQuery.ForPath([ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)])
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(dcqlQuery);
    }


    /// <summary>
    /// The presentation drop-out: runs the Core DCQL engine
    /// (<see cref="DcqlPathResolver"/> + <see cref="DisclosureComputation{TCredential}"/>)
    /// to pick the minimal disclosure set the query asks for, then signs the KBT
    /// (aud = client_id, cnonce = nonce) via <see cref="KbCwtIssuance.IssueAsync"/>
    /// and base64url-packages it. The CBOR/COSE composition lives here in the
    /// application layer; the OAuth library only invokes the delegate.
    /// </summary>
    public static ProduceVpTokenPresentationsDelegate BuildSdCwtProduceDelegate(
        SdToken<ReadOnlyMemory<byte>> storedCredential, PrivateKeyMemory holderKey)
    {
        return async (context, cancellationToken) =>
        {
            Dictionary<string, string> presentations = new(StringComparer.Ordinal);

            foreach(CredentialQuery query in context.Request.DcqlQuery!.Credentials!)
            {
                string queryId = query.Id
                    ?? throw new InvalidOperationException("DCQL credential query is missing the 'id' field.");

                //The one engine path every flow runs: DcqlDisclosure drives
                //DcqlEvaluator.EvaluateSingle -> DisclosureComputation.ComputeAsync over the
                //parsed SD-CWT token via SdTokenDcqlAdapter. SD-CWT has no always-visible
                //mandatory paths, so the lattice bottom is empty.
                DisclosureStrategyGraph<SdToken<ReadOnlyMemory<byte>>> graph = (await DcqlDisclosure.ComputeStrategyAsync(query, storedCredential, SdTokenDcqlAdapter.CreateMetadataExtractor<ReadOnlyMemory<byte>>(DcqlCredentialFormats.SdCwt), SdTokenDcqlAdapter.ClaimExtractor<ReadOnlyMemory<byte>>, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

                IReadOnlySet<CredentialPath> selectedPaths = graph.Decisions.Count > 0
                    ? graph.Decisions[0].SelectedPaths
                    : new HashSet<CredentialPath>();

                using SdToken<ReadOnlyMemory<byte>> selected =
                    storedCredential.SelectDisclosures(selectedPaths, Pool).Token;

                using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
                    selected, holderKey,
                    verifierAud: context.Request.ClientId,
                    verifierCnonce: context.Request.Nonce,
                    iat: context.Now,
                    SdKbtIssuance.BuildProtectedHeader,
                    SdKbtIssuance.BuildPayload,
                    CoseSerialization.BuildSigStructure,
                    CoseSerialization.SerializeCoseSign1,
                    context.MemoryPool,
                    cancellationToken).ConfigureAwait(false);

                presentations[queryId] = context.Base64UrlEncoder(kbt.AsReadOnlyMemory().Span);
            }

            return new Oid4VpPresentationSet { PresentationsByQueryId = presentations };
        };
    }


    /// <summary>
    /// Wallet side without the flow around it: selects the two claims
    /// <see cref="BuildSdCwtPreparedQuery"/> asks for, signs the SD-CWT Key Binding Token over that
    /// selection, and base64url-packages it as the <c>vp_token</c> value a presentation carries — the
    /// recipe a caller verifying at the parse boundary reuses, beside the engine-driven
    /// <see cref="BuildSdCwtProduceDelegate"/> the full flows run.
    /// </summary>
    /// <param name="storedCredential">The issued SD-CWT the wallet holds.</param>
    /// <param name="holderKey">The holder's signing key, matching the credential's <c>cnf</c> COSE_Key.</param>
    /// <param name="verifierAud">The Verifier identifier bound into the Key Binding Token's <c>aud</c>.</param>
    /// <param name="verifierCnonce">The Verifier's nonce bound into the Key Binding Token's <c>cnonce</c>.</param>
    /// <param name="iat">The instant the Key Binding Token is issued at.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base64url <c>vp_token</c> value.</returns>
    public static async ValueTask<string> ProduceVpTokenValueAsync(
        SdToken<ReadOnlyMemory<byte>> storedCredential,
        PrivateKeyMemory holderKey,
        string verifierAud,
        string verifierCnonce,
        DateTimeOffset iat,
        CancellationToken cancellationToken)
    {
        var selectedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath)
        };

        using SdToken<ReadOnlyMemory<byte>> selected =
            storedCredential.SelectDisclosures(selectedPaths, Pool).Token;

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            selected, holderKey,
            verifierAud: verifierAud,
            verifierCnonce: verifierCnonce,
            iat: iat,
            SdKbtIssuance.BuildProtectedHeader,
            SdKbtIssuance.BuildPayload,
            CoseSerialization.BuildSigStructure,
            CoseSerialization.SerializeCoseSign1,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return TestSetup.Base64UrlEncoder(kbt.AsReadOnlyMemory().Span);
    }


    /// <summary>
    /// Builds the <see cref="SdCwtVpVerificationSeams"/> wired to the concrete
    /// <c>Verifiable.Cbor.Sd</c> implementations, with the issuer key resolved out of band to
    /// <paramref name="issuerKey"/> — the seam set <see cref="StartAsync"/>, the parse-boundary
    /// tests, and a caller composing its own <see cref="TestHostShell"/> registration all reuse.
    /// </summary>
    /// <param name="issuerKey">The issuer public key <see cref="SdCwtVpVerificationSeams.ResolveIssuerKey"/> resolves to.</param>
    /// <returns>The wired seam set.</returns>
    public static SdCwtVpVerificationSeams BuildSeams(PublicKeyMemory issuerKey) =>
        new()
        {
            ParseCoseSign1 = CoseSerialization.ParseCoseSign1,
            ExtractKcwt = SdCwtVpParsing.ExtractKcwt,
            ParseSdCwt = bytes => SdCwtVpParsing.ParseEmbeddedSdCwt(bytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder),
            ExtractHolderKey = SdCwtVpParsing.ExtractHolderKey,
            ReadKbtClaims = SdCwtVpParsing.ReadKbtClaims,
            ExtractIssuer = SdCwtVpParsing.ExtractIssuer,
            ExtractCredentialType = SdCwtVpParsing.ExtractCredentialType,
            ExtractStatus = SdCwtVpParsing.ExtractStatus,
            ResolveIssuerKey = _ => issuerKey,
            VerifyCredential = async (token, key, pool, ct) =>
            {
                SdVerificationResult result = await token.VerifyAsync(
                    key, pool,
                    CoseSerialization.ParseCoseSign1, SdCwtPathExtraction.ExtractPaths,
                    CoseSerialization.BuildSigStructure, TestSetup.Base64UrlEncoder,
                    cancellationToken: ct).ConfigureAwait(false);

                return result.IsValid;
            },
            BuildSigStructure = CoseSerialization.BuildSigStructure
        };


    /// <summary>
    /// Issues an SD-CWT carrying <see cref="IssuerId"/>, the shared <c>given_name</c>/
    /// <c>family_name</c>/<c>email</c> claims and the holder's <c>cnf</c> COSE_Key, then rebuilds
    /// and re-parses the full wire form so the returned token carries real
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/> evidence — the recipe both
    /// <see cref="StartAsync"/> and a caller building its own presentation reuse.
    /// </summary>
    /// <param name="tp">The clock the <c>iat</c> claim is read from.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="holderPublic">The holder's public key, embedded in the <c>cnf</c> claim.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued, re-parsed token; the caller owns and disposes it.</returns>
    public static ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        FakeTimeProvider tp, PrivateKeyMemory privateKey, PublicKeyMemory holderPublic, CancellationToken cancellationToken) =>
        IssueSdCwtTokenAsync(tp, privateKey, holderPublic, status: null, cancellationToken);


    /// <summary>
    /// <see cref="IssueSdCwtTokenAsync(FakeTimeProvider, PrivateKeyMemory, PublicKeyMemory, CancellationToken)"/>
    /// with a Token Status List Status structure placed in the issuer-signed claims under CWT claim key
    /// <see cref="StatusListCborConstants.Status"/>, the placement
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token
    /// Status List, Section 6.3</see> gives a CWT Referenced Token: "If the Referenced Token is a CWT, the
    /// following content applies to the CWT Claims Set: 65535 (status): REQUIRED. The status claim contains
    /// the Status CBOR structure as described in this section." The structure rides the always-visible part
    /// of the payload, so it survives disclosure selection and reaches the verifier on every presentation.
    /// </summary>
    /// <param name="tp">The clock the <c>iat</c> claim is read from.</param>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="holderPublic">The holder's public key, embedded in the <c>cnf</c> claim.</param>
    /// <param name="status">
    /// The Status structure the issuer states, assembled by the <c>SdCwtWireFixtures.BuildStatusWith*</c>
    /// wire helpers, or <see langword="null"/> for a credential whose issuer published no status at all.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued, re-parsed token; the caller owns and disposes it.</returns>
    public static async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        FakeTimeProvider tp,
        PrivateKeyMemory privateKey,
        PublicKeyMemory holderPublic,
        IReadOnlyDictionary<string, object>? status,
        CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = IssuerId,
            [WellKnownCwtClaimNames.Iat] = tp.GetUtcNow().ToUnixTimeSeconds(),
            [WellKnownCwtClaimNames.Vct] = EudiPid.SdJwtVct,
            [WellKnownCwtClaimNames.Cnf] = SdCwtWireFixtures.BuildCnfWithHolderKey(holderPublic, CnfCoseKeyMember),
            [ClaimKeyGivenName] = "Erika",
            [ClaimKeyFamilyName] = "Mustermann",
            [ClaimKeyEmail] = "erika@example.de"
        };

        if(status is not null)
        {
            claims[StatusListCborConstants.Status] = status;
        }

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath),
            CredentialPath.FromJsonPointer(EmailPath)
        };

        SdToken<ReadOnlyMemory<byte>> issued = await claims.IssueSdCwtTokenAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths,
            TestSalts.DefaultGenerator(),
            privateKey, IssuerKeyId, Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Issuance carries no parsed DisclosurePaths/IssuerSignedClaims (SdToken's plain
        //constructor defaults both to empty), and issued.IssuerSigned alone carries no sd_claims
        //(the unprotected header entry lives beside the token, not embedded in it, until
        //serialized as a full SdCwtMessage). Rebuilding the full wire form and parsing it back —
        //what a wallet does once it stores an issued credential — is what gives the DCQL adapter
        //(both the verifier's and the wallet's own SdTokenDcqlAdapter selection step) real
        //evidence to match against.
        using(issued)
        {
            SdCwtMessage bare = SdCwtSerializer.Parse(issued.IssuerSigned, TestSalts.TestSaltTag, Pool);
            var full = new SdCwtMessage(bare.Payload, bare.ProtectedHeader, bare.Signature, issued.Disclosures);
            byte[] wireBytes = SdCwtSerializer.Serialize(full);

            return SdCwtSerializer.ParseToken(wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);
        }
    }
}
