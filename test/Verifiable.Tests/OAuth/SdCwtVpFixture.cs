using System.Buffers;
using System.Formats.Cbor;
using System.Globalization;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
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

    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string CredentialQueryId = "employee_cwt";

    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


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
        Assert.IsTrue(verified.Claims.TryGetValue(CredentialQueryId,
            out IReadOnlyDictionary<string, string>? claims),
            "Verified claims must be keyed by the DCQL credential query id.");
        Assert.AreEqual("Erika", claims![ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)],
            "The disclosed given_name must round-trip through the full flow.");
        Assert.AreEqual("Mustermann", claims[ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)],
            "The disclosed family_name must round-trip through the full flow.");
        Assert.IsFalse(claims.ContainsKey(ClaimKeyEmail.ToString(CultureInfo.InvariantCulture)),
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
                    Id = CredentialQueryId,
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
                    Id = CredentialQueryId,
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
                DisclosureStrategyGraph<SdToken<ReadOnlyMemory<byte>>> graph = (await DcqlDisclosure.ComputeStrategyAsync(
                    query,
                    storedCredential,
                    SdTokenDcqlAdapter.CreateMetadataExtractor<ReadOnlyMemory<byte>>(DcqlCredentialFormats.SdCwt),
                    SdTokenDcqlAdapter.ClaimExtractor<ReadOnlyMemory<byte>>,
                    cancellationToken: cancellationToken).ConfigureAwait(false)).Graph;

                HashSet<string> selectedClaimNames = graph.Decisions[0].SelectedPaths
                    .Select(path => path.ToString().TrimStart('/'))
                    .ToHashSet(StringComparer.Ordinal);

                using SdToken<ReadOnlyMemory<byte>> selected = storedCredential.SelectDisclosures(
                    disclosure => disclosure.ClaimName is not null
                        && selectedClaimNames.Contains(disclosure.ClaimName),
                    Pool);

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


    private static SdCwtVpVerificationSeams BuildSeams(PublicKeyMemory issuerKey) =>
        new()
        {
            ParseCoseSign1 = CoseSerialization.ParseCoseSign1,
            ExtractKcwt = SdCwtVpParsing.ExtractKcwt,
            ParseSdCwt = bytes => SdCwtVpParsing.ParseEmbeddedSdCwt(bytes, TestSalts.TestSaltTag, Pool),
            ExtractHolderKey = SdCwtVpParsing.ExtractHolderKey,
            ReadKbtClaims = SdCwtVpParsing.ReadKbtClaims,
            ExtractIssuer = SdCwtVpParsing.ExtractIssuer,
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


    private static async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        FakeTimeProvider tp, PrivateKeyMemory privateKey, PublicKeyMemory holderPublic, CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = IssuerId,
            [WellKnownCwtClaimNames.Iat] = tp.GetUtcNow().ToUnixTimeSeconds(),
            [WellKnownCwtClaimNames.Cnf] = BuildCnfWithHolderKey(holderPublic),
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
            SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths,
            TestSalts.DefaultGenerator(),
            privateKey, IssuerKeyId, Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    private static Dictionary<int, object> BuildCnfWithHolderKey(PublicKeyMemory holderPublic)
    {
        ReadOnlySpan<byte> compressed = holderPublic.AsReadOnlySpan();
        byte[] x = compressed[1..].ToArray();
        byte[] y = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        var coseKey = new Dictionary<int, object>
        {
            [1] = 2,   //kty = EC2.
            [-1] = 1,  //crv = P-256.
            [-2] = x,  //x coordinate.
            [-3] = y   //y coordinate.
        };

        return new Dictionary<int, object> { [CnfCoseKeyMember] = coseKey };
    }


    private static ReadOnlySpan<byte> SerializeCwtClaimMap(Dictionary<int, object> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CborValueConverter.WriteValue(writer, claims);

        return writer.Encode();
    }
}
