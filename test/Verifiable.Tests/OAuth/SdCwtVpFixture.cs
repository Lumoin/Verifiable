using Lumoin.Veritas.Cbor;
using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Globalization;
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
        IReadOnlyDictionary<CredentialPath, string> claims = credential.Extracted;
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
    public static ValueTask<string> ProduceVpTokenValueAsync(
        SdToken<ReadOnlyMemory<byte>> storedCredential,
        PrivateKeyMemory holderKey,
        string verifierAud,
        string verifierCnonce,
        DateTimeOffset iat,
        CancellationToken cancellationToken) =>
        ProduceVpTokenValueAsync(
            storedCredential, holderKey, verifierAud, verifierCnonce, iat,
            SdKbtIssuance.BuildProtectedHeader, SdKbtIssuance.BuildPayload, CoseSerialization.SerializeCoseSign1, cancellationToken);


    /// <summary>
    /// <see cref="ProduceVpTokenValueAsync(SdToken{ReadOnlyMemory{byte}}, PrivateKeyMemory, string, string, DateTimeOffset, CancellationToken)"/>
    /// with the Key Binding Token's protected header and payload built by the supplied builders and its wire form
    /// written by the supplied serializer, so a caller can put an exact wire shape of either in front of the Verifier
    /// while the holder signature over it stays genuine.
    /// </summary>
    /// <param name="storedCredential">The issued SD-CWT the wallet holds.</param>
    /// <param name="holderKey">The holder's signing key, matching the credential's <c>cnf</c> COSE_Key.</param>
    /// <param name="verifierAud">The Verifier identifier bound into the Key Binding Token's <c>aud</c>.</param>
    /// <param name="verifierCnonce">The Verifier's nonce bound into the Key Binding Token's <c>cnonce</c>.</param>
    /// <param name="iat">The instant the Key Binding Token is issued at.</param>
    /// <param name="buildProtectedHeader">Builds the Key Binding Token's protected header.</param>
    /// <param name="buildPayload">Builds the Key Binding Token's payload.</param>
    /// <param name="serializeCoseSign1">Writes the signed Key Binding Token's wire form.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base64url <c>vp_token</c> value.</returns>
    public static async ValueTask<string> ProduceVpTokenValueAsync(
        SdToken<ReadOnlyMemory<byte>> storedCredential,
        PrivateKeyMemory holderKey,
        string verifierAud,
        string verifierCnonce,
        DateTimeOffset iat,
        BuildKbtProtectedHeaderDelegate buildProtectedHeader,
        BuildKbtPayloadDelegate buildPayload,
        SerializeCoseSign1Delegate serializeCoseSign1,
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
            buildProtectedHeader,
            buildPayload,
            CoseSerialization.BuildSigStructure,
            serializeCoseSign1,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return TestSetup.Base64UrlEncoder(kbt.AsReadOnlyMemory().Span);
    }


    /// <summary>
    /// A <see cref="BuildKbtProtectedHeaderDelegate"/> that builds the genuine Key Binding Token protected header
    /// and appends a second <c>kcwt</c> (13) entry carrying the same embedded SD-CWT, so the header map carries
    /// label 13 twice and nothing else differs.
    /// </summary>
    /// <param name="coseAlgorithm">The holder key's COSE algorithm identifier.</param>
    /// <param name="presentationToken">The SD-CWT presentation token to embed.</param>
    /// <param name="pool">Memory pool the returned carrier rents from.</param>
    /// <returns>The protected header carrying <c>kcwt</c> twice.</returns>
    public static EncodedCoseProtectedHeader BuildProtectedHeaderWithKcwtTwice(
        int coseAlgorithm, SdToken<ReadOnlyMemory<byte>> presentationToken, BaseMemoryPool pool)
    {
        using EncodedCoseProtectedHeader validHeader = SdKbtIssuance.BuildProtectedHeader(coseAlgorithm, presentationToken, pool);

        var reader = new CborReader(validHeader.AsReadOnlyMemory(), CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The genuine protected header is a definite-length map.");
        writer.WriteStartMap(count + 1);
        ReadOnlyMemory<byte> kcwt = ReadOnlyMemory<byte>.Empty;
        for(int i = 0; i < count; i++)
        {
            int label = reader.ReadInt32();
            ReadOnlyMemory<byte> value = reader.ReadEncodedValue();
            writer.WriteInt32(label);
            writer.WriteEncodedValue(value.Span);
            if(label == CoseHeaderParameters.Kcwt)
            {
                kcwt = value;
            }
        }

        writer.WriteInt32(CoseHeaderParameters.Kcwt);
        writer.WriteEncodedValue(kcwt.Span);
        writer.WriteEndMap();

        return EncodedCoseProtectedHeader.FromBytes(buffer.WrittenSpan, pool);
    }


    /// <summary>
    /// A <see cref="BuildKbtProtectedHeaderDelegate"/> that builds the genuine Key Binding Token protected header
    /// and rewrites the embedded SD-CWT so its unprotected bucket carries <c>sd_claims</c> twice: the first entry
    /// holds the first selected Disclosure and the second entry the rest. The issuer signature does not cover
    /// the unprotected bucket and every Disclosure still travels, so only the repeated label differs.
    /// </summary>
    /// <param name="coseAlgorithm">The holder key's COSE algorithm identifier.</param>
    /// <param name="presentationToken">The SD-CWT presentation token to embed.</param>
    /// <param name="pool">Memory pool the returned carrier rents from.</param>
    /// <returns>The protected header whose embedded SD-CWT carries <c>sd_claims</c> twice.</returns>
    public static EncodedCoseProtectedHeader BuildProtectedHeaderWithSdClaimsTwice(
        int coseAlgorithm, SdToken<ReadOnlyMemory<byte>> presentationToken, BaseMemoryPool pool)
    {
        using EncodedCoseProtectedHeader validHeader = SdKbtIssuance.BuildProtectedHeader(coseAlgorithm, presentationToken, pool);

        var reader = new CborReader(validHeader.AsReadOnlyMemory(), CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The genuine protected header is a definite-length map.");
        writer.WriteStartMap(count);
        for(int i = 0; i < count; i++)
        {
            int label = reader.ReadInt32();
            ReadOnlyMemory<byte> value = reader.ReadEncodedValue();
            writer.WriteInt32(label);
            writer.WriteEncodedValue(label == CoseHeaderParameters.Kcwt ? SplitSdClaims(value) : value.Span);
        }

        writer.WriteEndMap();

        return EncodedCoseProtectedHeader.FromBytes(buffer.WrittenSpan, pool);
    }


    /// <summary>
    /// A <see cref="BuildKbtPayloadDelegate"/> that builds the genuine Key Binding Token payload and appends a
    /// second <c>aud</c> (3) claim with the same value, so the claims map carries claim key 3 twice and nothing
    /// else differs.
    /// </summary>
    /// <param name="aud">The verifier audience for the <c>aud</c> claim.</param>
    /// <param name="iat">The issuance timestamp in Unix seconds for the <c>iat</c> claim.</param>
    /// <param name="cnonce">The verifier nonce for the <c>cnonce</c> claim, or <see langword="null"/> to omit it.</param>
    /// <param name="pool">Memory pool the returned buffer is rented from.</param>
    /// <returns>The payload carrying <c>aud</c> twice, in a pool-rented buffer the caller owns.</returns>
    public static IMemoryOwner<byte> BuildPayloadWithAudTwice(string aud, long iat, string? cnonce, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> validPayload = SdKbtIssuance.BuildPayload(aud, iat, cnonce, pool);

        var reader = new CborReader(validPayload.Memory, CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The genuine payload is a definite-length map.");
        writer.WriteStartMap(count + 1);
        for(int i = 0; i < count; i++)
        {
            writer.WriteInt32(reader.ReadInt32());
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        }

        writer.WriteInt32(WellKnownCwtClaimNames.Aud);
        writer.WriteTextString(aud);
        writer.WriteEndMap();

        IMemoryOwner<byte> owner = pool.Rent(buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>
    /// A <see cref="BuildKbtPayloadDelegate"/> that builds the genuine Key Binding Token payload and writes its
    /// <c>iat</c> (6) claim as the integer -2^64, a well-formed CBOR integer below every value a signed 64-bit
    /// NumericDate holds, every other claim copied as encoded.
    /// </summary>
    /// <param name="aud">The verifier audience for the <c>aud</c> claim.</param>
    /// <param name="iat">The issuance timestamp the genuine payload carries; replaced in the written claims map.</param>
    /// <param name="cnonce">The verifier nonce for the <c>cnonce</c> claim, or <see langword="null"/> to omit it.</param>
    /// <param name="pool">Memory pool the returned buffer is rented from.</param>
    /// <returns>The payload carrying the unreadable <c>iat</c>, in a pool-rented buffer the caller owns.</returns>
    public static IMemoryOwner<byte> BuildPayloadWithIatBelowTheSignedRange(string aud, long iat, string? cnonce, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> validPayload = SdKbtIssuance.BuildPayload(aud, iat, cnonce, pool);

        var reader = new CborReader(validPayload.Memory, CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The genuine payload is a definite-length map.");
        writer.WriteStartMap(count);
        for(int i = 0; i < count; i++)
        {
            int claimKey = reader.ReadInt32();
            ReadOnlyMemory<byte> value = reader.ReadEncodedValue();
            writer.WriteInt32(claimKey);
            writer.WriteEncodedValue(claimKey == WellKnownCwtClaimNames.Iat ? IatBelowTheSignedRange.Span : value.Span);
        }

        writer.WriteEndMap();

        IMemoryOwner<byte> owner = pool.Rent(buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>The CBOR integer -2^64: major type 1 with the eight-byte argument 2^64 - 1.</summary>
    private static ReadOnlyMemory<byte> IatBelowTheSignedRange { get; } =
        new byte[] { 0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };


    /// <summary>
    /// Rewrites an SD-CWT COSE_Sign1 so its unprotected bucket carries <c>sd_claims</c> twice: the first entry
    /// holds the first Disclosure and the second entry the rest, every other part copied as encoded.
    /// </summary>
    /// <param name="sdCwt">The tagged SD-CWT COSE_Sign1, carrying one <c>sd_claims</c> entry with at least one Disclosure.</param>
    /// <returns>The rewritten COSE_Sign1 bytes.</returns>
    private static byte[] SplitSdClaims(ReadOnlyMemory<byte> sdCwt)
    {
        var reader = new CborReader(sdCwt, CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        _ = reader.ReadTag();
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        _ = reader.ReadStartArray();
        writer.WriteStartArray(4);
        writer.WriteEncodedValue(reader.ReadEncodedValue().Span);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The unprotected bucket is a definite-length map.");
        writer.WriteStartMap(count + 1);
        for(int i = 0; i < count; i++)
        {
            int label = reader.ReadInt32();
            if(label != CoseHeaderParameters.SdClaims)
            {
                writer.WriteInt32(label);
                writer.WriteEncodedValue(reader.ReadEncodedValue().Span);

                continue;
            }

            var disclosures = new List<ReadOnlyMemory<byte>>();
            _ = reader.ReadStartArray();
            while(reader.PeekState() != CborReaderState.EndArray)
            {
                disclosures.Add(reader.ReadEncodedValue());
            }

            reader.ReadEndArray();

            writer.WriteInt32(CoseHeaderParameters.SdClaims);
            writer.WriteStartArray(1);
            writer.WriteEncodedValue(disclosures[0].Span);
            writer.WriteEndArray();

            writer.WriteInt32(CoseHeaderParameters.SdClaims);
            writer.WriteStartArray(disclosures.Count - 1);
            foreach(ReadOnlyMemory<byte> disclosure in disclosures.Skip(1))
            {
                writer.WriteEncodedValue(disclosure.Span);
            }

            writer.WriteEndArray();
        }

        reader.ReadEndMap();
        writer.WriteEndMap();
        writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
        reader.ReadEndArray();
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Prepares a <see cref="BuildKbtProtectedHeaderDelegate"/> whose embedded SD-CWT carries the redacted-claim-keys
    /// map key <c>simple(59)</c> twice at the top level of its issuer-signed claims map: the one digest array of
    /// <paramref name="issued"/> is split over two such entries, the issuer signs the rewritten claims map over the
    /// same protected bucket, and the header builder puts that claims map and signature in place of the embedded
    /// SD-CWT's own. Every signature stays genuine and every Disclosure still travels, so only the repeated map key
    /// differs from an accepted presentation.
    /// </summary>
    /// <param name="issued">The issued SD-CWT, whose top-level claims map carries one digest array of at least two digests.</param>
    /// <param name="issuerKey">The issuer's signing key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The header builder.</returns>
    public static ValueTask<BuildKbtProtectedHeaderDelegate> PrepareProtectedHeaderWithRedactedClaimKeysTwiceAsync(
        SdToken<ReadOnlyMemory<byte>> issued, PrivateKeyMemory issuerKey, CancellationToken cancellationToken) =>
        PrepareProtectedHeaderWithRewrittenClaimsAsync(issued, issuerKey, SplitRedactedClaimKeys, cancellationToken);


    /// <summary>
    /// Answers a preparation like <see cref="PrepareProtectedHeaderWithRedactedClaimKeysTwiceAsync"/> whose rewrite
    /// appends <paramref name="entries"/>, encoded map entries, to the top level of the issued SD-CWT's issuer-signed
    /// claims map, raising the map's entry count by <paramref name="entryCount"/>.
    /// </summary>
    /// <param name="entries">The encoded entries appended to the claims map.</param>
    /// <param name="entryCount">How many entries <paramref name="entries"/> encodes.</param>
    /// <returns>The preparation.</returns>
    public static Func<SdToken<ReadOnlyMemory<byte>>, PrivateKeyMemory, CancellationToken, ValueTask<BuildKbtProtectedHeaderDelegate>> PrepareProtectedHeaderWithClaimsAppended(
        byte[] entries, int entryCount) =>
        (issued, issuerKey, cancellationToken) => PrepareProtectedHeaderWithRewrittenClaimsAsync(
            issued, issuerKey, payload => AppendClaimsMapEntries(payload, entries, entryCount), cancellationToken);


    /// <summary>
    /// Copies a definite-length claims map and appends <paramref name="entries"/> after its entries, raising its entry
    /// count by <paramref name="entryCount"/>.
    /// </summary>
    /// <param name="payload">The claims map.</param>
    /// <param name="entries">The encoded entries appended.</param>
    /// <param name="entryCount">How many entries <paramref name="entries"/> encodes.</param>
    /// <returns>The rewritten claims map bytes.</returns>
    private static byte[] AppendClaimsMapEntries(byte[] payload, byte[] entries, int entryCount)
    {
        var reader = new CborReader(payload, CborOptions.Lax);
        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The claims map is a definite-length map.");
        ReadOnlySpan<byte> originalEntries = payload.AsSpan(payload.Length - reader.BytesRemaining);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteStartMap(count + entryCount);

        return [.. buffer.WrittenSpan, .. originalEntries, .. entries];
    }


    /// <summary>
    /// Prepares a <see cref="BuildKbtProtectedHeaderDelegate"/> whose embedded SD-CWT carries the issued SD-CWT's
    /// issuer-signed claims map rewritten by <paramref name="rewriteClaims"/>, signed again by the issuer over the same
    /// protected bucket; every Disclosure still travels.
    /// </summary>
    /// <param name="issued">The issued SD-CWT.</param>
    /// <param name="issuerKey">The issuer's signing key.</param>
    /// <param name="rewriteClaims">Rewrites the issuer-signed claims map.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The header builder.</returns>
    private static async ValueTask<BuildKbtProtectedHeaderDelegate> PrepareProtectedHeaderWithRewrittenClaimsAsync(
        SdToken<ReadOnlyMemory<byte>> issued, PrivateKeyMemory issuerKey, Func<byte[], byte[]> rewriteClaims, CancellationToken cancellationToken)
    {
        var reader = new CborReader(issued.IssuerSigned, CborOptions.Lax);
        _ = reader.ReadTag();
        _ = reader.ReadStartArray();
        byte[] protectedHeader = reader.ReadByteString();
        reader.SkipValue();
        byte[] payload = reader.ReadByteString();

        byte[] rewrittenPayload = rewriteClaims(payload);
        using CoseSign1Message signed = await Verifiable.JCose.Cose.SignAsync(
            EncodedCoseProtectedHeader.FromBytes(protectedHeader, Pool),
            null,
            rewrittenPayload,
            CoseSerialization.BuildSigStructure,
            issuerKey,
            Pool,
            cancellationToken).ConfigureAwait(false);
        byte[] signature = signed.Signature.AsReadOnlySpan().ToArray();

        return (coseAlgorithm, presentationToken, pool) =>
        {
            using EncodedCoseProtectedHeader validHeader = SdKbtIssuance.BuildProtectedHeader(coseAlgorithm, presentationToken, pool);

            var headerReader = new CborReader(validHeader.AsReadOnlyMemory(), CborOptions.Lax);
            var buffer = new ArrayBufferWriter<byte>();
            var writer = new CborWriter(buffer, CborOptions.Lax);

            int count = headerReader.ReadStartMap() ?? throw new InvalidOperationException("The genuine protected header is a definite-length map.");
            writer.WriteStartMap(count);
            for(int i = 0; i < count; i++)
            {
                int label = headerReader.ReadInt32();
                ReadOnlyMemory<byte> value = headerReader.ReadEncodedValue();
                writer.WriteInt32(label);
                writer.WriteEncodedValue(label == CoseHeaderParameters.Kcwt ? ReplacePayloadAndSignature(value, rewrittenPayload, signature) : value.Span);
            }

            writer.WriteEndMap();

            return EncodedCoseProtectedHeader.FromBytes(buffer.WrittenSpan, pool);
        };
    }


    /// <summary>
    /// Rewrites a CWT claims map so its one top-level <c>simple(59)</c> digest array is split over two
    /// <c>simple(59)</c> entries: the first digest under the first, the rest under the second, every other entry
    /// copied as encoded.
    /// </summary>
    /// <param name="payload">The claims map, carrying one top-level <c>simple(59)</c> entry with at least two digests.</param>
    /// <returns>The rewritten claims map bytes.</returns>
    private static byte[] SplitRedactedClaimKeys(byte[] payload)
    {
        byte[] redactedClaimKeysMapKey = [0xF8, SdCwtConstants.RedactedClaimKeysSimpleValue];
        var reader = new CborReader(payload, CborOptions.Lax);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);

        int count = reader.ReadStartMap() ?? throw new InvalidOperationException("The claims map is a definite-length map.");
        writer.WriteStartMap(count + 1);
        for(int i = 0; i < count; i++)
        {
            ReadOnlyMemory<byte> mapKey = reader.ReadEncodedValue();
            if(!mapKey.Span.SequenceEqual(redactedClaimKeysMapKey))
            {
                writer.WriteEncodedValue(mapKey.Span);
                writer.WriteEncodedValue(reader.ReadEncodedValue().Span);

                continue;
            }

            var digests = new List<ReadOnlyMemory<byte>>();
            _ = reader.ReadStartArray();
            while(reader.PeekState() != CborReaderState.EndArray)
            {
                digests.Add(reader.ReadEncodedValue());
            }

            reader.ReadEndArray();

            writer.WriteEncodedValue(redactedClaimKeysMapKey);
            writer.WriteStartArray(1);
            writer.WriteEncodedValue(digests[0].Span);
            writer.WriteEndArray();

            writer.WriteEncodedValue(redactedClaimKeysMapKey);
            writer.WriteStartArray(digests.Count - 1);
            foreach(ReadOnlyMemory<byte> digest in digests.Skip(1))
            {
                writer.WriteEncodedValue(digest.Span);
            }

            writer.WriteEndArray();
        }

        reader.ReadEndMap();
        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Rewrites an SD-CWT COSE_Sign1 with <paramref name="payload"/> and <paramref name="signature"/> in place of its
    /// own, its protected and unprotected buckets copied as encoded.
    /// </summary>
    /// <param name="sdCwt">The tagged SD-CWT COSE_Sign1.</param>
    /// <param name="payload">The claims map bytes to carry.</param>
    /// <param name="signature">The issuer signature over <paramref name="payload"/>.</param>
    /// <returns>The rewritten COSE_Sign1 bytes.</returns>
    private static byte[] ReplacePayloadAndSignature(ReadOnlyMemory<byte> sdCwt, byte[] payload, byte[] signature)
    {
        var reader = new CborReader(sdCwt, CborOptions.Lax);
        _ = reader.ReadTag();
        _ = reader.ReadStartArray();
        ReadOnlyMemory<byte> protectedHeader = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> unprotectedHeader = reader.ReadEncodedValue();

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteEncodedValue(protectedHeader.Span);
        writer.WriteEncodedValue(unprotectedHeader.Span);
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
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
