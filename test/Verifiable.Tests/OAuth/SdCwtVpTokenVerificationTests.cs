using System.Buffers;
using System.Formats.Cbor;
using System.Globalization;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
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

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string CredentialQueryId = "employee_cwt";
    private const string VerifierAud = "https://verifier.example.com/response";
    private const string Cnonce = "n-vptoken-cwt-01";

    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";


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
            vpTokenValue, CredentialQueryId, BuildSeams(issuerPublic),
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

        Assert.IsTrue(parsed.ExtractedClaims.TryGetValue(CredentialQueryId,
            out IReadOnlyDictionary<string, string>? claims),
            "Extracted claims must be keyed by the DCQL credential query id.");
        Assert.AreEqual("Erika", claims![ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]);
        Assert.AreEqual("Mustermann", claims[ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)]);
        Assert.IsFalse(claims.ContainsKey(ClaimKeyEmail.ToString(CultureInfo.InvariantCulture)),
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
            vpTokenValue, CredentialQueryId, BuildSeams(wrongIssuerPublic),
            TestSetup.Base64UrlDecoder, saltReuseSeam: null, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.KbJwtSignatureValid,
            "The holder signature is independent of the issuer key and must still verify.");
        Assert.IsFalse(parsed.CredentialSignatureValid,
            "An issuer key that did not sign the credential must fail the credential signature.");
    }


    /// <summary>
    /// Verifier-side seams wired to the real <c>Verifiable.Cbor</c> implementations,
    /// with a trust resolver returning the supplied issuer public key.
    /// </summary>
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


    private static ReadOnlySpan<byte> SerializeCwtClaimMap(Dictionary<int, object> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CborValueConverter.WriteValue(writer, claims);

        return writer.Encode();
    }
}
