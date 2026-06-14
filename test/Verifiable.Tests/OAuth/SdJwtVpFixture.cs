using System.Buffers;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The SD-JWT VC (<c>dc+sd-jwt</c>) credential format expressed as a
/// <see cref="FormatFixture"/> for the scheme × format matrix: it builds a plain
/// host, issues a PID SD-JWT VC (holder JWK in <c>cnf</c>), registers the issuer's
/// trust, and wires the presentation drop-out
/// (<see cref="TestHostShell.BuildSdJwtProduceDelegate(string, PrivateKeyMemory)"/>).
/// The single source of the SD-JWT PID issuance shared by the matrix and the
/// <see cref="Oid4VpWalletClientTests"/> presentation/disclosure tests.
/// </summary>
internal static class SdJwtVpFixture
{
    /// <summary>The issuer identifier the PID is issued under and registered as trusted.</summary>
    public const string IssuerId = "https://issuer.example.com";

    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>The SD-JWT matrix-format row: name plus the per-run <see cref="FormatRun"/> factory.</summary>
    public static FormatFixture Format => new("dc+sd-jwt", StartAsync);


    private static async ValueTask<FormatRun> StartAsync(FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        TestHostShell app = new(tp);

        (string serializedSdJwt, PrivateKeyMemory holderKey, PublicKeyMemory issuerKey) =
            await IssuePidCredentialAsync(tp, cancellationToken).ConfigureAwait(false);
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        return new FormatRun
        {
            App = app,
            Query = DcqlFixtures.PidFamilyNamePrepared(),
            Produce = TestHostShell.BuildSdJwtProduceDelegate(serializedSdJwt, holderKey),
            AssertClaims = static verified => Assert.IsTrue(verified.Claims.ContainsKey("pid"),
                "Verifier must surface the wallet's presentation under the 'pid' credential query id."),
            Owned = [holderKey, issuerKey]
        };
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC (P-256 issuer signature, Ed25519 holder key in
    /// <c>cnf</c>, <c>given_name</c> + <c>family_name</c> disclosable). The caller
    /// owns the returned holder private key and issuer public key.
    /// </summary>
    public static async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: tp.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Erika"),
                new(EudiPid.SdJwt.FamilyName, "Mustermann")
            ]);

        HashSet<CredentialPath> disclosablePaths =
        [
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        ];

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }
}
