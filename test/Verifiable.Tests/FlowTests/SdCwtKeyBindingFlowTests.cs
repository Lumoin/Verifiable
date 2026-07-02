using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// Firewalled end-to-end tests for the SD-CWT OID4VP key-binding presentation flow:
/// issuer issues an SD-CWT carrying the holder's COSE_Key in its <c>cnf</c> claim →
/// wallet selects disclosures and signs an SD-CWT Key Binding Token (KBT) with its
/// private key → verifier receives ONLY the KBT wire bytes (plus the issuer public
/// key via a resolver) and runs <see cref="KbCwtVerification.VerifyAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// The three parties are firewalled — no shared in-memory disclosures, salts, or keys
/// cross the issuer → wallet → verifier boundary. The verifier reconstructs everything
/// it needs from the KBT bytes: the embedded SD-CWT (from <c>kcwt</c>), the holder
/// public key (from the embedded SD-CWT <c>cnf</c> COSE_Key), and the disclosed claims.
/// Every test uses real key material and real cryptography. The CBOR parse/extraction
/// seams are wired to the real <c>Verifiable.Cbor</c> implementations; the holder and
/// credential signature checks flow through real COSE verification.
/// </para>
/// <para>
/// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see> and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtKeyBindingFlowTests
{
    public required TestContext TestContext { get; set; }

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string VerifierAud = "https://verifier.example.com/response";
    private const string Cnonce = "n-flow";

    //Application-defined CWT claim keys for a test credential.
    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;

    //RFC 8747 §3.1: the cnf confirmation map carries the embedded COSE_Key under member 1.
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";


    [TestMethod]
    public async Task VerifierAcceptsKbtAndExtractsSelectedDisclosures()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //Wallet produces the KBT wire bytes; from here only the bytes + issuer key are used.
        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic).ConfigureAwait(false);

        Assert.IsTrue(result.HolderSignatureValid, "The KBT holder signature must verify.");
        Assert.IsTrue(result.CredentialSignatureValid,
            "The embedded SD-CWT must verify (issuer signature + per-disclosure digest binding).");
        Assert.AreEqual(VerifierAud, result.Audience);
        Assert.AreEqual(Cnonce, result.Cnonce);
        Assert.AreEqual(TimeProvider.GetUtcNow().ToUnixTimeSeconds(), result.IssuedAt?.ToUnixTimeSeconds());

        IReadOnlyDictionary<string, string> claims = result.DisclosedClaims;
        Assert.AreEqual("Erika", claims[ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture)]);
        Assert.AreEqual("Mustermann", claims[ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)]);
        Assert.IsFalse(claims.ContainsKey(ClaimKeyEmail.ToString(CultureInfo.InvariantCulture)),
            "The withheld email claim must not appear in the disclosed set.");

        //The verifier observes the shortest disclosure salt length for the salt-length signal.
        //Issuance used TestSalts.DefaultGenerator (the recommended 16-byte length).
        Assert.AreEqual(Salt.RecommendedByteLength, result.MinimumDisclosureSaltLengthBytes,
            "The shortest disclosure salt length must be captured from the embedded SD-CWT disclosures.");
    }


    [TestMethod]
    public async Task SameKbtVerifiedTwiceUnderSaltReuseStoreFlagsTheSecond()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        var store = new InMemoryCommitmentStore();
        CommitmentReuseDetectionSeam seam = new(
            SHA256.HashData, HashOutputByteLength: 32, Sha256CommitmentTag, store.IsSeen, store.Record);

        //First verification records the embedded disclosures' salts.
        SdCwtKbtVerificationResult first = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic, seam).ConfigureAwait(false);
        Assert.IsFalse(first.SaltReused, "First verification sees fresh salts.");

        //Re-verifying the SAME KBT replays the same disclosure salts (the embedded SD-CWT is fixed).
        SdCwtKbtVerificationResult second = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic, seam).ConfigureAwait(false);
        Assert.IsTrue(second.SaltReused, "Re-verifying the same KBT must detect the reused disclosure salts.");
    }


    private static readonly Tag Sha256CommitmentTag = Tag.Create(HashAlgorithmName.SHA256);


    /// <summary>A verifier-side commitment store keyed by commitment bytes, shared across two verifications.</summary>
    private sealed class InMemoryCommitmentStore
    {
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);

        public ValueTask<bool> IsSeen(DigestValue commitment, CancellationToken cancellationToken) =>
            ValueTask.FromResult(seen.Contains(Convert.ToHexString(commitment.AsReadOnlySpan())));

        public ValueTask Record(DigestValue commitment, CancellationToken cancellationToken)
        {
            seen.Add(Convert.ToHexString(commitment.AsReadOnlySpan()));

            return ValueTask.CompletedTask;
        }
    }


    [TestMethod]
    public async Task CredentialSignatureFailsWhenResolverReturnsWrongIssuerKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        //A different key than the one that signed the credential.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongIssuerPublic = wrongKeys.PublicKey;
        using PrivateKeyMemory wrongIssuerPrivate = wrongKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        //Resolver hands back a key that did NOT sign the credential.
        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), wrongIssuerPublic).ConfigureAwait(false);

        Assert.IsTrue(result.HolderSignatureValid,
            "The holder signature is independent of the issuer key and must still verify.");
        Assert.IsFalse(result.CredentialSignatureValid,
            "Verifying the credential under the wrong issuer key must fail.");
    }


    [TestMethod]
    public async Task HolderSignatureFailsWhenSignedByKeyNotInCnf()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        //The cnf carries this holder key...
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> cnfKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory cnfHolderPublic = cnfKeys.PublicKey;
        using PrivateKeyMemory cnfHolderPrivate = cnfKeys.PrivateKey;

        //...but the KBT is signed by a different (attacker) key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, cnfHolderPublic, attackerPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic).ConfigureAwait(false);

        Assert.IsFalse(result.HolderSignatureValid,
            "The KBT signed by a key that does not match the cnf COSE_Key must fail holder verification.");
        Assert.IsTrue(result.CredentialSignatureValid,
            "The credential itself is intact, so the issuer signature + digest binding still hold.");
    }


    //Issuer issues an SD-CWT (cnf = holder COSE_Key + selectively disclosable claims),
    //then the wallet selects given_name + family_name and signs the KBT with its private key.
    private async ValueTask<EncodedCoseSign1> IssueKbtAsync(
        PrivateKeyMemory issuerPrivate,
        PublicKeyMemory holderPublic,
        PrivateKeyMemory holderPrivate,
        string cnonce,
        DateTimeOffset iat)
    {
        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, holderPublic, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        return await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: cnonce,
            iat: iat,
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //The verifier side — wired entirely to the real Verifiable.Cbor seams and a resolver
    //returning the supplied issuer public key. It receives ONLY the KBT wire bytes and
    //the issuer public key; everything else is reconstructed from the bytes.
    private async ValueTask<SdCwtKbtVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> kbtBytes, PublicKeyMemory issuerKey, CommitmentReuseDetectionSeam? saltReuseSeam = null)
    {
        return await KbCwtVerification.VerifyAsync(
            kbtBytes,
            parseCoseSign1: CoseSerialization.ParseCoseSign1,
            extractKcwt: SdCwtVpParsing.ExtractKcwt,
            parseSdCwt: bytes => SdCwtVpParsing.ParseEmbeddedSdCwt(bytes, TestSalts.TestSaltTag, Pool),
            extractHolderKey: SdCwtVpParsing.ExtractHolderKey,
            readKbtClaims: SdCwtVpParsing.ReadKbtClaims,
            extractIssuer: SdCwtVpParsing.ExtractIssuer,
            resolveIssuerKey: _ => issuerKey,
            verifyCredential: async (token, key, pool, ct) =>
            {
                SdVerificationResult result = await token.VerifyAsync(
                    key, pool,
                    CoseSerialization.ParseCoseSign1, SdCwtPathExtraction.ExtractPaths, CoseSerialization.BuildSigStructure, TestSetup.Base64UrlEncoder,
                    cancellationToken: ct).ConfigureAwait(false);

                return result.IsValid;
            },
            buildSigStructure: CoseSerialization.BuildSigStructure,
            saltReuseSeam: saltReuseSeam,
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Issues a signed SD-CWT carrying the holder COSE_Key under cnf (claim 8) plus
    //given_name, family_name, and email as selectively disclosable claims.
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


    //Builds the cnf confirmation map { 1: COSE_Key } from a P-256 holder public key.
    //The COSE_Key is a nested int-keyed map so it serializes as a CBOR map the verifier's
    //COSE_Key reader can parse (kty=EC2, crv=P-256, x, y).
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


    //Selects given_name + family_name, leaving email behind.
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
