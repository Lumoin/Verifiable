using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Direct tests for <see cref="KbCwtIssuance"/> — the serialization-agnostic
/// SD-CWT Key Binding Token (KBT) issuer in <c>Verifiable.JCose.Sd</c>, the CBOR
/// twin of the SD-JWT <c>KbJwtIssuance</c>. Wires the real
/// <see cref="SdKbtIssuance"/> CBOR seams and <see cref="CoseSerialization"/>
/// delegates against real key material and real cryptography.
/// </summary>
[TestClass]
internal sealed class KbCwtIssuanceTests
{
    public required TestContext TestContext { get; set; }

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string VerifierAud = "https://verifier.example.com/response";

    //Application-defined CWT claim keys for a test credential, mirroring the
    //SD-CWT issuance helper in DcqlCwtPresentationFlowTests.
    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";


    [TestMethod]
    public async Task IssuesKbtSignedWithHolderKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: "n-sig",
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CoseSign1Message parsedKbt = CoseSerialization.ParseCoseSign1(kbt.AsReadOnlyMemory(), Pool);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            parsedKbt,
            CoseSerialization.BuildSigStructure,
            holderPublic,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The KBT holder signature must verify under the holder public key.");
    }


    [TestMethod]
    public async Task IssuesKbtWithTypAndKcwtProtectedHeader()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: null,
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CoseSign1Message parsedKbt = CoseSerialization.ParseCoseSign1(kbt.AsReadOnlyMemory(), Pool);

        IReadOnlyDictionary<int, object> header =
            CoseSerialization.ParseProtectedHeader(parsedKbt.ProtectedHeader.AsReadOnlySpan());

        Assert.IsTrue(header.ContainsKey(CoseHeaderParameters.Typ), "Protected header must carry typ (16).");
        Assert.AreEqual(
            (long)SdKbtIssuance.KbtTypeValue,
            Convert.ToInt64(header[CoseHeaderParameters.Typ], CultureInfo.InvariantCulture),
            "typ must be the KBT type value 294.");

        Assert.IsTrue(header.ContainsKey(CoseHeaderParameters.Alg), "Protected header must carry alg (1).");
        Assert.IsTrue(header.ContainsKey(CoseHeaderParameters.Kcwt), "Protected header must carry kcwt (13).");
    }


    [TestMethod]
    public async Task EmbeddedKcwtVerifiesEndToEndFromWireBytesOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: "n-kcwt",
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Firewalled: from here on, only the KBT wire bytes + the issuer public key are used —
        //no in-memory disclosures/salts from the issuance side. A verifier reconstructs the
        //embedded SD-CWT and runs the COMPLETE verification (issuer signature AND per-disclosure
        //digest binding). This is what proves the selected disclosures' salts survived the
        //re-serialization into kcwt; a signature-only check would not.
        using CoseSign1Message parsedKbt = CoseSerialization.ParseCoseSign1(kbt.AsReadOnlyMemory(), Pool);
        ReadOnlyMemory<byte> embeddedSdCwt = ExtractKcwtEncodedValue(parsedKbt.ProtectedHeader.AsReadOnlyMemory());

        SdCwtMessage parsedPresentation = SdCwtSerializer.Parse(embeddedSdCwt, TestSalts.TestSaltTag, Pool);

        HashSet<string> claimNames = new(StringComparer.Ordinal);
        foreach(SdDisclosure disclosure in parsedPresentation.Disclosures)
        {
            Assert.IsNotNull(disclosure.ClaimName);
            claimNames.Add(disclosure.ClaimName!);
        }

        Assert.Contains(ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture), claimNames);
        Assert.Contains(ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture), claimNames);
        Assert.DoesNotContain(ClaimKeyEmail.ToString(CultureInfo.InvariantCulture), claimNames);

        //The reconstructed token owns the parsed disclosures; full verification binds each one
        //to a digest in the issuer-signed payload.
        using SdToken<ReadOnlyMemory<byte>> embeddedToken =
            new(embeddedSdCwt, parsedPresentation.Disclosures);

        SdVerificationResult result = await embeddedToken.VerifyAsync(
            issuerPublic, Pool,
            CoseSerialization.ParseCoseSign1, SdCwtPathExtraction.ExtractPaths, CoseSerialization.BuildSigStructure, TestSetup.Base64UrlEncoder,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "Embedded presentation SD-CWT must pass full verification (issuer signature + digest binding); " +
            "a salt change during re-serialization would break digest binding here.");
        Assert.HasCount(2, result.ClaimResults);
        foreach(SdClaimVerificationResult claimResult in result.ClaimResults)
        {
            Assert.IsTrue(claimResult.IsValid, "Each embedded disclosure must bind to a payload digest.");
        }
    }


    [TestMethod]
    public async Task IssuesKbtWithSuppliedAudIatCnonce()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        DateTimeOffset iat = new(2026, 5, 10, 12, 0, 0, TimeSpan.Zero);
        const string Cnonce = "n-claims";

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: Cnonce,
            iat: iat,
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CoseSign1Message parsedKbt = CoseSerialization.ParseCoseSign1(kbt.AsReadOnlyMemory(), Pool);

        (string aud, long parsedIat, string? cnonce, bool hasIss, bool hasSub) = ReadKbtPayload(parsedKbt.Payload);

        Assert.AreEqual(VerifierAud, aud);
        Assert.AreEqual(iat.ToUnixTimeSeconds(), parsedIat);
        Assert.AreEqual(Cnonce, cnonce);
        Assert.IsFalse(hasIss, "iss (1) must not be present in a KBT payload.");
        Assert.IsFalse(hasSub, "sub (2) must not be present in a KBT payload.");
    }


    [TestMethod]
    public async Task OmitsCnonceWhenNull()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using EncodedCoseSign1 kbt = await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: null,
            iat: TimeProvider.GetUtcNow(),
            buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
            buildPayload: SdKbtIssuance.BuildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CoseSign1Message parsedKbt = CoseSerialization.ParseCoseSign1(kbt.AsReadOnlyMemory(), Pool);

        (_, _, string? cnonce, _, _) = ReadKbtPayload(parsedKbt.Payload);
        Assert.IsNull(cnonce, "cnonce (39) must be omitted when no nonce is supplied.");
    }


    [TestMethod]
    public async Task SurfacesCancellation()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            using EncodedCoseSign1 _ = await KbCwtIssuance.IssueAsync(
                presentationToken,
                holderPrivate,
                verifierAud: VerifierAud,
                verifierCnonce: "n-cancel",
                iat: TimeProvider.GetUtcNow(),
                buildProtectedHeader: SdKbtIssuance.BuildProtectedHeader,
                buildPayload: SdKbtIssuance.BuildPayload,
                buildSigStructure: CoseSerialization.BuildSigStructure,
                serializeCoseSign1: CoseSerialization.SerializeCoseSign1,
                memoryPool: Pool,
                cancellationToken: cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    //Issues a signed SD-CWT carrying given_name, family_name, and email as
    //selectively disclosable claims, mirroring DcqlCwtPresentationFlowTests.
    private async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = IssuerId,
            [WellKnownCwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
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


    //Selects given_name + family_name, leaving email behind. The presentation
    //token keeps the original issuer COSE_Sign1 in IssuerSigned and carries the
    //two selected disclosures in Disclosures.
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


    //Reads the KBT CWT-claims payload, returning aud/iat/cnonce and whether the
    //forbidden iss/sub claims are present.
    private static (string Aud, long Iat, string? Cnonce, bool HasIss, bool HasSub) ReadKbtPayload(ReadOnlyMemory<byte> payload)
    {
        var reader = new CborReader(payload, CborConformanceMode.Lax);

        string? aud = null;
        long? iat = null;
        string? cnonce = null;
        bool hasIss = false;
        bool hasSub = false;

        int? count = reader.ReadStartMap();
        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadInt32();
            switch(key)
            {
                case WellKnownCwtClaimNames.Iss:
                    hasIss = true;
                    reader.SkipValue();
                    break;
                case WellKnownCwtClaimNames.Sub:
                    hasSub = true;
                    reader.SkipValue();
                    break;
                case WellKnownCwtClaimNames.Aud:
                    aud = reader.ReadTextString();
                    break;
                case WellKnownCwtClaimNames.Iat:
                    iat = reader.ReadInt64();
                    break;
                case WellKnownCwtClaimNames.Cnonce:
                    cnonce = reader.ReadTextString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        Assert.IsNotNull(aud, "aud (3) must be present in a KBT payload.");
        Assert.IsNotNull(iat, "iat (6) must be present in a KBT payload.");
        return (aud!, iat!.Value, cnonce, hasIss, hasSub);
    }


    //Reads the kcwt (label 13) value out of the KBT protected header as the raw
    //encoded CBOR (the embedded COSE_Sign1 wire bytes).
    private static ReadOnlyMemory<byte> ExtractKcwtEncodedValue(ReadOnlyMemory<byte> protectedHeader)
    {
        var reader = new CborReader(protectedHeader, CborConformanceMode.Lax);

        int? count = reader.ReadStartMap();
        for(int i = 0; i < count; i++)
        {
            int key = reader.ReadInt32();
            if(key == CoseHeaderParameters.Kcwt)
            {
                return reader.ReadEncodedValue();
            }

            reader.SkipValue();
        }

        reader.ReadEndMap();
        throw new InvalidOperationException("kcwt (13) not found in the KBT protected header.");
    }
}
