using System.Buffers;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for the SD-JWT issuance pipeline at the
/// <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see> level.
/// The payload is any JSON object — not restricted to Verifiable Credentials.
/// </summary>
/// <remarks>
/// <para>
/// Two issuance paths exist for generic SD-JWT tokens:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Flat payloads:</strong> <see cref="SdJwtIssuance.IssueAsync"/> takes pre-built
/// mandatory claims and disclosures, places digests at root. Suitable for SD-JWT VC flat
/// claim structures (e.g., <c>iss</c>, <c>vct</c>, top-level claims).
/// </description></item>
/// <item><description>
/// <strong>Nested payloads:</strong> <see cref="SdJwtClaimRedaction.Redact"/> walks the
/// JSON tree and places <c>_sd</c> arrays at the correct nesting levels. Suitable for
/// any JSON structure including nested objects like <c>address</c>.
/// </description></item>
/// </list>
/// <para>
/// For VC-specific tests, see <see cref="SdJwtCredentialSecuringTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdJwtClaimRedactionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static JwtHeaderSerializer HeaderSerializer => header =>
        JsonSerializer.SerializeToUtf8Bytes(header);

    private static JwtPayloadSerializer PayloadSerializer => payload =>
        JsonSerializer.SerializeToUtf8Bytes(payload);


    // ──────────────────────────────────────────────────────────
    //  SdJwtClaimRedaction.Redact — nested payloads (RFC 9901)
    // ──────────────────────────────────────────────────────────

    [TestMethod]
    public void RedactTopLevelClaimsPlacesSdArrayAtRoot()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "vct": "IdentityCredential",
            "given_name": "Erika",
            "family_name": "Mustermann"
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/given_name"),
            CredentialPath.FromJsonPointer("/family_name")
        };

        var (payload, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        Assert.AreEqual("https://issuer.example.com", payload["iss"]);
        Assert.AreEqual("IdentityCredential", payload["vct"]);
        Assert.IsTrue(payload.ContainsKey(SdConstants.SdClaimName), "Root must have _sd array.");
        Assert.AreEqual(WellKnownHashAlgorithms.Sha256Iana, payload[SdConstants.SdAlgorithmClaimName]);

        Assert.HasCount(2, disclosures);
        Assert.AreEqual("given_name", disclosures[0].ClaimName);
        Assert.AreEqual("Erika", disclosures[0].ClaimValue);
        Assert.AreEqual("family_name", disclosures[1].ClaimName);
        Assert.AreEqual("Mustermann", disclosures[1].ClaimValue);
    }


    [TestMethod]
    public void RedactNestedClaimsPlacesSdArrayInsideParent()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "address": {
                "street": "Heidestrasse 17",
                "city": "Köln",
                "country": "DE"
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/address/street"),
            CredentialPath.FromJsonPointer("/address/city")
        };

        var (payload, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        Assert.AreEqual("https://issuer.example.com", payload["iss"]);
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdClaimName), "Root must not have _sd when no root claims are disclosable.");

        var address = (Dictionary<string, object>)payload["address"]!;
        Assert.AreEqual("DE", address["country"]);
        Assert.IsTrue(address.ContainsKey(SdConstants.SdClaimName), "Address must have _sd array.");
        Assert.IsFalse(address.ContainsKey("street"), "Disclosable claim must not be in mandatory payload.");
        Assert.IsFalse(address.ContainsKey("city"), "Disclosable claim must not be in mandatory payload.");

        Assert.HasCount(2, disclosures);
        Assert.AreEqual("street", disclosures[0].ClaimName);
        Assert.AreEqual("city", disclosures[1].ClaimName);
    }


    [TestMethod]
    public void RedactWithNoDisclosablePathsProducesNoSdMetadata()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "vct": "IdentityCredential",
            "iat": 1700000000
        }
        """;

        var (payload, disclosures) = SdJwtClaimRedaction.Redact(
            json, new HashSet<CredentialPath>(), () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        Assert.HasCount(3, payload);
        Assert.HasCount(0, disclosures);
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdClaimName), "No _sd when no disclosures.");
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdAlgorithmClaimName), "No _sd_alg when no disclosures.");
    }


    [TestMethod]
    public void RedactWholeNestedObjectProducesObjectValueDisclosure()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "address": {
                "street": "Heidestrasse 17",
                "city": "Köln",
                "country": "DE"
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/address")
        };

        var (payload, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        Assert.AreEqual("https://issuer.example.com", payload["iss"]);
        Assert.IsFalse(payload.ContainsKey("address"), "Disclosable object must not be in mandatory payload.");
        Assert.IsTrue(payload.ContainsKey(SdConstants.SdClaimName), "Root must have _sd array.");

        Assert.HasCount(1, disclosures);
        Assert.AreEqual("address", disclosures[0].ClaimName);
    }


    [TestMethod]
    public void RedactWithNumericAndBooleanValuesPreservesTypes()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "age": 42,
            "active": true,
            "score": 3.14
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/age"),
            CredentialPath.FromJsonPointer("/active"),
            CredentialPath.FromJsonPointer("/score")
        };

        var (_, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        Assert.HasCount(3, disclosures);
        Assert.AreEqual(42L, disclosures[0].ClaimValue);
        Assert.IsTrue((bool)disclosures[1].ClaimValue!);
        Assert.AreEqual(3.14m, disclosures[2].ClaimValue);
    }


    // ──────────────────────────────────────────────────────────
    //  SdJwtIssuance.IssueAsync — flat payloads (RFC 9901)
    // ──────────────────────────────────────────────────────────

    [TestMethod]
    public async Task IssueAsyncFlatPayloadProducesValidToken()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyMaterial.PrivateKey;
        using var publicKey = keyMaterial.PublicKey;

        var disclosures = new List<SdDisclosure>
        {
            SdDisclosure.CreateProperty(SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes), "given_name", "Erika"),
            SdDisclosure.CreateProperty(SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes), "family_name", "Mustermann")
        };

        var claims = new JwtPayload
        {
            [WellKnownJwtClaims.Iss] = "https://issuer.example.com",
            [WellKnownJwtClaims.Vct] = "IdentityCredential"
        };

        SdJwtToken token = await SdJwtIssuance.IssueAsync(
            claims, disclosures,
            SerializeDisclosure, ComputeDigest,
            privateKey, "key-1",
            WellKnownHashAlgorithms.Sha256Iana,
            WellKnownMediaTypes.Jwt.VcSdJwt,
            HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(token);
        Assert.HasCount(2, token.Disclosures);

        //Payload must contain _sd and _sd_alg.
        JsonElement payload = ParsePayload(token);
        Assert.IsTrue(payload.TryGetProperty(SdConstants.SdClaimName, out JsonElement sdArray), "Payload must contain _sd.");
        Assert.HasCount(2, sdArray.EnumerateArray().ToList());
        Assert.AreEqual(WellKnownHashAlgorithms.Sha256Iana,
            payload.GetProperty(SdConstants.SdAlgorithmClaimName).GetString());
    }


    [TestMethod]
    public async Task IssueAsyncFlatPayloadRoundTripsWithExtraction()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyMaterial.PrivateKey;

        var disclosures = new List<SdDisclosure>
        {
            SdDisclosure.CreateProperty(SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes), "given_name", "Erika"),
            SdDisclosure.CreateProperty(SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes), "family_name", "Mustermann"),
            SdDisclosure.CreateProperty(SaltGenerator.Create(SdConstants.DefaultSaltLengthBytes), "birthdate", "1964-08-12")
        };

        var claims = new JwtPayload
        {
            [WellKnownJwtClaims.Iss] = "https://issuer.example.com",
            [WellKnownJwtClaims.Vct] = "IdentityCredential"
        };

        SdJwtToken token = await SdJwtIssuance.IssueAsync(
            claims, disclosures,
            SerializeDisclosure, ComputeDigest,
            privateKey, "key-1",
            WellKnownHashAlgorithms.Sha256Iana,
            WellKnownMediaTypes.Jwt.VcSdJwt,
            HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<SdDisclosure, CredentialPath> extractedPaths = SdJwtPathExtraction.ExtractPaths(
            token, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool);

        Assert.HasCount(3, extractedPaths);

        var pathValues = new HashSet<CredentialPath>(extractedPaths.Values);
        Assert.Contains(CredentialPath.FromJsonPointer("/given_name"), pathValues);
        Assert.Contains(CredentialPath.FromJsonPointer("/family_name"), pathValues);
        Assert.Contains(CredentialPath.FromJsonPointer("/birthdate"), pathValues);
    }


    // ──────────────────────────────────────────────────────────
    //  Redact → sign → extract round-trip (nested, RFC 9901)
    // ──────────────────────────────────────────────────────────

    [TestMethod]
    public async Task RedactThenSignNestedPayloadRoundTrips()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var privateKey = keyMaterial.PrivateKey;

        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "address": {
                "street": "Heidestrasse 17",
                "city": "Köln",
                "country": "DE"
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/address/street"),
            CredentialPath.FromJsonPointer("/address/city")
        };

        //Phase 1-3: Redact produces a ready-to-sign payload.
        var (payload, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

        //Sign the redacted payload directly.
        UnsignedJwt unsigned = UnsignedJwt.ForSigning(privateKey, "key-1", payload, "sd-jwt");
        using JwsMessage jwsMessage = await unsigned.SignAsync(
            privateKey, HeaderSerializer, PayloadSerializer,
            TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string issuerJwt = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        var token = new SdJwtToken(issuerJwt, disclosures.ToList());

        //Extract and verify round-trip.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> extractedPaths = SdJwtPathExtraction.ExtractPaths(
            token, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool);

        Assert.HasCount(2, extractedPaths);

        var pathValues = new HashSet<CredentialPath>(extractedPaths.Values);
        Assert.Contains(CredentialPath.FromJsonPointer("/address/street"), pathValues);
        Assert.Contains(CredentialPath.FromJsonPointer("/address/city"), pathValues);
    }


    //Delegate wiring — same pattern used by DcqlPresentationFlowTests.

    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }

    private static string ComputeDigest(string encodedDisclosure, EncodeDelegate encoder)
    {
        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encodedDisclosure, WellKnownHashAlgorithms.Sha256Iana, encoder);
    }

    private static JsonElement ParsePayload(SdJwtToken token)
    {
        string[] jwtParts = token.IssuerSigned.Split('.');
        using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(jwtParts[1], SensitiveMemoryPool<byte>.Shared);
        using JsonDocument doc = JsonDocument.Parse(payloadBytes.Memory);

        return doc.RootElement.Clone();
    }
}