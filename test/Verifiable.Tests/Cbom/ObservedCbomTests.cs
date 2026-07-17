using System.Buffers;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography.Cbom;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Cbom;

/// <summary>
/// Tests for the observed ("runtime") CBOM. The runtime view reports what actually
/// executed in a workload, derived from the captured <c>crypto.*</c> telemetry: the
/// algorithms exercised, the entropy material consumed, the producing library, and the
/// entropy &#8594; DRBG &#8594; material &#8594; library dependency edges.
/// </summary>
/// <remarks>
/// <para>
/// The workload routes through the project's test crypto infrastructure
/// (<see cref="TestKeyMaterialProvider"/>, <see cref="MicrosoftCryptographicFunctions"/>,
/// and <see cref="CryptographicKeyEvents"/>) registered by the test module initializer —
/// never <c>System.Security.Cryptography</c> directly. The <see cref="CbomObserver"/>
/// scopes capture by a per-run trace id so parallel tests do not cross-contaminate.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ObservedCbomTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task ObservedCbomCapturesEntropyMaterialAlgorithmsAndDependencies()
    {
        using CbomObserver observer = new();

        CbomDocument document = await observer.ObserveAsync(
            RunWorkloadAsync,
            "2026-06-18T00:00:00Z",
            "1.2.3").ConfigureAwait(false);

        string json = CbomJsonRenderer.Render(document);
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        Assert.AreEqual("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.AreEqual("1.6", root.GetProperty("specVersion").GetString());

        JsonElement[] components = root.GetProperty("components").EnumerateArray().ToArray();

        //Related-crypto-material for the entropy that was drawn (salt and/or nonce).
        JsonElement[] entropyMaterial = components
            .Where(c => c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "related-crypto-material")
            .Where(c =>
            {
                string? type = c.GetProperty("cryptoProperties")
                    .GetProperty("relatedCryptoMaterialProperties").GetProperty("type").GetString();
                return type is "salt" or "nonce";
            })
            .ToArray();

        Assert.IsGreaterThan(0, entropyMaterial.Length,
            "The observed CBOM must include related-crypto-material for the entropy drawn (salt/nonce).");

        //The producing crypto library must appear as a related-crypto-material asset.
        bool hasLibrary = components.Any(c =>
            c.GetProperty("bom-ref").GetString()!.StartsWith("crypto/library/", System.StringComparison.Ordinal));
        Assert.IsTrue(hasLibrary,
            "The observed CBOM must record the producing crypto library.");

        //Algorithm assets for what executed: at least the SHA-256 digest and the DRBG.
        JsonElement[] algorithmAssets = components
            .Where(c => c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "algorithm")
            .ToArray();
        Assert.IsGreaterThan(0, algorithmAssets.Length,
            "The observed CBOM must include algorithm assets for the operations that executed.");

        bool hasDigest = algorithmAssets.Any(c =>
            c.GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("primitive").GetString() == "hash");
        Assert.IsTrue(hasDigest, "The SHA-256 digest must surface as a hash algorithm asset.");

        //At least one dependency edge (material -> DRBG/algorithm and library).
        JsonElement dependencies = root.GetProperty("dependencies");
        Assert.IsGreaterThan(0, dependencies.GetArrayLength(),
            "The observed CBOM must include at least one dependency edge.");

        //Every entropy material must depend on the DRBG and name the producing library.
        foreach(JsonElement material in entropyMaterial)
        {
            string materialRef = material.GetProperty("bom-ref").GetString()!;
            JsonElement edge = dependencies.EnumerateArray()
                .First(d => d.GetProperty("ref").GetString() == materialRef);

            string[] dependsOn = edge.GetProperty("dependsOn").EnumerateArray()
                .Select(x => x.GetString()!)
                .ToArray();

            Assert.Contains(
                (string r) => r.StartsWith("crypto/algorithm/csprng-drbg", System.StringComparison.Ordinal),
                dependsOn,
                "Entropy material must depend on the CSPRNG/DRBG.");
            Assert.Contains(
                (string r) => r.StartsWith("crypto/library/", System.StringComparison.Ordinal),
                dependsOn,
                "Entropy material must name the producing crypto library.");
        }
    }


    [TestMethod]
    public async Task ObservedCbomCapturesSignatureAndKeyGenerationAlgorithms()
    {
        using CbomObserver observer = new();

        CbomDocument document = await observer.ObserveAsync(
            RunSigningWorkloadAsync,
            "2026-06-18T00:00:00Z",
            "1.2.3").ConfigureAwait(false);

        string json = CbomJsonRenderer.Render(document);
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        JsonElement[] components = root.GetProperty("components").EnumerateArray().ToArray();

        JsonElement[] algorithmAssets = components
            .Where(c => c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "algorithm")
            .ToArray();

        //The P-256 sign and verify span collapse to one ECDSA signature algorithm asset whose
        //cryptoFunctions union both functions and whose curve is reported.
        JsonElement signatureAsset = algorithmAssets.Single(c =>
            c.GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("primitive").GetString() == "signature"
            && c.GetProperty("cryptoProperties").GetProperty("algorithmProperties").TryGetProperty("cryptoFunctions", out JsonElement functions)
            && functions.EnumerateArray().Any(f => f.GetString() == "sign"));

        JsonElement signatureProperties = signatureAsset.GetProperty("cryptoProperties").GetProperty("algorithmProperties");
        Assert.AreEqual("ECDSA", signatureProperties.GetProperty("parameterSetIdentifier").GetString(),
            "The observed signature asset must record the ECDSA algorithm.");
        Assert.AreEqual("P-256", signatureProperties.GetProperty("curve").GetString(),
            "The observed signature asset must record the P-256 curve.");

        string[] signatureFunctions = signatureProperties.GetProperty("cryptoFunctions").EnumerateArray()
            .Select(x => x.GetString()!)
            .ToArray();
        Assert.Contains("sign", signatureFunctions, "The signature asset must include the sign function.");
        Assert.Contains("verify", signatureFunctions, "The signature asset must include the verify function (merged from the verify span).");

        //The signing algorithm must depend on the producing crypto library.
        string signatureRef = signatureAsset.GetProperty("bom-ref").GetString()!;
        JsonElement dependencies = root.GetProperty("dependencies");
        JsonElement signatureEdge = dependencies.EnumerateArray()
            .First(d => d.GetProperty("ref").GetString() == signatureRef);
        string[] signatureDependsOn = signatureEdge.GetProperty("dependsOn").EnumerateArray()
            .Select(x => x.GetString()!)
            .ToArray();
        Assert.Contains(
            (string r) => r.StartsWith("crypto/library/", System.StringComparison.Ordinal),
            signatureDependsOn,
            "The signature algorithm must name the producing crypto library.");

        //The Ed25519 key generation surfaces a keygen algorithm asset plus a private-key material.
        bool hasKeygenAsset = algorithmAssets.Any(c =>
        {
            JsonElement properties = c.GetProperty("cryptoProperties").GetProperty("algorithmProperties");
            return properties.GetProperty("parameterSetIdentifier").GetString() == "Ed25519"
                && properties.GetProperty("cryptoFunctions").EnumerateArray().Any(f => f.GetString() == "keygen");
        });
        Assert.IsTrue(hasKeygenAsset, "The key generation must surface a keygen algorithm asset.");

        bool hasPrivateKeyMaterial = components.Any(c =>
            c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "related-crypto-material"
            && c.GetProperty("cryptoProperties").GetProperty("relatedCryptoMaterialProperties").TryGetProperty("type", out JsonElement t)
            && t.GetString() == "private-key");
        Assert.IsTrue(hasPrivateKeyMaterial, "The key generation must surface a private-key related-crypto-material asset.");
    }


    [TestMethod]
    public async Task ObservedCbomDerivesKeyGenerationPrimitiveFromTheAlgorithm()
    {
        using CbomObserver observer = new();

        CbomDocument document = await observer.ObserveAsync(
            RunPrimitiveDerivationWorkloadAsync,
            "2026-06-18T00:00:00Z",
            "1.2.3").ConfigureAwait(false);

        string json = CbomJsonRenderer.Render(document);
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        JsonElement[] keygenAssets = root.GetProperty("components").EnumerateArray()
            .Where(c => c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "algorithm")
            .Where(c => c.GetProperty("cryptoProperties").GetProperty("algorithmProperties")
                .GetProperty("cryptoFunctions").EnumerateArray().Any(f => f.GetString() == "keygen"))
            .ToArray();

        //Each generated key's primitive is derived from its algorithm through the shared
        //AlgorithmCatalog, so a KEM key generation is "kem", a key-agreement key generation is
        //"keyagree", and a signature key generation is "signature" — never the single hardcoded
        //value the producer used to assume for every key.
        string PrimitiveFor(string parameterSet) => keygenAssets
            .Single(c => c.GetProperty("cryptoProperties").GetProperty("algorithmProperties")
                .GetProperty("parameterSetIdentifier").GetString() == parameterSet)
            .GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("primitive").GetString()!;

        Assert.AreEqual("kem", PrimitiveFor("ML-KEM-768"), "An ML-KEM key generation must derive the kem primitive.");
        Assert.AreEqual("keyagree", PrimitiveFor("X25519"), "An X25519 key generation must derive the keyagree primitive.");
        Assert.AreEqual("signature", PrimitiveFor("ML-DSA-65"), "An ML-DSA key generation must derive the signature primitive.");
    }


    [TestMethod]
    public async Task ObservedCbomScopesCaptureByRunSoParallelWorkIsExcluded()
    {
        using CbomObserver observer = new();

        //Draw entropy OUTSIDE the observed run. Its spans land in the same process-wide
        //listener but must be excluded because they carry a different trace id.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using(Salt outsideSalt = CryptographicKeyEvents.GenerateSalt(32, CryptoTags.MdocIssuerSignedItemRandom, pool))
        {
            CbomDocument document = await observer.ObserveAsync(
                () =>
                {
                    using Nonce insideNonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, pool);
                    _ = insideNonce.UseNonce();
                    return Task.CompletedTask;
                },
                "2026-06-18T00:00:00Z",
                "1.2.3").ConfigureAwait(false);

            string json = CbomJsonRenderer.Render(document);
            using JsonDocument parsed = JsonDocument.Parse(json);

            JsonElement[] materialTypes = parsed.RootElement.GetProperty("components").EnumerateArray()
                .Where(c => c.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "related-crypto-material")
                .Where(c => c.GetProperty("cryptoProperties").GetProperty("relatedCryptoMaterialProperties").TryGetProperty("type", out _))
                .ToArray();

            bool hasNonce = materialTypes.Any(c =>
                c.GetProperty("cryptoProperties").GetProperty("relatedCryptoMaterialProperties").GetProperty("type").GetString() == "nonce");
            bool hasSalt = materialTypes.Any(c =>
                c.GetProperty("cryptoProperties").GetProperty("relatedCryptoMaterialProperties").GetProperty("type").GetString() == "salt");

            Assert.IsTrue(hasNonce, "The nonce drawn inside the observed run must be captured.");
            Assert.IsFalse(hasSalt, "The salt drawn outside the observed run must not be captured.");
        }
    }


    //A real workload exercising the newly instrumented sign/verify/keygen surfaces: a P-256
    //ECDSA sign and verify via the Microsoft provider (the sign and verify spans collapse to
    //one merged signature asset) and an Ed25519 key generation via the BouncyCastle provider
    //(inside the run, so the keygen span inherits the run trace id).
    private static async Task RunSigningWorkloadAsync()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] payload = Encoding.UTF8.GetBytes("Observed CBOM signing workload payload.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys =
            MicrosoftKeyMaterialCreator.CreateP256Keys(pool);

        using PublicKeyMemory publicKey = signingKeys.PublicKey;
        using PrivateKeyMemory privateKey = signingKeys.PrivateKey;

        (Signature signature, CryptoEvent? _) = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), payload, pool).ConfigureAwait(false);
        using var disposableSignature = signature;

        (bool isValid, CryptoEvent? _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            payload, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.IsTrue(isValid, "The observed signing-workload signature must verify.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> generatedKeys =
            BouncyCastleKeyMaterialCreator.CreateEd25519Keys(pool);
        generatedKeys.PublicKey.Dispose();
        generatedKeys.PrivateKey.Dispose();
    }


    //A real workload generating three keys whose primitives differ — an ML-KEM key
    //(key-encapsulation), an X25519 key (key-agreement), and an ML-DSA key (signature) — so the
    //observed CBOM must derive a different primitive for each from the algorithm the producer
    //stamped, not a single assumed value.
    private static Task RunPrimitiveDerivationWorkloadAsync()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> kemKeys =
            BouncyCastleKeyMaterialCreator.CreateMlKem768Keys(pool);
        kemKeys.PublicKey.Dispose();
        kemKeys.PrivateKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> agreementKeys =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(pool);
        agreementKeys.PublicKey.Dispose();
        agreementKeys.PrivateKey.Dispose();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signatureKeys =
            BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys(pool);
        signatureKeys.PublicKey.Dispose();
        signatureKeys.PrivateKey.Dispose();

        return Task.CompletedTask;
    }


    //A real workload: P-256 sign/verify via the Microsoft provider, plus a SHA-256 digest
    //and entropy-backed salt and nonce via the registered key-event delegates.
    private static async Task RunWorkloadAsync()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] payload = Encoding.UTF8.GetBytes("Observed CBOM test workload payload.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        (Signature signature, CryptoEvent? _) = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), payload, pool).ConfigureAwait(false);
        using var disposableSignature = signature;

        (bool isValid, CryptoEvent? _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            payload, signature.AsReadOnlyMemory(), publicKey.AsReadOnlyMemory()).ConfigureAwait(false);
        Assert.IsTrue(isValid, "The observed-workload signature must verify.");

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            payload, outputByteLength: 32, CryptoTags.Sha256Digest, pool).ConfigureAwait(false);
        Assert.AreEqual(32, digest.Length);

        using Salt salt = CryptographicKeyEvents.GenerateSalt(32, CryptoTags.MdocIssuerSignedItemRandom, pool);
        using Nonce nonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, pool);
        _ = nonce.UseNonce();
    }
}
