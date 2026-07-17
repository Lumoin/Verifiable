using System.Buffers;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.Fido2;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// End-to-end flow tests for the <c>fido2</c> CLI commands and their MCP tool wrappers
/// (<see cref="McpToolNames.VerifyFido2Registration"/>, <see cref="McpToolNames.VerifyFido2Assertion"/>,
/// <see cref="McpToolNames.CreateFido2Challenge"/>). Mirrors <see cref="CbomCliTests"/>'s pattern
/// exactly: every test spawns the real built <c>verifiable</c> executable (or drives it over stdio via
/// a real MCP client) — never an in-process <c>VerifiableOperations</c> call — so the shipped
/// composition root is what is actually exercised
/// (<c>feedback_flow_tests_run_shipped_path</c>). Every vector is minted fresh at test time and
/// written to temp files — the verifier under test reconstructs everything from those wire bytes
/// only. Every signature the CLI verifies (assertion signatures, packed <c>attStmt</c>, the MDS blob
/// JWS) comes from an independent oracle (raw <see cref="ECDsa"/>/<see cref="RSA"/>, the
/// <c>Verifiable.Tests.Fido2</c> test-vector helpers), never the CLI's own registered provider.
/// Credential keys that are embedded as a public key only, with no signature to check against them
/// in this file, come from <see cref="TestKeyMaterialProvider"/> instead.
/// </summary>
[TestClass]
internal sealed class Fido2CliTests
{
    /// <summary>The MSTest context for the current test run.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party ID every fixture in this file uses.</summary>
    private const string RpId = "relyingparty.example";

    /// <summary>The origin every fixture in this file uses.</summary>
    private const string Origin = "https://relyingparty.example";

    /// <summary>The base64url-encoded challenge every fixture in this file uses.</summary>
    private const string Challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The temp directory this test class's files are written to and removed from.</summary>
    private string tempDirectory = null!;


    [TestInitialize]
    public void Initialize()
    {
        tempDirectory = Path.Combine(Path.GetTempPath(), $"fido2-cli-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);
    }


    [TestCleanup]
    public void Cleanup()
    {
        if(Directory.Exists(tempDirectory))
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }


    [TestMethod]
    public async Task RegistrationNoneFormatWithNoAnchorsSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        credentialKeyMaterial.PrivateKey.Dispose();
        using PublicKeyMemory credentialPublicKey = credentialKeyMaterial.PublicKey;
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(
            BuildP256CoseKey(credentialPublicKey, WellKnownCoseAlgorithms.Es256));

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            ["fido2", "verify-registration", attestationObjectPath, clientDataPath, "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument record = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual(1, record.RootElement.GetProperty("version").GetInt32());
        Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, record.RootElement.GetProperty("type").GetString());
    }


    [TestMethod]
    public async Task RegistrationPackedCertifiedWithFileTrustAnchorSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using PackedFixture fixture = CreatePackedRegistrationFixture();
        string attestationObjectPath = WriteTempFile("attestation-object.cbor", fixture.AttestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", fixture.ClientDataJsonBytes);
        string trustAnchorPath = WriteTempFile("attestation-root.der", fixture.AttestationRootCertificate.RawData);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--trust-anchor", trustAnchorPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument record = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual(1, record.RootElement.GetProperty("version").GetInt32());
    }


    [TestMethod]
    public async Task RegistrationPackedCertifiedThroughMdsBlobSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using PackedFixture fixture = CreatePackedRegistrationFixture();

        //Cert-factory: CertificateRequest-based X.509 CA minting needs a real ECDsa key.
        using ECDsa mdsRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 mdsRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Root Fido2CliTests", mdsRootKey);
        //Cert-factory (leaf) and independent oracle: also signs the MDS blob JWS the CLI verifies.
        using ECDsa mdsSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 mdsSigningCertificate = MetadataBlobTestVectors.CreateMdsSigningCertificate(mdsRootCertificate, mdsSigningKey);

        string metadataStatementJson = MetadataBlobTestVectors.BuildMetadataStatementJson([fixture.AttestationRootCertificate.RawData]);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(
            aaguid: fixture.Aaguid,
            metadataStatementJson: metadataStatementJson,
            statusReportJsons: [MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.FidoCertified, "2020-01-01")]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [mdsSigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2099-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(mdsSigningKey, data));

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", fixture.AttestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", fixture.ClientDataJsonBytes);
        string mdsBlobPath = WriteTempFile("mds-blob.jws", blobBytes);
        string mdsRootPath = WriteTempFile("mds-root.der", mdsRootCertificate.RawData);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--mds-blob", mdsBlobPath, "--mds-root", mdsRootPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument record = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual(1, record.RootElement.GetProperty("version").GetInt32());
    }


    [TestMethod]
    public async Task RegistrationTamperedAttestationObjectFailsWithExitCodeOne()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        credentialKeyMaterial.PrivateKey.Dispose();
        using PublicKeyMemory credentialPublicKey = credentialKeyMaterial.PublicKey;
        //Oracle: computed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce, then corrupted to force a mismatch.
        byte[] tamperedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        tamperedRpIdHash[0] ^= 0xFF;

        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(
            BuildP256CoseKey(credentialPublicKey, WellKnownCoseAlgorithms.Es256),
            rpIdHash: tamperedRpIdHash);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            ["fido2", "verify-registration", attestationObjectPath, clientDataPath, "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule failed", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task RegistrationWithDiscouragedUserVerificationSucceedsAndAuthenticatorAttachmentFlowsIntoRecord()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        credentialKeyMaterial.PrivateKey.Dispose();
        using PublicKeyMemory credentialPublicKey = credentialKeyMaterial.PublicKey;
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(
            BuildP256CoseKey(credentialPublicKey, WellKnownCoseAlgorithms.Es256));

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath, "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--user-verification", "discouraged", "--authenticator-attachment", "platform"
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument record = JsonDocument.Parse(result.Stdout);
        Assert.AreEqual("platform", record.RootElement.GetProperty("authenticatorAttachment").GetString());
    }


    [TestMethod]
    public async Task RegistrationWithUnrecognizedUserVerificationValueFailsWithExitCodeOne()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        credentialKeyMaterial.PrivateKey.Dispose();
        using PublicKeyMemory credentialPublicKey = credentialKeyMaterial.PublicKey;
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(
            BuildP256CoseKey(credentialPublicKey, WellKnownCoseAlgorithms.Es256));

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath, "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--user-verification", "not-a-real-value"
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Unrecognized --user-verification value", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task RegistrationEdDsaCredentialFailsWithCleanUnsupportedAlgorithmMessage()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Placeholder X coordinate — the CLI must reject the unsupported algorithm before this
        //value is ever inspected, so its content is immaterial to the assertion.
        CoseKey edDsaCoseKey = new(kty: CoseKeyTypes.Okp, alg: WellKnownCoseAlgorithms.EdDsa, curve: CoseKeyCurves.Ed25519, x: new byte[32]);
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(edDsaCoseKey);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            ["fido2", "verify-registration", attestationObjectPath, clientDataPath, "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Unsupported credential algorithm", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("ES256", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task AssertionEs256RoundTripFromRealRegistrationSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Independent oracle: the same framework ECDsa instance mints the embedded credential key
        //and later signs the assertion, so the CLI's signature verification checks a signature it
        //did not produce itself.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 7);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
        string signaturePath = WriteTempFile("signature.bin", signature);
        string clientDataPath = WriteTempFile("assertion-client-data.json", clientDataJson);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument verdict = JsonDocument.Parse(result.Stdout);
        Assert.IsTrue(verdict.RootElement.GetProperty("isAcceptable").GetBoolean());
        Assert.IsTrue(verdict.RootElement.GetProperty("signatureValid").GetBoolean());
        Assert.AreEqual(7u, verdict.RootElement.GetProperty("signCount").GetUInt32());
    }


    [TestMethod]
    public async Task AssertionWithRequiredUserVerificationAndClearUvFlagFailsNamingTheClaim()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Independent oracle: the same framework ECDsa instance mints the embedded credential key
        //and later signs the assertion, so the CLI's signature verification checks a signature it
        //did not produce itself.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        //UP set, UV clear — the axis this test exercises.
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.UserPresentBit, signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
        string signaturePath = WriteTempFile("signature.bin", signature);
        string clientDataPath = WriteTempFile("assertion-client-data.json", clientDataJson);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge, "--user-verification", "required"
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Fido2AssertionUserVerified", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task AssertionRs256RoundTripFromRealRegistrationSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Independent oracle: the same framework RSA instance mints the embedded credential key and
        //later signs the assertion, so the CLI's signature verification checks a signature it did
        //not produce itself.
        using RSA credentialKey = RSA.Create(2048);
        RSAParameters publicParameters = credentialKey.ExportParameters(includePrivateParameters: false);
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, alg: WellKnownCoseAlgorithms.Rs256, n: publicParameters.Modulus, e: publicParameters.Exponent);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey, credentialPublicKeyCbor: EncodeRsaCoseKeyCbor(coseKey));

        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 3);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = credentialKey.SignData(toBeSigned, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
        string signaturePath = WriteTempFile("signature.bin", signature);
        string clientDataPath = WriteTempFile("assertion-client-data.json", clientDataJson);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument verdict = JsonDocument.Parse(result.Stdout);
        Assert.IsTrue(verdict.RootElement.GetProperty("isAcceptable").GetBoolean());
        Assert.AreEqual(3u, verdict.RootElement.GetProperty("signCount").GetUInt32());
    }


    [TestMethod]
    public async Task AssertionTamperedSignatureFailsNamingTheClaim()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Independent oracle: the same framework ECDsa instance mints the embedded credential key
        //and later signs the assertion, so the pre-tamper signature the CLI must reject is one it
        //did not produce itself.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);
        signature[^1] ^= 0xFF;

        string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
        string signaturePath = WriteTempFile("signature.bin", signature);
        string clientDataPath = WriteTempFile("assertion-client-data.json", clientDataJson);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("assertion signature did not verify", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task CreateChallengeDefaultLengthDecodesToThirtyTwoBytesAndTwoCallsDiffer()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        var firstResult = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["fido2", "challenge"], TestContext.CancellationToken).ConfigureAwait(false);
        var secondResult = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["fido2", "challenge"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, firstResult.ExitCode, firstResult.Stderr);
        Assert.AreEqual(0, secondResult.ExitCode, secondResult.Stderr);

        string firstChallenge = firstResult.Stdout.Trim();
        string secondChallenge = secondResult.Stdout.Trim();

        Assert.AreNotEqual(firstChallenge, secondChallenge);
        Assert.AreEqual(32, DecodedBase64UrlLength(firstChallenge));
    }


    [TestMethod]
    public async Task CreateChallengeBelowFloorFailsWithExitCodeOne()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath, ["fido2", "challenge", "--length", "15"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
    }


    [TestMethod]
    public async Task EmitCbomObserveStillCapturesSignatureAndHashAfterFido2WorkloadAddition()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["cbom", "--observe"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        using JsonDocument document = JsonDocument.Parse(result.Stdout);
        List<string> primitives = CollectAlgorithmPrimitives(document.RootElement);
        Assert.Contains("signature", primitives, "Observed CBOM must still capture a signature operation after the FIDO2 workload addition.");
        Assert.Contains("hash", primitives, "Observed CBOM must still capture a digest operation after the FIDO2 workload addition.");
    }


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpToolsAreRegisteredAndCreateFido2ChallengeIsCallable()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            var toolNames = tools.Select(tool => tool.Name).ToList();

            Assert.Contains(McpToolNames.VerifyFido2Registration, toolNames);
            Assert.Contains(McpToolNames.VerifyFido2Assertion, toolNames);
            Assert.Contains(McpToolNames.CreateFido2Challenge, toolNames);

            var challengeResult = await client.CallToolAsync(
                McpToolNames.CreateFido2Challenge,
                new Dictionary<string, object?>(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, challengeResult.IsError, "CreateFido2Challenge must not return an error.");
            string challenge = string.Concat(challengeResult.Content.OfType<TextContentBlock>().Select(block => block.Text));
            Assert.AreEqual(32, DecodedBase64UrlLength(challenge));
        }
    }


    /// <summary>Fails the caller's test with <see cref="Assert.Inconclusive(string)"/> when the CLI executable is not built, else returns its path.</summary>
    private static string? RequireExecutable()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");
        }

        return executablePath;
    }


    /// <summary>Writes <paramref name="content"/> to a fresh file under this test's temp directory.</summary>
    private string WriteTempFile(string fileName, byte[] content)
    {
        string path = Path.Combine(tempDirectory, $"{Guid.NewGuid():N}-{fileName}");
        File.WriteAllBytes(path, content);

        return path;
    }


    /// <summary>Decodes a base64url string and returns the decoded byte count, for length assertions.</summary>
    private static int DecodedBase64UrlLength(string value)
    {
        using IMemoryOwner<byte> buffer = BaseMemoryPool.Shared.Rent(Base64Url.GetMaxDecodedLength(value.Length));
        Base64Url.TryDecodeFromChars(value, buffer.Memory.Span, out int bytesWritten);

        return bytesWritten;
    }


    /// <summary>
    /// Collects the <c>algorithmProperties.primitive</c> value of every algorithm component in a
    /// CBOM document (the <c>CbomCliTests</c> structural-assertion pattern, reused here so this
    /// test does not depend on the CLI's exact JSON whitespace formatting).
    /// </summary>
    private static List<string> CollectAlgorithmPrimitives(JsonElement root)
    {
        var primitives = new List<string>();
        foreach(JsonElement component in root.GetProperty("components").EnumerateArray())
        {
            if(component.TryGetProperty("cryptoProperties", out JsonElement cryptoProperties)
                && cryptoProperties.TryGetProperty("algorithmProperties", out JsonElement algorithmProperties)
                && algorithmProperties.TryGetProperty("primitive", out JsonElement primitive)
                && primitive.GetString() is string value)
            {
                primitives.Add(value);
            }
        }

        return primitives;
    }


    /// <summary>
    /// Runs the real <c>verify-registration</c> CLI command for a <c>none</c>-format credential, and
    /// returns the path to the credential record JSON file it wrote — the verb-to-verb round trip
    /// through files ruling 12 requires for the assertion flow tests.
    /// </summary>
    private async Task<string> RegisterNoneCredentialAsync(string executablePath, CoseKey coseKey, byte[]? credentialPublicKeyCbor = null)
    {
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(coseKey, credentialPublicKeyCbor: credentialPublicKeyCbor);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);
        string recordOutputPath = Path.Combine(tempDirectory, $"{Guid.NewGuid():N}-credential-record.json");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--output", recordOutputPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.IsTrue(File.Exists(recordOutputPath), "The registration verb must write the credential record file.");

        return recordOutputPath;
    }


    /// <summary>
    /// Builds a <c>none</c>-format registration's <c>attestationObject</c>/<c>clientDataJSON</c> wire
    /// bytes for <paramref name="credentialPublicKey"/>.
    /// </summary>
    private static (byte[] AttestationObjectBytes, byte[] ClientDataJsonBytes, Guid Aaguid) BuildNoneRegistrationMaterial(
        CoseKey credentialPublicKey, byte[]? rpIdHash = null, byte[]? credentialPublicKeyCbor = null)
    {
        Guid aaguid = Guid.NewGuid();
        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] effectiveRpIdHash = rpIdHash ?? SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        //Opaque random credential identifier — a junk payload, not key material.
        byte[] credentialId = RandomNumberGenerator.GetBytes(16);
        byte[] coseKeyCbor = credentialPublicKeyCbor ?? MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, coseKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(effectiveRpIdHash, flags, signCount: 0, attestedCredentialData);

        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, Challenge, Origin);
        //0xA0 is the canonical CBOR encoding of an empty map — the `none` format's attStmt.
        byte[] attestationObject = EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.None, [0xA0], authenticatorData);

        return (attestationObject, clientDataJson, aaguid);
    }


    /// <summary>
    /// Mints a packed-certified registration fixture: an independent attestation root/leaf pair, an
    /// ES256 credential, and the real wire <c>authData</c>/<c>clientDataJSON</c>/<c>attestationObject</c>
    /// bytes — mirrors <c>MetadataDrivenRegistrationTests</c>'s own fixture shape.
    /// </summary>
    private static PackedFixture CreatePackedRegistrationFixture()
    {
        Guid aaguid = Guid.NewGuid();

        //Cert-factory: CertificateRequest-based X.509 CA minting needs a real ECDsa key.
        ECDsa attestationRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationRootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test Fido2CliTests Attestation Root", attestationRootKey);
        //Cert-factory (leaf) and independent oracle: also signs the packed attStmt below, which the
        //CLI verifies against the leaf certificate's public key.
        ECDsa attestationLeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationLeafCertificate = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            attestationRootCertificate, attestationLeafKey, isCertificateAuthority: false,
            Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        //The WebAuthn credential key itself is embedded as a public key only — it never signs
        //anything in this fixture, so it is mere fixture material sourced from the project's
        //key-material provider rather than a freshly minted framework key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        credentialKeyMaterial.PrivateKey.Dispose();
        using PublicKeyMemory credentialPublicKeyMaterial = credentialKeyMaterial.PublicKey;
        CoseKey credentialPublicKey = BuildP256CoseKey(credentialPublicKeyMaterial, WellKnownCoseAlgorithms.Es256);
        //Opaque random credential identifier — a junk payload, not key material.
        byte[] credentialId = RandomNumberGenerator.GetBytes(16);
        //Oracle: recomputed independently of the CLI so its own rpIdHash derivation from --rp-id is
        //exercised against a value it did not produce.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));

        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialData);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(attestationLeafKey, toBeSigned);

        byte[] attStmtCbor = EncodePackedAttStmt(WellKnownCoseAlgorithms.Es256, signature, [attestationLeafCertificate.RawData]);
        byte[] attestationObjectBytes = EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.Packed, attStmtCbor, authenticatorData);

        return new PackedFixture(aaguid, attestationObjectBytes, clientDataJson, attestationRootCertificate, attestationLeafCertificate, attestationLeafKey, attestationRootKey);
    }


    /// <summary>
    /// Builds a P-256 COSE_Key view directly from a <see cref="PublicKeyMemory"/>'s SEC1 point — the
    /// <see cref="TestKeyMaterialProvider"/>-sourced counterpart to
    /// <see cref="Fido2AttestationTestVectors.CreateP256CoseKey"/> for fixtures whose credential key
    /// is embedded as a public key only and never signs anything in this file.
    /// </summary>
    private static CoseKey BuildP256CoseKey(PublicKeyMemory publicKey, int? alg)
    {
        EllipticCurveUtilities.ExtractCoordinates(publicKey.AsReadOnlySpan(), EllipticCurveTypes.P256, out ReadOnlySpan<byte> x, out ReadOnlySpan<byte> y);

        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: alg, curve: CoseKeyCurves.P256, x: x.ToArray(), y: y.ToArray());
    }


    /// <summary>Encodes a valid <c>attestationObject</c> CBOR map in the CTAP2 canonical CBOR encoding form.</summary>
    private static byte[] EncodeAttestationObject(string format, byte[] attStmtCbor, byte[] authData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(format);
        writer.WriteTextString("attStmt");
        writer.WriteEncodedValue(attStmtCbor);
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Encodes a valid <c>packed</c> <c>attStmt</c> CBOR map (<c>alg</c>/<c>sig</c>/<c>x5c</c>).</summary>
    private static byte[] EncodePackedAttStmt(int alg, byte[] sig, IReadOnlyList<byte[]> x5c)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("alg");
        writer.WriteInt32(alg);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5c.Count);
        foreach(byte[] certificate in x5c)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Encodes an RSA COSE_Key CBOR map (<c>kty</c>/<c>alg</c>/<c>n</c>/<c>e</c>) — the RS256
    /// credential-embedding shape <see cref="MdocCborCoseKeyWriter"/> does not itself support (it
    /// targets the EC2/OKP mdoc key shapes only).
    /// </summary>
    private static byte[] EncodeRsaCoseKeyCbor(CoseKey coseKey)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyParameters.Kty);
        writer.WriteInt32(coseKey.Kty);
        writer.WriteInt32(CoseKeyParameters.Alg);
        writer.WriteInt32(coseKey.Alg!.Value);
        writer.WriteInt32(CoseKeyParameters.RsaN);
        writer.WriteByteString(coseKey.N!.Value.Span);
        writer.WriteInt32(CoseKeyParameters.RsaE);
        writer.WriteByteString(coseKey.E!.Value.Span);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// A minted packed-certified registration fixture. Owns and disposes every certificate and key.
    /// </summary>
    private sealed class PackedFixture: IDisposable
    {
        public PackedFixture(
            Guid aaguid,
            byte[] attestationObjectBytes,
            byte[] clientDataJsonBytes,
            X509Certificate2 attestationRootCertificate,
            X509Certificate2 attestationLeafCertificate,
            ECDsa attestationLeafKey,
            ECDsa attestationRootKey)
        {
            Aaguid = aaguid;
            AttestationObjectBytes = attestationObjectBytes;
            ClientDataJsonBytes = clientDataJsonBytes;
            AttestationRootCertificate = attestationRootCertificate;
            AttestationLeafCertificate = attestationLeafCertificate;
            AttestationLeafKey = attestationLeafKey;
            AttestationRootKey = attestationRootKey;
        }

        public Guid Aaguid { get; }
        public byte[] AttestationObjectBytes { get; }
        public byte[] ClientDataJsonBytes { get; }
        public X509Certificate2 AttestationRootCertificate { get; }
        public X509Certificate2 AttestationLeafCertificate { get; }
        public ECDsa AttestationLeafKey { get; }
        public ECDsa AttestationRootKey { get; }

        public void Dispose()
        {
            AttestationRootCertificate.Dispose();
            AttestationLeafCertificate.Dispose();
            AttestationLeafKey.Dispose();
            AttestationRootKey.Dispose();
        }
    }
}
