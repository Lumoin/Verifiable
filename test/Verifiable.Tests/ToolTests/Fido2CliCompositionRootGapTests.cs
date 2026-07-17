using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Cbor;
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
/// Wave-8 test-gap closure for the FIDO2 CLI/MCP composition root (synthesis package F): drives the
/// <c>android-key</c>/<c>fido-u2f</c> attestation formats, the <c>VerifyFido2Registration</c>/
/// <c>VerifyFido2Assertion</c> MCP tools, the ECDSA P-384/P-521 and RSASSA-PSS assertion algorithms, the
/// <c>--trust-anchor</c>/<c>--mds-blob</c> mutual-exclusion guard, the newly wired
/// <c>--require-tee-enforced-authorizations</c> knob, and the per-verb file-not-found error paths through
/// the REAL built executable — none of which <see cref="Fido2CliTests"/> exercises. Mirrors that file's
/// pattern exactly: every test spawns the real <c>verifiable</c> executable (or drives it over stdio via a
/// real MCP client), and every vector is minted fresh at test time by an independent oracle (raw
/// <see cref="ECDsa"/>/<see cref="RSA"/>, BouncyCastle for RSA-PSS, the <c>Verifiable.Tests.Fido2</c>
/// test-vector helpers), never the CLI's own registered provider.
/// </summary>
[TestClass]
internal sealed class Fido2CliCompositionRootGapTests
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
        tempDirectory = Path.Combine(Path.GetTempPath(), $"fido2-cli-gap-tests-{Guid.NewGuid():N}");
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


    // ---------------------------------------------------------------------------------------
    // Finding #11 — MCP VerifyFido2Registration/VerifyFido2Assertion are never actually invoked
    // (only ListToolsAsync presence + CreateFido2Challenge are covered elsewhere).
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The MCP <c>VerifyFido2Registration</c>/<c>VerifyFido2Assertion</c> tools, driven over a real
    /// stdio JSON-RPC client with named arguments matching the wrapper's own parameter names — the
    /// binding path a renamed/reordered parameter (e.g. the wrapper's own <c>mdsBlobPath</c>/
    /// <c>mdsRootPath</c>) would break silently, since <see cref="Fido2CliTests"/> only calls
    /// <c>CreateFido2Challenge</c> over MCP.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpVerifyFido2RegistrationAndAssertionRoundTripSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Oracle-keep: the private half independently signs the assertion below via
        //Fido2AttestationTestVectors.SignWithEcdsaP256, so the MCP verifier is exercised against a
        //signature genuinely external to the CLI's own crypto stack.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(
            Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256));

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            var registrationResult = await client.CallToolAsync(
                McpToolNames.VerifyFido2Registration,
                new Dictionary<string, object?>
                {
                    ["attestationObjectPath"] = attestationObjectPath,
                    ["clientDataJsonPath"] = clientDataPath,
                    ["rpId"] = RpId,
                    ["origin"] = Origin,
                    ["challenge"] = Challenge
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, registrationResult.IsError, "VerifyFido2Registration must not return an error.");
            string recordJson = string.Concat(registrationResult.Content.OfType<TextContentBlock>().Select(block => block.Text));
            using(JsonDocument record = JsonDocument.Parse(recordJson))
            {
                Assert.AreEqual(1, record.RootElement.GetProperty("version").GetInt32());
            }

            string credentialRecordPath = WriteTempFile("credential-record.json", Encoding.UTF8.GetBytes(recordJson));

            //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
            //what VerifyFido2Assertion's own RP ID check computes.
            byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
            byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 9);
            byte[] assertionClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
            using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(assertionClientDataJson, BaseMemoryPool.Shared);
            byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
            byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

            string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
            string signaturePath = WriteTempFile("signature.bin", signature);
            string assertionClientDataPath = WriteTempFile("assertion-client-data.json", assertionClientDataJson);

            var assertionResult = await client.CallToolAsync(
                McpToolNames.VerifyFido2Assertion,
                new Dictionary<string, object?>
                {
                    ["credentialRecordPath"] = credentialRecordPath,
                    ["authenticatorDataPath"] = authenticatorDataPath,
                    ["signaturePath"] = signaturePath,
                    ["clientDataJsonPath"] = assertionClientDataPath,
                    ["rpId"] = RpId,
                    ["origin"] = Origin,
                    ["challenge"] = Challenge
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, assertionResult.IsError, "VerifyFido2Assertion must not return an error.");
            string verdictJson = string.Concat(assertionResult.Content.OfType<TextContentBlock>().Select(block => block.Text));
            using JsonDocument verdict = JsonDocument.Parse(verdictJson);
            Assert.IsTrue(verdict.RootElement.GetProperty("isAcceptable").GetBoolean());
            Assert.IsTrue(verdict.RootElement.GetProperty("signatureValid").GetBoolean());
            Assert.AreEqual(9u, verdict.RootElement.GetProperty("signCount").GetUInt32());
        }
    }


    /// <summary>
    /// The MCP wrapper's <c>mdsBlobPath</c>/<c>mdsRootPath</c> named arguments specifically — an
    /// <c>android-key</c> registration resolved through a real MDS BLOB over the JSON-RPC binding path,
    /// naming the two arguments the synthesis's cited mutation (a swapped
    /// <c>mdsBlobPath</c>/<c>mdsRootPath</c> order in the MCP wrapper) would silently break.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpVerifyFido2RegistrationThroughMdsBlobAndMdsRootArgumentsSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using AndroidKeyFixture fixture = CreateAndroidKeyRegistrationFixture(
            AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);

        //Cert-factory-keep: CertificateRequest (inside CreateMdsRootCa) requires a framework
        //AsymmetricAlgorithm to mint the self-signed MDS root CA certificate.
        using ECDsa mdsRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 mdsRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Root Fido2CliCompositionRootGapTests", mdsRootKey);
        //Cert-factory-keep: CertificateRequest (inside CreateMdsSigningCertificate) requires a framework
        //AsymmetricAlgorithm; the same key also independently signs the MDS BLOB JWS below (SignEs256).
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

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            var result = await client.CallToolAsync(
                McpToolNames.VerifyFido2Registration,
                new Dictionary<string, object?>
                {
                    ["attestationObjectPath"] = attestationObjectPath,
                    ["clientDataJsonPath"] = clientDataPath,
                    ["rpId"] = RpId,
                    ["origin"] = Origin,
                    ["challenge"] = Challenge,
                    ["mdsBlobPath"] = mdsBlobPath,
                    ["mdsRootPath"] = mdsRootPath
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, result.IsError, "VerifyFido2Registration through the MDS BLOB arguments must not return an error.");
            string recordJson = string.Concat(result.Content.OfType<TextContentBlock>().Select(block => block.Text));
            using JsonDocument record = JsonDocument.Parse(recordJson);
            Assert.AreEqual(1, record.RootElement.GetProperty("version").GetInt32());
        }
    }


    // ---------------------------------------------------------------------------------------
    // Finding #12 — the --trust-anchor / --mds-blob+--mds-root mutual-exclusion guard is untested.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Supplying both <c>--trust-anchor</c> and <c>--mds-blob</c>/<c>--mds-root</c> together is
    /// rejected with the specific mutual-exclusion message, never silently taking the trust-anchor
    /// branch and ignoring the MDS arguments.
    /// </summary>
    [TestMethod]
    public async Task RegistrationWithBothTrustAnchorAndMdsBlobFailsWithMutualExclusionMessage()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //The credential key never signs anything here: the mutual-exclusion guard fires before the
        //attestation object is even parsed, so the embedded public key is mere fixture material.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(credentialPublicKey);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);

        //Neither file needs to exist nor be well-formed: the mutual-exclusion guard runs before either is read.
        string trustAnchorPath = Path.Combine(tempDirectory, "unused-trust-anchor.der");
        string mdsBlobPath = Path.Combine(tempDirectory, "unused-mds-blob.jws");
        string mdsRootPath = Path.Combine(tempDirectory, "unused-mds-root.der");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--trust-anchor", trustAnchorPath, "--mds-blob", mdsBlobPath, "--mds-root", mdsRootPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("not both", result.Stderr, StringComparison.Ordinal);
    }


    // ---------------------------------------------------------------------------------------
    // Finding #13 — android-key/fido-u2f are never driven through the CLI/MCP composition root
    // (Fido2CliTests only mints none/packed fixtures).
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An <c>android-key</c> registration, minted as real wire <c>attestationObject</c> bytes, verifies
    /// successfully through the real <c>verify-registration</c> CLI command with a file trust anchor —
    /// proving <see cref="Fido2AttestationSelectors.FromFormats"/>'s <c>android-key</c> wiring in
    /// <c>VerifiableOperations.Fido2</c>'s composition root, not merely the direct-verifier level.
    /// </summary>
    [TestMethod]
    public async Task RegistrationAndroidKeyFormatWithFileTrustAnchorSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using AndroidKeyFixture fixture = CreateAndroidKeyRegistrationFixture(
            AndroidKeyAttestationTestVectors.EmptyAuthorizationList, AndroidKeyAttestationTestVectors.ConformantAuthorizationList);

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


    /// <summary>
    /// A <c>fido-u2f</c> registration, minted as real wire <c>attestationObject</c> bytes, verifies
    /// successfully through the real <c>verify-registration</c> CLI command with a file trust anchor —
    /// the composition-root counterpart to <see cref="RegistrationAndroidKeyFormatWithFileTrustAnchorSucceeds"/>.
    /// </summary>
    [TestMethod]
    public async Task RegistrationFidoU2fFormatWithFileTrustAnchorSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using FidoU2fFixture fixture = CreateFidoU2fRegistrationFixture();

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


    // ---------------------------------------------------------------------------------------
    // Finding #14 — requireTeeEnforcedAuthorizations was unreachable from either front door.
    // Source fix landed in this change: Program.cs's verify-registration command now exposes
    // --require-tee-enforced-authorizations, and VerifiableMcpServer's VerifyFido2Registration
    // now exposes the matching parameter. These two tests prove the knob is load-bearing through
    // the real CLI composition root (the MCP side reuses the identical VerifiableOperations call).
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A software-only android-key credential (origin/purpose satisfied only by <c>softwareEnforced</c>,
    /// <c>teeEnforced</c> empty) succeeds under the CLI's default union-mode policy, i.e. without
    /// <c>--require-tee-enforced-authorizations</c>.
    /// </summary>
    [TestMethod]
    public async Task RegistrationAndroidKeySoftwareOnlyKeySucceedsWithoutTeeEnforcementFlag()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using AndroidKeyFixture fixture = CreateAndroidKeyRegistrationFixture(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: AndroidKeyAttestationTestVectors.EmptyAuthorizationList);

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
    }


    /// <summary>
    /// The SAME software-only android-key credential is rejected, naming
    /// <see cref="Fido2AttestationErrors.KeyOriginNotGenerated"/>, when
    /// <c>--require-tee-enforced-authorizations</c> is supplied — proving the newly wired CLI knob is
    /// load-bearing (this exact fixture succeeds without it, per the paired positive test) rather than
    /// a parsed-but-ignored option.
    /// </summary>
    [TestMethod]
    public async Task RegistrationAndroidKeySoftwareOnlyKeyFailsWithTeeEnforcementFlagNamingKeyOriginNotGenerated()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        using AndroidKeyFixture fixture = CreateAndroidKeyRegistrationFixture(
            softwareEnforced: AndroidKeyAttestationTestVectors.ConformantAuthorizationList,
            teeEnforced: AndroidKeyAttestationTestVectors.EmptyAuthorizationList);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", fixture.AttestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", fixture.ClientDataJsonBytes);
        string trustAnchorPath = WriteTempFile("attestation-root.der", fixture.AttestationRootCertificate.RawData);

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--trust-anchor", trustAnchorPath, "--require-tee-enforced-authorizations"
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains(Fido2AttestationErrors.KeyOriginNotGenerated.Code, result.Stderr, StringComparison.Ordinal);
    }


    // ---------------------------------------------------------------------------------------
    // Finding #28 — only ES256/RS256 round-trip through a live CLI signature; ES384/ES512/PS256
    // (and by extension the registry entries backing them) are never exercised.
    // ---------------------------------------------------------------------------------------

    /// <summary>An ES384 assertion, signed by an independent P-384 <see cref="ECDsa"/> oracle, verifies through the real CLI.</summary>
    [TestMethod]
    public async Task AssertionEs384RoundTripFromRealRegistrationSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Oracle-keep: the private half independently signs the assertion below via
        //Fido2AttestationTestVectors.SignWithEcdsaP384, so the ES384 registry wiring is exercised
        //against a signature genuinely external to the CLI's own crypto stack.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP384CoseKey(credentialKey, WellKnownCoseAlgorithms.Es384);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what the CLI's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 5);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP384(credentialKey, toBeSigned);

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
        Assert.AreEqual(5u, verdict.RootElement.GetProperty("signCount").GetUInt32());
    }


    /// <summary>An ES512 assertion, signed by an independent P-521 <see cref="ECDsa"/> oracle, verifies through the real CLI.</summary>
    [TestMethod]
    public async Task AssertionEs512RoundTripFromRealRegistrationSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Oracle-keep: the private half independently signs the assertion below via
        //Fido2AttestationTestVectors.SignWithEcdsaP521, so the ES512 registry wiring is exercised
        //against a signature genuinely external to the CLI's own crypto stack.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP521CoseKey(credentialKey, WellKnownCoseAlgorithms.Es512);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what the CLI's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 6);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP521(credentialKey, toBeSigned);

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
        Assert.AreEqual(6u, verdict.RootElement.GetProperty("signCount").GetUInt32());
    }


    /// <summary>
    /// A PS256 (RSASSA-PSS/SHA-256) assertion, signed by the independent BouncyCastle PSS oracle,
    /// verifies through the real CLI — the PSS-family registry-wiring representative the synthesis calls
    /// out alongside ES384/ES512.
    /// </summary>
    [TestMethod]
    public async Task AssertionPs256RoundTripFromRealRegistrationSucceeds()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Oracle-keep: the private half independently signs the assertion below via
        //Fido2AttestationTestVectors.SignWithRsaPssSha256Async (a BouncyCastle RSASSA-PSS oracle), so
        //the PS256 registry wiring is exercised against a signature genuinely external to the CLI's
        //own crypto stack.
        using RSA credentialKey = RSA.Create(2048);
        RSAParameters publicParameters = credentialKey.ExportParameters(includePrivateParameters: false);
        CoseKey coseKey = new(kty: CoseKeyTypes.Rsa, alg: WellKnownCoseAlgorithms.Ps256, n: publicParameters.Modulus, e: publicParameters.Exponent);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey, credentialPublicKeyCbor: EncodeRsaCoseKeyCbor(coseKey));

        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what the CLI's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 2);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = await Fido2AttestationTestVectors.SignWithRsaPssSha256Async(credentialKey, toBeSigned).ConfigureAwait(false);

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
        Assert.AreEqual(2u, verdict.RootElement.GetProperty("signCount").GetUInt32());
    }


    // ---------------------------------------------------------------------------------------
    // Finding #29 — the nine purpose-built file-read catch blocks are never driven with a missing path;
    // only the outer catch-all's exit code (not the verb-specific message) would be proven either way.
    // ---------------------------------------------------------------------------------------

    /// <summary>A missing <c>attestation-object</c> path fails with the registration verb's own file-read message.</summary>
    [TestMethod]
    public async Task RegistrationWithMissingAttestationObjectFileFailsNamingRegistrationInputFiles()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        string missingAttestationObjectPath = Path.Combine(tempDirectory, "does-not-exist-attestation-object.cbor");
        string unusedClientDataPath = Path.Combine(tempDirectory, "unused-client-data.json");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", missingAttestationObjectPath, unusedClientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error reading registration input files", result.Stderr, StringComparison.Ordinal);
    }


    /// <summary>A missing <c>credential-record</c> path fails with the assertion verb's own file-read message.</summary>
    [TestMethod]
    public async Task AssertionWithMissingCredentialRecordFileFailsNamingAssertionInputFiles()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        string missingCredentialRecordPath = Path.Combine(tempDirectory, "does-not-exist-credential-record.json");
        string unusedAuthenticatorDataPath = Path.Combine(tempDirectory, "unused-authenticator-data.bin");
        string unusedSignaturePath = Path.Combine(tempDirectory, "unused-signature.bin");
        string unusedClientDataPath = Path.Combine(tempDirectory, "unused-client-data.json");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", missingCredentialRecordPath, unusedAuthenticatorDataPath, unusedSignaturePath, unusedClientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error reading assertion input files", result.Stderr, StringComparison.Ordinal);
    }


    /// <summary>A missing <c>--trust-anchor</c> path fails with its own dedicated file-read message.</summary>
    [TestMethod]
    public async Task RegistrationWithMissingTrustAnchorFileFailsNamingTrustAnchorCertificate()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //The credential key never signs anything here: the missing trust anchor file fails before
        //the attestation object is parsed, so the embedded public key is mere fixture material.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(credentialPublicKey);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);
        string missingTrustAnchorPath = Path.Combine(tempDirectory, "does-not-exist-trust-anchor.der");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--trust-anchor", missingTrustAnchorPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error reading trust anchor certificate", result.Stderr, StringComparison.Ordinal);
    }


    /// <summary>A missing <c>--mds-blob</c> path fails with its own dedicated MDS file-read message.</summary>
    [TestMethod]
    public async Task RegistrationWithMissingMdsBlobFileFailsNamingMdsInputFiles()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //The credential key never signs anything here: the missing MDS blob file fails before the
        //attestation object is parsed, so the embedded public key is mere fixture material.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        (byte[] attestationObjectBytes, byte[] clientDataJsonBytes, _) = BuildNoneRegistrationMaterial(credentialPublicKey);

        string attestationObjectPath = WriteTempFile("attestation-object.cbor", attestationObjectBytes);
        string clientDataPath = WriteTempFile("client-data.json", clientDataJsonBytes);
        string missingMdsBlobPath = Path.Combine(tempDirectory, "does-not-exist-mds-blob.jws");
        //Never read: the blob path throws first, so this argument's own existence is immaterial.
        string unusedMdsRootPath = Path.Combine(tempDirectory, "unused-mds-root.der");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-registration", attestationObjectPath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge,
                "--mds-blob", missingMdsBlobPath, "--mds-root", unusedMdsRootPath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error reading MDS input files", result.Stderr, StringComparison.Ordinal);
    }


    /// <summary>A missing <c>--user-handle</c> path fails with its own dedicated file-read message.</summary>
    [TestMethod]
    public async Task AssertionWithMissingUserHandleFileFailsNamingUserHandleFile()
    {
        string? executablePath = RequireExecutable();
        if(executablePath is null) { return; }

        //Oracle-keep: the private half independently signs the assertion below via SignWithEcdsaP256.
        //The CLI reads and fails on the missing --user-handle file before reaching signature
        //verification (see VerifiableOperations.Fido2's verify-assertion handler), so a genuine
        //signature — rather than junk bytes — guarantees this test reaches that file-read failure
        //deterministically instead of risking an earlier, unrelated crypto error.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey coseKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        string credentialRecordPath = await RegisterNoneCredentialAsync(executablePath, coseKey);

        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what the CLI's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags: (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit), signCount: 1);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Get, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        string authenticatorDataPath = WriteTempFile("authenticator-data.bin", authenticatorData);
        string signaturePath = WriteTempFile("signature.bin", signature);
        string clientDataPath = WriteTempFile("assertion-client-data.json", clientDataJson);
        string missingUserHandlePath = Path.Combine(tempDirectory, "does-not-exist-user-handle.bin");

        var result = await VerifiableCliTestHelpers.RunCliAsync(
            executablePath,
            [
                "fido2", "verify-assertion", credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath,
                "--rp-id", RpId, "--origin", Origin, "--challenge", Challenge, "--user-handle", missingUserHandlePath
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error reading user-handle file", result.Stderr, StringComparison.Ordinal);
    }


    // ---------------------------------------------------------------------------------------
    // Shared helpers (file-local; this file never edits VerifiableCliTestHelpers.cs or Fido2CliTests.cs).
    // ---------------------------------------------------------------------------------------

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


    /// <summary>
    /// Runs the real <c>verify-registration</c> CLI command for a <c>none</c>-format credential, and
    /// returns the path to the credential record JSON file it wrote — the verb-to-verb round trip the
    /// assertion algorithm-matrix and file-error tests in this file need.
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
    /// bytes for <paramref name="credentialPublicKey"/> — the same fixture shape
    /// <see cref="Fido2CliTests"/> builds privately, duplicated here rather than shared per this wave's
    /// file-discipline rule (no edits to existing test files).
    /// </summary>
    private static (byte[] AttestationObjectBytes, byte[] ClientDataJsonBytes, Guid Aaguid) BuildNoneRegistrationMaterial(
        CoseKey credentialPublicKey, byte[]? credentialPublicKeyCbor = null)
    {
        Guid aaguid = Guid.NewGuid();
        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what verify-registration's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        //Junk/noise payload: the credential ID's byte content is never independently checked, only that
        //it round-trips through the CLI's parsing, so a fresh random value carries no fixture-determinism
        //requirement.
        byte[] credentialId = RandomNumberGenerator.GetBytes(16);
        byte[] coseKeyCbor = credentialPublicKeyCbor ?? MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, coseKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialData);

        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, Challenge, Origin);
        byte[] attestationObject = Fido2AttestationTestVectors.EncodeAttestationObject(WellKnownWebAuthnAttestationFormats.None, [0xA0], authenticatorData);

        return (attestationObject, clientDataJson, aaguid);
    }


    /// <summary>
    /// Encodes an RSA COSE_Key CBOR map (<c>kty</c>/<c>alg</c>/<c>n</c>/<c>e</c>) — the RSA
    /// credential-embedding shape <see cref="MdocCborCoseKeyWriter"/> does not itself support (it
    /// targets the EC2/OKP mdoc key shapes only), needed here for the PS256 algorithm-matrix fixture.
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
    /// Mints an <c>android-key</c> registration fixture whose key description extension carries
    /// <paramref name="softwareEnforced"/>/<paramref name="teeEnforced"/> — an independent root CA, an
    /// ES256 credential, a conformant <c>attestationChallenge</c> (the real <c>clientDataHash</c>), and
    /// the real wire <c>authData</c>/<c>clientDataJSON</c>/<c>attestationObject</c> bytes, mirroring
    /// <see cref="AndroidKeyAttestationTests"/>'s own end-to-end fixture shape but routed through this
    /// file's CLI-facing rpId/origin/challenge constants.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ECDsa keys and X509Certificate2 instances transfers to the returned AndroidKeyFixture, which the caller disposes via a using declaration.")]
    private static AndroidKeyFixture CreateAndroidKeyRegistrationFixture(
        AndroidKeyAuthorizationList softwareEnforced, AndroidKeyAuthorizationList teeEnforced)
    {
        Guid aaguid = Guid.NewGuid();

        //Cert-factory-keep: CertificateRequest (inside CreateSelfSignedCa) requires a framework
        //AsymmetricAlgorithm to mint the self-signed attestation root.
        ECDsa attestationRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationRootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa(
            "CN=Test Fido2CliCompositionRootGapTests Android Key Root", attestationRootKey);

        //Cert-factory-keep: CertificateRequest (inside CreateEcCredCert) requires a framework
        //AsymmetricAlgorithm to mint the credential's own certificate; the same key also
        //independently signs the android-key attStmt below (SignWithEcdsaP256).
        ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);
        byte[] attestationChallenge = clientDataHash.AsReadOnlySpan().ToArray();

        byte[] keyDescriptionBytes = AndroidKeyAttestationTestVectors.EncodeKeyDescriptionExtensionValue(attestationChallenge, softwareEnforced, teeEnforced);
        X509Certificate2 credCert = AndroidKeyAttestationTestVectors.CreateEcCredCert(attestationRootCertificate, credentialKey, keyDescriptionBytes);

        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);
        //Junk/noise payload: the credential ID's byte content is never independently checked, only that
        //it round-trips through the CLI's parsing, so a fresh random value carries no fixture-determinism
        //requirement.
        byte[] credentialId = RandomNumberGenerator.GetBytes(16);
        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what verify-registration's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialData);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authenticatorData, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        byte[] attStmtCbor = AndroidKeyAttestationTestVectors.EncodeAndroidKeyAttStmt(
            WellKnownCoseAlgorithms.Es256, signature, [credCert.RawData, attestationRootCertificate.RawData]);
        byte[] attestationObjectBytes = Fido2AttestationTestVectors.EncodeAttestationObject(
            WellKnownWebAuthnAttestationFormats.AndroidKey, attStmtCbor, authenticatorData);

        return new AndroidKeyFixture(aaguid, attestationObjectBytes, clientDataJson, attestationRootCertificate, credCert, credentialKey, attestationRootKey);
    }


    /// <summary>
    /// Mints a <c>fido-u2f</c> registration fixture: an independent attestation root/leaf pair, an ES256
    /// credential, and the real wire <c>authData</c>/<c>clientDataJSON</c>/<c>attestationObject</c>
    /// bytes — mirrors <see cref="FidoU2fAttestationTests"/>'s own end-to-end fixture shape but routed
    /// through this file's CLI-facing rpId/origin/challenge constants.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ECDsa keys and X509Certificate2 instances transfers to the returned FidoU2fFixture, which the caller disposes via a using declaration.")]
    private static FidoU2fFixture CreateFidoU2fRegistrationFixture()
    {
        Guid aaguid = Guid.NewGuid();

        //Cert-factory-keep: CertificateRequest (inside CreateSelfSignedCa) requires a framework
        //AsymmetricAlgorithm to mint the self-signed attestation root.
        ECDsa attestationRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 attestationRootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa(
            "CN=Test Fido2CliCompositionRootGapTests U2F Root", attestationRootKey);
        //Cert-factory-keep: CertificateRequest (inside CreateLeafAttestationCertificate) requires a
        //framework AsymmetricAlgorithm to mint the leaf certificate; the same key also independently
        //signs the U2F verification data below (SignWithEcdsaP256).
        ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 leafCertificate = Fido2AttestationTestVectors.CreateLeafAttestationCertificate(
            attestationRootCertificate, leafKey, isCertificateAuthority: false, Fido2AttestationTestVectors.RequiredOrganizationalUnit, aaguidExtensionValue: null);

        //The credential key never signs anything here — the leaf certificate's own key (leafKey)
        //signs the U2F verification data below — so it is mere fixture material for the credential's
        //public COSE key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        //Junk/noise payload: the credential ID's byte content is never independently checked, only that
        //it round-trips through the CLI's parsing, so a fresh random value carries no fixture-determinism
        //requirement.
        byte[] credentialId = RandomNumberGenerator.GetBytes(16);
        //Oracle-keep: independently recomputes SHA-256 of the RP ID so the wire rpIdHash matches
        //what verify-registration's own RP ID check computes.
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));

        byte[] credentialPublicKeyCbor = MdocCborCoseKeyWriter.Write(credentialPublicKey).ToArray();
        byte[] attestedCredentialData = Fido2TestVectors.BuildAttestedCredentialData(aaguid, credentialId, credentialPublicKeyCbor);
        byte flags = (byte)(AuthenticatorDataFlags.UserPresentBit | AuthenticatorDataFlags.UserVerifiedBit | AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(rpIdHash, flags, signCount: 0, attestedCredentialData);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(WellKnownClientDataTypes.Create, Challenge, Origin);
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash(clientDataJson, BaseMemoryPool.Shared);

        byte[] verificationData = FidoU2fAttestationTestVectors.BuildVerificationData(
            rpIdHash, clientDataHash, credentialId, credentialPublicKey.X!.Value.Span, credentialPublicKey.Y!.Value.Span);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(leafKey, verificationData);

        byte[] attStmtCbor = EncodeFidoU2fAttStmt(signature, leafCertificate.RawData);
        byte[] attestationObjectBytes = Fido2AttestationTestVectors.EncodeAttestationObject(
            WellKnownWebAuthnAttestationFormats.FidoU2f, attStmtCbor, authenticatorData);

        return new FidoU2fFixture(attestationObjectBytes, clientDataJson, attestationRootCertificate, leafCertificate, leafKey, attestationRootKey);
    }


    /// <summary>Encodes a valid <c>fido-u2f</c> <c>attStmt</c> CBOR map (<c>sig</c>/<c>x5c</c>, single-element certificate array).</summary>
    private static byte[] EncodeFidoU2fAttStmt(byte[] sig, byte[] certificateDerBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("sig");
        writer.WriteByteString(sig);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(1);
        writer.WriteByteString(certificateDerBytes);
        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>A minted <c>android-key</c> registration fixture. Owns and disposes every certificate and key.</summary>
    private sealed class AndroidKeyFixture: IDisposable
    {
        public AndroidKeyFixture(
            Guid aaguid,
            byte[] attestationObjectBytes,
            byte[] clientDataJsonBytes,
            X509Certificate2 attestationRootCertificate,
            X509Certificate2 credCert,
            ECDsa credentialKey,
            ECDsa attestationRootKey)
        {
            Aaguid = aaguid;
            AttestationObjectBytes = attestationObjectBytes;
            ClientDataJsonBytes = clientDataJsonBytes;
            AttestationRootCertificate = attestationRootCertificate;
            CredCert = credCert;
            CredentialKey = credentialKey;
            AttestationRootKey = attestationRootKey;
        }

        public Guid Aaguid { get; }
        public byte[] AttestationObjectBytes { get; }
        public byte[] ClientDataJsonBytes { get; }
        public X509Certificate2 AttestationRootCertificate { get; }
        public X509Certificate2 CredCert { get; }
        public ECDsa CredentialKey { get; }
        public ECDsa AttestationRootKey { get; }

        public void Dispose()
        {
            AttestationRootCertificate.Dispose();
            CredCert.Dispose();
            CredentialKey.Dispose();
            AttestationRootKey.Dispose();
        }
    }


    /// <summary>A minted <c>fido-u2f</c> registration fixture. Owns and disposes every certificate and key.</summary>
    private sealed class FidoU2fFixture: IDisposable
    {
        public FidoU2fFixture(
            byte[] attestationObjectBytes,
            byte[] clientDataJsonBytes,
            X509Certificate2 attestationRootCertificate,
            X509Certificate2 leafCertificate,
            ECDsa leafKey,
            ECDsa attestationRootKey)
        {
            AttestationObjectBytes = attestationObjectBytes;
            ClientDataJsonBytes = clientDataJsonBytes;
            AttestationRootCertificate = attestationRootCertificate;
            LeafCertificate = leafCertificate;
            LeafKey = leafKey;
            AttestationRootKey = attestationRootKey;
        }

        public byte[] AttestationObjectBytes { get; }
        public byte[] ClientDataJsonBytes { get; }
        public X509Certificate2 AttestationRootCertificate { get; }
        public X509Certificate2 LeafCertificate { get; }
        public ECDsa LeafKey { get; }
        public ECDsa AttestationRootKey { get; }

        public void Dispose()
        {
            AttestationRootCertificate.Dispose();
            LeafCertificate.Dispose();
            LeafKey.Dispose();
            AttestationRootKey.Dispose();
        }
    }
}
