using System.Buffers;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Example-based tests for the SD-JWT structural verifier
/// (<see cref="SdJwtVerificationExtensions.VerifyAsync(SdToken{string}, PublicKeyMemory, MemoryPool{byte}, ExtractSdJwtPathsDelegate, string, System.Threading.CancellationToken)"/>):
/// issuer JWS signature plus per-disclosure digest binding against the holder-selected set.
/// All tests use real key material and cryptographic operations.
/// </summary>
[TestClass]
internal sealed class SdJwtVerificationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private const string GivenNameClaim = "given_name";
    private const string FamilyNameClaim = "family_name";


    [TestMethod]
    public async Task VerifyFullyDisclosedTokenReportsAllClaimsBound()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using SdToken<string> token =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        SdVerificationResult result = await token.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A fully disclosed, untampered token must verify.");
        Assert.AreEqual(SdVerificationFailureReason.None, result.FailureReason);
        Assert.HasCount(2, result.ClaimResults);
        foreach(SdClaimVerificationResult claimResult in result.ClaimResults)
        {
            Assert.IsTrue(claimResult.IsValid, "Each disclosed claim must bind to a path in the payload.");
        }
    }


    [TestMethod]
    public async Task VerifyTokenIssuedWithDecoysSucceedsAndDecoysAreIgnored()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        //Issue with five decoy digests padding the _sd array. A decoy is the same digest function
        //over random bytes — there is no disclosure behind it.
        using SdToken<string> token = await IssueAsync(
            privateKey, TestContext.CancellationToken, DecoyDigestPolicy.Fixed(5)).ConfigureAwait(false);

        SdVerificationResult result = await token.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Decoys are unmatched digests the verifier ignores; the token must still verify.");
        Assert.AreEqual(SdVerificationFailureReason.None, result.FailureReason);
        Assert.HasCount(2, result.ClaimResults, "Only the two real disclosures bind; the five decoys produce no claim results.");
        foreach(SdClaimVerificationResult claimResult in result.ClaimResults)
        {
            Assert.IsTrue(claimResult.IsValid, "Each real disclosed claim must still bind.");
        }
    }


    [TestMethod]
    public async Task DecoyPolicyStateThreadsThroughEndToEndIssuance()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        //A decision engine supplied as per-call State and reached via ctx.State — the static lambda
        //captures nothing, so the probe can only arrive through the threaded options. This exercises
        //the whole issuance pipeline (IssueSdJwtTokenAsync -> SdIssuance -> SdJwtPipeline.Redact ->
        //SdJwtClaimRedaction -> DecoyDigests.Augment -> policy), not just the redaction step.
        var probe = new DecoyProbe { DecoysPerLocation = 3 };
        DecoyDigestCountDelegate policy = static context =>
        {
            var engine = (DecoyProbe)context.State!;

            return engine.Decide(context);
        };

        using SdToken<string> token = await IssueAsync(
            privateKey, TestContext.CancellationToken, new DecoyDigestOptions(policy, probe)).ConfigureAwait(false);

        Assert.AreEqual(1, probe.Invocations, "The policy must run once per _sd location, end to end.");
        Assert.AreEqual(2, probe.RealCountsSeen[0], "The engine must see the real-disclosure count (both claims at the root).");

        //And the decoy-padded token still verifies with exactly the two real claims bound.
        SdVerificationResult result = await token.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The token issued with state-driven decoys must still verify.");
        Assert.HasCount(2, result.ClaimResults);
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFailsAtIssuerSignature()
    {
        var issuerKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = issuerKeyMaterial.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeyMaterial.PublicKey;

        //A distinct, freshly generated pair — CreateP256KeyMaterial returns copies of the same
        //cached pair, so a wrong-key test must use CreateFresh* for a genuinely different key.
        var wrongKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = wrongKeyMaterial.PublicKey;
        using PrivateKeyMemory wrongPrivateKey = wrongKeyMaterial.PrivateKey;

        using SdToken<string> token =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        SdVerificationResult result = await token.VerifyAsync(
            wrongPublicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Verification under the wrong key must fail.");
        Assert.AreEqual(SdVerificationFailureReason.IssuerSignatureInvalid, result.FailureReason);
        Assert.HasCount(0, result.ClaimResults, "Digest binding must not run when the signature is invalid.");
    }


    [TestMethod]
    public async Task VerifyWithMismatchedHashFailsDigestBinding()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using SdToken<string> token =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //Issued under the default sha-256. Verifying the digest binding under sha-384 recomputes
        //every disclosure digest differently, so none match the payload's stored digests. The
        //JWS signature is independent of the disclosure hash, so it still verifies — isolating
        //the failure to the digest-binding step.
        SdVerificationResult result = await token.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, WellKnownHashAlgorithms.Sha384Iana, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SdVerificationFailureReason.ClaimVerificationFailed, result.FailureReason);
        Assert.HasCount(2, result.ClaimResults);
        foreach(SdClaimVerificationResult claimResult in result.ClaimResults)
        {
            Assert.IsFalse(claimResult.IsValid);
            Assert.AreEqual(SdClaimVerificationFailureReason.DigestMismatch, claimResult.FailureReason);
        }
    }


    [TestMethod]
    public async Task VerifySelectedSubsetTrustsSelectedDisclosuresNotWireForm()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using SdToken<string> issuedToken =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //Narrow the presentation to a single disclosure. The payload still carries both _sd
        //digests; the verifier binds only the selected token.Disclosures, so the subset verifies
        //with exactly one bound claim and never processes the withheld disclosure.
        using SdToken<string> presentation = issuedToken.SelectDisclosures(
            d => d.ClaimName == GivenNameClaim, Pool);

        Assert.HasCount(1, presentation.Disclosures);

        SdVerificationResult result = await presentation.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A narrowed presentation must verify against the selected disclosures.");
        Assert.AreEqual(SdVerificationFailureReason.None, result.FailureReason);
        Assert.HasCount(1, result.ClaimResults);
        Assert.IsTrue(result.ClaimResults[0].IsValid);
    }


    [TestMethod]
    public async Task VerifyVerboseExposesPayloadAndBoundPaths()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using SdToken<string> token =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        (SdVerificationResult result, SdJwtVerificationContext? context) = await token.VerifyVerboseAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using(context)
        {
            Assert.IsTrue(result.IsValid);
            Assert.IsNotNull(context, "A token past the signature check must expose intermediate context.");
            Assert.HasCount(2, context.BoundPaths);
            Assert.IsGreaterThan(0, context.Payload.Length, "The decoded redacted payload must be exposed.");
        }
    }


    [TestMethod]
    public async Task VerifyVerboseReturnsNullContextWhenSignatureInvalid()
    {
        var issuerKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = issuerKeyMaterial.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerKeyMaterial.PublicKey;

        var wrongKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = wrongKeyMaterial.PublicKey;
        using PrivateKeyMemory wrongPrivateKey = wrongKeyMaterial.PrivateKey;

        using SdToken<string> token =
            await IssueAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        (SdVerificationResult result, SdJwtVerificationContext? context) = await token.VerifyVerboseAsync(
            wrongPublicKey, Pool, SdJwtPathExtraction.ExtractPaths, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using(context)
        {
            Assert.IsFalse(result.IsValid);
            Assert.AreEqual(SdVerificationFailureReason.IssuerSignatureInvalid, result.FailureReason);
            Assert.IsNull(context, "No payload is decoded when the signature is invalid, so there is no context.");
        }
    }


    [TestMethod]
    public async Task IssueSdJwtTokenVerboseExposesTokenAndRedactedPayload()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        JwtPayload claims = JwtPayload.ForIssuance(
            issuer: "https://issuer.example",
            issuedAt: TimeProvider.System.GetUtcNow(),
            claims:
            [
                new(GivenNameClaim, "Erika"),
                new(FamilyNameClaim, "Mustermann")
            ]);
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{GivenNameClaim}"),
            CredentialPath.FromJsonPointer($"/{FamilyNameClaim}")
        };

        (SdToken<string> token, ReadOnlyMemory<byte> redactedPayload) = await claims.IssueSdJwtTokenVerboseAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(), privateKey, IssuerKeyId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using(token)
        {
            Assert.IsGreaterThan(0, token.IssuerSigned.Length, "The token must carry the compact JWS.");
            Assert.HasCount(2, token.Disclosures);
            Assert.IsGreaterThan(0, redactedPayload.Length, "The redacted JSON payload must be exposed alongside the token.");
        }
    }


    private static async ValueTask<SdToken<string>> IssueAsync(
        PrivateKeyMemory privateKey, CancellationToken cancellationToken, DecoyDigestOptions decoyOptions = default)
    {
        JwtPayload claims = JwtPayload.ForIssuance(
            issuer: "https://issuer.example",
            issuedAt: TimeProvider.System.GetUtcNow(),
            claims:
            [
                new(GivenNameClaim, "Erika"),
                new(FamilyNameClaim, "Mustermann")
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{GivenNameClaim}"),
            CredentialPath.FromJsonPointer($"/{FamilyNameClaim}")
        };

        return await claims.IssueSdJwtTokenAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            privateKey, IssuerKeyId, Pool,
            decoyOptions: decoyOptions,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
