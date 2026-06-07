using System.Linq;
using System.Security.Cryptography;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow test proving that Data Integrity <c>ecdsa-sd-2023</c> derivation is driven by
/// the shared, query-language-neutral selective-disclosure engine — the same engine SD-JWT,
/// mdoc, and SD-CWT use — with no dependency on DCQL or any presentation protocol.
/// </summary>
/// <remarks>
/// <para>
/// The verifier's request is a plain set of <see cref="CredentialPath"/> values.
/// <see cref="DataIntegritySelectiveDisclosure.ComputeDisclosurePathsAsync"/> runs the neutral
/// <c>DisclosureComputation</c> over the credential's full claim surface to produce the minimal
/// disclosure, which then drives <c>DeriveProofAsync</c>. The verifier reconstructs the derived
/// credential from wire bytes only before verifying.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DataIntegritySdPresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTime ProofCreated = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private const string IssuerVerificationMethodId = "did:example:issuer#key-1";

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256IssuerKeys { get; } =
        BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256EphemeralKeys { get; } =
        BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();
    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, CredentialSecuringMaterial.JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, CredentialSecuringMaterial.JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(CredentialSecuringMaterial.JsonOptions);

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static readonly ExchangeContext EmptyContext = new();


    /// <summary>
    /// Issuer base-signs a credential; the holder runs the neutral disclosure engine over a
    /// plain requested-path set to compute the minimal disclosure, derives an ecdsa-sd proof
    /// from it, and a firewalled verifier validates the reconstructed derived credential.
    /// </summary>
    [TestMethod]
    public async ValueTask EcdsaSdDerivationDrivenByNeutralDisclosureEngineSucceeds()
    {
        var cancellationToken = TestContext.CancellationToken;
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        var mandatoryPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        };

        //Issuer creates the base proof carrying all claims with selective-disclosure capability.
        var signedCredential = await credential.CreateBaseProofAsync(
            P256IssuerKeys.PrivateKey,
            P256EphemeralKeys,
            IssuerVerificationMethodId,
            ProofCreated,
            mandatoryPaths.ToList(),
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        //Holder verifies the issuer's base proof.
        var baseVerification = await signedCredential.VerifyBaseProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(baseVerification.IsValid);

        //Verifier expresses a plain requested-path set — no DCQL, no presentation protocol.
        var requestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        //The neutral selective-disclosure engine computes the minimal disclosure.
        var selectedPaths = await DataIntegritySelectiveDisclosure.ComputeDisclosurePathsAsync(
            signedCredential,
            requestedPaths,
            mandatoryPaths,
            SerializeCredential,
            cancellationToken).ConfigureAwait(false);

        //Minimal disclosure: required + mandatory, with unrelated claims trimmed away.
        Assert.Contains(CredentialPath.FromJsonPointer("/issuer"), selectedPaths);
        Assert.Contains(CredentialPath.FromJsonPointer("/type"), selectedPaths);
        Assert.Contains(CredentialPath.FromJsonPointer("/credentialSubject/degree/name"), selectedPaths);
        Assert.DoesNotContain(CredentialPath.FromJsonPointer("/validFrom"), selectedPaths);
        Assert.DoesNotContain(CredentialPath.FromJsonPointer("/credentialSubject/degree/type"), selectedPaths);

        //Holder derives the proof from the engine's decision.
        var derivedCredential = await signedCredential.DeriveProofAsync(
            selectedPaths,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        //Firewalled verifier: reconstruct the derived credential from wire bytes only.
        var wire = SerializeCredential(derivedCredential);
        var received = JsonSerializerExtensions.Deserialize<DataIntegritySecuredCredential>(
            wire, CredentialSecuringMaterial.JsonOptions)!;

        var derivedVerification = await received.VerifyDerivedProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(derivedVerification.IsValid);

        //The undisclosed claim is absent from the reconstructed derived credential.
        Assert.IsNull(received.ValidFrom, "validFrom was not selected, so it must not appear in the derived credential.");
    }
}
