using Lumoin.Veritas.Cbor;
using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for COSE-secured Verifiable Credentials carried inside a
/// Verifiable Presentation as an <see cref="EnvelopedVerifiableCredential"/>.
/// </summary>
/// <remarks>
/// <para>
/// A COSE_Sign1-secured credential is opaque binary CBOR, so VC-DM 2.0 carries it inside a
/// presentation as an <see cref="EnvelopedVerifiableCredential"/> whose <c>id</c> is a
/// base64 <c>data:</c> URL (RFC 2397). The holder builds the presentation, the verifier
/// reconstructs it from the wire JSON only, decodes the COSE bytes from the <c>data:</c> URL,
/// and verifies the issuer signature.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see> and
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC Data Model 2.0 §3.3</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CosePresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string AlumniCredentialType = "AlumniCredential";
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";

    //RFC 2397 base64 data: URL prefix for a COSE-enveloped credential per VC-JOSE-COSE.
    private const string VcCoseDataUrlPrefix = "data:application/vc+cose;base64,";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder(BaseMemoryPool.Shared);

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));


    /// <summary>
    /// Holder wraps a COSE-secured credential in a presentation as an enveloped credential;
    /// the verifier reconstructs the presentation from wire JSON, decodes the COSE bytes from
    /// the <c>data:</c> URL, and verifies the issuer signature.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WrapCoseCredentialInPresentationAndVerify(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderDid = holderDidDocument.Id!.ToString();

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Issuer secures the credential as a COSE_Sign1 message and serializes it to CBOR.
        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 coseBytes = CoseSerialization.SerializeCoseSign1(message, BaseMemoryPool.Shared);
        string coseBase64 = Convert.ToBase64String(coseBytes.AsReadOnlyMemory().Span);

        //Holder wraps the COSE bytes as an EnvelopedVerifiableCredential (data: URL) in a presentation.
        var presentation = new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            EnvelopedVerifiableCredential =
            [
                new EnvelopedVerifiableCredential
                {
                    Id = VcCoseDataUrlPrefix + coseBase64,
                    Type = [CredentialConstants.EnvelopedVerifiableCredentialType]
                }
            ]
        };

        //The presentation travels to the verifier as wire JSON; the verifier reconstructs it.
        string presentationJson = JsonSerializerExtensions.Serialize(presentation, JsonOptions);
        var receivedPresentation = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(presentationJson, JsonOptions)!;

        Assert.IsNotNull(receivedPresentation.EnvelopedVerifiableCredential);
        Assert.HasCount(1, receivedPresentation.EnvelopedVerifiableCredential);

        var envelopedId = receivedPresentation.EnvelopedVerifiableCredential[0].Id!;
        Assert.StartsWith(VcCoseDataUrlPrefix, envelopedId, "The enveloped credential id must be a vc+cose base64 data: URL.");

        //Verifier decodes the COSE bytes from the data: URL, parses, and verifies the signature.
        byte[] decodedCose = Convert.FromBase64String(envelopedId[VcCoseDataUrlPrefix.Length..]);
        using CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(decodedCose, BaseMemoryPool.Shared);

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "COSE credential verification must succeed.");
        Assert.IsNotNull(result.Credential);
        var verifiedCredential = result.Credential!.Value.Value;
        Assert.AreEqual(holderDid, verifiedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, verifiedCredential.Issuer!.Id);
    }


    /// <summary>
    /// A presentation carrying a COSE-secured credential whose genuinely signed protected bucket repeats
    /// <c>kid</c> is reconstructed from the wire JSON like any other, and the verifier's COSE parse of the enveloped
    /// credential refuses it as malformed with the parser's own failure, before any signature is judged.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </summary>
    [TestMethod]
    public async Task PresentationOfACoseCredentialRepeatingKidIsRefused()
    {
        using var privateKey = DataIntegrity.CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        const string holderDid = "did:example:holder";
        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            TimeProvider.GetUtcNow().UtcDateTime,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The issuer signs over a protected bucket that carries kid twice; the signature itself is genuine.
        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            IssuerDidWeb + "#key-1",
            CredentialToCborBytes,
            CoseWireFixtures.CoseProtectedHeaderWithKidTwiceToCborBytes,
            CoseSerialization.BuildSigStructure,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The library's serializer refuses to write a protected bucket repeating a label, so the wire form is assembled as given.
        using EncodedCoseSign1 coseBytes = CoseWireFixtures.SerializeCoseSign1AsGiven(message, BaseMemoryPool.Shared);

        var presentation = new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            EnvelopedVerifiableCredential =
            [
                new EnvelopedVerifiableCredential
                {
                    Id = VcCoseDataUrlPrefix + Convert.ToBase64String(coseBytes.AsReadOnlyMemory().Span),
                    Type = [CredentialConstants.EnvelopedVerifiableCredentialType]
                }
            ]
        };

        string presentationJson = JsonSerializerExtensions.Serialize(presentation, JsonOptions);
        var receivedPresentation = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(presentationJson, JsonOptions)!;

        string envelopedId = receivedPresentation.EnvelopedVerifiableCredential![0].Id!;
        byte[] decodedCose = Convert.FromBase64String(envelopedId[VcCoseDataUrlPrefix.Length..]);

        _ = Assert.ThrowsExactly<CborContentException>(
            () => CoseSerialization.ParseCoseSign1(decodedCose, BaseMemoryPool.Shared),
            "RFC 9052 Section 3: a credential whose protected bucket repeats kid is malformed and is not parsed.");
    }


    private static ReadOnlySpan<byte> CredentialToCborBytes(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> CoseProtectedHeaderToCborBytes(IReadOnlyDictionary<int, object> header) =>
        CoseSerialization.SerializeProtectedHeader(header);

    private static VerifiableCredential CredentialFromJsonBytes(ReadOnlySpan<byte> bytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(bytes, JsonOptions)!;
}
