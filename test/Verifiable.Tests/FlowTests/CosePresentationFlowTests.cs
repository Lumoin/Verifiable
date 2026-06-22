using System;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

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
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

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
            Context = new Context { Contexts = [Context.Credentials20] },
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


    private static ReadOnlySpan<byte> CredentialToCborBytes(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> CoseProtectedHeaderToCborBytes(IReadOnlyDictionary<int, object> header) =>
        CoseSerialization.SerializeProtectedHeader(header);

    private static VerifiableCredential CredentialFromJsonBytes(ReadOnlySpan<byte> bytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(bytes, JsonOptions)!;
}
