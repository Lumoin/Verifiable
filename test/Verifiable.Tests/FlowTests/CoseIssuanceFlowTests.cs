using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for COSE-secured Verifiable Credentials.
/// These tests demonstrate issuing and verifying credentials using COSE_Sign1 envelopes.
/// </summary>
/// <remarks>
/// <para>
/// COSE (CBOR Object Signing and Encryption) provides an external securing mechanism
/// for Verifiable Credentials. The credential becomes the payload of a COSE_Sign1 message
/// with Tag(18) per RFC 9052.
/// </para>
/// <para>
/// These tests parallel <see cref="JwsIssuanceFlowTests"/> to ensure parity between
/// the two external envelope mechanisms defined in
/// <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CoseIssuanceFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string HolderDidExample = "did:example:holder";
    private const string AlumniCredentialType = "AlumniCredential";
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));


    /// <summary>
    /// Tests the complete credential issuance and verification flow using COSE_Sign1.
    /// Exercises DID document construction, credential building, signing, CBOR wire
    /// format serialization, parsing, and signature verification.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithCoseSucceeds(DidWebTestData testData)
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
        var validUntil = validFrom.AddYears(10);

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            validUntil: validUntil,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Sign as COSE_Sign1.
        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Serialize to CBOR wire format and parse back (simulates network transit).
        byte[] coseBytes = CoseSerialization.SerializeCoseSign1(message);
        CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(coseBytes);

        //Verify the signature from the parsed message.
        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "COSE credential verification must succeed.");
        Assert.IsNotNull(result.Credential);
        Assert.AreEqual(holderDid, result.Credential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, result.Credential.Issuer!.Id);
    }


    /// <summary>
    /// Tests that a tampered COSE_Sign1 payload fails verification.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCoseCredentialFailsVerification(DidWebTestData testData)
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

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Tamper with the payload by flipping bytes.
        byte[] tamperedPayload = message.Payload.ToArray();
        if(tamperedPayload.Length > 10)
        {
            tamperedPayload[5] ^= 0xFF;
            tamperedPayload[10] ^= 0xFF;
        }

        var tamperedMessage = new CoseSign1Message(
            message.ProtectedHeaderBytes.ToArray(),
            message.UnprotectedHeader,
            tamperedPayload,
            message.Signature.ToArray());

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            tamperedMessage,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Tampered COSE credential verification must fail.");
    }


    /// <summary>
    /// Tests that the COSE protected header contains correct algorithm, key ID,
    /// content type, and type parameters per VC-JOSE-COSE.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task CoseHeaderContainsCorrectMetadata(DidWebTestData testData)
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

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<int, object> header = CoseSerialization.ParseProtectedHeader(
            message.ProtectedHeaderBytes.Span);

        Assert.IsTrue(header.ContainsKey(CoseHeaderParameters.Alg), "Protected header must contain algorithm.");
        Assert.AreEqual(issuerVerificationMethodId, header[CoseHeaderParameters.Kid]);
        Assert.AreEqual(
            WellKnownMediaTypes.Application.ApplicationVc,
            header[CoseHeaderParameters.ContentType]?.ToString(),
            "Content type must indicate a Verifiable Credential.");
        Assert.AreEqual(
            WellKnownMediaTypes.Application.VcCose,
            header[CoseHeaderParameters.Typ]?.ToString(),
            "Type must indicate COSE-secured VC.");
    }


    /// <summary>
    /// Tests that the COSE payload round-trips through the credential model,
    /// preserving issuer, subject, validity, and type metadata.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task CosePayloadPreservesCredentialMetadata(DidWebTestData testData)
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

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var validUntil = validFrom.AddYears(10);

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            validUntil: validUntil,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        CoseSign1Message message = await unsignedCredential.SignCoseAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential deserialized = CredentialFromJsonBytes(message.Payload.Span);

        Assert.AreEqual(unsignedCredential.Id, deserialized.Id);
        Assert.AreEqual(IssuerDidWeb, deserialized.Issuer?.Id);
        Assert.AreEqual(unsignedCredential.ValidFrom, deserialized.ValidFrom);
        Assert.AreEqual(unsignedCredential.ValidUntil, deserialized.ValidUntil);
        Assert.Contains("VerifiableCredential", deserialized.Type!);
        Assert.Contains(AlumniCredentialType, deserialized.Type!);
    }


    private static ReadOnlySpan<byte> CredentialToCborBytes(VerifiableCredential credential) =>
        JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> CoseProtectedHeaderToCborBytes(IReadOnlyDictionary<int, object> header) =>
        CoseSerialization.SerializeProtectedHeader(header);

    private static VerifiableCredential CredentialFromJsonBytes(ReadOnlySpan<byte> bytes) =>
        JsonSerializer.Deserialize<VerifiableCredential>(bytes, JsonOptions)!;
}