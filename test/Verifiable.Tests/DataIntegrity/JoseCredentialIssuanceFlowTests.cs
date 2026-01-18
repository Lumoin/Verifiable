using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// End-to-end flow tests for JOSE-secured Verifiable Credentials.
/// These tests demonstrate issuing and verifying credentials using JWS envelopes.
/// </summary>
/// <remarks>
/// <para>
/// JOSE (JSON Object Signing and Encryption) provides an external securing mechanism
/// for Verifiable Credentials, as opposed to the embedded proofs used by Data Integrity.
/// The credential becomes the payload of a signed JWT.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-jose-cose/">Securing Verifiable Credentials using JOSE and COSE</see>.
/// </para>
/// </remarks>
[TestClass]
public sealed class JoseCredentialIssuanceFlowTests
{
    /// <summary>
    /// Test context providing test run information and cancellation support.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    //Test DID identifiers.
    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string HolderDidExample = "did:example:holder";

    //Credential constants.
    private const string AlumniCredentialType = "AlumniCredential";

    //Claim keys and values.
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";

    //Serialization options.
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    //Shared builder instances.
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    /// <summary>
    /// Fake time provider for deterministic testing.
    /// </summary>
    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));


    /// <summary>
    /// Serializes a credential to UTF-8 JSON bytes.
    /// </summary>
    private static CredentialToJsonBytesDelegate CredentialSerializer => credential =>
        JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);


    /// <summary>
    /// Deserializes a credential from UTF-8 JSON bytes.
    /// </summary>
    private static CredentialFromJsonBytesDelegate CredentialDeserializer => jsonBytes =>
        JsonSerializer.Deserialize<VerifiableCredential>(jsonBytes, JsonOptions)!;


    /// <summary>
    /// Serializes a JWT header dictionary to UTF-8 JSON bytes.
    /// </summary>
    private static JwtHeaderSerializer HeaderSerializer => header =>
        JsonSerializer.SerializeToUtf8Bytes(header);


    /// <summary>
    /// Deserializes a JWT header from UTF-8 JSON bytes.
    /// </summary>
    private static JwtHeaderDeserializer HeaderDeserializer => headerBytes =>
        JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);


    /// <summary>
    /// Tests the complete credential issuance and verification flow using JOSE/JWS.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithJoseSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken);

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
            cancellationToken: TestContext.CancellationToken);

        //Sign as JWS.
        JwsMessage jwsMessage = await unsignedCredential.SignJwsAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Verify the JWS structure.
        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        //Verify the signature.
        var verificationResult = await JwsCredentialVerification.VerifyAsync(
            jws,
            testData.KeyPair.PublicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verificationResult.IsValid);
        Assert.IsNotNull(verificationResult.Credential);
        Assert.AreEqual(holderDid, verificationResult.Credential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, verificationResult.Credential.Issuer!.Id);
    }


    /// <summary>
    /// Tests that tampered JWS credentials fail verification.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedJwsCredentialFailsVerification(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

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
            cancellationToken: TestContext.CancellationToken);

        JwsMessage jwsMessage = await unsignedCredential.SignJwsAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Tamper with the payload by modifying the JWS string.
        string[] parts = jws.Split('.');
        string tamperedPayload = parts[1].Length > 10
            ? parts[1].Substring(0, 5) + "XXXXX" + parts[1].Substring(10)
            : "tampered";
        string tamperedJws = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        var verificationResult = await JwsCredentialVerification.VerifyAsync(
            tamperedJws,
            testData.KeyPair.PublicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsFalse(verificationResult.IsValid);
    }


    /// <summary>
    /// Tests that the JWS header contains correct algorithm and type information.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task JwsHeaderContainsCorrectMetadata(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

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
            cancellationToken: TestContext.CancellationToken);

        JwsMessage jwsMessage = await unsignedCredential.SignJwsAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Decode and verify header.
        string[] parts = jws.Split('.');
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        var header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.IsTrue(header.ContainsKey(JwkProperties.Alg));
        Assert.IsTrue(header.ContainsKey(JwkProperties.Typ));
        Assert.IsTrue(header.ContainsKey(JwkProperties.Kid));

        //Verify the typ is the VC+LD+JWT media type.
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcLdJwt, header[JwkProperties.Typ].ToString());

        //Verify the kid matches the verification method ID.
        Assert.AreEqual(issuerVerificationMethodId, header[JwkProperties.Kid].ToString());
    }


    /// <summary>
    /// Tests using a custom media type for non-JSON-LD credentials.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task JwsWithCustomMediaTypeSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

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
            cancellationToken: TestContext.CancellationToken);

        //Use the non-JSON-LD media type.
        JwsMessage jwsMessage = await unsignedCredential.SignJwsAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            mediaType: WellKnownMediaTypes.Jwt.VcJwt,
            cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Decode and verify header has the custom media type.
        string[] parts = jws.Split('.');
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], SensitiveMemoryPool<byte>.Shared);
        var header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes.Memory.Span);

        Assert.IsNotNull(header);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.VcJwt, header[JwkProperties.Typ].ToString());
    }
}