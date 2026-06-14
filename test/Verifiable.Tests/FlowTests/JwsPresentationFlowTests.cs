using System;
using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for JWS-secured Verifiable Credentials carried inside a
/// Verifiable Presentation as an <see cref="EnvelopedVerifiableCredential"/>.
/// </summary>
/// <remarks>
/// <para>
/// An enveloping-secured (JWS) credential is an opaque compact-JWS string, so VC-DM 2.0
/// carries it inside a presentation as an <see cref="EnvelopedVerifiableCredential"/> whose
/// <c>id</c> is a <c>data:</c> URL (RFC 2397). The holder builds the presentation, the
/// verifier reconstructs it from the wire JSON only, extracts the JWS from the
/// <c>data:</c> URL, and verifies the issuer signature.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see> and
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC Data Model 2.0 §3.3</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JwsPresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string AlumniCredentialType = "AlumniCredential";
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";

    //RFC 2397 data: URL prefix for a JWS-enveloped credential per VC-JOSE-COSE.
    private const string VcJwtDataUrlPrefix = "data:application/vc+jwt,";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    private static CredentialToJsonBytesDelegate CredentialSerializer => credential =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, JsonOptions);

    private static CredentialFromJsonBytesDelegate CredentialDeserializer => jsonBytes =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(jsonBytes, JsonOptions)!;

    private static Verifiable.Core.Model.Credentials.JwtHeaderSerializer HeaderSerializer => header =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(header, JsonOptions);

    private static JwtHeaderDeserializer HeaderDeserializer => headerBytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerBytes, JsonOptions)!;


    /// <summary>
    /// Holder wraps a JWS-secured credential in a presentation as an enveloped credential;
    /// the verifier reconstructs the presentation from wire JSON, extracts the JWS from the
    /// <c>data:</c> URL, and verifies the issuer signature.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WrapJwsCredentialInPresentationAndVerify(DidWebTestData testData)
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

        //Issuer secures the credential as a compact JWS.
        JwsMessage jwsMessage = await unsignedCredential.SignJwsAsync(
            privateKey,
            issuerVerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Holder wraps the JWS as an EnvelopedVerifiableCredential (data: URL) in a presentation.
        var presentation = new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            EnvelopedVerifiableCredential =
            [
                new EnvelopedVerifiableCredential
                {
                    Id = VcJwtDataUrlPrefix + jws,
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
        Assert.StartsWith(VcJwtDataUrlPrefix, envelopedId, "The enveloped credential id must be a vc+jwt data: URL.");

        //Verifier extracts the JWS from the data: URL and verifies the issuer signature.
        string extractedJws = envelopedId[VcJwtDataUrlPrefix.Length..];

        var verificationResult = await CredentialJwsExtensions.VerifyJwsAsync(
            extractedJws,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
        Assert.IsNotNull(verificationResult.Credential);
        var verifiedCredential = verificationResult.Credential!.Value.Value;
        Assert.AreEqual(holderDid, verifiedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, verifiedCredential.Issuer!.Id);
    }
}
