using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Siop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="SelfIssuedIdTokenValidation"/> — the SIOPv2 §11.1
/// Relying Party validation of Self-Issued ID Tokens. Tokens are minted with the
/// JCose signing composition exactly as a wallet would, independent of any library
/// issuance path, so the validator is exercised adversarially: every negative case
/// is a token a malicious or broken Self-Issued OP could present.
/// </summary>
[TestClass]
internal sealed class SiopSelfIssuedIdTokenValidationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://verifier.example.org/cb";
    private const string RequestNonce = "n-0S6_WzA2Mj";

    private static string[] AllowedAlgorithms { get; } = [WellKnownJwaValues.Es256];

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task ValidatesJwkThumbprintSelfIssuedIdToken()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsStructurallyValid);
        Assert.IsTrue(result.IsSelfIssued);
        Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, result.SubjectSyntaxType);
        Assert.IsTrue(result.IsSubJwkShapeValid);
        Assert.IsTrue(result.IsAlgorithmAllowed);
        Assert.IsTrue(result.IsSignatureValid);
        Assert.IsTrue(result.IsSubjectConfirmed);
        Assert.IsTrue(result.IsAudienceValid);
        Assert.IsTrue(result.IsNonceValid);
        Assert.IsTrue(result.IsUnexpired);
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(sub, result.Subject);
        Assert.AreEqual(RequestNonce, result.Nonce);
    }


    [TestMethod]
    public async Task DetectsAttesterSignedIdTokenWhenIssDiffersFromSub()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: "https://op.example.com", sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsStructurallyValid);
        Assert.IsFalse(result.IsSelfIssued);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual("https://op.example.com", result.Issuer);
        Assert.AreEqual(sub, result.Subject);
    }


    [TestMethod]
    public async Task RejectsThumbprintTokenWithoutSubJwk()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, _) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: null).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSubJwkShapeValid);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsSubjectConfirmed);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsKeySubstitutionInSubJwk()
    {
        //The §11.1 thumbprint check is what stops an attacker from re-signing a token
        //with their own key while claiming the victim's subject identifier: the
        //substituted sub_jwk verifies the signature, but its RFC 7638 thumbprint can
        //never equal the victim's sub.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> victimKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory victimPublic = victimKeys.PublicKey;
        using PrivateKeyMemory victimPrivate = victimKeys.PrivateKey;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        (string victimSub, _) = ComposeThumbprintSubject(victimPublic);
        (_, Dictionary<string, object> attackerJwk) = ComposeThumbprintSubject(attackerPublic);
        string idToken = await MintTokenAsync(
            attackerPrivate, iss: victimSub, sub: victimSub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: attackerJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSignatureValid);
        Assert.IsFalse(result.IsSubjectConfirmed);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsDuplicateSubJwkMemberName()
    {
        //RFC 7519 §4: "The Claim Names within a JWT Claims Set MUST be unique." The payload below
        //carries "sub_jwk" twice: the FIRST occurrence — the position the minted token already
        //carries it in — is the honest key a first-match reader (and, before this fix, this
        //validator's ExtractObjectProperties) would confirm and verify successfully; the LAST is an
        //attacker's substituted key a last-value-wins reader would resolve instead. The payload is
        //hand-edited JSON text — never rebuilt through JwtPayloadSerializer — re-signed over its
        //exact bytes with the project's own signing primitive.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> subjectKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = subjectKeys.PublicKey;
        using PrivateKeyMemory subjectPrivate = subjectKeys.PrivateKey;
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory _ = attackerKeys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        string[] parts = idToken.Split('.');
        string payloadJson;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payloadJson = Encoding.UTF8.GetString(payloadBytes.Memory.Span).TrimEnd('\0');
        }

        string attackerAlgorithm = CryptoFormatConversions.DefaultTagToJwaConverter(attackerPublic.Tag);
        IReadOnlyDictionary<string, string> attackerJwk = DpopJwkUtilities.ToJwk(
            attackerPublic, attackerAlgorithm, TestSetup.Base64UrlEncoder);
        string attackerJwkJson =
            "{" + string.Join(",", attackerJwk.Select(member => $"\"{member.Key}\":\"{member.Value}\"")) + "}";

        //Splice a second, attacker-controlled "sub_jwk" member in just before the closing brace.
        //The honest "sub_jwk" the minted payload already carries stays where it is (FIRST); this
        //appended one becomes the LAST occurrence of the same member name.
        Assert.EndsWith("}", payloadJson);
        string duplicateBearingPayload = payloadJson[..^1] + $",\"sub_jwk\":{attackerJwkJson}}}";

        string payloadSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(duplicateBearingPayload));
        byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{payloadSegment}");
        using var signature = await subjectPrivate.SignAsync(signingInput, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        string signatureSegment = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
        string duplicateBearingToken = $"{parts[0]}.{payloadSegment}.{signatureSegment}";

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            duplicateBearingToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Refused outright — no key is confirmed or verified under either occurrence.
        Assert.IsFalse(result.IsStructurallyValid);
        Assert.IsFalse(result.IsSubjectConfirmed);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsTamperedPayload()
    {
        //Front-channel tampering: an attacker splices a replayed token's nonce to the
        //RP's fresh value. The nonce comparison then passes, but the signature no
        //longer verifies — the secure invariant is that the signed value wins.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: "n-replayed",
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        string[] parts = idToken.Split('.');
        string payloadJson;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payloadJson = Encoding.UTF8.GetString(payloadBytes.Memory.Span).TrimEnd('\0');
        }

        string tamperedJson = payloadJson.Replace("n-replayed", RequestNonce, StringComparison.Ordinal);
        string tamperedPayload = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedJson));
        string tamperedToken = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            tamperedToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsNonceValid);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsAudienceMismatch()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: "https://other-verifier.example.com",
            nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsAudienceValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task AcceptsAudienceArrayContainingClientId()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub,
            aud: new List<object> { "https://other.example.com", ClientId },
            nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsAudienceValid);
        Assert.IsTrue(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsNonceMismatchAndAbsence()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string mismatched = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: "n-other",
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);
        string absent = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: null,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult mismatchedResult = await SelfIssuedIdTokenValidation.ValidateAsync(
            mismatched, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        SelfIssuedIdTokenValidationResult absentResult = await SelfIssuedIdTokenValidation.ValidateAsync(
            absent, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(mismatchedResult.IsNonceValid);
        Assert.IsFalse(mismatchedResult.IsValid);
        Assert.IsFalse(absentResult.IsNonceValid);
        Assert.IsFalse(absentResult.IsValid);
    }


    [TestMethod]
    public async Task RejectsExpiredToken()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(-1),
            issuedAt: TimeProvider.GetUtcNow().AddMinutes(-10),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsUnexpired);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsDisallowedAlgorithmWithoutEvaluatingSignature()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        string[] edDsaOnly = [WellKnownJwaValues.EdDsa];
        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, edDsaOnly, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsAlgorithmAllowed);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsAlgNoneEvenWhenListedAsAllowed()
    {
        //An unsigned token with alg=none must never validate, even against a
        //misconfigured allow-list, per RFC 8725 §3.1.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        JwtPayload payload = ComposePayload(
            iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk);
        JwtHeader header = new(capacity: 1)
        {
            [WellKnownJwkMemberNames.Alg] = "none"
        };
        string headerSegment = TestSetup.Base64UrlEncoder(HeaderSerializer(header));
        string payloadSegment = TestSetup.Base64UrlEncoder(PayloadSerializer(payload));
        string unsignedToken = $"{headerSegment}.{payloadSegment}.";

        string[] misconfiguredAllowList = ["none", WellKnownJwaValues.Es256];
        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            unsignedToken, ClientId, RequestNonce, misconfiguredAllowList, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsAlgorithmAllowed);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsSubJwkCarryingPrivateKeyMaterial()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        subJwk[WellKnownJwkMemberNames.D] = "8VNdNxOLg6TtwTHRiZjTJLTrYpJpYTehv2GESNcAxcs";
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: sub, sub: sub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSubJwkShapeValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task ValidatesDecentralizedIdentifierToken()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        const string Did = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
        const string KeyId = Did + "#key-1";
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: Did, sub: Did, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: null, keyId: KeyId).ConfigureAwait(false);

        string? resolvedDid = null;
        string? resolvedKid = null;
        ValueTask<PublicKeyMemory?> resolver(string did, string? kid, CancellationToken _)
        {
            resolvedDid = did;
            resolvedKid = kid;

            return ValueTask.FromResult<PublicKeyMemory?>(subjectPublic);
        }

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
resolver,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SiopSubjectSyntaxType.DecentralizedIdentifier, result.SubjectSyntaxType);
        Assert.IsTrue(result.IsSubJwkShapeValid);
        Assert.IsTrue(result.IsSignatureValid);
        Assert.IsTrue(result.IsSubjectConfirmed);
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(Did, resolvedDid);
        Assert.AreEqual(KeyId, resolvedKid);
    }


    [TestMethod]
    public async Task RejectsDecentralizedIdentifierTokenCarryingSubJwk()
    {
        //§8: sub_jwk MUST NOT be included for the Decentralized Identifier Subject
        //Syntax Type — accepting it would let an attacker steer verification away
        //from the DID Document key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        const string Did = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
        (_, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: Did, sub: Did, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(string _1, string? _2, CancellationToken _3) =>
            ValueTask.FromResult<PublicKeyMemory?>(subjectPublic);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
resolver,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SiopSubjectSyntaxType.DecentralizedIdentifier, result.SubjectSyntaxType);
        Assert.IsFalse(result.IsSubJwkShapeValid);
        Assert.IsFalse(result.IsSignatureValid);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task FailsClosedWhenDidResolverIsUnwiredOrReturnsNull()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        const string Did = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: Did, sub: Did, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: null).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult unwiredResult = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        static ValueTask<PublicKeyMemory?> unresolvable(string _1, string? _2, CancellationToken _3) =>
            ValueTask.FromResult<PublicKeyMemory?>(null);
        SelfIssuedIdTokenValidationResult unresolvedResult = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
unresolvable,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(unwiredResult.IsSubjectConfirmed);
        Assert.IsFalse(unwiredResult.IsSignatureValid);
        Assert.IsFalse(unwiredResult.IsValid);
        Assert.IsFalse(unresolvedResult.IsSubjectConfirmed);
        Assert.IsFalse(unresolvedResult.IsSignatureValid);
        Assert.IsFalse(unresolvedResult.IsValid);
    }


    [TestMethod]
    public async Task RejectsUnknownSubjectSyntaxType()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        const string OpaqueSub = "user-12345";
        (_, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        string idToken = await MintTokenAsync(
            subjectPrivate, iss: OpaqueSub, sub: OpaqueSub, aud: ClientId, nonce: RequestNonce,
            expiresAt: TimeProvider.GetUtcNow().AddMinutes(5), issuedAt: TimeProvider.GetUtcNow(),
            subJwk: subJwk).ConfigureAwait(false);

        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSelfIssued);
        Assert.AreEqual(SiopSubjectSyntaxType.Unknown, result.SubjectSyntaxType);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public async Task RejectsMalformedToken()
    {
        SelfIssuedIdTokenValidationResult result = await SelfIssuedIdTokenValidation.ValidateAsync(
            "not-a-jwt", ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsStructurallyValid);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// RFC 7519 Section 2: <c>exp</c> and <c>iat</c> are NumericDates. A token carrying either as a value that names no date - a
    /// string of digits, a literal, an object, an array, a number naming an instant no clock represents - is structurally
    /// invalid, never one read as carrying no date: a relying party policing <c>iat</c> is never handed an absent date for a
    /// token that carries one, and an unreadable <c>exp</c> is told from an omitted one. Everything else about the token is valid
    /// and it is signed over its exact bytes.
    /// </summary>
    /// <param name="claim">The date claim written malformed.</param>
    /// <param name="value">Its value as the payload writes it.</param>
    [TestMethod]
    [DataRow("exp", "\"1893456000\"", DisplayName = "exp as a string of digits")]
    [DataRow("exp", "true", DisplayName = "exp as the true literal")]
    [DataRow("exp", "null", DisplayName = "exp as the null literal")]
    [DataRow("exp", "1e400", DisplayName = "exp naming no instant a clock represents")]
    [DataRow("iat", "\"1700000000\"", DisplayName = "iat as a string of digits")]
    [DataRow("iat", "{}", DisplayName = "iat as an object")]
    [DataRow("iat", "[1700000000]", DisplayName = "iat as an array")]
    public async Task ATokenWhoseExpOrIatIsNoNumericDateIsStructurallyInvalid(string claim, string value)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        DateTimeOffset? expiresAt = WellKnownJwtClaimNames.IsExp(claim) ? null : TimeProvider.GetUtcNow().AddMinutes(5);
        DateTimeOffset? issuedAt = WellKnownJwtClaimNames.IsIat(claim) ? null : TimeProvider.GetUtcNow();
        var payload = ComposePayload(sub, sub, ClientId, RequestNonce, expiresAt, issuedAt, subJwk);
        var idToken = await SignRawAsync(subjectPrivate, WithRawMember(payload, claim, value)).ConfigureAwait(false);

        var result = await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsStructurallyValid, "A date the token carries that names no date makes it structurally invalid.");
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// The answers a malformed date is told from, on tokens signed over their exact bytes as the malformed ones are: a token
    /// carrying both dates as NumericDates validates, a fraction kept as written (RFC 7519 Section 2: "non-integer values can be
    /// represented"); one omitting <c>iat</c> validates with no <c>iat</c> surfaced; and one omitting the <c>exp</c> §11.1 judges
    /// is structurally valid but not unexpired.
    /// </summary>
    [TestMethod]
    public async Task NumericDatesValidateAnOmittedIatIsNoneAndAnOmittedExpIsNotUnexpired()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory subjectPublic = keys.PublicKey;
        using PrivateKeyMemory subjectPrivate = keys.PrivateKey;

        (string sub, Dictionary<string, object> subJwk) = ComposeThumbprintSubject(subjectPublic);
        var now = TimeProvider.GetUtcNow();
        var writtenExp = now.AddMinutes(5).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture) + ".5";
        var bothDates = WithRawMember(ComposePayload(sub, sub, ClientId, RequestNonce, null, now, subJwk), WellKnownJwtClaimNames.Exp, writtenExp);
        var noIat = WithRawMember(ComposePayload(sub, sub, ClientId, RequestNonce, null, null, subJwk), WellKnownJwtClaimNames.Exp, writtenExp);
        var noExp = Encoding.UTF8.GetString(PayloadSerializer(ComposePayload(sub, sub, ClientId, RequestNonce, null, now, subJwk)));

        var bothResult = await ValidateRawAsync(await SignRawAsync(subjectPrivate, bothDates).ConfigureAwait(false)).ConfigureAwait(false);
        var noIatResult = await ValidateRawAsync(await SignRawAsync(subjectPrivate, noIat).ConfigureAwait(false)).ConfigureAwait(false);
        var noExpResult = await ValidateRawAsync(await SignRawAsync(subjectPrivate, noExp).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsTrue(bothResult.IsValid);
        Assert.AreEqual(writtenExp, bothResult.ExpiresAt!.ToString());
        Assert.IsTrue(noIatResult.IsValid, "SIOPv2 section 11.1 judges no iat, so a token omitting it validates.");
        Assert.IsNull(noIatResult.IssuedAt, "An omitted iat is none.");
        Assert.IsTrue(noExpResult.IsStructurallyValid, "An omitted exp is no malformed one.");
        Assert.IsFalse(noExpResult.IsUnexpired, "SIOPv2 section 11.1: a token with no exp is not before its expiry.");
        Assert.IsFalse(noExpResult.IsValid);
    }


    /// <summary>Validates a self-issued ID Token under this class's relying party, nonce, algorithms and clock.</summary>
    /// <param name="idToken">The compact token.</param>
    /// <returns>The validation outcome.</returns>
    private async Task<SelfIssuedIdTokenValidationResult> ValidateRawAsync(string idToken) =>
        await SelfIssuedIdTokenValidation.ValidateAsync(
            idToken, ClientId, RequestNonce, AllowedAlgorithms, TimeProvider.GetUtcNow(),
            resolveDidVerificationKey: null,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// The payload's JSON text with one member appended whose value is written as given, raw, so a value no serializer of a
    /// claims set writes - a string of digits for a date, a number no double holds - reaches the validator as written.
    /// </summary>
    /// <param name="payload">The claims serialized first, none named <paramref name="name"/>.</param>
    /// <param name="name">The appended member's name.</param>
    /// <param name="rawValue">The appended member's value as JSON text.</param>
    /// <returns>The payload's JSON text.</returns>
    private static string WithRawMember(JwtPayload payload, string name, string rawValue)
    {
        var json = Encoding.UTF8.GetString(PayloadSerializer(payload));

        return json[..^1] + ",\"" + name + "\":" + rawValue + "}";
    }


    /// <summary>
    /// Signs a payload's exact JSON text under the subject's key with the header <c>{"alg":...,"typ":"JWT"}</c>, never through a
    /// serializer, so the bytes the validator reads are the bytes written.
    /// </summary>
    /// <param name="signingKey">The subject's private key.</param>
    /// <param name="payloadJson">The payload's JSON text.</param>
    /// <returns>The compact token.</returns>
    private async Task<string> SignRawAsync(PrivateKeyMemory signingKey, string payloadJson)
    {
        var algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        var headerSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes("{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\"}"));
        var payloadSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{headerSegment}.{payloadSegment}");

        using var signature = await signingKey.SignAsync(signingInput, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        return $"{headerSegment}.{payloadSegment}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";
    }


    //Composes the RFC 9278 thumbprint subject and the sub_jwk claim value for a key:
    //the same projection a wallet performs when it self-issues.
    private static (string Sub, Dictionary<string, object> SubJwk) ComposeThumbprintSubject(
        PublicKeyMemory subjectPublic)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(subjectPublic.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            subjectPublic, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, TestSetup.Base64UrlEncoder, Pool);

        Dictionary<string, object> subJwk = new(jwk.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in jwk)
        {
            subJwk[member.Key] = member.Value;
        }

        return (SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint, subJwk);
    }


    private static JwtPayload ComposePayload(
        string iss,
        string sub,
        object aud,
        string? nonce,
        DateTimeOffset? expiresAt,
        DateTimeOffset? issuedAt,
        Dictionary<string, object>? subJwk)
    {
        JwtPayload payload = new(capacity: 7)
        {
            [WellKnownJwtClaimNames.Iss] = iss,
            [WellKnownJwtClaimNames.Sub] = sub,
            [WellKnownJwtClaimNames.Aud] = aud
        };

        if(nonce is not null)
        {
            payload[WellKnownJwtClaimNames.Nonce] = nonce;
        }

        if(expiresAt is DateTimeOffset exp)
        {
            payload[WellKnownJwtClaimNames.Exp] = exp.ToUnixTimeSeconds();
        }

        if(issuedAt is DateTimeOffset iat)
        {
            payload[WellKnownJwtClaimNames.Iat] = iat.ToUnixTimeSeconds();
        }

        if(subJwk is not null)
        {
            payload[WellKnownJwtClaimNames.SubJwk] = subJwk;
        }

        return payload;
    }


    //Mints a Self-Issued ID Token with the same JCose composition a wallet uses:
    //UnsignedJwt.SignAsync with the subject's key, alg derived from the key's Tag.
    private async ValueTask<string> MintTokenAsync(
        PrivateKeyMemory signingKey,
        string iss,
        string sub,
        object aud,
        string? nonce,
        DateTimeOffset? expiresAt,
        DateTimeOffset? issuedAt,
        Dictionary<string, object>? subJwk,
        string? keyId = null)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };

        if(keyId is not null)
        {
            header[WellKnownJwkMemberNames.Kid] = keyId;
        }

        JwtPayload payload = ComposePayload(iss, sub, aud, nonce, expiresAt, issuedAt, subJwk);

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }
}
