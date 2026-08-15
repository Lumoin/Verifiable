using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Independent-oracle, conformant-peer interop proof for the <c>ObjectIdByURI</c> mechanism's Signing Input
/// composition (clause 5.2.8.3.2, JA-5.2.8.3.2-04/-C1..-C5), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>. The per-object
/// base64url-encoded-and-concatenated stream JA-5.2.8.3.2-C4/-C5 build IS the JWS Payload's own contribution to
/// the RFC 7515 §5.1 Signing Input — it goes in verbatim, never base64url-encoded a second time by the ordinary
/// <c>b64</c>-conditional whole-payload transform RFC 7797 §3 otherwise applies.
/// </summary>
/// <remarks>
/// <strong>Firewalled, independent oracle.</strong> The expected Signing Input is assembled directly from the
/// clause's own steps — base64url-encode each dereferenced object separately (C4), concatenate the resulting
/// TEXT's bytes (C5), then place that concatenation verbatim after <c>protected "."</c> (RFC 7515 §5.1) — using
/// only the base64url ENCODE primitive, never <see cref="JAdESSignatureCreation"/>/<see cref="JAdESSignatureValidation"/>'s
/// own signing-input assembly. The produced signature is verified against this independently-built input via the
/// raw <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/> primitive directly — never through
/// <see cref="Jws.VerifySignatureAsync(string, System.ReadOnlyMemory{byte}, System.ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, System.ReadOnlyMemory{byte}, BaseMemoryPool, System.Threading.CancellationToken)"/>,
/// so this proof never shares code with the (potentially buggy) composition it exists to catch.
/// </remarks>
[TestClass]
internal sealed class JAdESObjectIdByUriSigningInputCompositionOracleTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Creates a two-reference <c>ObjectIdByURI</c> signature (default <c>b64</c>, absent-or-true: per-object
    /// encoding applies per JA-5.2.8.3.2-C4) and proves BOTH directions: the produced signature verifies against
    /// the independently-assembled, single-encoded Signing Input (creation is spec-correct), and
    /// <see cref="JAdESSignatureValidation"/> accepts the same wire bytes through the same dereference stub
    /// (validation reconstructs the identical Signing Input — a double-encoding regression on either side would
    /// make the two sides disagree on what bytes were signed and fail one of these two assertions).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.3.2-04, JA-5.2.8.3.2-C1, JA-5.2.8.3.2-C2, JA-5.2.8.3.2-C5.
    /// </remarks>
    [TestMethod]
    public async Task ObjectIdByUriCreationAndValidationBuildTheSigningInputExactlyOnceMatchingIndependentOracle()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] objectA = [0x01, 0x02, 0x03];
        byte[] objectB = [0xAA, 0xBB];
        var store = new Dictionary<string, byte[]>
        {
            ["urn:test:a"] = objectA,
            ["urn:test:b"] = objectB
        };
        var context = new JAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using DigestValue x5tDigest = TestDigest();
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: x5tDigest);

        using JAdESSignatureCreationResult created = await JAdESSignatureCreation.SignAsync(
            headers,
            new JAdESDetachedObjectIdByUriPayloadInput([
                new JAdESDetachedObjectReferenceInput("urn:test:a", null),
                new JAdESDetachedObjectReferenceInput("urn:test:b", null)
            ]),
            unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            DereferenceFromDictionaryAsync,
            context,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string protectedSegment = created.Message.Signatures[0].Protected;
        byte[] signatureBytes = created.Message.Signatures[0].SignatureBytes.ToArray();

        //Independent oracle: JA-5.2.8.3.2-C4/-C5 verbatim -- base64url-encode EACH object separately, then
        //concatenate the resulting ENCODED TEXT's bytes; this concatenation IS the JWS Payload's contribution
        //and goes into the RFC 7515 §5.1 Signing Input verbatim -- never re-encoded as a whole a second time.
        string encodedA = TestSetup.Base64UrlEncoder(objectA);
        string encodedB = TestSetup.Base64UrlEncoder(objectB);
        byte[] expectedSigningInput = Encoding.ASCII.GetBytes(protectedSegment + "." + encodedA + encodedB);

        (bool oracleVerified, _) = await MicrosoftCryptographicFunctions.VerifyP256Async(
            expectedSigningInput, signatureBytes, publicKey.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(oracleVerified,
            "The produced signature must verify against the Signing Input assembled directly from " +
            "JA-5.2.8.3.2-C4/-C5's own text -- a conformant peer building the Signing Input from the clause " +
            "alone must reproduce the same bytes this library signed.");

        //ObjectIdByURI is always a detached-payload mechanism (JA-5.2.8.1-02's own attached-payload prohibition,
        //JAdESHeaderRules-enforced) -- Compact serialization refuses a detached payload (RFC 7515 §7.1 carries
        //no way to omit the payload segment), so Flattened JSON serialization is the wire form here.
        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult validationResult = await JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            DereferenceFromDictionaryAsync,
            context,
            externalDetachedPayload: null,
            httpHeadersContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, validationResult.Failure?.Message);
    }


    private static ValueTask<JAdESDetachedObjectDereferenceResult> DereferenceFromDictionaryAsync(
        string uriReference,
        JAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var store = (Dictionary<string, byte[]>)context.State!;
        if(!store.TryGetValue(uriReference, out byte[]? content))
        {
            return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
                new JAdESDetachedObjectDereferenceFailure($"No test fixture object registered for reference '{uriReference}'."));
        }

        return ValueTask.FromResult<JAdESDetachedObjectDereferenceResult>(
            new JAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data))));
    }


    private static byte[] JsonSerialize(object value) => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value);


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}
