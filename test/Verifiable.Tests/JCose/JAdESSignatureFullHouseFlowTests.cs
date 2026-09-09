using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
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
/// The JAdES full-house B-B flow: every clause 5.1/5.2 signed header the
/// dedicated <see cref="JAdESSignatureCreationTests"/>/<see cref="JAdESSignatureValidationTests"/> suites leave
/// unpopulated in isolation -- <c>cty</c>, <c>kid</c>, <c>x5u</c>, <c>x5t#S256</c>, <c>srCms</c>, <c>sigPl</c>,
/// <c>srAts</c>, <c>adoTst</c>, <c>sigPId</c>, plus both claimed-signing-time members (<c>iat</c>/<c>sigT</c>
/// together) -- present simultaneously on ONE attached message together with a populated <c>etsiU</c>, created,
/// serialized, wire-copied, and validated through both JSON serialization forms a message carrying a JWS
/// Unprotected Header can use (JA-4-05 structurally excludes Compact once <c>etsiU</c> is populated), with the
/// promoted facts asserted member-by-member against independently-kept expectations -- the
/// <c>CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader</c> family
/// precedent, transposed to JWS.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope (mirrors the CB-AdES precedent's own bar).</strong> <c>sigD</c> is excluded: it requires a
/// detached payload, and the three sigD mechanisms already have their own dedicated coverage in
/// <see cref="JAdESSignatureCreationTests"/>/<see cref="JAdESSignatureValidationTests"/>. <c>x5c</c>/<c>x5t#o</c>/
/// <c>sigX5ts</c> (the three alternative signing-certificate-identification arms besides <c>x5t#S256</c>) and
/// <c>crit</c>/<c>b64</c> are likewise left to their own dedicated coverage (<c>JAdESProtectedHeaderJsonTests</c>,
/// the sigD-mechanism tests) rather than duplicated here -- this flow's job is the headers that only co-occur
/// naturally on ONE fully-populated message, not an exhaustive re-declaration of every member the dedicated
/// suites already prove in isolation.
/// </para>
/// <para>
/// <strong>Firewalled, wire-bytes-only.</strong> Every asserted value is read off <see cref="JAdESValidationResult.Verified"/>'s
/// promoted <see cref="JAdESVerifiedSignatureFacts"/> after a full parse/decode/verify round trip through wire
/// bytes alone, compared against independently-kept local expectations -- never the creation-side objects.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESSignatureFullHouseFlowTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Flow: attached payload, every clause 5.1/5.2 signed header this scope covers (see the class remarks) plus
    /// a populated <c>etsiU</c>, created once and validated through Flattened and General JWS JSON Serialization
    /// in turn -- every decoded member asserted against an independently-kept expectation.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">ETSI TS 119 182-1 V1.2.1</see>
    /// JA-4-01, JA-4-02, JA-5.2.3-04, JA-5.2.4-03, JA-5.2.4-06, JA-5.2.5-03, JA-5.2.6-04, JA-5.2.6-08,
    /// JA-5.2.7.1-03.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "JAdESSignatureCreationResult on a successful JAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), disposed here via 'using created'. The nested srCms/sigPl/srAts/" +
            "adoTst/sigPId construction is a constructor argument passed straight into headers's own " +
            "construction, so ownership passes onward with it; Roslyn's CA2000 analysis flags each nested " +
            "'new' expression independently of the enclosing aggregate that actually owns and disposes them.")]
    [TestMethod]
    public async Task FullHouseAttachedFlowRoundTripsThroughBothJsonFormsAndPromotesEverySignedHeaderAndEtsiU()
    {
        byte[] payloadBytes = "JAdES full-house attached ES256 payload"u8.ToArray();
        const string expectedContentType = "application/octet-stream";
        const string expectedKeyId = "full-house-key-id";
        var expectedX5u = new Uri("https://example.org/jades/full-house/signing-certificate.cer");
        const string expectedCommitmentId = "urn:jades:full-house:commitment:proof-of-origin";
        const string expectedLocality = "Tallinn";
        const string expectedCountry = "EE";
        const string expectedClaimedMediaType = "application/vnd.example.full-house-claimed+json";
        const string expectedClaimedEncoding = "utf-8";
        const string expectedClaimedValue = "full-house-claimed-value";
        byte[] timestampTokenDerBytes = [0x30, 0x03, 0x02, 0x01, 0x2A];
        const string expectedPolicyId = "urn:jades:full-house:policy:1";

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //A well-formed (not merely opaque) base64url-mode cSig element: this flow round-trips through
        //validation's own etsiU re-parse, so the fixture must actually decode, per JAdESEtsiUJson's own
        //opaque-carrier contract -- mirroring JAdESSignatureValidationTests.EtsiUUnsignedHeadersRoundTripIntoVerifiedFacts.
        string cSigBase64Url = TestSetup.Base64UrlEncoder("{\"cSig\":\"full-house-opaque\"}"u8);
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.Base64Url,
            [new JAdESUnsignedHeaderElementCounterSignature(
                PooledMemory.FromBytes(Encoding.ASCII.GetBytes(cSigBase64Url), BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        var srCms = new AdESSignerCommitments([new AdESCommitment(new AdESObjectIdentifier(expectedCommitmentId))]);
        var sigPl = new AdESSignatureProductionPlace { AddressLocality = expectedLocality, AddressCountry = expectedCountry };
        var srAts = new AdESSignerAttributes(claimed:
        [
            new JAdESQualifyingAttribute(expectedClaimedMediaType, expectedClaimedEncoding, [expectedClaimedValue])
        ]);
        var adoTst = new AdESTimestampContainer([new AdESTimestampToken { Val = timestampTokenDerBytes }]);
        var sigPId = new AdESSignaturePolicyIdentifier(new AdESObjectIdentifier(expectedPolicyId));

        var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            contentType: expectedContentType,
            keyId: expectedKeyId,
            x5u: expectedX5u,
            x5tHashS256: TestDigest(),
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            sigT: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            signerCommitments: srCms,
            signatureProductionPlace: sigPl,
            signerAttributes: srAts,
            payloadTimestamps: adoTst,
            signaturePolicyIdentifier: sigPId);

        using JAdESSignatureCreationResult created = await JAdESSignatureCreation.SignAsync(
            headers,
            new JAdESAttachedPayloadInput(payloadBytes),
            unsignedHeaders,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        foreach(JoseSerializationFormat format in new[] { JoseSerializationFormat.FlattenedJson, JoseSerializationFormat.GeneralJson })
        {
            byte[] wireBytes = JAdESSignatureCreation.Serialize(created, format, TestSetup.Base64UrlEncoder, JsonSerialize);

            using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
                wireBytes,
                JAdESMessageJson.TryParse,
                JAdESProtectedHeaderJson.Decode,
                JAdESProtectedHeaderJson.DetectX5tPresence,
                JAdESEtsiUJson.TryParse,
                publicKey,
                MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                httpHeadersContext: null,
                unknownMechanismHandler: null,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsValid, $"Expected {format} to validate: {result.Failure?.Message}");
            Assert.IsNotNull(result.Verified);

            JAdESProtectedHeaders decoded = result.Verified!.Value.Value.Headers;

            Assert.AreEqual(WellKnownJwaValues.Es256, decoded.Algorithm);
            Assert.AreEqual(expectedContentType, decoded.ContentType);
            Assert.AreEqual(expectedKeyId, decoded.KeyId);
            Assert.AreEqual(expectedX5u, decoded.X5U);
            Assert.IsNotNull(decoded.X5tHashS256);
            Assert.AreEqual(TestClock.CanonicalEpoch.ToUnixTimeSeconds(), decoded.IssuedAt?.Value.ToUnixTimeSeconds());
            Assert.AreEqual(TestClock.CanonicalEpoch.ToUnixTimeSeconds(), decoded.SigT?.Value.ToUnixTimeSeconds());

            Assert.IsNotNull(decoded.SignerCommitments);
            Assert.HasCount(1, decoded.SignerCommitments!.Commitments);
            Assert.AreEqual(expectedCommitmentId, decoded.SignerCommitments.Commitments[0].CommitmentId.Id);

            Assert.IsNotNull(decoded.SignatureProductionPlace);
            Assert.AreEqual(expectedLocality, decoded.SignatureProductionPlace!.AddressLocality);
            Assert.AreEqual(expectedCountry, decoded.SignatureProductionPlace.AddressCountry);

            Assert.IsNotNull(decoded.SignerAttributes);
            Assert.IsNotNull(decoded.SignerAttributes!.Claimed);
            Assert.HasCount(1, decoded.SignerAttributes.Claimed!);
            var claimedAttribute = (JAdESQualifyingAttribute)decoded.SignerAttributes.Claimed[0];
            Assert.AreEqual(expectedClaimedMediaType, claimedAttribute.MediaType);
            Assert.AreEqual(expectedClaimedEncoding, claimedAttribute.Encoding);

            Assert.IsNotNull(decoded.PayloadTimestamps);
            Assert.HasCount(1, decoded.PayloadTimestamps!.TstTokens);
            Assert.IsTrue(timestampTokenDerBytes.AsSpan().SequenceEqual(decoded.PayloadTimestamps.TstTokens[0].Val.Span));
            Assert.IsNull(decoded.PayloadTimestamps.CanonAlg);

            Assert.IsNotNull(decoded.SignaturePolicyIdentifier);
            Assert.AreEqual(expectedPolicyId, decoded.SignaturePolicyIdentifier!.Id.Id);

            Assert.IsNotNull(result.Verified.Value.Value.UnsignedHeaders);
            Assert.AreEqual(1, result.Verified.Value.Value.UnsignedHeaders!.Count);
            Assert.AreEqual(JAdESUnsignedHeaderElement.CounterSignatureKind, result.Verified.Value.Value.UnsignedHeaders[0].Kind);
        }
    }


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);
        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}
