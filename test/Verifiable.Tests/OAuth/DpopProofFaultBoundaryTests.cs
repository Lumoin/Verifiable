using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the fault boundary of <see cref="DpopProofValidator.ValidateAsync"/> beyond the reading of a proof's parts: the decoder's
/// refusal of wire text as no base64url, its <see cref="FormatException"/>, answers the proof - an invalid JWK for a coordinate of
/// the embedded key, a signature that does not verify for the signature segment - while any other exception of the decoder, the
/// delegate the receiver supplied, surfaces as the fault it is; and a part refusal naming a defect no reading answers reaches the
/// validator's refusal of the reading that answered it through the public parser seam.
/// </summary>
[TestClass]
internal sealed class DpopProofFaultBoundaryTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The instant the proofs are issued and validated at.</summary>
    private static DateTimeOffset IssuedAt { get; } = TestClock.CanonicalEpoch;

    /// <summary>The target URI the proofs name and the requests are made to.</summary>
    private const string Target = "https://as.example.com/token";

    /// <summary>The clock the validation reads.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(IssuedAt);


    /// <summary>
    /// The embedded key's <c>x</c> coordinate, decoded by the receiver's decoder while the library reconstructs the key: a decoder
    /// that throws an <see cref="ArgumentException"/> for it is faulty, and the fault surfaces rather than being answered as the
    /// proof's invalid JWK; the control, the decoder refusing the coordinate as no base64url text, answers an invalid JWK.
    /// </summary>
    /// <returns>A task completing once both proofs are judged.</returns>
    [TestMethod]
    public async Task ACoordinateDecoderFaultSurfacesAndItsRefusalAnswersAnInvalidJwk()
    {
        var proof = await BuildProofAsync().ConfigureAwait(false);
        var x = EmbeddedKeyX(proof);

        var refused = await ValidateAsync(proof, DecoderFailingOn(x, static () => new FormatException("The coordinate is no base64url text."))).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidJwk, refused.FailureReason, "The decoder's refusal of the coordinate answers an invalid JWK.");
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => ValidateAsync(proof, DecoderFailingOn(x, static () => new ArgumentException("The decoder failed.")))).ConfigureAwait(false);
    }


    /// <summary>
    /// The signature segment, decoded by the receiver's decoder while the library verifies the proof's signature (RFC 7515 section
    /// 5.2): a decoder that throws an <see cref="InvalidOperationException"/> for it is faulty, and the fault surfaces rather than
    /// being answered as a signature that does not verify; the control, the decoder refusing the segment as no base64url text,
    /// answers a failed signature.
    /// </summary>
    /// <returns>A task completing once both proofs are judged.</returns>
    [TestMethod]
    public async Task ASignatureSegmentDecoderFaultSurfacesAndItsRefusalAnswersAFailedSignature()
    {
        var proof = await BuildProofAsync().ConfigureAwait(false);
        var signatureSegment = proof.Split('.')[2];

        var refused = await ValidateAsync(proof, DecoderFailingOn(signatureSegment, static () => new FormatException("The segment is no base64url text."))).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.SignatureFailed, refused.FailureReason, "The decoder's refusal of the signature answers a failed signature.");
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => ValidateAsync(proof, DecoderFailingOn(signatureSegment, static () => new InvalidOperationException("The decoder failed.")))).ConfigureAwait(false);
    }


    /// <summary>
    /// RFC 7515 section 7.1: a compact JWS whose protected header or signature segment is empty carries no header or signature to
    /// verify, which the verification answers as not verifying, without handing the empty text to the decoder.
    /// </summary>
    /// <returns>A task completing once both serializations are judged.</returns>
    [TestMethod]
    public async Task AJwsWithAnEmptyHeaderOrSignatureSegmentDoesNotVerify()
    {
        var proof = await BuildProofAsync().ConfigureAwait(false);
        var parts = proof.Split('.');
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        var emptySignature = await Jws.VerifyAsync($"{parts[0]}.{parts[1]}.", TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        var emptyHeader = await Jws.VerifyAsync($".{parts[1]}.{parts[2]}", TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, publicKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(emptySignature, "An empty signature segment does not verify.");
        Assert.IsFalse(emptyHeader, "An empty protected header segment does not verify.");
    }


    /// <summary>
    /// A receiver composes its own reading of a proof's parts through <see cref="DpopJwsPartParser"/>; a reading answering a
    /// member refusal of a defect no DPoP proof's reading names is refused by the validator as the fault of the reading that
    /// answered it, never given a known category.
    /// </summary>
    /// <returns>A task completing once the proof is judged.</returns>
    [TestMethod]
    public async Task APartRefusalOfAnUndefinedDefectFromAComposedParserIsTheParsersFault()
    {
        var proof = await BuildProofAsync().ConfigureAwait(false);
        var undefinedDefect = (DpopProofMemberDefect)99;
        var parser = DpopJwsPartParser.Default with
        {
            ParseHeader = _ => new DpopProofPartRefused<DpopProofHeader>(
                new DpopProofMemberRefusal(DpopProofMember.Alg, WellKnownJoseHeaderNames.Alg, new JsonMemberAbsent(), undefinedDefect))
        };

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => ValidateAsync(proof, TestSetup.Base64UrlDecoder, parser)).ConfigureAwait(false);
    }


    /// <summary>
    /// RFC 7518 sections 6.2.1.2 and 6.2.1.3 and NIST SP 800-186 appendix D.1.1.1: a proof whose embedded key's coordinates are of
    /// the curve's width but name no point of it carries no public key, so it is an invalid JWK, refused before any signature
    /// is verified under a key the coordinates do not state; the header is written that way by the producer before signing.
    /// </summary>
    /// <returns>A task completing once the proof is judged.</returns>
    [TestMethod]
    public async Task AProofWhoseKeyNamesNoPointOfTheCurveIsAnInvalidJwk()
    {
        var serializer = DpopTestSupport.Serializer with
        {
            SerializeHeader = header =>
            {
                var written = new Dictionary<string, object?>(DpopTestSupport.Serializer.SerializeHeader(header), StringComparer.Ordinal);
                var jwk = Assert.IsInstanceOfType<Dictionary<string, object>>(written[WellKnownJoseHeaderNames.Jwk]);
                using var y = TestSetup.Base64UrlDecoder(Assert.IsInstanceOfType<string>(jwk[WellKnownJwkMemberNames.Y]), BaseMemoryPool.Shared);
                var offCurveY = y.Memory.ToArray();
                offCurveY[^1] ^= 0x01;

                written[WellKnownJoseHeaderNames.Jwk] = new Dictionary<string, object>(jwk, StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Y] = TestSetup.Base64UrlEncoder(offCurveY)
                };

                return written;
            }
        };

        var proof = await BuildProofAsync(serializer).ConfigureAwait(false);

        var result = await ValidateAsync(proof, TestSetup.Base64UrlDecoder).ConfigureAwait(false);

        Assert.AreEqual(DpopProofValidationFailureReason.InvalidJwk, result.FailureReason);
    }


    /// <summary>A decoder decoding as the library's test wiring does, except that it fails for one text with the exception given.</summary>
    /// <param name="failingText">The text it fails for.</param>
    /// <param name="failure">The exception it fails with.</param>
    /// <returns>The decoder.</returns>
    private static DecodeDelegate DecoderFailingOn(string failingText, Func<Exception> failure) => (source, pool) =>
        source.SequenceEqual(failingText) ? throw failure() : TestSetup.Base64UrlDecoder(source, pool);


    /// <summary>The <c>x</c> coordinate of the key a proof's header embeds, as the header writes it.</summary>
    /// <param name="proof">The proof.</param>
    /// <returns>The coordinate's base64url text.</returns>
    private static string EmbeddedKeyX(string proof)
    {
        using var header = TestSetup.Base64UrlDecoder(proof.Split('.')[0], BaseMemoryPool.Shared);
        var read = DpopProofHeader.Read(header.Memory.Span) as DpopProofPartRead<DpopProofHeader>;

        return read?.Part.Jwk[WellKnownJwkMemberNames.X] ?? throw new InvalidOperationException("A proof the library composed reads.");
    }


    /// <summary>Builds and signs a proof for a POST to the target, issued now, under a fresh P-256 key.</summary>
    /// <returns>The compact proof.</returns>
    private Task<string> BuildProofAsync() => BuildProofAsync(DpopTestSupport.Serializer);


    /// <summary>Builds and signs a proof for a POST to the target, issued now, under a fresh P-256 key, written by the serializer given.</summary>
    /// <param name="serializer">The serializer writing the proof's header and claims before signing.</param>
    /// <returns>The compact proof.</returns>
    private async Task<string> BuildProofAsync(DpopJwsPartSerializer serializer)
    {
        var key = new DpopKey(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        var claims = new DpopProofClaims
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = Target,
            Iat = IssuedAt,
            Jti = Guid.NewGuid().ToString("N")
        };

        return await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Validates a proof for a POST to the target with the decoder given and the library's readings of its parts.</summary>
    /// <param name="proof">The proof.</param>
    /// <param name="decoder">The decoder the receiver supplies.</param>
    /// <returns>The validation result.</returns>
    private Task<DpopProofValidationResult> ValidateAsync(string proof, DecodeDelegate decoder) =>
        ValidateAsync(proof, decoder, DpopJwsPartParser.Default);


    /// <summary>Validates a proof for a POST to the target with the decoder and the readings of its parts given.</summary>
    /// <param name="proof">The proof.</param>
    /// <param name="decoder">The decoder the receiver supplies.</param>
    /// <param name="parser">The readings of the proof's parts.</param>
    /// <returns>The validation result.</returns>
    private async Task<DpopProofValidationResult> ValidateAsync(string proof, DecodeDelegate decoder, DpopJwsPartParser parser)
    {
        var request = new DpopProofValidationRequest
        {
            Proof = proof,
            HttpMethod = WellKnownHttpMethods.Post,
            HttpUrl = Target,
            ExpectedNonce = null,
            NonceRequired = false,
            AccessToken = null
        };

        return await DpopProofValidator.ValidateAsync(
            request,
            DpopTestSupport.Es256Verification,
            parser,
            TestSetup.Base64UrlEncoder,
            decoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            TimeSpan.FromSeconds(30),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
