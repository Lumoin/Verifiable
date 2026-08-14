using System.Buffers;
using System.Linq;
using System.Reflection;
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
/// The promotion-discipline template proof: an <see cref="UnverifiedJAdESMessage"/>
/// -- the untrusted parse result -- is NOT accepted where a <see cref="Verified{T}"/> is demanded, proven both at
/// compile time (the type system offers no conversion, and every minting surface is non-public -- checked here
/// via reflection, since a negative-compilation claim has no direct expression inside an MSTest method body) and
/// at runtime (a message that parses and decodes successfully but fails cryptographic verification never reaches
/// <see cref="JAdESValidationResult.Verified"/>). This is the family-wide template for the
/// <c>Unverified*</c>/<see cref="Verified{T}"/> promotion discipline elsewhere in the library.
/// </summary>
/// <remarks>
/// <strong>The non-forgeability claim, stated precisely.</strong> A non-public <see cref="Verified{T}"/>
/// constructor stops any OTHER assembly from CALLING it -- but a struct's own <see langword="default"/> is not a
/// constructor call, so <see langword="default"/>(<see cref="Verified{JAdESVerifiedSignatureFacts}"/>) was
/// (before <see cref="Verified{T}"/>'s own IsVerified/guarded-Value hardening) reachable by any caller and, once
/// reached, indistinguishable from a genuinely minted instance to code that read <c>.Value</c> without checking.
/// <see cref="DefaultVerifiedInstanceIsInertAndNeverPassesAsProof"/> proves that gap is closed: the type's own
/// default is now detectable (<c>IsVerified</c> false) and its <c>Value</c> throws rather than silently handing
/// back a fabricated <see cref="JAdESVerifiedSignatureFacts"/>. The accurate claim is therefore "no external
/// caller can mint a <see cref="Verified{T}"/> carrying ARBITRARY data via the constructor, AND the language's
/// own free default is now surfaced as inert rather than passing as unexamined proof" -- not the older, looser
/// "cannot be fabricated" framing this class's own test names still use for the constructor-level guarantee only.
/// </remarks>
[TestClass]
internal sealed class JAdESPromotionDisciplineTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Compile-time proof, verified via reflection: neither <see cref="UnverifiedJAdESMessage"/> nor the two
    /// carrier types it decodes into (<see cref="JAdESProtectedHeaders"/>, <see cref="JAdESUnsignedHeaders"/>)
    /// defines an implicit or explicit conversion operator targeting <see cref="Verified{JAdESVerifiedSignatureFacts}"/>
    /// -- so <c>Verified&lt;JAdESVerifiedSignatureFacts&gt; v = unverifiedMessage;</c> is a genuine compile error
    /// (CS0029) everywhere this assertion holds, not merely an untested convention.
    /// </summary>
    [TestMethod]
    public void NoConversionExistsFromUnverifiedTypesToVerifiedFacts()
    {
        Type verifiedFactsType = typeof(Verified<JAdESVerifiedSignatureFacts>);

        AssertNoConversionOperatorTargets(typeof(UnverifiedJAdESMessage), verifiedFactsType);
        AssertNoConversionOperatorTargets(typeof(JAdESProtectedHeaders), verifiedFactsType);
        AssertNoConversionOperatorTargets(typeof(JAdESUnsignedHeaders), verifiedFactsType);
    }


    /// <summary>
    /// <see cref="Verified{JAdESVerifiedSignatureFacts}"/>'s own constructor is non-public (family-wide,
    /// <c>Verified.cs</c>'s own remarks: "intentionally internal ... only first-party verification paths ...
    /// construct one") -- an external assembly cannot wrap decoded-but-unverified data into a
    /// <see cref="Verified{T}"/> even by direct construction, let alone by an implicit conversion.
    /// </summary>
    [TestMethod]
    public void VerifiedFactsConstructorIsNotPublic()
    {
        ConstructorInfo[] constructors = typeof(Verified<JAdESVerifiedSignatureFacts>).GetConstructors(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.IsGreaterThan(0, constructors.Length);
        Assert.IsTrue(constructors.All(static c => !c.IsPublic),
            "Verified<T>'s constructor must stay non-public -- a public constructor would let any caller mint a 'verified' value without going through JAdESSignatureValidation.ValidateAsync.");
    }


    /// <summary>
    /// <see cref="JAdESVerifiedSignatureFacts"/>'s own constructor is <see langword="internal"/> (its own
    /// remarks: "minted only by <see cref="JAdESSignatureValidation"/>") -- the facts a <see cref="Verified{T}"/>
    /// wraps cannot themselves be fabricated from outside this library either.
    /// </summary>
    [TestMethod]
    public void VerifiedSignatureFactsConstructorIsNotPublic()
    {
        ConstructorInfo[] constructors = typeof(JAdESVerifiedSignatureFacts).GetConstructors(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.IsGreaterThan(0, constructors.Length);
        Assert.IsTrue(constructors.All(static c => !c.IsPublic));
    }


    /// <summary>
    /// <see cref="JAdESValidationResult"/> has no public constructor, and its <c>Success</c>/<c>Failed</c>
    /// minting factories are non-public -- the ONLY public route to an instance carrying a non-null
    /// <see cref="JAdESValidationResult.Verified"/> is <see cref="JAdESSignatureValidation.ValidateAsync"/>
    /// itself, which performs the actual cryptographic check before minting one.
    /// </summary>
    [TestMethod]
    public void ValidationResultHasNoPublicConstructorOrMintingFactory()
    {
        Type resultType = typeof(JAdESValidationResult);

        ConstructorInfo[] constructors = resultType.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.IsGreaterThan(0, constructors.Length);
        Assert.IsTrue(constructors.All(static c => !c.IsPublic));

        MethodInfo? success = resultType.GetMethod("Success", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
        MethodInfo? failed = resultType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .FirstOrDefault(static m => m.Name == "Failed");

        Assert.IsNotNull(success);
        Assert.IsFalse(success!.IsPublic, "Success must stay non-public -- minting a 'valid' result is JAdESSignatureValidation's exclusive responsibility.");
        Assert.IsNotNull(failed);
        Assert.IsFalse(failed!.IsPublic);
    }


    /// <summary>
    /// Runtime proof: a message whose wire bytes parse and whose protected header decodes successfully, but
    /// whose cryptographic signature check fails, NEVER reaches <see cref="JAdESValidationResult.Verified"/> --
    /// the decoded-but-unverified facts remain reachable only through <see cref="JAdESValidationResult.Headers"/>,
    /// a plain (non-<see cref="Verified{T}"/>) carrier, exactly the "unverified data is not accepted where
    /// Verified&lt;T&gt; is demanded" guarantee at the one point only runtime state can prove it (a parse that
    /// succeeded is not itself proof of authenticity).
    /// </summary>
    [TestMethod]
    public async Task ParsedButCryptographicallyInvalidMessageNeverPromotesToVerified()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using DigestValue x5tDigest = TestDigest();
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: x5tDigest);

        using JAdESSignatureCreationResult created = await JAdESSignatureCreation.SignAsync(
            headers,
            new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);
        byte[] tamperedWire = FlipLastCharOfSegment(wireBytes, segmentIndex: 2);

        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            tamperedWire,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            httpHeadersContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.Verified, "A parsed-but-cryptographically-invalid message must never promote to Verified<T> -- the guarantee this whole class proves.");
        Assert.IsNotNull(result.Headers, "The decoded (unverified) facts must still be reachable -- through Headers, never through Verified.");
    }


    /// <summary>
    /// The mirror-image invariant: a genuinely valid message's decoded facts are reachable ONLY through
    /// <see cref="JAdESValidationResult.Verified"/> -- <see cref="JAdESValidationResult.Headers"/>/
    /// <see cref="JAdESValidationResult.UnsignedHeaders"/> stay <see langword="null"/> on success, so a consumer
    /// can never accidentally read unpromoted facts off a successful result either.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulValidationExposesFactsOnlyThroughVerified()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using DigestValue x5tDigest = TestDigest();
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: x5tDigest);

        using JAdESSignatureCreationResult created = await JAdESSignatureCreation.SignAsync(
            headers,
            new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = JAdESSignatureCreation.Serialize(created, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);

        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            httpHeadersContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsNull(result.Headers, "On success, the decoded facts must be reachable only through Verified -- never duplicated onto Headers too.");
        Assert.IsNull(result.UnsignedHeaders);
    }


    /// <summary>
    /// Verified&lt;T&gt; hardening: the struct's own free default -- unreachable through any minting
    /// path this library exposes, but reachable through the language itself (<see langword="default"/>, an
    /// uninitialized field, a skipped array element) -- is INERT. <see cref="Verified{T}.IsVerified"/> reports
    /// <see langword="false"/> for it, and reading <see cref="Verified{T}.Value"/> throws
    /// <see cref="InvalidOperationException"/> rather than silently handing back
    /// <see langword="default"/>(<see cref="JAdESVerifiedSignatureFacts"/>) as if it had passed verification.
    /// </summary>
    [TestMethod]
    public void DefaultVerifiedInstanceIsInertAndNeverPassesAsProof()
    {
        Verified<JAdESVerifiedSignatureFacts> defaultInstance = default;

        Assert.IsFalse(defaultInstance.IsVerified, "The struct's own default must never report itself as verified.");
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = defaultInstance.Value);
    }


    private static void AssertNoConversionOperatorTargets(Type source, Type target)
    {
        List<Type> conversionTargets = [.. source.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .Where(static m => m.Name is "op_Implicit" or "op_Explicit")
            .Select(static m => m.ReturnType)];

        Assert.DoesNotContain(target, conversionTargets,
            $"{source.Name} must define no conversion operator to {target.Name} -- the compiler must reject assigning unverified data where Verified<T> is demanded.");
    }


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


    /// <summary>Flips the last character's top base64url-alphabet bit of a Compact-serialization segment, mirroring <c>JAdESSignatureValidationTests</c>'s identical helper.</summary>
    private static byte[] FlipLastCharOfSegment(byte[] compactWireBytes, int segmentIndex)
    {
        string compact = Encoding.ASCII.GetString(compactWireBytes);
        string[] parts = compact.Split('.');
        int index = Base64UrlAlphabet.IndexOf(parts[segmentIndex][^1], StringComparison.Ordinal);
        parts[segmentIndex] = parts[segmentIndex][..^1] + Base64UrlAlphabet[index ^ 0b100000];

        return Encoding.ASCII.GetBytes(string.Join('.', parts));
    }


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);
        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}
