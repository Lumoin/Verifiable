using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Throw-posture tests for <see cref="CBAdESSignatureCreation"/> and the shared <see cref="CBAdESHeaderRules"/>
/// rule surface it composes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clauses 4-6 and 5.2.8 (the B-B creation e2e, wavecb-contract.md stage S3).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two entry points, deliberately mixed.</strong> Some cases below call
/// <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
/// end to end (via <see cref="SignCreateAsync"/>); others call <see cref="CBAdESHeaderRules.EnsureConformant"/>
/// directly against a hand-built <see cref="CBAdESProtectedHeaders"/>. This is not inconsistency — it follows
/// two structural facts this file records loudly at the exact test sites they apply to: (1) sigD-plus-attached-
/// payload (CB-5.2.8-03) is UNREACHABLE through <see cref="CBAdESSignatureCreation"/> at all, because
/// <see cref="CBAdESDetachedSigDPayloadInput"/> always resolves <c>payloadIsDetached</c> to <see langword="true"/>;
/// (2) the sigD <c>hashM</c> MD5 surface (CB-6.2.1-02) is unreachable through the orchestrator's
/// <c>ObjectIdByURIHash</c> path specifically, because <see cref="CBAdESSignatureCreation"/>'s own digest-
/// algorithm resolution refuses any non-SHA-256/384/512 identifier — MD5 included — with
/// <see cref="NotSupportedException"/> before <c>hashV</c> computation ever runs, so the
/// <see cref="CBAdESHeaderRules"/> <see cref="ArgumentException"/> for that surface never fires through that
/// path. Both remain reachable, and tested, directly against the shared rule surface — exactly what a validator
/// consuming the same rules over already-decoded, non-conformant wire content would exercise.
/// </para>
/// <para>
/// <strong>Ownership discipline around <see cref="CBAdESSignatureCreation.SignAsync"/>'s "sole producer"
/// contract.</strong> On a SUCCESSFUL call, ownership of the <c>headers</c> argument transfers into the
/// returned <see cref="CBAdESSignatureCreationResult.Headers"/> (see that method's remarks) — every succeeding
/// test therefore disposes only the result, never the original <see cref="CBAdESProtectedHeaders"/> local. On a
/// FAILING call (an exception before the successful-return point), no transfer occurs — every throw-posture
/// test therefore wraps its <see cref="CBAdESProtectedHeaders"/> local in a <see langword="using"/> declaration.
/// Digest/thumbprint fixtures that <see cref="CBAdESProtectedHeaders"/> or one of its owned members will in
/// turn own are constructed INLINE, as constructor-argument expressions, never assigned to a separately-disposed
/// named local — the single disposal path is the outermost owning aggregate.
/// </para>
/// <para>
/// <strong>No closure capture (dereference/unknown-mechanism seams).</strong> <see cref="DereferenceFromStoreAsync"/>
/// and <see cref="HandleUnknownMechanismAsync"/> are plain <see langword="static"/> methods; the fixed
/// URI-reference-to-bytes store every sigD test needs reaches them exclusively through the explicit, per-call
/// <see cref="CBAdESDetachedObjectDereferenceContext.State"/> (an <see cref="ObjectStore"/> instance), never a
/// captured lambda variable — mirroring <c>Verifiable.Tests.Cose.CoseTests.TestResolverState</c>'s own
/// explicit-state convention for a resolver/binder seam.
/// </para>
/// <para>
/// <strong>Digest fixtures.</strong> Every <see cref="DigestValue"/> this file mints goes through the
/// registered <see cref="CryptographicKeyEvents"/> digest delegate seam via <see cref="CreateDigestAsync"/>,
/// never a hand-rolled hash — including the oracle digests the <c>ObjectIdByURIHash</c> <c>hashV</c> test
/// compares against, which is the independent path proving creation's own computed digests are correct rather
/// than merely self-consistent.
/// </para>
/// <para>
/// <strong>Key material.</strong> Every signing key is P-256, minted through
/// <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/> (the Microsoft backend), signed via the explicit-
/// delegate <see cref="CBAdESSignatureCreation.SignAsync"/> overload with
/// <see cref="MicrosoftCryptographicFunctions.SignP256Async"/> — mirroring
/// <c>Verifiable.Tests.Cose.CoseTests</c>'s own explicit-delegate composition pattern exactly, so this stage's
/// tests never depend on the <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> resolution
/// path the registry-resolved overload would exercise instead.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESSignatureCreationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Creation with none of <c>x5t</c>, <c>x5ts</c>, or <c>x5chain</c> present throws, citing CB-5.2.2-07 (D9).
    /// </summary>
    [TestMethod]
    public async Task CreationWithNoCertificateReferenceThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-5.2.2-07", exception.Message);
    }


    /// <summary>
    /// Creation with ONLY <c>x5t</c> present satisfies the tri-way (CB-5.2.2-07) — one of the three positive
    /// legs.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task CreationWithOnlyX5TSatisfiesTriWay()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.Headers.X5T);
        Assert.IsNull(result.Headers.CertificateDigests);
        Assert.IsNull(result.Headers.X5Chain);
    }


    /// <summary>
    /// Creation with ONLY <c>x5ts</c> present satisfies the tri-way (CB-5.2.2-07) — the second positive leg.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. The nested CBAdESCertificateThumbprints/" +
            "CBAdESCertificateThumbprint fixtures are constructor arguments passed straight into headers's own " +
            "construction, so their ownership passes to headers and then onward with it; Roslyn's CA2000 " +
            "analysis flags each nested 'new' expression independently of the enclosing aggregate that actually " +
            "owns and disposes them.")]
    [TestMethod]
    public async Task CreationWithOnlyCertificateDigestsSatisfiesTriWay()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            certificateDigests: new CBAdESCertificateThumbprints(
            [
                new CBAdESCertificateThumbprint(
                    new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
                    await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "signing-certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false)),
                new CBAdESCertificateThumbprint(
                    new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384),
                    await CreateDigestAsync(WellKnownCoseAlgorithms.Sha384, "intermediate-certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false))
            ]));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result.Headers.X5T);
        Assert.IsNotNull(result.Headers.CertificateDigests);
        Assert.IsNull(result.Headers.X5Chain);
    }


    /// <summary>
    /// Creation with ONLY <c>x5chain</c> present satisfies the tri-way (CB-5.2.2-07) — the third positive leg.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task CreationWithOnlyX5ChainSatisfiesTriWay()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5chain: new CBAdESX5ChainSingleCertificate(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result.Headers.X5T);
        Assert.IsNull(result.Headers.CertificateDigests);
        Assert.IsNotNull(result.Headers.X5Chain);
    }


    /// <summary>
    /// A missing CWT Claims member throws, citing CB-6.3-10/D10 -- asserted directly against
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/> (see the class remarks for why this rule is exercised
    /// directly rather than through <see cref="CBAdESSignatureCreation"/>). Before wavecb S3 FX-E,
    /// <see cref="CBAdESProtectedHeaders"/>'s own constructor guarded <see cref="CBAdESProtectedHeaders.CwtClaims"/>
    /// non-null, making <see cref="CBAdESCwtClaimsMissingViolation"/> structurally unreachable through
    /// <see cref="CBAdESHeaderRules"/> and this test assert at the construction site instead; now that
    /// <see cref="CBAdESProtectedHeaders.CwtClaims"/> is nullable, the rules surface is where this violation is
    /// actually reachable from, so this test moved there -- the creation throw posture
    /// (<see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>)
    /// still throws through this exact same <see cref="CBAdESHeaderRules.EnsureConformant"/> call (its PASS 1),
    /// unchanged.
    /// </summary>
    [TestMethod]
    public async Task MissingCwtClaimsThrowsCitingCB6310()
    {
        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            cwtClaims: null,
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false, unsignedHeaders: null));

        Assert.Contains("CB-6.3-10", exception.Message);
    }


    /// <summary>
    /// Constructing <see cref="CBAdESCwtClaims"/> with a claimed signing time that carries a non-zero UTC offset
    /// throws, citing CB-6.3-a -- the additional clause 6.3 requirement that the generator include the claimed
    /// UTC time (not any other offset) as the <c>iat</c> content. This is the model's own construction-time
    /// guard (<see cref="CBAdESCwtClaims.CBAdESCwtClaims(DateTimeOffset)"/>), independent of and reached before
    /// either <see cref="CBAdESHeaderRules.EnsureConformant"/> or <see cref="CBAdESSignatureCreation.SignAsync"/>
    /// ever runs.
    /// </summary>
    [TestMethod]
    public void ConstructingCwtClaimsWithNonZeroOffsetThrowsCitingCB63a()
    {
        var nonUtcSigningTime = new DateTimeOffset(2026, 8, 3, 12, 0, 0, TimeSpan.FromHours(2));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new CBAdESCwtClaims(nonUtcSigningTime));

        Assert.Contains("CB-6.3-a", exception.Message);
    }


    /// <summary>
    /// When CWT Claims is present, the signed protected header carries label 15 (CWT Claims) with claim key 6
    /// (<c>iat</c>) equal to the caller-supplied claimed signing time — verified via an INDEPENDENT
    /// <see cref="CborReader"/> over the encoded <see cref="EncodedCoseProtectedHeader"/> bytes, never by
    /// re-decoding through <see cref="CBAdESSignatureSerialization"/> itself (CB-6.3-10/CB-5.1.9-06).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task SignedProtectedHeaderCarriesCwtClaimsIat()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<int, ReadOnlyMemory<byte>> protectedHeaderEntries =
            ReadProtectedHeaderEntries(result.Message.ProtectedHeader.AsReadOnlyMemory());
        Assert.IsTrue(protectedHeaderEntries.ContainsKey(CoseHeaderParameters.CwtClaims), "The protected header must carry the CWT Claims member (label 15).");

        (int claimKey, long issuedAtSeconds) = ReadCwtClaimsMember(protectedHeaderEntries[CoseHeaderParameters.CwtClaims]);

        Assert.AreEqual(WellKnownCwtClaimNames.Iat, claimKey, "The CWT Claims map's sole member must be claim key 6 (iat).");
        Assert.AreEqual(TestClock.CanonicalEpoch.ToUnixTimeSeconds(), issuedAtSeconds, "iat must equal the caller-supplied claimed signing time.");
    }


    /// <summary>
    /// Both <c>content type</c> and <c>sigD</c> present throws, citing CB-5.1.3-03 — asserted directly against
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/> (see the class remarks for why this rule is exercised
    /// directly rather than through <see cref="CBAdESSignatureCreation"/>).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESDetachedObjects/CBAdESDetachedObjectEntry constructions are " +
            "constructor arguments passed straight into the enclosing 'using var headers' aggregate's own " +
            "construction; ownership passes to headers, which this test disposes. Roslyn's CA2000 analysis " +
            "flags each nested 'new' expression independently of the enclosing aggregate that actually owns " +
            "and disposes them.")]
    [TestMethod]
    public async Task ContentTypeAndDetachedObjectsBothPresentThrows()
    {
        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            contentType: new CBAdESContentTypeText("application/octet-stream"),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            detachedObjects: new CBAdESDetachedObjects(
                CBAdESDetachedMechanisms.ObjectIdByURI,
                [new CBAdESDetachedObjectEntry("urn:test:object", digest: null, contentType: null)]));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: true, unsignedHeaders: null));

        Assert.Contains("CB-5.1.3-03", exception.Message);
    }


    /// <summary>
    /// <c>sigD</c> present with an ATTACHED payload throws, citing CB-5.2.8-03 — asserted directly against
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/>. This combination is STRUCTURALLY UNREACHABLE through
    /// <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// itself (a load-bearing design fact, recorded loudly): <see cref="CBAdESDetachedSigDPayloadInput"/> always
    /// resolves <c>payloadIsDetached</c> to <see langword="true"/>, so no call through the orchestrator can ever
    /// construct this exact violation — it remains reachable, and tested, only directly against the shared rule
    /// surface, exactly as a wire-content validator parsing an already-decoded, non-conformant message would
    /// exercise it. <c>crit</c> includes <c>sigD</c>'s label so the crit-presence rule (CB-5.1.10-04) does not
    /// also fire, isolating CB-5.2.8-03 as the sole violation.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESDetachedObjects/CBAdESDetachedObjectEntry constructions are " +
            "constructor arguments passed straight into the enclosing 'using var headers' aggregate's own " +
            "construction; ownership passes to headers, which this test disposes. Roslyn's CA2000 analysis " +
            "flags each nested 'new' expression independently of the enclosing aggregate that actually owns " +
            "and disposes them.")]
    [TestMethod]
    public async Task DetachedObjectsWithAttachedPayloadThrows()
    {
        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            detachedObjects: new CBAdESDetachedObjects(
                CBAdESDetachedMechanisms.ObjectIdByURI,
                [new CBAdESDetachedObjectEntry("urn:test:object", digest: null, contentType: null)]),
            criticalLabels: [new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD)]);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false, unsignedHeaders: null));

        Assert.Contains("CB-5.2.8-03", exception.Message);
    }


    /// <summary>
    /// When <c>sigD</c> is resolved, creation auto-adds label 267 to <c>crit</c> even when the caller never
    /// listed it (CB-5.1.10-04; S3 coordinator ruling (3)) — verified via an INDEPENDENT <see cref="CborReader"/>
    /// over the encoded protected header bytes — while a caller-supplied extra <c>crit</c> label survives
    /// alongside it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task SigDPresentAutoAddsCriticalLabelAndPreservesCallerLabels()
    {
        const int CallerCriticalLabel = 999;

        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:auto-add-crit"] = "auto-add-crit-object"u8.ToArray() });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            criticalLabels: [new CoseHeaderIntegerLabel(CallerCriticalLabel)]);

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURI,
            [new CBAdESDetachedObjectReferenceInput("urn:test:auto-add-crit", null)]);

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            payloadInput,
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<int, ReadOnlyMemory<byte>> protectedHeaderEntries =
            ReadProtectedHeaderEntries(result.Message.ProtectedHeader.AsReadOnlyMemory());
        List<int> criticalLabels = ReadIntArray(protectedHeaderEntries[CoseHeaderParameters.Crit]);

        Assert.Contains(CBAdESHeaderParameters.SigD, criticalLabels, "crit must include sigD's label (267) even though the caller never listed it (CB-5.1.10-04).");
        Assert.Contains(CallerCriticalLabel, criticalLabels, "A caller-supplied crit label must survive alongside the auto-added label.");
        Assert.HasCount(2, criticalLabels, "Only the caller's own label and the auto-added sigD label should be present.");
    }


    /// <summary>
    /// An MD5-labelled <c>x5t</c> digest throws, citing CB-6.2.1-02 — reached through
    /// <see cref="CBAdESSignatureCreation"/>'s PASS 1 rule check, before any dereferencing I/O.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateThumbprint construction is a constructor argument passed " +
            "straight into the enclosing 'using var headers' aggregate's own construction; ownership passes to " +
            "headers, which this test disposes. Roslyn's CA2000 analysis flags the nested 'new' expression " +
            "independently of the enclosing aggregate that actually owns and disposes it.")]
    [TestMethod]
    public async Task X5TWithMd5DigestThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: new CBAdESCertificateThumbprint(
                new CBAdESDigestAlgorithmTextIdentifier("MD5"),
                await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "md5-labelled-certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false)));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-6.2.1-02", exception.Message);
    }


    /// <summary>
    /// An MD5-labelled <c>x5ts</c> entry throws, citing CB-6.2.1-02 — reached through
    /// <see cref="CBAdESSignatureCreation"/>'s PASS 1 rule check.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateThumbprints/CBAdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using var headers' aggregate's own " +
            "construction; ownership passes to headers, which this test disposes. Roslyn's CA2000 analysis " +
            "flags each nested 'new' expression independently of the enclosing aggregate that actually owns " +
            "and disposes them.")]
    [TestMethod]
    public async Task CertificateDigestsEntryWithMd5DigestThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            certificateDigests: new CBAdESCertificateThumbprints(
            [
                new CBAdESCertificateThumbprint(
                    new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
                    await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "signing-certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false)),
                new CBAdESCertificateThumbprint(
                    new CBAdESDigestAlgorithmTextIdentifier("MD5"),
                    await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "md5-labelled-intermediate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false))
            ]));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-6.2.1-02", exception.Message);
    }


    /// <summary>
    /// An MD5-labelled <c>sigPId</c> digest throws, citing CB-6.2.1-02 — reached through
    /// <see cref="CBAdESSignatureCreation"/>'s PASS 1 rule check. The tri-way is satisfied via <c>x5t</c>,
    /// independent of the component under test.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESSignaturePolicyIdentifier construction is a constructor argument " +
            "passed straight into the enclosing 'using var headers' aggregate's own construction; ownership " +
            "passes to headers, which this test disposes. Roslyn's CA2000 analysis flags the nested 'new' " +
            "expression independently of the enclosing aggregate that actually owns and disposes it.")]
    [TestMethod]
    public async Task SignaturePolicyIdentifierDigestWithMd5DigestThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            signaturePolicyIdentifier: new CBAdESSignaturePolicyIdentifier(
                new CBAdESObjectIdentifier(new Uri("urn:test:policy")),
                new CBAdESDigestAlgorithmTextIdentifier("MD5"),
                await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "policy-document-bytes"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false)));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-6.2.1-02", exception.Message);
    }


    /// <summary>
    /// An MD5-labelled <c>sigD.hashM</c> throws, citing CB-6.2.1-02 — asserted directly against
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/>, NOT through
    /// <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>.
    /// A load-bearing design fact, recorded loudly (see also the class remarks): under the
    /// <c>ObjectIdByURIHash</c> mechanism, <see cref="CBAdESSignatureCreation"/>'s digest-parameter resolution
    /// refuses ANY non-SHA-256/384/512 identifier — MD5 included — with <see cref="NotSupportedException"/>
    /// before <c>hashV</c> computation ever runs, so this specific <see cref="ArgumentException"/> is never the
    /// one a caller of the orchestrator observes for that surface; it remains reachable (and citable in the
    /// CB-* matrix) directly against the shared rule surface, which is what THIS test exercises. <c>crit</c>
    /// includes <c>sigD</c>'s label and the entry carries a real (non-MD5-content) digest so every OTHER rule
    /// passes, isolating the MD5 denylist violation as the sole one reported.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESDetachedObjects/CBAdESDetachedObjectEntry constructions are " +
            "constructor arguments passed straight into the enclosing 'using var headers' aggregate's own " +
            "construction; ownership passes to headers, which this test disposes. Roslyn's CA2000 analysis " +
            "flags each nested 'new' expression independently of the enclosing aggregate that actually owns " +
            "and disposes them.")]
    [TestMethod]
    public async Task DetachedObjectsHashAlgorithmMd5Throws()
    {
        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            detachedObjects: new CBAdESDetachedObjects(
                CBAdESDetachedMechanisms.ObjectIdByURIHash,
                [new CBAdESDetachedObjectEntry(
                    "urn:test:object",
                    await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "md5-surface-bytes"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false),
                    contentType: null)],
                hashAlgorithm: new CBAdESDigestAlgorithmTextIdentifier("MD5")),
            criticalLabels: [new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD)]);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            CBAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: true, unsignedHeaders: null));

        Assert.Contains("CB-6.2.1-02", exception.Message);
    }


    /// <summary>
    /// The <c>ObjectIdByURI</c> mechanism carrying a non-null <c>hashM</c> throws, citing CB-5.2.8.2.2-02 —
    /// that mechanism carries neither <c>hashM</c> nor <c>hashV</c>. Thrown before any dereferencing I/O runs.
    /// </summary>
    [TestMethod]
    public async Task ObjectIdByUriWithHashAlgorithmThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: new ObjectStore(new Dictionary<string, byte[]>()));
        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURI,
            [new CBAdESDetachedObjectReferenceInput("urn:test:object", null)],
            HashAlgorithm: new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                payloadInput,
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                DereferenceFromStoreAsync,
                context,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-5.2.8.2.2-02", exception.Message);
    }


    /// <summary>
    /// The <c>ObjectIdByURIHash</c> mechanism computes <c>hashV</c> itself (a caller supplying no digests is
    /// LEGAL creation input); each computed entry equals the SHA-256 digest of the corresponding referenced
    /// object computed independently via the registered digest delegate (the oracle path), positionally
    /// matching <c>pars</c> (CB-5.2.8.2.3-02/-05).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task ObjectIdByUriHashComputesHashVMatchingRegisteredDigest()
    {
        byte[] objectA = "hash-object-a"u8.ToArray();
        byte[] objectB = "hash-object-b"u8.ToArray();
        var store = new ObjectStore(new Dictionary<string, byte[]>
        {
            ["urn:test:hash-a"] = objectA,
            ["urn:test:hash-b"] = objectB
        });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURIHash,
            [
                new CBAdESDetachedObjectReferenceInput("urn:test:hash-a", null),
                new CBAdESDetachedObjectReferenceInput("urn:test:hash-b", null)
            ],
            HashAlgorithm: new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            payloadInput,
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue expectedDigestA = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, objectA, TestContext.CancellationToken).ConfigureAwait(false);
        using DigestValue expectedDigestB = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, objectB, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<CBAdESDetachedObjectEntry> entries = result.Headers.DetachedObjects!.DetachedObjects;

        Assert.HasCount(2, entries);
        Assert.AreEqual("urn:test:hash-a", entries[0].Reference);
        Assert.IsTrue(expectedDigestA.AsReadOnlySpan().SequenceEqual(entries[0].Digest!.AsReadOnlySpan()),
            "hashV[0] must equal the oracle SHA-256 digest of the first referenced object, computed via the registered digest delegate.");
        Assert.AreEqual("urn:test:hash-b", entries[1].Reference);
        Assert.IsTrue(expectedDigestB.AsReadOnlySpan().SequenceEqual(entries[1].Digest!.AsReadOnlySpan()),
            "hashV[1] must equal the oracle SHA-256 digest of the second referenced object, positionally matching pars.");
    }


    /// <summary>
    /// Under the <c>ObjectIdByURI</c> mechanism over a two-object store, the SIGNED payload (the Sig_structure
    /// input) is the order-preserving concatenation of the dereferenced objects (CB-5.2.8.2.2-05) — asserted
    /// via <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> AND an
    /// independently concatenated expectation, then proven against the actual signature (not merely the
    /// reconstruction helper) by verifying a reconstituted <see cref="CoseSign1Message"/> whose payload is the
    /// concatenation.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. verifiableOverConcatenation (below) " +
            "deliberately shares its ProtectedHeader/UnprotectedHeader/Signature members with result.Message " +
            "(see the inline comment immediately above it) rather than owning independent disposables, and is " +
            "never disposed directly because 'using result' already disposes those same shared carriers once, " +
            "mirroring CBAdESSignatureCreation's own documented abandoned-intermediate-message convention.")]
    [TestMethod]
    public async Task ObjectIdByUriPayloadIsOrderPreservingConcatenation()
    {
        byte[] objectA = "first-detached-object"u8.ToArray();
        byte[] objectB = "second-detached-object"u8.ToArray();
        var store = new ObjectStore(new Dictionary<string, byte[]>
        {
            ["urn:test:object-a"] = objectA,
            ["urn:test:object-b"] = objectB
        });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURI,
            [
                new CBAdESDetachedObjectReferenceInput("urn:test:object-a", null),
                new CBAdESDetachedObjectReferenceInput("urn:test:object-b", null)
            ]);

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            payloadInput,
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        using PooledMemory reconstructed = await CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync(
            ["urn:test:object-a", "urn:test:object-b"],
            DereferenceFromStoreAsync,
            context,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] independentlyConcatenated = [.. objectA, .. objectB];

        Assert.IsTrue(independentlyConcatenated.AsSpan().SequenceEqual(reconstructed.AsReadOnlySpan()),
            "The reconstruction method must reproduce the order-preserving concatenation (CB-5.2.8.2.2-05).");

        //Proves the SIGNATURE (not merely the reconstruction helper) covers exactly the concatenated bytes: a
        //second CoseSign1Message wrapper around the SAME ProtectedHeader/Signature carriers result.Message
        //already owns, with Payload substituted for the reconstructed concatenation, must verify. Deliberately
        //NOT disposed -- it shares its two disposable members with result.Message, which the outer 'using'
        //already disposes once; mirrors CBAdESSignatureCreation's own documented "abandoned intermediate
        //message" convention.
        var verifiableOverConcatenation = new CoseSign1Message(
            result.Message.ProtectedHeader, result.Message.UnprotectedHeader, independentlyConcatenated, result.Message.Signature);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            verifiableOverConcatenation,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The COSE signature must verify over the order-preserving concatenation, even though the wire payload is empty.");
        Assert.HasCount(0, result.Message.Payload, "The wire payload must be empty (nil-detached) for a sigD-referenced signature.");
    }


    /// <summary>
    /// Under the <c>ObjectIdByURIHash</c> mechanism, the COSE Payload contributes as an EMPTY stream to the
    /// signature-value computation (CB-5.2.8.2.3-06) — asserted via both the produced
    /// <see cref="CoseSign1Message.Payload"/> state (empty) and a direct verification of the produced message
    /// exactly as returned, proving the Sig_structure input was literally empty, matching the wire payload.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task ObjectIdByUriHashSignsEmptyPayload()
    {
        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:single-hash"] = "single-hash-object"u8.ToArray() });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURIHash,
            [new CBAdESDetachedObjectReferenceInput("urn:test:single-hash", null)],
            HashAlgorithm: new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            payloadInput,
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            DereferenceFromStoreAsync,
            context,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, result.Message.Payload, "The wire payload must be empty (nil-detached) under ObjectIdByURIHash.");

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            result.Message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The signature must verify directly over the produced message's own (empty) payload, proving the Sig_structure input was literally empty (CB-5.2.8.2.3-06).");
    }


    /// <summary>
    /// The wavecb S3 FX-C leak regression: <c>content type</c> is caller-supplied ALONGSIDE an
    /// <c>ObjectIdByURIHash</c> <see cref="CBAdESDetachedSigDPayloadInput"/> -- PASS 1 (over the caller's own,
    /// pre-resolution <c>headers</c>) does not yet see <c>sigD</c> at all and therefore passes, so resolution
    /// runs a genuine dereference and computes a real <c>hashV</c> digest through the registered digest delegate
    /// (a real pool rental), building <see cref="CBAdESDetachedObjects"/> -- only THEN does PASS 2 (over the
    /// merged <c>effectiveHeaders</c>, which now carries both <c>content type</c> and <c>DetachedObjects</c>)
    /// throw citing CB-5.1.3-03. Before the fix, nothing disposed the freshly-built
    /// <see cref="CBAdESDetachedObjects"/> on that PASS 2 throw, leaking its digest's pool rental; the catch
    /// clause added for wavecb S3 FX-C disposes <c>resolution.DetachedObjects</c> on exactly this path. A
    /// <see cref="MeteredHousePool"/> proves the rental returns to zero rather than leaking.
    /// </summary>
    [TestMethod]
    public async Task CreationDisposesDetachedObjectsOnPass2RuleViolationLeavingNoOutstandingPoolRentals()
    {
        using var pool = new MeteredHousePool();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:pass2-leak-check"] = "pass2-leak-check-object"u8.ToArray() });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            contentType: new CBAdESContentTypeText("application/octet-stream"),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            CBAdESDetachedMechanisms.ObjectIdByURIHash,
            [new CBAdESDetachedObjectReferenceInput("urn:test:pass2-leak-check", null)],
            HashAlgorithm: new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            CBAdESSignatureCreation.SignAsync(
                headers,
                payloadInput,
                unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader,
                CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                DereferenceFromStoreAsync,
                context,
                unknownMechanismHandler: null,
                pool.Pool,
                cancellationToken: TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-5.1.3-03", exception.Message);
        Assert.AreEqual(0, pool.OutstandingCount,
            "The internally-built DetachedObjects' hashV digest rental -- computed via one real dereference+digest before PASS 2's throw -- must be disposed by the wavecb S3 FX-C catch clause, not leaked.");
    }


    /// <summary>
    /// An unrecognized <c>mId</c> with no caller-supplied mechanism handler throws, citing CB-5.2.6-07.
    /// </summary>
    [TestMethod]
    public async Task UnknownMechanismWithoutHandlerThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: new ObjectStore(new Dictionary<string, byte[]>()));
        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            "urn:test:third-party-mechanism",
            [new CBAdESDetachedObjectReferenceInput("urn:test:whatever", null)]);

        NotSupportedException exception = await Assert.ThrowsExactlyAsync<NotSupportedException>(() =>
            SignCreateAsync(
                headers,
                payloadInput,
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                DereferenceFromStoreAsync,
                context,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-5.2.6-07", exception.Message);
    }


    /// <summary>
    /// An unrecognized <c>mId</c> WITH a caller-supplied mechanism handler succeeds; the signature is proven to
    /// cover exactly the handler's returned payload.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. verifiableOverHandlerPayload (below) " +
            "deliberately shares its ProtectedHeader/UnprotectedHeader/Signature members with result.Message " +
            "(see the inline comment immediately above it) rather than owning independent disposables, and is " +
            "never disposed directly because 'using result' already disposes those same shared carriers once, " +
            "mirroring CBAdESSignatureCreation's own documented abandoned-intermediate-message convention.")]
    [TestMethod]
    public async Task UnknownMechanismWithHandlerSignsHandlerPayload()
    {
        byte[] handlerPayload = "third-party-mechanism-payload"u8.ToArray();
        var store = new ObjectStore(new Dictionary<string, byte[]> { ["urn:test:whatever"] = handlerPayload });
        var context = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));

        var payloadInput = new CBAdESDetachedSigDPayloadInput(
            "urn:test:third-party-mechanism",
            [new CBAdESDetachedObjectReferenceInput("urn:test:whatever", null)]);

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            payloadInput,
            unsignedHeaders: null,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            context,
            HandleUnknownMechanismAsync,
            TestContext.CancellationToken).ConfigureAwait(false);

        //See ObjectIdByUriPayloadIsOrderPreservingConcatenation's remarks for why this wrapper is deliberately
        //never disposed -- it shares its owned members with result.Message.
        var verifiableOverHandlerPayload = new CoseSign1Message(
            result.Message.ProtectedHeader, result.Message.UnprotectedHeader, handlerPayload, result.Message.Signature);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            verifiableOverHandlerPayload,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "The signature must verify over the unknown-mechanism handler's returned payload.");
        Assert.HasCount(0, result.Message.Payload, "The wire payload must be empty for a detached signature.");
    }


    /// <summary>
    /// A <c>uHeaders</c> set carrying a <c>sigPSt</c> element with <c>sigPId</c> ABSENT throws, citing CB-6.3-b.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreWithoutSigPIdThrows()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false));
            //sigPId deliberately omitted.

        using var unsignedHeaders = new CBAdESUnsignedHeaders(
        [
            new CBAdESUnsignedHeaderElementSignaturePolicyStore(
                new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreDocument(new byte[] { 0x01 })))
        ]);

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.Contains("CB-6.3-b", exception.Message);
    }


    /// <summary>
    /// A <c>uHeaders</c> set carrying a <c>sigPSt</c> element WITH <c>sigPId</c> present (whose digest is
    /// unconditionally required by its own constructor, satisfying the gate's digest half by construction)
    /// succeeds (CB-6.3-b).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using result'. The nested CBAdESSignaturePolicyIdentifier " +
            "construction is a constructor argument passed straight into headers's own construction, so its " +
            "ownership passes to headers and then onward with it; Roslyn's CA2000 analysis flags the nested " +
            "'new' expression independently of the enclosing aggregate that actually owns and disposes it.")]
    [TestMethod]
    public async Task SignaturePolicyStoreWithSigPIdSucceeds()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            signaturePolicyIdentifier: new CBAdESSignaturePolicyIdentifier(
                new CBAdESObjectIdentifier(new Uri("urn:test:policy")),
                new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
                await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "policy-document"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false)));

        using var unsignedHeaders = new CBAdESUnsignedHeaders(
        [
            new CBAdESUnsignedHeaderElementSignaturePolicyStore(
                new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreDocument(new byte[] { 0x01 })))
        ]);

        using CBAdESSignatureCreationResult result = await SignCreateAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
            unsignedHeaders,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.Headers.SignaturePolicyIdentifier);
    }


    /// <summary>
    /// <c>x5bag</c> (label 32) is NOT profiled by this document (CB-4.4-07, wavecb S3 FX-G: ETSI TS 119 152-1
    /// V1.1.1 never mentions <c>x5bag</c> anywhere) -- a caller carrying it as an
    /// <see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/> entry round-trips it byte-exact through the
    /// SHIPPED <see cref="CBAdESSignatureCreation.SignAsync"/> -&gt; <see cref="CBAdESSignatureValidation.ValidateAsync"/>
    /// composition -- construction no longer throws a profiled-label collision for label 32 now that
    /// <c>CoseHeaderParameters.X5Bag</c> was removed from <see cref="CBAdESProtectedHeaders"/>'s local
    /// <c>IsProfiledLabel</c> switch.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task UnprofiledX5BagLabelRoundTripsByteExactThroughCreateAndValidate()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var x5BagWriter = new CborWriter(CborConformanceMode.Canonical);
        x5BagWriter.WriteByteString(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        byte[] unprofiledX5BagBytes = x5BagWriter.Encode();

        var x5BagLabel = new CoseHeaderIntegerLabel(CoseHeaderParameters.X5Bag);

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            unprofiledHeaders: new Dictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>
            {
                [x5BagLabel] = unprofiledX5BagBytes
            });

        byte[] wireCopy;
        {
            using CBAdESSignatureCreationResult creationResult = await SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid);
        Assert.IsNotNull(validationResult.Headers!.UnprofiledHeaders);
        Assert.IsTrue(validationResult.Headers.UnprofiledHeaders!.ContainsKey(x5BagLabel));
        Assert.IsTrue(unprofiledX5BagBytes.AsSpan().SequenceEqual(validationResult.Headers.UnprofiledHeaders[x5BagLabel].Span));
    }


    /// <summary>
    /// A NEGATIVE unprofiled label (e.g. -1) round-trips byte-exact through the SHIPPED
    /// <see cref="CBAdESSignatureCreation.SignAsync"/> -&gt; <see cref="CBAdESSignatureValidation.ValidateAsync"/>
    /// composition -- the wavecb S3 FX-B regression. Before the fix, a self-round-trip of a canonically-encoded
    /// protected header carrying a negative label after a positive one (e.g. <c>x5t</c>, label 34) broke: the
    /// naive <c>key &lt;= previousKey</c> SIGNED-integer comparison the top-level map-key reader used to apply
    /// rejected the negative label as "not ascending", even though the writer itself produced exactly that byte
    /// order (major type 1's magnitude encoding does not correspond to signed integer order). Post wavecb S3
    /// FX-H, <see cref="Verifiable.Cbor.CBAdESSignatureSerialization.ParseCBAdESSign1"/>'s top-level
    /// protected-header loop reads this map's keys through its own local <c>ReadProtectedHeaderMapKey</c>
    /// helper (general encoded-bytes canonical comparison, not the integer-only
    /// <see cref="CborReaderExtensions.ReadAscendingMapKey"/>), which shares the SAME underlying canonical-order
    /// principle FX-B corrected <see cref="CborReaderExtensions.ReadAscendingMapKey"/> to use -- so this
    /// round-trip exercises that shared fix end to end, exactly as the fix spec asks.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task UnprofiledNegativeLabelRoundTripsThroughCreateAndValidate()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var negativeLabelWriter = new CborWriter(CborConformanceMode.Canonical);
        negativeLabelWriter.WriteByteString(new byte[] { 0xFE, 0xED });
        byte[] unprofiledNegativeLabelBytes = negativeLabelWriter.Encode();

        var negativeLabel = new CoseHeaderIntegerLabel(-1);

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            unprofiledHeaders: new Dictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>
            {
                [negativeLabel] = unprofiledNegativeLabelBytes
            });

        byte[] wireCopy;
        {
            using CBAdESSignatureCreationResult creationResult = await SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A negative unprofiled label must self-round-trip -- ParseCBAdESSign1 must accept the exact byte order EncodeCBAdESProtectedHeader/the .NET canonical writer produced.");
        Assert.IsNotNull(validationResult.Headers!.UnprofiledHeaders);
        Assert.IsTrue(validationResult.Headers.UnprofiledHeaders!.ContainsKey(negativeLabel));
        Assert.IsTrue(unprofiledNegativeLabelBytes.AsSpan().SequenceEqual(validationResult.Headers.UnprofiledHeaders[negativeLabel].Span));
    }


    /// <summary>
    /// A <c>tstr</c>-arm <c>crit</c> element AND a <c>tstr</c>-keyed <see cref="CBAdESProtectedHeaders.UnprofiledHeaders"/>
    /// entry (the general COSE <c>label: int / tstr</c> union RFC 9052 §1.4/§3.1 reuses unnarrowed, wavecb S3
    /// FX-H) round-trip byte-exact through the SHIPPED <see cref="CBAdESSignatureCreation.SignAsync"/> -&gt;
    /// <see cref="CBAdESSignatureValidation.ValidateAsync"/> composition -- the writer side of FX-H's label
    /// union (<see cref="Verifiable.Cbor.CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>'s per-arm
    /// dispatch and canonical-encoded-bytes sort; the crit array's per-arm <c>EncodeCritical</c> writer), paired
    /// with the reader side (<see cref="CBAdESSignatureValidationTests.ParseAcceptsIndependentlyMintedTextArmCritAndUnprofiledHeader"/>
    /// covers the reader side independently minted, without going through this file's encoder at all).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignCreateAsync call (see that type's own ownership " +
            "remarks), which this test disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task TextArmCriticalLabelAndUnprofiledHeaderRoundTripThroughCreateAndValidate()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var criticalLabel = new CoseHeaderTextLabel("x-test-crit");
        var unprofiledLabel = new CoseHeaderTextLabel("x-test-ext");

        var unprofiledWriter = new CborWriter(CborConformanceMode.Canonical);
        unprofiledWriter.WriteByteString(new byte[] { 0xCA, 0xFE });
        byte[] unprofiledBytes = unprofiledWriter.Encode();

        var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            x5t: await CreateX5TAsync(TestContext.CancellationToken).ConfigureAwait(false),
            criticalLabels: [criticalLabel],
            unprofiledHeaders: new Dictionary<CoseHeaderLabel, ReadOnlyMemory<byte>>
            {
                [unprofiledLabel] = unprofiledBytes
            });

        byte[] wireCopy;
        {
            using CBAdESSignatureCreationResult creationResult = await SignCreateAsync(
                headers,
                new CBAdESAttachedPayloadInput(new byte[] { 0x01 }),
                unsignedHeaders: null,
                privateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                dereference: null,
                dereferenceContext: null,
                unknownMechanismHandler: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid);
        Assert.IsNotNull(validationResult.Headers!.CriticalLabels);
        Assert.Contains(criticalLabel, validationResult.Headers.CriticalLabels!, "The tstr-arm crit element must round-trip.");
        Assert.IsNotNull(validationResult.Headers.UnprofiledHeaders);
        Assert.IsTrue(validationResult.Headers.UnprofiledHeaders!.ContainsKey(unprofiledLabel));
        Assert.IsTrue(unprofiledBytes.AsSpan().SequenceEqual(validationResult.Headers.UnprofiledHeaders[unprofiledLabel].Span));
    }


    /// <summary>
    /// Composes <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// against the shipped <see cref="CBAdESSignatureSerialization"/> CBOR seams and
    /// <see cref="CoseSerialization.BuildSigStructure"/> — the one call shape every test in this file shares.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate.</param>
    /// <param name="payloadInput">The COSE Payload to sign over.</param>
    /// <param name="unsignedHeaders">The <c>uHeaders</c> set to incorporate, or <see langword="null"/>.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing delegate.</param>
    /// <param name="dereference">The <c>sigD</c> dereference delegate, or <see langword="null"/>.</param>
    /// <param name="dereferenceContext">The dereference/unknown-mechanism context, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">The unknown-<c>mId</c> handler, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    private static ValueTask<CBAdESSignatureCreationResult> SignCreateAsync(
        CBAdESProtectedHeaders headers,
        CBAdESSigningPayloadInput payloadInput,
        CBAdESUnsignedHeaders? unsignedHeaders,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        CancellationToken cancellationToken) =>
        CBAdESSignatureCreation.SignAsync(
            headers,
            payloadInput,
            unsignedHeaders,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader,
            CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure,
            privateKey,
            signingDelegate,
            dereference,
            dereferenceContext,
            unknownMechanismHandler,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    /// <summary>
    /// Computes a real digest through the registered <see cref="CryptographicKeyEvents"/> digest delegate seam —
    /// the test-side oracle path every <see cref="DigestValue"/> fixture in this file goes through, per the
    /// hash-via-registered-digest working convention (never a hand-rolled hash).
    /// </summary>
    /// <param name="coseHashAlgorithm">The IANA COSE Algorithms digest-algorithm identifier (SHA-256/384/512 only).</param>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The computed digest. The caller owns and disposes it.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(int coseHashAlgorithm, byte[] input, CancellationToken cancellationToken)
    {
        (Tag tag, int outputByteLength) = coseHashAlgorithm switch
        {
            WellKnownCoseAlgorithms.Sha256 => (CryptoTags.Sha256Digest, 32),
            WellKnownCoseAlgorithms.Sha384 => (CryptoTags.Sha384Digest, 48),
            WellKnownCoseAlgorithms.Sha512 => (CryptoTags.Sha512Digest, 64),
            _ => throw new ArgumentOutOfRangeException(nameof(coseHashAlgorithm), coseHashAlgorithm, "Unsupported test digest algorithm.")
        };

        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), outputByteLength, tag, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a minimal, tri-way-satisfying <c>x5t</c> fixture (SHA-256) — the single-component shortcut every
    /// test in this file that needs the tri-way rule (CB-5.2.2-07) satisfied, without exercising the specific
    /// component under test, uses.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The certificate-thumbprint fixture. Ownership transfers to whichever aggregate receives it.</returns>
    private static async ValueTask<CBAdESCertificateThumbprint> CreateX5TAsync(CancellationToken cancellationToken)
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "signing-certificate"u8.ToArray(), cancellationToken).ConfigureAwait(false);

        return new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);
    }


    /// <summary>
    /// Reads a CBOR protected-header map into a label-to-raw-item-bytes dictionary, using a FRESH, INDEPENDENT
    /// <see cref="CborReader"/> over raw primitives only — never <see cref="CBAdESSignatureSerialization"/>'s
    /// own decode path.
    /// </summary>
    /// <param name="protectedHeaderBytes">The encoded protected-header map bytes.</param>
    /// <returns>Each member's label mapped to its own encoded item bytes.</returns>
    private static Dictionary<int, ReadOnlyMemory<byte>> ReadProtectedHeaderEntries(ReadOnlyMemory<byte> protectedHeaderBytes)
    {
        var reader = new CborReader(protectedHeaderBytes, CborConformanceMode.Canonical);
        int? mapLength = reader.ReadStartMap();
        Assert.IsNotNull(mapLength, "The protected header must be a definite-length CBOR map.");

        var entries = new Dictionary<int, ReadOnlyMemory<byte>>(mapLength.Value);
        for(int i = 0; i < mapLength.Value; i++)
        {
            int label = reader.ReadInt32();
            entries[label] = reader.ReadEncodedValue();
        }

        reader.ReadEndMap();

        return entries;
    }


    /// <summary>
    /// Reads a CWT Claims header value's sole member (claim key, <c>NumericDate</c> whole-seconds value) via a
    /// FRESH, INDEPENDENT <see cref="CborReader"/>.
    /// </summary>
    /// <param name="encodedCwtClaims">The CWT Claims member's own encoded item bytes.</param>
    /// <returns>The sole member's claim key and its <c>NumericDate</c> value, in whole seconds since the Unix epoch.</returns>
    private static (int ClaimKey, long IssuedAtSeconds) ReadCwtClaimsMember(ReadOnlyMemory<byte> encodedCwtClaims)
    {
        var reader = new CborReader(encodedCwtClaims, CborConformanceMode.Canonical);
        int? memberCount = reader.ReadStartMap();
        Assert.IsNotNull(memberCount, "The CWT Claims map must be definite-length.");
        Assert.AreEqual(1, memberCount.Value, "The CWT Claims map must carry exactly one member (iat only).");

        int claimKey = reader.ReadInt32();
        long issuedAtSeconds = reader.ReadInt64();
        reader.ReadEndMap();

        return (claimKey, issuedAtSeconds);
    }


    /// <summary>
    /// Reads a CBOR array of integers via a FRESH, INDEPENDENT <see cref="CborReader"/> — used to decode the
    /// <c>crit</c> header's own encoded item bytes.
    /// </summary>
    /// <param name="encodedArray">The array's own encoded item bytes.</param>
    /// <returns>The decoded integers, in wire order.</returns>
    private static List<int> ReadIntArray(ReadOnlyMemory<byte> encodedArray)
    {
        var reader = new CborReader(encodedArray, CborConformanceMode.Canonical);
        int? length = reader.ReadStartArray();
        Assert.IsNotNull(length, "The array must be definite-length.");

        var values = new List<int>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            values.Add(reader.ReadInt32());
        }

        reader.ReadEndArray();

        return values;
    }


    /// <summary>
    /// Dereferences a URI-reference against a fixed <see cref="ObjectStore"/> reached exclusively through
    /// <paramref name="context"/> (no closure capture) — the <see cref="CBAdESDetachedObjectDereferenceDelegate"/>
    /// every sigD test in this file supplies.
    /// </summary>
    /// <param name="uriReference">The URI-reference to dereference.</param>
    /// <param name="context">The per-call caller state, carrying the fixture's <see cref="ObjectStore"/> as <see cref="CBAdESDetachedObjectDereferenceContext.State"/>.</param>
    /// <param name="pool">Memory pool the fetched content is rented from.</param>
    /// <param name="cancellationToken">Cancellation token (unused — the fixture never awaits real I/O).</param>
    /// <returns>The dereferenced content, or a failure signal when the reference is unregistered.</returns>
    private static ValueTask<CBAdESDetachedObjectDereferenceResult> DereferenceFromStoreAsync(
        string uriReference,
        CBAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var store = (ObjectStore)context.State!;
        if(!store.ObjectsByReference.TryGetValue(uriReference, out byte[]? content))
        {
            return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(
                new CBAdESDetachedObjectDereferenceFailure($"No test fixture object registered for reference '{uriReference}'."));
        }

        return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(
            new CBAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data))));
    }


    /// <summary>
    /// Retrieves the COSE Payload for a third-party <c>sigD.mId</c> by concatenating, in wire order, the
    /// referenced objects looked up in a fixed <see cref="ObjectStore"/> reached exclusively through
    /// <paramref name="context"/> (no closure capture) — the <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>
    /// the unknown-mechanism test in this file supplies.
    /// </summary>
    /// <param name="mechanismIdentifier">The unrecognized <c>mId</c> value (unused — this fixture handles any third-party mechanism identically).</param>
    /// <param name="references">The <c>sigD.pars</c> entries, in wire order.</param>
    /// <param name="hashAlgorithm">The caller-declared <c>hashM</c> (unused — this fixture produces no digests).</param>
    /// <param name="context">The per-call caller state, carrying the fixture's <see cref="ObjectStore"/> as <see cref="CBAdESDetachedObjectDereferenceContext.State"/>.</param>
    /// <param name="pool">Memory pool the returned payload is rented from.</param>
    /// <param name="cancellationToken">Cancellation token (unused — the fixture never awaits real I/O).</param>
    /// <returns>The concatenated COSE Payload bytes, pool-routed. Ownership transfers to the caller.</returns>
    private static ValueTask<PooledMemory> HandleUnknownMechanismAsync(
        string mechanismIdentifier,
        IReadOnlyList<CBAdESDetachedObjectReferenceInput> references,
        CBAdESDigestAlgorithmIdentifier? hashAlgorithm,
        CBAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var store = (ObjectStore)context.State!;

        var buffers = new byte[references.Count][];
        int totalLength = 0;
        for(int i = 0; i < references.Count; ++i)
        {
            buffers[i] = store.ObjectsByReference[references[i].Reference];
            totalLength += buffers[i].Length;
        }

        byte[] concatenated = new byte[totalLength];
        int offset = 0;
        for(int i = 0; i < buffers.Length; ++i)
        {
            buffers[i].CopyTo(concatenated, offset);
            offset += buffers[i].Length;
        }

        return ValueTask.FromResult(PooledMemory.FromBytes(concatenated, pool, Tag.Create(Purpose.Data)));
    }


    /// <summary>
    /// The explicit, no-closure-capture per-call context state <see cref="DereferenceFromStoreAsync"/> and
    /// <see cref="HandleUnknownMechanismAsync"/> read through <see cref="CBAdESDetachedObjectDereferenceContext.State"/> —
    /// a fixed URI-reference-to-bytes store, mirroring <c>Verifiable.Tests.Cose.CoseTests.TestResolverState</c>'s
    /// own explicit-state convention for a resolver/binder seam (caller data reaches a library callback as an
    /// explicit per-call parameter, never a captured lambda variable).
    /// </summary>
    /// <param name="ObjectsByReference">The fixture's fixed detached-object content, keyed by URI-reference.</param>
    private sealed record ObjectStore(IReadOnlyDictionary<string, byte[]> ObjectsByReference);
}
