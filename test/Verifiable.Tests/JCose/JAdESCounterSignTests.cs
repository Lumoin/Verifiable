using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the <c>cSig</c> countersignature verbs (<see cref="JAdESCounterSign"/>) and the decode-for-
/// inspection seam (<see cref="JAdESCounterSignatureJson"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.3.2.
/// </summary>
/// <remarks>
/// Every signing key is P-256, minted through <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>,
/// signed/verified via the explicit-delegate <see cref="MicrosoftCryptographicFunctions"/> pair, mirroring
/// <c>JAdESSignatureCreationTests</c>'s own convention.
/// </remarks>
[TestClass]
internal sealed class JAdESCounterSignTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static readonly JwtPartEncoder<Dictionary<string, object>> HeaderEncoder =
        static header => new TaggedMemory<byte>(JsonSerializer.SerializeToUtf8Bytes(header), Tag.Create(Purpose.Data));


    /// <summary>Both incorporation modes verify a compact-serialized nested countersignature (JA-5.3.2-03/-04).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.2-01.
    /// </remarks>
    [DataRow(JAdESEtsiUIncorporationMode.ClearJson, DisplayName = "ClearJson")]
    [DataRow(JAdESEtsiUIncorporationMode.Base64Url, DisplayName = "Base64Url")]
    [TestMethod]
    public async Task CountersignAndVerify_CompactNestedForm_RoundTripsInBothContainerModes(JAdESEtsiUIncorporationMode containerMode)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] embeddingSignatureValue = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(containerMode, $"{{\"cSig\":\"{compact}\"}}");

        bool decoded = JAdESCounterSignatureJson.TryDecode(
            element, containerMode, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);

        Assert.IsTrue(decoded);
        using(nested)
        {
            bool verified = await JAdESCounterSign.VerifyAsync(
                nested!.Wire, embeddingSignatureValue, TestSetup.Base64UrlEncoder, publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified);
        }
    }


    /// <summary>A Flattened-JSON-serialized nested countersignature (JA-5.3.2-05) decodes and verifies too.</summary>
    [TestMethod]
    public async Task CountersignAndVerify_FlattenedJsonNestedForm_RoundTrips()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] embeddingSignatureValue = [9, 9, 9, 9];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] flattened = JwsSerialization.SerializeFlattenedJson(countersignature, TestSetup.Base64UrlEncoder, static o => JsonSerializer.SerializeToUtf8Bytes(o));
        string wireText = $"{{\"cSig\":{Encoding.UTF8.GetString(flattened)}}}";

        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, wireText);

        bool decoded = JAdESCounterSignatureJson.TryDecode(
            element, JAdESEtsiUIncorporationMode.ClearJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);

        Assert.IsTrue(decoded);
        using(nested)
        {
            bool verified = await JAdESCounterSign.VerifyAsync(
                nested!.Wire, embeddingSignatureValue, TestSetup.Base64UrlEncoder, publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified);
        }
    }


    /// <summary>JA-5.3.2-03: a countersignature whose payload does not bind to the embedding signature value is refused.</summary>
    [TestMethod]
    public async Task Verify_PayloadBindingMismatch_ReturnsFalse()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] signedOverValue = [1, 1, 1];
        byte[] differentEmbeddingValue = [2, 2, 2];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            signedOverValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, $"{{\"cSig\":\"{compact}\"}}");

        JAdESCounterSignatureJson.TryDecode(element, JAdESEtsiUIncorporationMode.ClearJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);
        using(nested)
        {
            bool verified = await JAdESCounterSign.VerifyAsync(
                nested!.Wire, differentEmbeddingValue, TestSetup.Base64UrlEncoder, publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(verified);
        }
    }


    /// <summary>A countersignature verified against a public key that did not produce it is refused.</summary>
    [TestMethod]
    public async Task Verify_WrongPublicKey_ReturnsFalse()
    {
        var signerKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = signerKeyPair.PrivateKey;
        signerKeyPair.PublicKey.Dispose();

        //CreateP256KeyMaterial returns copies of ONE cached key pair (test speed); a genuinely different key
        //requires CreateFreshP256KeyMaterial (TestKeyMaterialProvider's own documented distinction, mirroring
        //JAdESSignatureValidationTests.WrongKeyFailsSignatureVerification's identical need).
        var otherKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unrelatedPublicKey = otherKeyPair.PublicKey;
        otherKeyPair.PrivateKey.Dispose();

        byte[] embeddingSignatureValue = [7, 7, 7];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, $"{{\"cSig\":\"{compact}\"}}");

        JAdESCounterSignatureJson.TryDecode(element, JAdESEtsiUIncorporationMode.ClearJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);
        using(nested)
        {
            bool verified = await JAdESCounterSign.VerifyAsync(
                nested!.Wire, embeddingSignatureValue, TestSetup.Base64UrlEncoder, unrelatedPublicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(verified);
        }
    }


    /// <summary>Malformed wire text (no <c>cSig</c> member) fails closed rather than throwing.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryDecode leaves 'nested' null on every false-returning path (fail-closed contract), so there is nothing to dispose on this test's asserted failure path; Roslyn cannot trace that contract from the call site alone.")]
    [TestMethod]
    public void TryDecode_MissingCSigMember_ReturnsFalse()
    {
        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, "{\"notCSig\":1}");

        bool decoded = JAdESCounterSignatureJson.TryDecode(
            element, JAdESEtsiUIncorporationMode.ClearJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);

        Assert.IsFalse(decoded);
        Assert.IsNull(nested);
    }


    /// <summary>A <c>cSig</c> value that is neither a string nor a nested-JWS-shaped object fails closed.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryDecode leaves 'nested' null on every false-returning path (fail-closed contract), so there is nothing to dispose on this test's asserted failure path; Roslyn cannot trace that contract from the call site alone.")]
    [TestMethod]
    public void TryDecode_CSigValueNotAJws_ReturnsFalse()
    {
        using JAdESUnsignedHeaderElementCounterSignature element = BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, "{\"cSig\":42}");

        bool decoded = JAdESCounterSignatureJson.TryDecode(
            element, JAdESEtsiUIncorporationMode.ClearJson, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? nested);

        Assert.IsFalse(decoded);
        Assert.IsNull(nested);
    }


    /// <summary>No <c>cSig</c> elements in <c>etsiU</c> yields no violations from the async check.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public async Task CheckCounterSignaturesAsync_NoCounterSignatureElements_ReturnsEmpty()
    {
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementUnknown("customKind", PooledMemory.FromBytes("{\"customKind\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckCounterSignaturesAsync(
            unsignedHeaders, JAdESEtsiUIncorporationMode.ClearJson, ReadOnlyMemory<byte>.Empty,
            JAdESCounterSignatureJson.TryDecode, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            static _ => null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>A malformed <c>cSig</c> element reports <see cref="JAdESCounterSignatureVerificationFailureReason.DecodeFailed"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public async Task CheckCounterSignaturesAsync_MalformedCSig_ReportsDecodeFailed()
    {
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes("{\"notCSig\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckCounterSignaturesAsync(
            unsignedHeaders, JAdESEtsiUIncorporationMode.ClearJson, ReadOnlyMemory<byte>.Empty,
            JAdESCounterSignatureJson.TryDecode, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            static _ => null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, violations);
        var violation = (JAdESCounterSignatureVerificationViolation)violations[0];
        Assert.AreEqual(JAdESCounterSignatureVerificationFailureReason.DecodeFailed, violation.Reason);
        Assert.AreEqual(0, violation.InstanceOrdinal);
    }


    /// <summary>A decodable <c>cSig</c> element whose key the resolver cannot resolve reports <see cref="JAdESCounterSignatureVerificationFailureReason.KeyUnresolved"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "BuildCounterSignatureElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public async Task CheckCounterSignaturesAsync_UnresolvableKey_ReportsKeyUnresolved()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        keyPair.PublicKey.Dispose();

        byte[] embeddingSignatureValue = [3, 3, 3];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, $"{{\"cSig\":\"{compact}\"}}")]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckCounterSignaturesAsync(
            unsignedHeaders, JAdESEtsiUIncorporationMode.ClearJson, embeddingSignatureValue,
            JAdESCounterSignatureJson.TryDecode, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            static _ => null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, violations);
        var violation = (JAdESCounterSignatureVerificationViolation)violations[0];
        Assert.AreEqual(JAdESCounterSignatureVerificationFailureReason.KeyUnresolved, violation.Reason);
    }


    /// <summary>A conformant, resolvable, verifiable <c>cSig</c> element reports no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "BuildCounterSignatureElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public async Task CheckCounterSignaturesAsync_ConformantCounterSignature_ReturnsEmpty()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] embeddingSignatureValue = [4, 4, 4, 4];

        using JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            HeaderEncoder,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compact = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [BuildCounterSignatureElement(JAdESEtsiUIncorporationMode.ClearJson, $"{{\"cSig\":\"{compact}\"}}")]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckCounterSignaturesAsync(
            unsignedHeaders, JAdESEtsiUIncorporationMode.ClearJson, embeddingSignatureValue,
            JAdESCounterSignatureJson.TryDecode, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
            _ => publicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary><see cref="JAdESLevelRules.EnsureCounterSignaturesVerifiedAsync"/> throws naming the failing requirement.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element construction is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate's own construction, which the local using disposes.")]
    [TestMethod]
    public async Task EnsureCounterSignaturesVerifiedAsync_MalformedCSig_ThrowsNamingRequirement()
    {
        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes("{\"notCSig\":1}"u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await JAdESLevelRules.EnsureCounterSignaturesVerifiedAsync(
                unsignedHeaders, JAdESEtsiUIncorporationMode.ClearJson, ReadOnlyMemory<byte>.Empty,
                JAdESCounterSignatureJson.TryDecode, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
                static _ => null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsTrue(exception.Message.Contains("JA-5.3.2-03", StringComparison.Ordinal));
    }


    /// <summary>
    /// Builds a <c>cSig</c> element carrying <paramref name="clearJsonWireText"/> as its own wire text, encoded
    /// per <paramref name="mode"/> — clear as-is, or base64url-opaque (the RAW base64url STRING content, no
    /// surrounding quotes, matching <c>JAdESEtsiUJson.BuildBase64UrlElement</c>'s own wire shape).
    /// </summary>
    private static JAdESUnsignedHeaderElementCounterSignature BuildCounterSignatureElement(JAdESEtsiUIncorporationMode mode, string clearJsonWireText)
    {
        byte[] wireBytes = mode == JAdESEtsiUIncorporationMode.Base64Url
            ? Encoding.ASCII.GetBytes(TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(clearJsonWireText)))
            : Encoding.UTF8.GetBytes(clearJsonWireText);

        return new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(wireBytes, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)));
    }
}
