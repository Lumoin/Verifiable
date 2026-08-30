using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the seal envelope verbs (<c>SealEnvelopeAsync</c>, <c>UnsealEnvelopeAsync</c>,
/// <c>UnsealEnvelopeUnderPolicyAsync</c>) against the in-house behavioural <see cref="TpmSimulator"/>: a sealed
/// data object carries at most <c>MAX_SYM_DATA</c> (128) octets (TPM 2.0 Library Part 2, clause 11.1.13, Table
/// 169; clause 11.1.14, Table 170), so the envelope seals a 256-bit content key and the payload rides under it
/// with an AEAD, bound to the sealed key through the additional authenticated data. Every round trip runs
/// through the production verbs, the real response codecs and the simulator's own <c>TPM2_Create</c>/
/// <c>TPM2_Load</c>/<c>TPM2_Unseal</c> ladders (Part 3, clauses 12.1, 12.2, 12.7), so what is proven is that the
/// persisted form a caller stores is the form a later process opens.
/// </summary>
[TestClass]
internal sealed class TpmSealEnvelopeExtensionsTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The policy session hash algorithm, matching the verbs' fixed nameAlg.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>A payload width eight times the widest sealed data object.</summary>
    private const int WidePayloadLength = 8 * Tpm2bSensitiveData.MaxSize;

    /// <summary>The width of the content key the envelope seals.</summary>
    private const int ContentKeyLength = 32;

    /// <summary>The authorization value the content key is sealed under.</summary>
    private static byte[] SealAuth { get; } = "envelope-seal-auth"u8.ToArray();

    /// <summary>A value that is not <see cref="SealAuth"/>.</summary>
    private static byte[] WrongSealAuth { get; } = "envelope-seal-wrong"u8.ToArray();

    /// <summary>
    /// A payload wider than any sealed data object seals as an envelope, persists through its serialized form,
    /// parses back in a fresh instance and unseals by password byte for byte
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 3, clauses 12.1 and 12.7</see>).
    /// </summary>
    [TestMethod]
    public async Task APayloadWiderThanMaxSymDataRoundTripsByPasswordAcrossADiskByteRoundTrip()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(APayloadWiderThanMaxSymDataRoundTripsByPasswordAcrossADiskByteRoundTrip), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] payload = WidePayload();
            byte[] stored = await SealWideAsync(tpm, parentHandle, payload, SealAuth, pool).ConfigureAwait(false);

            using TpmSealedEnvelope parsed = ParseEnvelope(stored, pool);
            TpmResult<DecryptedContent> result = await tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, parsed, SealAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Unsealing the envelope by password failed: '{result.ResponseCode}'.");

            using DecryptedContent plaintext = result.Value;
            Assert.IsTrue(plaintext.AsReadOnlySpan().SequenceEqual(payload), "The payload must unseal byte for byte from the persisted envelope alone.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The envelope's content key is sealed under an authorization policy exactly as <c>SealAsync</c> seals, and
    /// a policy session that satisfies it — here <c>TPM2_PolicyCommandCode(TPM_CC_Unseal)</c> — opens the
    /// envelope through the policy arm
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 12.7 and 23.11</see>).
    /// </summary>
    [TestMethod]
    public async Task APayloadWiderThanMaxSymDataRoundTripsUnderASatisfiedPolicySession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(APayloadWiderThanMaxSymDataRoundTripsUnderASatisfiedPolicySession), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        uint policyHandle = 0;
        try
        {
            byte[] payload = WidePayload();
            byte[] stored = await SealWideAsync(tpm, parentHandle, payload, ReadOnlyMemory<byte>.Empty, pool, PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_Unseal), noDa: true).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse started = startResult.Value;
            policyHandle = started.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(policyHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            using TpmSealedEnvelope parsed = ParseEnvelope(stored, pool);
            TpmResult<DecryptedContent> result = await tpm.UnsealEnvelopeUnderPolicyAsync(parentHandle, ReadOnlyMemory<byte>.Empty, parsed, policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Unsealing the envelope under a satisfied policy session failed: '{result.ResponseCode}'.");

            using DecryptedContent plaintext = result.Value;
            Assert.IsTrue(plaintext.AsReadOnlySpan().SequenceEqual(payload), "The payload must unseal byte for byte under the policy session.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The persisted envelope carries the payload only in encrypted form: no run of the plaintext appears in the
    /// stored octets, which are wider than the payload by the sealed key, the IV and the tag.
    /// </summary>
    [TestMethod]
    public async Task ThePersistedEnvelopeCarriesNoPlaintextOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ThePersistedEnvelopeCarriesNoPlaintextOctets), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] payload = WidePayload();
            byte[] stored = await SealWideAsync(tpm, parentHandle, payload, SealAuth, pool).ConfigureAwait(false);

            Assert.IsGreaterThan(WidePayloadLength, stored.Length, "The envelope must carry the sealed key, the IV and the tag beside the ciphertext.");
            Assert.IsLessThan(0, stored.AsSpan().IndexOf(payload.AsSpan(0, 64)), "The persisted envelope must not carry the payload in the clear.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The sealed object inside the envelope is the content key — <c>TPM2_Unseal()</c> on it through the plain
    /// <c>UnsealAsync</c> yields 32 octets, within the <c>MAX_SYM_DATA</c> bound a real TPM enforces — never the
    /// payload
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.13, Table 169; Part 3, clause 12.7</see>).
    /// </summary>
    [TestMethod]
    public async Task TheEnvelopeSealsAContentKeyNotThePayload()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(TheEnvelopeSealsAContentKeyNotThePayload), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] stored = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);

            var reader = new TpmReader(stored);
            using TpmSealedBlob sealedKey = TpmSealedBlob.Parse(ref reader, pool);
            Assert.IsLessThan(stored.Length, reader.Consumed, "The sealed key must be a prefix of the envelope, not the whole of it.");

            TpmResult<UnsealResponse> unsealResult = await tpm.UnsealAsync(parentHandle, ReadOnlyMemory<byte>.Empty, sealedKey, SealAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unsealing the envelope's sealed object failed: '{unsealResult.ResponseCode}'.");
            using UnsealResponse unsealed = unsealResult.Value;

            Assert.AreEqual(ContentKeyLength, unsealed.OutData.Length, "The sealed object must be the 32-octet content key.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A persisted envelope whose ciphertext was altered fails authentication and the unseal fails closed with
    /// the AEAD delegates' <see cref="CryptographicException"/> channel (the platform AES-GCM's own
    /// <see cref="AuthenticationTagMismatchException"/> is one) — no partial or garbled payload is ever returned.
    /// </summary>
    [TestMethod]
    public async Task ATamperedCiphertextIsRefusedWithACryptographicException()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ATamperedCiphertextIsRefusedWithACryptographicException), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] tampered = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);
            tampered[^1] ^= 0x01;

            using TpmSealedEnvelope parsed = ParseEnvelope(tampered, pool);
            _ = await Assert.ThrowsAsync<CryptographicException>(
                () => tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, parsed, SealAuth, TestContext.CancellationToken).AsTask(),
                "An altered ciphertext must fail authentication and the unseal must fail closed.").ConfigureAwait(false);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The ciphertext is bound to exactly the sealed key that opens it: grafting another envelope's sealed key
    /// onto this one unseals a different content key, so the authentication fails and the unseal fails closed.
    /// </summary>
    [TestMethod]
    public async Task ASealedKeyGraftedFromAnotherEnvelopeIsRefusedWithACryptographicException()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ASealedKeyGraftedFromAnotherEnvelopeIsRefusedWithACryptographicException), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] envelopeA = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);
            byte[] envelopeB = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);
            int sealedKeyLengthA = SealedKeyLength(envelopeA, pool);
            int sealedKeyLengthB = SealedKeyLength(envelopeB, pool);
            Assert.AreEqual(sealedKeyLengthA, sealedKeyLengthB, "Two content keys sealed under one parent must serialize to the same width.");

            envelopeB.AsSpan(0, sealedKeyLengthB).CopyTo(envelopeA);

            using TpmSealedEnvelope grafted = ParseEnvelope(envelopeA, pool);
            _ = await Assert.ThrowsAsync<CryptographicException>(
                () => tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, grafted, SealAuth, TestContext.CancellationToken).AsTask(),
                "A grafted sealed key must not open another envelope's ciphertext.").ConfigureAwait(false);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An envelope whose sealed object is not a 256-bit content key — a plain <c>SealAsync</c> blob of another
    /// width grafted in — is refused before any decryption on the same <see cref="CryptographicException"/>
    /// channel an authentication failure takes, so a consumer has one failure to handle.
    /// </summary>
    [TestMethod]
    public async Task AForeignSealedObjectOfTheWrongWidthIsRefusedWithACryptographicException()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(AForeignSealedObjectOfTheWrongWidthIsRefusedWithACryptographicException), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] envelope = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);
            int sealedKeyLength = SealedKeyLength(envelope, pool);

            TpmResult<TpmSealedBlob> foreignResult = await tpm.SealAsync(parentHandle, ReadOnlyMemory<byte>.Empty, new byte[16], SealAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(foreignResult.IsSuccess, $"Sealing the foreign 16-octet object failed: '{foreignResult.ResponseCode}'.");
            using TpmSealedBlob foreign = foreignResult.Value;

            //A 16-octet sealed object serializes to the same wrapped width as a 32-octet one only by accident;
            //the graft rebuilds the envelope around the foreign prefix whatever its width.
            byte[] foreignBytes = Serialize(foreign, pool);
            byte[] grafted = new byte[foreignBytes.Length + envelope.Length - sealedKeyLength];
            foreignBytes.CopyTo(grafted, 0);
            envelope.AsSpan(sealedKeyLength).CopyTo(grafted.AsSpan(foreignBytes.Length));

            using TpmSealedEnvelope parsed = ParseEnvelope(grafted, pool);
            _ = await Assert.ThrowsExactlyAsync<CryptographicException>(
                () => tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, parsed, SealAuth, TestContext.CancellationToken).AsTask(),
                "A sealed object that is not a content key must be refused before any decryption.").ConfigureAwait(false);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A wrong <c>sealAuth</c> is the TPM's refusal of the content key's unseal, not an AEAD failure: it rides the
    /// result as the session-encoded <c>TPM_RC_AUTH_FAIL</c> a dictionary-attack-protected sealed object answers
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.7; Part 2, clause 6.6.2</see>).
    /// </summary>
    [TestMethod]
    public async Task AWrongSealAuthIsRefusedThroughTheResult()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(AWrongSealAuthIsRefusedThroughTheResult), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] stored = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);

            using TpmSealedEnvelope parsed = ParseEnvelope(stored, pool);
            TpmResult<DecryptedContent> result = await tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, parsed, WrongSealAuth, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A wrong sealAuth must be refused.");
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "A wrong sealAuth on a DA-protected content key must be the session-encoded TPM_RC_AUTH_FAIL.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <see cref="TpmSealedEnvelope.Parse"/> refuses a stored envelope that carries trailing octets, so a store
    /// that grew is never partially trusted.
    /// </summary>
    [TestMethod]
    public async Task ParseRefusesTrailingOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ParseRefusesTrailingOctets), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] stored = await SealWideAsync(tpm, parentHandle, WidePayload(), SealAuth, pool).ConfigureAwait(false);
            byte[] grown = new byte[stored.Length + 1];
            stored.CopyTo(grown, 0);

            _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseEnvelope(grown, pool), "Trailing octets must be refused.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The plain <c>SealAsync</c> refuses a secret wider than <c>MAX_SYM_DATA</c> loudly and client-side — the
    /// failure the envelope verbs exist to lift — rather than sending a <c>TPM2_Create</c> a real TPM would answer
    /// <c>TPM_RC_SIZE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.13, Table 169</see>).
    /// </summary>
    [TestMethod]
    public async Task SealAsyncPastMaxSymDataThrowsBeforeTheWire()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SealAsyncPastMaxSymDataThrowsBeforeTheWire), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] tooWide = new byte[Tpm2bSensitiveData.MaxSize + 1];

            _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
                () => tpm.SealAsync(parentHandle, ReadOnlyMemory<byte>.Empty, tooWide, SealAuth, cancellationToken: TestContext.CancellationToken).AsTask(),
                "A secret wider than MAX_SYM_DATA must be refused before the wire.").ConfigureAwait(false);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The registry-resolving overloads and the delegate-taking overloads interoperate in both directions: an
    /// envelope sealed through the registered AEAD opens under the explicit AES-256-GCM delegate, and one sealed
    /// under the explicit delegate opens through the registered AEAD — the registry overloads resolve exactly the
    /// function the delegate overloads are handed.
    /// </summary>
    [TestMethod]
    public async Task TheRegistryOverloadsAndTheDelegateOverloadsInteroperate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(TheRegistryOverloadsAndTheDelegateOverloadsInteroperate), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        uint parentHandle = await CreateStorageParentAsync(tpm, pool).ConfigureAwait(false);
        try
        {
            byte[] payload = WidePayload();

            TpmResult<TpmSealedEnvelope> registrySealed = await tpm.SealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, payload, SealAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(registrySealed.IsSuccess, $"Sealing through the registry overload failed: '{registrySealed.ResponseCode}'.");
            using TpmSealedEnvelope fromRegistry = registrySealed.Value;
            TpmResult<DecryptedContent> delegateOpened = await tpm.UnsealEnvelopeAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, fromRegistry, SealAuth, BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(delegateOpened.IsSuccess, $"Opening through the delegate overload failed: '{delegateOpened.ResponseCode}'.");
            using DecryptedContent delegatePlaintext = delegateOpened.Value;
            Assert.IsTrue(delegatePlaintext.AsReadOnlySpan().SequenceEqual(payload), "The registry-sealed envelope must open under the explicit AES-256-GCM delegate.");

            TpmResult<TpmSealedEnvelope> delegateSealed = await tpm.SealEnvelopeAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, payload, SealAuth, BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(delegateSealed.IsSuccess, $"Sealing through the delegate overload failed: '{delegateSealed.ResponseCode}'.");
            using TpmSealedEnvelope fromDelegate = delegateSealed.Value;
            TpmResult<DecryptedContent> registryOpened = await tpm.UnsealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, fromDelegate, SealAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(registryOpened.IsSuccess, $"Opening through the registry overload failed: '{registryOpened.ResponseCode}'.");
            using DecryptedContent registryPlaintext = registryOpened.Value;
            Assert.IsTrue(registryPlaintext.AsReadOnlySpan().SequenceEqual(payload), "The delegate-sealed envelope must open through the registered AEAD.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Creates an empty-auth ECC storage parent under the owner hierarchy and returns its handle; the caller flushes it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The loaded parent's handle.</returns>
    private async Task<uint> CreateStorageParentAsync(TpmDevice tpm, BaseMemoryPool pool)
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        return parent.ObjectHandle.Value;
    }

    /// <summary>Seals <paramref name="payload"/> as an envelope through the registry overload and returns its persisted form.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="parentHandle">The loaded storage parent.</param>
    /// <param name="payload">The payload to seal.</param>
    /// <param name="sealAuth">The authorization value the content key is sealed under.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authPolicy">The authorization policy the content key is bound to, or empty.</param>
    /// <param name="noDa">Whether the content key is exempt from dictionary-attack protection.</param>
    /// <returns>The serialized envelope.</returns>
    private async Task<byte[]> SealWideAsync(TpmDevice tpm, uint parentHandle, byte[] payload, ReadOnlyMemory<byte> sealAuth, BaseMemoryPool pool, ReadOnlyMemory<byte> authPolicy = default, bool noDa = false)
    {
        TpmResult<TpmSealedEnvelope> sealResult = await tpm.SealEnvelopeAsync(parentHandle, ReadOnlyMemory<byte>.Empty, payload, sealAuth, authPolicy, noDa, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(sealResult.IsSuccess, $"Sealing the envelope failed: '{sealResult.ResponseCode}'.");
        using TpmSealedEnvelope envelope = sealResult.Value;

        int size = envelope.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span[..size]);
        envelope.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>Serializes a sealed blob into its persisted form.</summary>
    /// <param name="sealedBlob">The sealed blob.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The serialized blob.</returns>
    private static byte[] Serialize(TpmSealedBlob sealedBlob, BaseMemoryPool pool)
    {
        int size = sealedBlob.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span[..size]);
        sealedBlob.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>Parses a persisted envelope into a fresh instance the caller owns.</summary>
    /// <param name="stored">The persisted envelope.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed envelope.</returns>
    private static TpmSealedEnvelope ParseEnvelope(byte[] stored, BaseMemoryPool pool)
    {
        var reader = new TpmReader(stored);

        return TpmSealedEnvelope.Parse(ref reader, pool);
    }

    /// <summary>The width of the sealed-key prefix of a persisted envelope.</summary>
    /// <param name="stored">The persisted envelope.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The number of octets the sealed key occupies.</returns>
    private static int SealedKeyLength(byte[] stored, BaseMemoryPool pool)
    {
        var reader = new TpmReader(stored);
        using TpmSealedBlob sealedKey = TpmSealedBlob.Parse(ref reader, pool);

        return reader.Consumed;
    }

    /// <summary>A recognisable payload eight times the widest sealed data object.</summary>
    /// <returns>The payload.</returns>
    private static byte[] WidePayload()
    {
        byte[] payload = new byte[WidePayloadLength];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)((i * 7) + 3);
        }

        return payload;
    }

    /// <summary>The <c>TPM2_PolicyCommandCode()</c> policyDigest for <see cref="SessionAlg"/> binding <paramref name="commandCode"/>.</summary>
    /// <param name="commandCode">The command code the policy binds.</param>
    /// <returns>The predicted digest.</returns>
    private static byte[] PolicyCommandCodeDigest(TpmCcConstants commandCode)
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] digest = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, commandCode, SessionAlg, digest);

        return digest;
    }
}
