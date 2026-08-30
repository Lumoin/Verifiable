using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Hardening coverage for <c>TPM2_VerifySequenceComplete()</c>, <c>TPM2_VerifySequenceStart()</c>, and
/// <c>TPM2_PolicyAuthorize()</c>'s ticket recompute against the in-house behavioural <see cref="TpmSimulator"/>:
/// the key-identity binding by Name rather than handle, the completion-side scheme structural guard the
/// simulator generates only from a random primary (so it is proven by driving the shipped, public
/// <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly over a state captured from the
/// simulator's own trace and a single flipped field), a malformed wire hint/context
/// framing, and <c>TPM2_PolicyAuthorize()</c>'s per-ticket-tag metadata hash recompute for a
/// <c>TPM_ST_DIGEST_VERIFIED</c> ticket whose metadata differs from the authority key's own <c>nameAlg</c> —
/// both its success case and its fail-closed refusal of a <c>checkTicket.metadata</c> naming a hash algorithm
/// this simulator does not implement
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clauses 20.3, 20.4.1, 23.16.1, 23.16.2; Part 2: Structures, clauses
/// 9.31, 10.6.4).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifySequenceHardeningTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA authority-key test.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The policy session hash algorithm used to build every <c>approvedPolicy</c> in this file.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// A transient handle value distinct from any handle the shared <c>NextObjectHandle</c> allocator would
    /// produce in these tests — stands in for a verification key reloaded at a different numeric handle in the
    /// flipped-state Name-binding drive.
    /// </summary>
    private const uint ReloadedVerificationKeyHandleValue = 0x8000_FFFFu;

    /// <summary>A placeholder ECDSA signature (r ‖ s, both zero) for gates that reject before the verify effect ever runs.</summary>
    private static byte[] PlaceholderEcdsaSignature { get; } = new byte[2 * P256ComponentSize];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The key identity a completing command must match is bound by Name, not by numeric handle: a key
    /// Name-equal to the one that started the sequence but loaded at a DIFFERENT handle still completes it.
    /// Because the simulator assigns primaries a random key pair, the positive half of this rule cannot be
    /// exercised by loading a genuine second copy of the same key over the wire; it is instead proven by
    /// capturing the state right after <c>TPM2_VerifySequenceStart()</c> from the simulator's own trace
    /// subscription, installing the SAME (shared, not disposed) starting key's <see cref="TransientKeyState"/>
    /// under a second, different handle via a record <c>with</c> expression, and driving the public
    /// <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly with a
    /// <see cref="TpmVerifySequenceCompleteRequested"/> naming that new handle — exactly the input
    /// <c>TryParseVerifySequenceComplete</c> would have produced from a real wire frame. No private member,
    /// reflection, or production-code test seam is touched
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3: "If keyHandle refers to a key that is not the same as
    /// the key that was used to start the signature context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY" — by
    /// exclusion, a key that IS the same reproduces the same Name and is admitted).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAgainstAKeyNameEqualCopyAtADifferentHandleProducesTheVerifyAction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_VerifySequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeStartingKey), "The starting key must be present in the captured post-Start state.");
        TransientKeyState startingKey = maybeStartingKey!;

        Assert.IsTrue(capturedState.SequenceObjects.TryGetValue(sequenceHandle, out SequenceObjectState? maybeSequence), "The started sequence must be present in the captured post-Start state.");
        SequenceObjectState sequence = maybeSequence!;

        TpmiDhObject reloadedHandle = TpmiDhObject.FromValue(ReloadedVerificationKeyHandleValue);
        TransientKeyState nameEqualCopyAtANewHandle = startingKey with { Handle = reloadedHandle };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(reloadedHandle, nameEqualCopyAtANewHandle)
        };

        //A real, rented signature carrier — TpmtSignature.Dispose() is idempotently guarded, so this using's own
        //Dispose on scope exit is a harmless second call on the same instance the declared action still borrows;
        //nothing else in this drive ever runs the verification effect that would otherwise release it.
        using TpmtSignature placeholderSignature = TpmtSignature.Create(sequence.Scheme.Value, sequence.HashAlg.Value, PlaceholderEcdsaSignature, pool);
        using var request = new TpmVerifySequenceCompleteRequested(sequenceHandle, reloadedHandle, Tpm2bAuth.Empty, sequence.Scheme, sequence.HashAlg, placeholderSignature);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnVerifySequenceComplete always yields a transition — either a rejection or a declared verification action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmEccVerifySequenceAction>(
            nonNullResult.NextState.NextAction,
            "A key Name-equal to the one that started the sequence, loaded at a DIFFERENT handle, must produce the verification action rather than a TPM_RC_SIGN_CONTEXT_KEY rejection.");
    }

    /// <summary>
    /// The other half of the Name-binding rule: a DIFFERENT key's state installed at the SAME numeric handle the
    /// sequence started under is refused with <c>TPM_RC_SIGN_CONTEXT_KEY</c>, proving the gate compares Names and
    /// not handles — an implementation comparing handles instead would incorrectly accept this request, since
    /// <c>keyHandle</c> equals the handle the sequence recorded
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAgainstADifferentKeyLoadedAtTheStartingHandleReturnsSignContextKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse startingKeyPrimary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse otherKeyPrimary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, startingKeyPrimary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_VerifySequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(otherKeyPrimary.ObjectHandle, out TransientKeyState? maybeOtherKey), "The other key must be present in the captured post-Start state.");
        TransientKeyState otherKey = maybeOtherKey!;

        Assert.IsTrue(capturedState.SequenceObjects.TryGetValue(sequenceHandle, out SequenceObjectState? maybeSequence), "The started sequence must be present in the captured post-Start state.");
        SequenceObjectState sequence = maybeSequence!;

        TransientKeyState otherKeyAtTheStartingHandle = otherKey with { Handle = startingKeyPrimary.ObjectHandle };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(startingKeyPrimary.ObjectHandle, otherKeyAtTheStartingHandle)
        };

        using TpmtSignature placeholderSignature = TpmtSignature.Create(sequence.Scheme.Value, sequence.HashAlg.Value, PlaceholderEcdsaSignature, pool);
        using var request = new TpmVerifySequenceCompleteRequested(sequenceHandle, startingKeyPrimary.ObjectHandle, Tpm2bAuth.Empty, sequence.Scheme, sequence.HashAlg, placeholderSignature);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnVerifySequenceComplete always yields a transition — either a rejection or a declared verification action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");
        var rejection = (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, rejection.ResponseCode,
            "A different key's state installed at the sequence's OWN starting handle must still be refused with TPM_RC_SIGN_CONTEXT_KEY: the gate compares Names, not handles.");
    }

    /// <summary>
    /// The sequence's own retained <c>Scheme</c>/<c>HashAlg</c> — resolved once at
    /// <c>TPM2_VerifySequenceStart()</c> from the key's template — must still agree with the Name-matched key's
    /// CURRENT retained scheme at completion: a <see cref="SequenceObjectState"/> whose <c>HashAlg</c> was
    /// altered after Start (so it no longer matches the unchanged key's own retained
    /// <see cref="TransientKeyState.SigningSchemeHashAlg"/>) is refused with <c>TPM_RC_SCHEME</c>, even though the
    /// completing request's own <c>SignatureScheme</c>/<c>SchemeHashAlg</c> agree with the altered sequence — so
    /// the refusal can only come from the key-vs-sequence comparison, not from the request-vs-sequence one.
    /// Because a key's scheme lives inside its Name-computed public area and cannot change while the sequence
    /// stays open, this gate is unreachable over the wire and is proven by driving the public transition delegate
    /// with a flipped, captured state
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6: the sequence's scheme/hash are resolved once from the
    /// key at Start; clause 20.4.1: "The TPM will verify that the signing scheme (including the hash or XOF
    /// algorithm) in signature matches the signing scheme of keyHandle (TPM_RC_SCHEME)" — clause 20.4 is
    /// expressly "like TPM2_VerifySequenceComplete()", so the same match rule governs clause 20.3's own
    /// keyHandle/signature scheme check).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithASequenceRetainedPairDifferentFromTheKeysRetainedPairReturnsScheme()
    {
        TpmHeaderOnlyResponse rejection = await DriveVerifySequenceCompleteWithAFlippedSequenceAsync(
            sequence => sequence with { HashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384) }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SCHEME, rejection.ResponseCode,
            "A sequence whose retained HashAlg no longer matches the Name-matched key's own retained SigningSchemeHashAlg must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// The mirror structural check on the key side: a key whose retained signing scheme has been forced to
    /// <see langword="null"/> is refused with <c>TPM_RC_SCHEME</c> at completion even though its Name (computed
    /// over the ORIGINAL, non-null scheme) still matches the sequence's <c>StartingKeyName</c> — the completing
    /// request's own <c>SignatureScheme</c>/<c>SchemeHashAlg</c> still agree with the sequence's unaltered
    /// retained pair, so the refusal can only come from the key-side short-circuit. Proven with the same
    /// flipped-state technique as the sequence-side guard above
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAgainstAKeyForcedNullSigningSchemeReturnsScheme()
    {
        TpmHeaderOnlyResponse rejection = await DriveVerifySequenceCompleteWithAFlippedStartingKeyAsync(
            startingKey => startingKey with { SigningScheme = null, SigningSchemeHashAlg = null }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SCHEME, rejection.ResponseCode,
            "A key whose retained signing scheme is NULL must be refused with TPM_RC_SCHEME at TPM2_VerifySequenceComplete(), even though the completing request's own SignatureScheme/SchemeHashAlg agree with the sequence's retained pair.");
    }

    /// <summary>
    /// A hand-framed <c>TPM2_VerifySequenceStart()</c> carrying a non-empty <c>auth</c>, a 1-octet <c>hint</c>,
    /// and a 1-octet <c>context</c> is refused with <c>TPM_RC_SIZE</c> (the hint gate fires first, ahead of the
    /// context gate, under every scheme this simulator executes), and the refusal returns ALL THREE already-
    /// parsed carriers to the pool — the whole request, not only the one field whose gate actually fired
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6, Table 89; Part 2: Structures, clause 11.3.9, Table
    /// 222: "For TPM_ALG_EDDSA, hint contains the encoded R value from the signature. For all other signature
    /// algorithms, this buffer must be zero-length.").
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartWithANonEmptyHintAndContextHandFramedReturnsSizeAndReturnsEveryParsedCarrierToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;

        byte[] nonEmptyAuth = "attempted-verify-sequence-auth"u8.ToArray();
        byte[] nonEmptyHint = [0x01];
        byte[] nonEmptyContext = [0x01];
        TpmRcConstants code = await SubmitVerifySequenceStartCommandAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, primary.ObjectHandle.Value, nonEmptyAuth, nonEmptyHint, nonEmptyContext).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty hint under ECDSA (and, independently, a non-empty context) must be refused with TPM_RC_SIZE.");
        Assert.AreEqual(
            baseline, housePool.OutstandingCount,
            "A refused TPM2_VerifySequenceStart() must return the parsed auth, hint, and context rentals to the pool — the hint gate fires first, but the rejection releases the whole request, including the still-live context rental behind it.");
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c> recomputes Equation (5) for a <c>TPM_ST_DIGEST_VERIFIED</c> ticket by
    /// hashing <c>toBeSigned</c> under the ticket's OWN <c>[tag]metadata</c> hash — the hash algorithm the
    /// signature was actually verified under — not under <c>keySign</c>'s <c>nameAlg</c>. An RSA authority key
    /// created with <c>nameAlg</c> SHA-256 (the template default) but signing scheme RSASSA/SHA-384 makes the two
    /// differ: its <c>TPM2_VerifyDigestSignature()</c> ticket records metadata SHA-384, and
    /// <c>TPM2_PolicyAuthorize()</c> must still SUCCEED against it — a nameAlg-substituting implementation would
    /// hash under SHA-256 instead and refuse it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.4, Table 111: the <c>digestVerified</c> arm's
    /// metadata is "The hash algorithm or XOF ... used to produce the digest that was verified"; Part 3:
    /// Commands, clause 23.16.2: "TPM2_VerifySequenceComplete() or TPM2_VerifyDigestSignature() (which do not
    /// require modifying the scheme when used with TPM2_PolicyAuthorize()) are preferred instead").
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeAcceptsADigestVerifiedTicketWhoseMetadataDiffersFromTheAuthorityKeysNameAlg()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateRsaAuthorityKeyWithSha384SchemeAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();

        (byte[] approvedPolicy, byte[] policyRef, TpmtTkVerified genuineTicket) = await MintDigestVerifiedTicketWithSha384MetadataAsync(
            tpm, registry, pool, authorityKey.ObjectHandle).ConfigureAwait(false);
        using TpmtTkVerified ticket = genuineTicket;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, ticket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                authorizeResult.IsSuccess,
                $"TPM2_PolicyAuthorize() must SUCCEED against a DIGEST_VERIFIED ticket whose metadata (SHA-384) differs from keySign's nameAlg (SHA-256): '{authorizeResult.ResponseCode}'.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The discriminating negative half of
    /// <see cref="PolicyAuthorizeAcceptsADigestVerifiedTicketWhoseMetadataDiffersFromTheAuthorityKeysNameAlg"/>:
    /// the SAME genuine ticket's HMAC bytes, re-tagged with a DIFFERENT metadata hash (SHA-256 in place of the
    /// SHA-384 it was actually minted under), is refused — Equation (5)'s recompute now hashes
    /// <c>toBeSigned</c> under the wrong width/algorithm and the HMAC no longer matches
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 23.16.1: "If the ticket is not valid, the TPM shall return
    /// TPM_RC_POLICY.").
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithADigestVerifiedTicketRetaggedWithTheWrongMetadataReturnsPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateRsaAuthorityKeyWithSha384SchemeAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();

        (byte[] approvedPolicy, byte[] policyRef, TpmtTkVerified genuineTicket) = await MintDigestVerifiedTicketWithSha384MetadataAsync(
            tpm, registry, pool, authorityKey.ObjectHandle).ConfigureAwait(false);
        byte[] genuineHmac = genuineTicket.Hmac.ToArray();
        TpmiRhHierarchy ticketHierarchy = genuineTicket.Hierarchy;
        genuineTicket.Dispose();

        using TpmtTkVerified wrongMetadataTicket = MintTicketWithMetadata(
            TpmStConstants.TPM_ST_DIGEST_VERIFIED, ticketHierarchy, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), genuineHmac, pool);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyAuthorizeResponse> authorizeResult = await tpm.PolicyAuthorizeAsync(
                sessionHandle, approvedPolicy, policyRef, keySign, wrongMetadataTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(authorizeResult.IsSuccess, "A genuine ticket's HMAC, re-tagged with the WRONG metadata hash, must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_POLICY, authorizeResult.ResponseCode,
                "The recompute under the wrong metadata hash must fail Equation (5)'s comparison and answer TPM_RC_POLICY.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>checkTicket.[tag]metadata</c> naming SHA3-256 — a TCG-registered hash algorithm this simulator does
    /// not implement — is refused with <c>TPM_RC_HASH</c> before the ticket recompute ever selects an
    /// unsupported digest width or provider, and no exception escapes the submission
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 9.31, Table 77: "The selector in Table 77 indicates all
    /// of the hash algorithms that have an algorithm ID assigned by the TCG and does not indicate the algorithms
    /// that will be accepted by a TPM" — naming <c>#TPM_RC_HASH</c> for one that is not).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithACheckTicketMetadataOfAnUnimplementedTcgHashAlgorithmReturnsHashWithNoExceptionEscaping()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] approvedPolicy = BuildApprovedPolicyForUnseal();
        byte[] keySign = BuildPlausibleSha256Name();
        byte[] hmac = new byte[32];

        TpmRcConstants code = await SubmitPolicyAuthorizeWithRawCheckTicketAsync(
            tpm, registry, pool, approvedPolicy, policyRef: [], keySign, TpmAlgIdConstants.TPM_ALG_SHA3_256, hmac).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HASH, code,
            "checkTicket.metadata naming a TCG-registered hash algorithm this simulator does not implement (SHA3-256) must be refused with TPM_RC_HASH, never an escaping exception.");
    }

    /// <summary>
    /// The mirror of
    /// <see cref="PolicyAuthorizeWithACheckTicketMetadataOfAnUnimplementedTcgHashAlgorithmReturnsHashWithNoExceptionEscaping"/>
    /// for SHA-1: this codebase deliberately excludes SHA-1 from the signing-digest path, so a
    /// <c>checkTicket.metadata</c> naming it must be refused exactly as an unimplemented algorithm is, even
    /// though SHA-1 does not itself throw out of the width lookup
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 9.31, Table 77).
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithACheckTicketMetadataOfSha1ReturnsHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] approvedPolicy = BuildApprovedPolicyForUnseal();
        byte[] keySign = BuildPlausibleSha256Name();
        byte[] hmac = new byte[32];

        TpmRcConstants code = await SubmitPolicyAuthorizeWithRawCheckTicketAsync(
            tpm, registry, pool, approvedPolicy, policyRef: [], keySign, TpmAlgIdConstants.TPM_ALG_SHA1, hmac).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, code, "checkTicket.metadata naming SHA-1 must be refused with TPM_RC_HASH.");
    }

    /// <summary>
    /// A <c>checkTicket.[tag]metadata</c> naming SHA-384 — a hash algorithm this simulator DOES implement — is
    /// admitted past the metadata gate, so a garbage <c>hmac</c> under it reaches the actual recompute and is
    /// refused for the ordinary reason: the recompute ran and did not match. This proves the metadata gate is
    /// selective (it refuses only unsupported algorithms, not SHA-384 itself) and that the fail-closed refusal
    /// above is not merely "every checkTicket answers TPM_RC_HASH"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 23.16.1: "If the ticket is not valid, the TPM shall return
    /// TPM_RC_POLICY.").
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithACheckTicketMetadataOfSha384AndAGarbageHmacReturnsPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] approvedPolicy = BuildApprovedPolicyForUnseal();
        byte[] keySign = BuildPlausibleSha256Name();
        byte[] garbageHmac = "not a real ticket hmac at all, just filler"u8.ToArray();

        TpmRcConstants code = await SubmitPolicyAuthorizeWithRawCheckTicketAsync(
            tpm, registry, pool, approvedPolicy, policyRef: [], keySign, TpmAlgIdConstants.TPM_ALG_SHA384, garbageHmac).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY, code,
            "checkTicket.metadata of SHA-384 (a supported algorithm) must pass the metadata gate; a garbage hmac then fails the recompute and answers TPM_RC_POLICY, not TPM_RC_HASH.");
    }

    /// <summary>
    /// The <c>TPM2_VerifySequenceComplete()</c> arm of the shared ECDSA rebuild: a <c>signatureR</c> carried with
    /// an extra leading zero octet encodes the same integer and verifies the accumulated message, minting the
    /// ticket as the fixed-width form does (TPM 2.0 Library Part 3, clause 20.3; Part 2, clause 11.3.2, Table
    /// 214; clause 11.2.5.1, Table 197). Framed by hand because the typed input only takes the fixed-width
    /// IEEE P1363 form.
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteAcceptsASignatureRWithALeadingZeroOctetAsTheSameInteger()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] message = "Verifiable in-house TPM verification sequence over a zero-padded signatureR."u8.ToArray();
        byte[] digest = SHA256.HashData(message);
        (byte[] r, byte[] s) = await SignDigestEcdsaComponentsAsync(tpm, registry, pool, primary.ObjectHandle, digest).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, message).ConfigureAwait(false);

        byte[] zeroPaddedR = [0x00, .. ToFixed(r, P256ComponentSize)];
        byte[] body = BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants.TPM_ALG_SHA256, zeroPaddedR, ToFixed(s, P256ComponentSize));

        TpmRcConstants code = await SubmitVerifySequenceCompleteCommandAsync(simulator, pool, sequenceHandle.Value, primary.ObjectHandle.Value, body).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A signatureR with an insignificant leading zero octet encodes the same integer and must verify the sequence (Table 214/197).");
    }

    /// <summary>
    /// Captures the starting key's state right after <c>TPM2_VerifySequenceStart()</c>, applies
    /// <paramref name="flipKey"/> to it, installs the flipped copy at the SAME handle the sequence recorded (so
    /// the Name comparison at completion still passes and the flipped gate is the only one that can fire), and
    /// drives the public <see cref="TpmLifecycleTransitions.Create"/> transition delegate directly with a
    /// completing request naming that handle and the UNFLIPPED sequence's own retained scheme/hash — isolating
    /// the key-side half of the structural scheme guard from the sequence-side half.
    /// </summary>
    /// <param name="flipKey">Produces the flipped copy of the captured starting key's state.</param>
    /// <returns>The header-only rejection the transition produced.</returns>
    private async Task<TpmHeaderOnlyResponse> DriveVerifySequenceCompleteWithAFlippedStartingKeyAsync(Func<TransientKeyState, TransientKeyState> flipKey)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_VerifySequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeStartingKey), "The starting key must be present in the captured post-Start state.");
        TransientKeyState startingKey = maybeStartingKey!;

        Assert.IsTrue(capturedState.SequenceObjects.TryGetValue(sequenceHandle, out SequenceObjectState? maybeSequence), "The started sequence must be present in the captured post-Start state.");
        SequenceObjectState sequence = maybeSequence!;

        TransientKeyState flippedKey = flipKey(startingKey);
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(primary.ObjectHandle, flippedKey)
        };

        using TpmtSignature placeholderSignature = TpmtSignature.Create(sequence.Scheme.Value, sequence.HashAlg.Value, PlaceholderEcdsaSignature, pool);
        using var request = new TpmVerifySequenceCompleteRequested(sequenceHandle, primary.ObjectHandle, Tpm2bAuth.Empty, sequence.Scheme, sequence.HashAlg, placeholderSignature);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnVerifySequenceComplete always yields a transition — either a rejection or a declared verification action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");

        return (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
    }

    /// <summary>
    /// The sequence-side mirror of <see cref="DriveVerifySequenceCompleteWithAFlippedStartingKeyAsync"/>: applies
    /// <paramref name="flipSequence"/> to the captured <see cref="SequenceObjectState"/> instead of the key, and
    /// drives the completing request with the FLIPPED sequence's own retained scheme/hash — so only the
    /// key-vs-sequence comparison, never the request-vs-sequence one, can trip the gate.
    /// </summary>
    /// <param name="flipSequence">Produces the flipped copy of the captured sequence's state.</param>
    /// <returns>The header-only rejection the transition produced.</returns>
    private async Task<TpmHeaderOnlyResponse> DriveVerifySequenceCompleteWithAFlippedSequenceAsync(Func<SequenceObjectState, SequenceObjectState> flipSequence)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time TPM2_VerifySequenceStart() returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.SequenceObjects.TryGetValue(sequenceHandle, out SequenceObjectState? maybeStartingSequence), "The started sequence must be present in the captured post-Start state.");
        SequenceObjectState startingSequence = maybeStartingSequence!;

        SequenceObjectState flippedSequence = flipSequence(startingSequence);
        TpmSimulatorState mutatedState = capturedState with
        {
            SequenceObjects = capturedState.SequenceObjects.SetItem(sequenceHandle, flippedSequence)
        };

        using TpmtSignature placeholderSignature = TpmtSignature.Create(flippedSequence.Scheme.Value, flippedSequence.HashAlg.Value, PlaceholderEcdsaSignature, pool);
        using var request = new TpmVerifySequenceCompleteRequested(sequenceHandle, primary.ObjectHandle, Tpm2bAuth.Empty, flippedSequence.Scheme, flippedSequence.HashAlg, placeholderSignature);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnVerifySequenceComplete always yields a transition — either a rejection or a declared verification action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");

        return (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
    }

    /// <summary>
    /// Submits <see cref="VerifySequenceStartInput.Create"/> with no session (Auth Index None; no authorization
    /// of <c>keyHandle</c> is required) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The candidate verification key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySequenceStartResponse>> SubmitVerifyStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a verification sequence via <see cref="SubmitVerifyStartAsync"/>, asserting success, and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The verification key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        TpmResult<VerifySequenceStartResponse> result = await SubmitVerifyStartAsync(tpm, registry, pool, keyHandle, sequenceAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifySequenceStart()</c> command with a caller-chosen tag, <c>hint</c>, and
    /// <c>context</c> body, bypassing <see cref="VerifySequenceStartInput"/> (which always frames
    /// <c>TPM_ST_NO_SESSIONS</c> and empty hint/context) — letting a caller submit a non-empty hint/context
    /// directly against the simulator.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="hint">The <c>hint</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifySequenceStartCommand(
        BaseMemoryPool pool, ushort tag, uint keyHandle, ReadOnlySpan<byte> sequenceAuth, ReadOnlySpan<byte> hint, ReadOnlySpan<byte> context, out int length)
    {
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                          //Handle area: @keyHandle.
            + (sizeof(ushort) + sequenceAuth.Length) //auth: TPM2B_AUTH.
            + (sizeof(ushort) + hint.Length)         //hint: TPM2B_SIGNATURE_HINT.
            + (sizeof(ushort) + context.Length);     //context: TPM2B_SIGNATURE_CTX.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifySequenceStart);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteTpm2b(sequenceAuth);
            writer.WriteTpm2b(hint);
            writer.WriteTpm2b(context);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_VerifySequenceStart()</c> built by
    /// <see cref="FrameVerifySequenceStartCommand"/> straight to the simulator (bypassing
    /// <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag to frame verbatim.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="sequenceAuth">The <c>auth</c> parameter's octets.</param>
    /// <param name="hint">The <c>hint</c> parameter's octets.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifySequenceStartCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, byte[] sequenceAuth, byte[] hint, byte[] context)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifySequenceStartCommand(pool, tag, keyHandle, sequenceAuth, hint, context, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Signs <paramref name="digest"/> with an RSA key via <c>TPM2_SignDigest()</c> over an empty-password
    /// session and returns the raw RSASSA signature octets.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The RSA signing key handle.</param>
    /// <param name="digest">The 48-octet SHA-384 digest to sign.</param>
    /// <returns>The raw RSA signature octets.</returns>
    private async Task<byte[]> SignDigestRsaSha384Async(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() (RSASSA/SHA-384) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm, "TPM2_SignDigest() must produce the key's own retained RSASSA scheme.");

        return signature.Signature.RsaSignature.Buffer.ToArray();
    }

    /// <summary>
    /// Builds <c>toBeSigned = approvedPolicy ‖ policyRef</c> for the owner hierarchy's Unseal-restricted policy,
    /// signs its independent framework SHA-384 digest with <paramref name="authorityKeyHandle"/> via
    /// <c>TPM2_SignDigest()</c>, mints the <c>TPM_ST_DIGEST_VERIFIED</c> ticket via
    /// <c>TPM2_VerifyDigestSignature()</c> under scheme hash SHA-384, and asserts the ticket's own metadata
    /// records SHA-384 — proving the discriminating setup (metadata differs from the key's SHA-256 nameAlg)
    /// actually holds before either consuming test uses it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authorityKeyHandle">The RSA authority key's handle.</param>
    /// <returns>The predicted <c>approvedPolicy</c>, the <c>policyRef</c> used, and the minted ticket (the caller disposes it).</returns>
    private async Task<(byte[] ApprovedPolicy, byte[] PolicyRef, TpmtTkVerified Ticket)> MintDigestVerifiedTicketWithSha384MetadataAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject authorityKeyHandle)
    {
        byte[] policyRef = "digest-verified-metadata-hash-ref"u8.ToArray();
        byte[] approvedPolicy = BuildApprovedPolicyForUnseal();

        byte[] toBeSigned = [.. approvedPolicy, .. policyRef];
        byte[] digest = SHA384.HashData(toBeSigned);

        byte[] rsaSignature = await SignDigestRsaSha384Async(tpm, registry, pool, authorityKeyHandle, digest).ConfigureAwait(false);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForRsaSsa(
            authorityKeyHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA384, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature() (RSASSA/SHA-384) failed: '{verifyResult.ResponseCode}'.");

        using VerifyDigestSignatureResponse verified = verifyResult.Value;
        Assert.IsTrue(verified.Validation.Metadata.HasValue, "A TPM_ST_DIGEST_VERIFIED ticket must carry metadata (Table 111's digestVerified arm).");
        Assert.AreEqual(
            TpmAlgIdConstants.TPM_ALG_SHA384, verified.Validation.Metadata!.Value.Value,
            "The ticket's metadata must record the scheme hash (SHA-384) the signature was actually verified under, not the authority key's nameAlg (SHA-256).");

        TpmtTkVerified ticket = MintTicketWithMetadata(
            verified.Validation.Tag, verified.Validation.Hierarchy, verified.Validation.Metadata!.Value, verified.Validation.Hmac, pool);

        return (approvedPolicy, policyRef, ticket);
    }

    /// <summary>
    /// Composes a TPMT_TK_VERIFIED value claiming <paramref name="tag"/>, <paramref name="hierarchy"/>, and
    /// <paramref name="metadata"/> over <paramref name="hmac"/> exactly as an attacker (or, here, a test
    /// isolating one field) would submit one on the wire (TPM 2.0 Library Part 2, clause 10.6.5), parsed back
    /// through the production wire shape so the result is a genuine ticket value with a caller-chosen metadata.
    /// </summary>
    /// <param name="tag">The ticket structure tag to claim (always <c>TPM_ST_DIGEST_VERIFIED</c> in this file).</param>
    /// <param name="hierarchy">The hierarchy the ticket claims.</param>
    /// <param name="metadata">The metadata hash algorithm to claim.</param>
    /// <param name="hmac">The ticket HMAC octets.</param>
    /// <param name="pool">The memory pool backing the parsed ticket.</param>
    /// <returns>The composed ticket; the caller disposes it.</returns>
    private static TpmtTkVerified MintTicketWithMetadata(TpmStConstants tag, TpmiRhHierarchy hierarchy, TpmiAlgHash metadata, ReadOnlySpan<byte> hmac, BaseMemoryPool pool)
    {
        int size = sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort) + hmac.Length;
        using IMemoryOwner<byte> owner = pool.Rent(size);
        Span<byte> wire = owner.Memory.Span[..size];
        var writer = new TpmWriter(wire);
        writer.WriteUInt16((ushort)tag);
        hierarchy.WriteTo(ref writer);
        metadata.WriteTo(ref writer);
        writer.WriteUInt16((ushort)hmac.Length);
        writer.WriteBytes(hmac);
        var reader = new TpmReader(wire);

        return TpmtTkVerified.Parse(ref reader, pool);
    }

    /// <summary>
    /// Builds a syntactically valid, 34-octet <c>TPM2B_NAME</c> — a 2-octet <c>nameAlg</c> of
    /// <c>TPM_ALG_SHA256</c> followed by a 32-octet placeholder digest — for use as <c>keySign</c> in the
    /// unsupported-metadata tests, which never look it up against any loaded object:
    /// <c>TPM2_PolicyAuthorize()</c> reads only its leading <c>nameAlg</c> octets and folds the whole buffer into
    /// the policyDigest, never resolving it to a live key.
    /// </summary>
    /// <returns>The 34-octet Name octets.</returns>
    private static byte[] BuildPlausibleSha256Name()
    {
        byte[] name = new byte[sizeof(ushort) + P256ComponentSize];
        var writer = new TpmWriter(name);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteBytes(new byte[P256ComponentSize]);

        return name;
    }

    /// <summary>
    /// Independently predicts the owner hierarchy's <c>approvedPolicy</c> for an Unseal-restricted policy session
    /// — the zero digest extended once by <c>TPM2_CC_Unseal</c> under <see cref="SessionAlg"/> — matching what a
    /// real policy session's <c>TPM2_PolicyCommandCode(TPM_CC_Unseal)</c> produces from a fresh start.
    /// </summary>
    /// <returns>The predicted <c>approvedPolicy</c> octets.</returns>
    private static byte[] BuildApprovedPolicyForUnseal()
    {
        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] approvedPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy);

        return approvedPolicy;
    }

    /// <summary>
    /// Starts a fresh, non-trial policy session restricted to <c>TPM_CC_Unseal</c>, submits a hand-composed
    /// <see cref="PolicyAuthorizeInput"/> tagged <c>TPM_ST_DIGEST_VERIFIED</c> carrying a caller-chosen
    /// <paramref name="checkTicketMetadataAlg"/> and <paramref name="checkTicketHmac"/> against it over the real
    /// wire, flushes the session, and returns the response code — the mechanism behind the three
    /// unsupported-metadata tests.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="approvedPolicy">The policy digest the session is driven to (via <c>PolicyCommandCode(Unseal)</c>).</param>
    /// <param name="policyRef">The opaque policy qualifier.</param>
    /// <param name="keySign">The claimed signer's Name.</param>
    /// <param name="checkTicketMetadataAlg">The <c>checkTicket.[tag]metadata</c> hash algorithm to claim.</param>
    /// <param name="checkTicketHmac">The claimed ticket HMAC octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPolicyAuthorizeWithRawCheckTicketAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] approvedPolicy, byte[] policyRef, byte[] keySign,
        TpmAlgIdConstants checkTicketMetadataAlg, byte[] checkTicketHmac)
    {
        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
                sessionHandle, approvedPolicy, policyRef, keySign,
                (ushort)TpmStConstants.TPM_ST_DIGEST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER,
                TpmiAlgHash.FromValue(checkTicketMetadataAlg), checkTicketHmac, pool);

            TpmResult<PolicyAuthorizeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
                tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            return result.ResponseCode;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing/verification primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an unrestricted, empty-password RSA 2048 signing/verification primary under the owner hierarchy
    /// whose template <c>nameAlg</c> is the factory's hard-coded SHA-256 while its signing scheme is
    /// RSASSA/SHA-384 — the two independent hash algorithms <see cref="CreatePrimaryInput.ForRsaSigningKey"/>
    /// admits, deliberately made to differ.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaAuthorityKeyWithSha384SchemeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA384), pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, nameAlg SHA-256, scheme RSASSA/SHA-384) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Flushes a transient object or session handle when one is present (non-zero), ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-verify-sequence-hardening",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>
    /// Captures the most recent post-transition <see cref="TpmSimulatorState"/> the simulator's own
    /// <see cref="IObservable{T}"/> trace emits — the exact same public channel a replay journal or metrics
    /// subscriber would use, not a test-only hook into production code.
    /// </summary>
    private sealed class LastStateObserver: IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
    {
        /// <summary>Gets the state after the most recently observed step, or <see langword="null"/> before the first one.</summary>
        public TpmSimulatorState? LastState { get; private set; }

        /// <inheritdoc/>
        public void OnNext(TraceEntry<TpmSimulatorState, TpmSimulatorInput> value) => LastState = value.StateAfter;

        /// <inheritdoc/>
        public void OnError(Exception error)
        {
        }

        /// <inheritdoc/>
        public void OnCompleted()
        {
        }
    }

    /// <summary>
    /// Signs <paramref name="digest"/> through <c>TPM2_SignDigest()</c> over an empty-password session and returns
    /// the ECDSA components exactly as the TPM answered them, unpadded.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The ECDSA signing key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <returns>The <c>signatureR</c> and <c>signatureS</c> octets.</returns>
    private async Task<(byte[] R, byte[] S)> SignDigestEcdsaComponentsAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] digest)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(keyHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest() (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;

        return (signature.Signature.SignatureR!.AsReadOnlySpan().ToArray(), signature.Signature.SignatureS!.AsReadOnlySpan().ToArray());
    }

    /// <summary>Feeds <paramref name="buffer"/> to an empty-authValue sequence via <c>TPM2_SequenceUpdate()</c>, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="buffer">The update buffer.</param>
    private async Task UpdateSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_VerifySequenceComplete()</c> command — <c>@sequenceHandle</c> authorized by one empty
    /// <c>TPM_RS_PW</c> slot, <c>keyHandle</c> unauthorized, then the caller's already-marshaled
    /// <c>TPMT_SIGNATURE</c> body verbatim — bypassing <see cref="VerifySequenceCompleteInput"/>, which only takes
    /// the fixed-width IEEE P1363 form.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameVerifySequenceCompleteCommand(
        BaseMemoryPool pool, uint sequenceHandle, uint keyHandle, ReadOnlySpan<byte> signatureBody, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + 2 * sizeof(uint)                 //Handle area: @sequenceHandle, keyHandle.
            + sizeof(uint) + PasswordSlotSize  //authorizationSize + one empty TPM_RS_PW slot.
            + signatureBody.Length;            //signature: TPMT_SIGNATURE.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_VerifySequenceComplete);
            header.WriteTo(ref writer);
            writer.WriteUInt32(sequenceHandle);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteBytes(signatureBody);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_VerifySequenceComplete()</c> built by
    /// <see cref="FrameVerifySequenceCompleteCommand"/> straight to the simulator and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The <c>@sequenceHandle</c> handle value.</param>
    /// <param name="keyHandle">The <c>keyHandle</c> handle value.</param>
    /// <param name="signatureBody">The already-marshaled <c>TPMT_SIGNATURE</c> body.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitVerifySequenceCompleteCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sequenceHandle, uint keyHandle, byte[] signatureBody)
    {
        using IMemoryOwner<byte> commandOwner = FrameVerifySequenceCompleteCommand(pool, sequenceHandle, keyHandle, signatureBody, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Builds an ECDSA <c>TPMT_SIGNATURE</c> body — sigAlg, hashAlg, then <c>signatureR</c> and <c>signatureS</c>
    /// each as its own TPM2B — from two independently sized components, exactly as Table 214 frames them.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm carried inside the member.</param>
    /// <param name="signatureR">The <c>signatureR</c> octets, written verbatim.</param>
    /// <param name="signatureS">The <c>signatureS</c> octets, written verbatim.</param>
    /// <returns>The marshaled body.</returns>
    private static byte[] BuildEcdsaSignatureBodyFromComponents(TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signatureR, ReadOnlySpan<byte> signatureS)
    {
        byte[] body = new byte[2 * sizeof(ushort) + sizeof(ushort) + signatureR.Length + sizeof(ushort) + signatureS.Length];
        var writer = new TpmWriter(body);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        writer.WriteUInt16((ushort)hashAlg);
        writer.WriteTpm2b(signatureR);
        writer.WriteTpm2b(signatureS);

        return body;
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 encoding requires. The simulator
    /// returns TPM2B integers that may omit leading zero bytes.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
