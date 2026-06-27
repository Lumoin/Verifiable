using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.EventLogs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// A parsed TPM quote operation in an attestation log: the attested PCR composite digest and the caller nonce.
/// </summary>
/// <param name="PcrDigest">The PCR composite digest the quote attested.</param>
/// <param name="Nonce">The qualifyingData nonce echoed in the attestation.</param>
internal sealed record TpmQuoteOperation(byte[] PcrDigest, byte[] Nonce);

/// <summary>
/// The accumulated state of a TPM attestation log: the bound attestation key, the most recently attested PCR
/// digest, and how many quotes have been verified into the log.
/// </summary>
/// <param name="AttestationKey">The compressed public key of the attestation key bound at genesis.</param>
/// <param name="LatestPcrDigest">The PCR composite digest from the most recently applied quote.</param>
/// <param name="QuoteCount">The number of quotes verified into the log.</param>
internal sealed record TpmAttestationState(byte[] AttestationKey, byte[] LatestPcrDigest, int QuoteCount);

/// <summary>
/// The trust input an application supplies to attestation-log replay: the attestation key it has enrolled (and
/// therefore decided to trust). In a production system this trust decision is the result of validating the AK's
/// EK-bound credential — the place an EK→AK certificate chain is checked through
/// <c>ValidateCertificateChainAsyncDelegate</c> — rather than a pre-enrolled key.
/// </summary>
/// <param name="EnrolledAttestationKey">The compressed public key of the enrolled attestation key.</param>
internal sealed record TpmAttestationTrustContext(byte[] EnrolledAttestationKey);

/// <summary>
/// Exemplifies, from a library-user's perspective, a real TPM attestation log built on the generic crypto-proof
/// replay path: a richer domain state than a bare counter, hash-chain–linked entries, and proof validation that
/// composes the domain-agnostic signature check (<see cref="CryptoProofValidation"/>) with a domain rule —
/// every quote must be signed by the attestation key the application enrolled and bound at genesis.
/// </summary>
/// <remarks>
/// <para>
/// This is the "what's possible" shape: a relying party creates an attestation key, enrolls it (the trust
/// decision), then accumulates quotes as a tamper-evident <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>
/// stream. The signer-key trust is carried on the validation context, which is exactly where an EK→AK certificate
/// chain validated through <c>ValidateCertificateChainAsyncDelegate</c> would replace the pre-enrolled-key
/// comparison (gap #4: EK/AK + credential activation). Nothing here is TPM-specific in the library: the quote is
/// reduced to neutral <see cref="CryptoProof"/> carriers and the same path serves any signed-attestation domain.
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorAttestationLogTests
{
    /// <summary>The number of bytes in a NIST P-256 ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The PCR bank the quotes select from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCRs the quotes cover.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>The nonce for the genesis quote.</summary>
    private static byte[] GenesisNonce { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>The nonce for the second quote.</summary>
    private static byte[] SecondNonce { get; } =
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

    /// <summary>The challenge secret wrapped during credential activation to prove AK↔EK co-residence at enrollment.</summary>
    private static byte[] EnrollmentChallenge { get; } =
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Connects to the simulator (if one is reachable) and brings up a TPM device for the class.</summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>Releases the TPM device and simulator connection.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>Skips the test when no simulator is reachable.</summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task MultiQuoteAttestationLogReplaysAndAccumulatesState()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        try
        {
            using PublicKeyMemory akKey = ak.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                P256ComponentSize, CryptoTags.P256PublicKey, pool);
            byte[] enrolled = akKey.AsReadOnlySpan().ToArray();

            //The application enrolled this AK out of band (the trust decision), then accumulates quotes over it.
            (byte[] canonical0, TpmQuoteOperation op0, Signature signature0) = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle, GenesisNonce).ConfigureAwait(false);
            (byte[] canonical1, TpmQuoteOperation op1, Signature signature1) = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle, SecondNonce).ConfigureAwait(false);

            using Signature sig0 = signature0;
            using Signature sig1 = signature1;

            LogEntry<TpmQuoteOperation, CryptoProof> genesis = BuildEntry(0, previousDigest: null, canonical0, op0, new CryptoProof(sig0, akKey, CryptoAlgorithm.P256));
            LogEntry<TpmQuoteOperation, CryptoProof> update = BuildEntry(1, previousDigest: genesis.Digest, canonical1, op1, new CryptoProof(sig1, akKey, CryptoAlgorithm.P256));

            IReadOnlyList<LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof>> results =
                await ReplayAllAsync([genesis, update], enrolled).ConfigureAwait(false);

            Assert.HasCount(2, results, "Both entries must be processed.");
            Assert.IsTrue(results[0].IsSuccess, $"Genesis must verify; error: '{results[0].Error}'.");
            Assert.IsTrue(results[1].IsSuccess, $"The second quote must verify; error: '{results[1].Error}'.");

            Assert.IsInstanceOfType<ActiveLogState<TpmAttestationState>>(results[1].State);
            var finalState = ((ActiveLogState<TpmAttestationState>)results[1].State).Value;
            Assert.AreEqual(2, finalState.QuoteCount, "The log must have accumulated two verified quotes.");
            Assert.IsTrue(finalState.AttestationKey.AsSpan().SequenceEqual(enrolled), "The bound AK must be the enrolled key.");
            Assert.IsTrue(finalState.LatestPcrDigest.AsSpan().SequenceEqual(op1.PcrDigest), "The latest state must reflect the most recent quote's PCR digest.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task QuoteFromUnenrolledKeyIsRejected()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //The enrolled AK (owner hierarchy) and a different, unenrolled key (endorsement hierarchy).
        using CreatePrimaryResponse enrolledAk = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse otherAk = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            try
            {
                using PublicKeyMemory enrolledKey = enrolledAk.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                    P256ComponentSize, CryptoTags.P256PublicKey, pool);
                using PublicKeyMemory otherKey = otherAk.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                    P256ComponentSize, CryptoTags.P256PublicKey, pool);
                byte[] enrolled = enrolledKey.AsReadOnlySpan().ToArray();

                (byte[] canonical0, TpmQuoteOperation op0, Signature signature0) = await QuoteAsync(tpm, registry, pool, enrolledAk.ObjectHandle, GenesisNonce).ConfigureAwait(false);
                (byte[] canonical1, TpmQuoteOperation op1, Signature signature1) = await QuoteAsync(tpm, registry, pool, otherAk.ObjectHandle, SecondNonce).ConfigureAwait(false);

                using Signature sig0 = signature0;
                using Signature sig1 = signature1;

                LogEntry<TpmQuoteOperation, CryptoProof> genesis = BuildEntry(0, previousDigest: null, canonical0, op0, new CryptoProof(sig0, enrolledKey, CryptoAlgorithm.P256));

                //The second quote is cryptographically valid (the other AK signed its own quote), but it was not
                //signed by the enrolled AK, so the domain trust rule must reject it even though the signature checks.
                LogEntry<TpmQuoteOperation, CryptoProof> rogue = BuildEntry(1, previousDigest: genesis.Digest, canonical1, op1, new CryptoProof(sig1, otherKey, CryptoAlgorithm.P256));

                IReadOnlyList<LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof>> results =
                    await ReplayAllAsync([genesis, rogue], enrolled).ConfigureAwait(false);

                Assert.HasCount(2, results, "Both entries must be presented; replay stops after the rejected one.");
                Assert.IsTrue(results[0].IsSuccess, $"Genesis (enrolled AK) must verify; error: '{results[0].Error}'.");
                Assert.IsFalse(results[1].IsSuccess, "A quote from an unenrolled key must be rejected.");
                Assert.IsTrue(
                    results[1].Error is not null && results[1].Error!.Contains("enrolled attestation key", StringComparison.Ordinal),
                    $"The rejection must cite the enrolled-AK rule; got '{results[1].Error}'.");

                //The log state holds at the last good entry: one verified quote from the enrolled AK.
                Assert.IsInstanceOfType<ActiveLogState<TpmAttestationState>>(results[1].State);
                Assert.AreEqual(1, ((ActiveLogState<TpmAttestationState>)results[1].State).Value.QuoteCount);
            }
            finally
            {
                await FlushAsync(tpm, registry, otherAk.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, enrolledAk.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task EnrolledViaActivationThenAttestationLogReplays()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //The endorsement (credential) key and the attestation key.
        using CreatePrimaryResponse ek = await CreateStoragePrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
            try
            {
                //1. ENROLL: prove the AK co-resides with the EK via credential activation. Only a TPM holding both
                //the EK (to decrypt the seed) and the AK (whose Name the credential is bound to) recovers the
                //challenge. The application's decision to trust this AK is gated on this proof.
                bool enrolled = await EnrollByActivationAsync(tpm, registry, pool, ek, ak).ConfigureAwait(false);
                Assert.IsTrue(enrolled, "The AK must pass credential activation against the EK to be enrolled.");

                using PublicKeyMemory akKey = ak.OutPublic.PublicArea.Unique.Ecc!.ToCompressedPublicKeyMemory(
                    P256ComponentSize, CryptoTags.P256PublicKey, pool);
                byte[] enrolledKey = akKey.AsReadOnlySpan().ToArray();

                //2. ATTEST: the now-enrolled AK signs a quote, which replays as the genesis of its attestation log
                //against the trust context whose enrolled key was established by the activation above. (In
                //production the EK is itself trusted via its EK-certificate chain to the manufacturer CA — gap #4a;
                //here the locally created EK stands in, but the AK↔EK binding is genuinely proven.)
                (byte[] canonical, TpmQuoteOperation op, Signature signature) = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle, GenesisNonce).ConfigureAwait(false);
                using Signature sig = signature;

                LogEntry<TpmQuoteOperation, CryptoProof> genesis = BuildEntry(0, previousDigest: null, canonical, op, new CryptoProof(sig, akKey, CryptoAlgorithm.P256));

                IReadOnlyList<LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof>> results =
                    await ReplayAllAsync([genesis], enrolledKey).ConfigureAwait(false);

                Assert.HasCount(1, results, "The genesis entry must be processed.");
                Assert.IsTrue(results[0].IsSuccess, $"The enrolled AK's quote must verify; error: '{results[0].Error}'.");
                Assert.IsInstanceOfType<ActiveLogState<TpmAttestationState>>(results[0].State);

                var state = ((ActiveLogState<TpmAttestationState>)results[0].State).Value;
                Assert.AreEqual(1, state.QuoteCount);
                Assert.IsTrue(state.AttestationKey.AsSpan().SequenceEqual(enrolledKey), "The log must bind the enrolled AK.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Performs credential activation to prove the attestation key co-resides with the endorsement key: wraps a
    /// challenge to the EK bound to the AK's Name, then recovers it through the AK. Returns whether the recovered
    /// secret matches the challenge — the enrollment proof.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ek">The endorsement/credential key.</param>
    /// <param name="ak">The attestation key being enrolled.</param>
    /// <returns><see langword="true"/> when activation recovers the challenge, proving AK↔EK co-residence.</returns>
    private async Task<bool> EnrollByActivationAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, CreatePrimaryResponse ek, CreatePrimaryResponse ak)
    {
        byte[] objectName = ak.Name.Span.ToArray();
        using MakeCredentialInput makeInput = MakeCredentialInput.Create(ek.ObjectHandle, EnrollmentChallenge, objectName, pool);
        TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential failed: '{makeResult.ResponseCode}'.");

        using MakeCredentialResponse made = makeResult.Value;
        using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
            ak.ObjectHandle, ek.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, pool);
        using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
            tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        if(!activateResult.IsSuccess)
        {
            return false;
        }

        using ActivateCredentialResponse activated = activateResult.Value;

        return activated.CertInfo.AsReadOnlySpan().SequenceEqual(EnrollmentChallenge);
    }

    /// <summary>
    /// Creates a restricted-decrypt ECC storage primary (the endorsement/credential key) under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage key ({hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Replays the given attestation-log entries through <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>
    /// with the composed proof validation and returns every result.
    /// </summary>
    /// <param name="entries">The hash-chain–linked log entries.</param>
    /// <param name="enrolledAttestationKey">The compressed public key the application enrolled.</param>
    /// <returns>One result per processed entry.</returns>
    private async Task<IReadOnlyList<LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof>>> ReplayAllAsync(
        IReadOnlyList<LogEntry<TpmQuoteOperation, CryptoProof>> entries,
        byte[] enrolledAttestationKey)
    {
        ValidateProofDelegate<TpmAttestationState, TpmQuoteOperation, CryptoProof, TpmAttestationTrustContext> baseValidate =
            CryptoProofValidation.CreateValidateProof<TpmAttestationState, TpmQuoteOperation, TpmAttestationTrustContext>();

        var context = new LogReplayContext<TpmAttestationState, TpmQuoteOperation, CryptoProof, TpmAttestationTrustContext>
        {
            Classify = OperationClassifiers.ByIndex<TpmQuoteOperation, CryptoProof>(),
            VerifyChainIntegrity = VerifyIntegrity,
            ValidateProof = async (entry, state, trust, cancellationToken) =>
            {
                //Compose: the generic crypto-proof signature check first, then the domain trust rule. The signer
                //must be the enrolled AK at genesis (the seam for EK→AK chain validation) and the bound AK after.
                string? signatureError = await baseValidate(entry, state, trust, cancellationToken).ConfigureAwait(false);
                if(signatureError is not null)
                {
                    return signatureError;
                }

                byte[] signer = entry.Proofs[0].SignerKey.AsReadOnlySpan().ToArray();
                byte[] expected = state is ActiveLogState<TpmAttestationState> active
                    ? active.Value.AttestationKey
                    : trust.EnrolledAttestationKey;

                return signer.AsSpan().SequenceEqual(expected)
                    ? null
                    : "The quote was not signed by the enrolled attestation key.";
            },
            ValidationContext = new TpmAttestationTrustContext(enrolledAttestationKey),
            Apply = LogReplayDefaults.CreateApplyDelegate<TpmAttestationState, TpmQuoteOperation, CryptoProof>(
                genesis: static (_, entry, _) =>
                {
                    TpmQuoteOperation op = entry.Operation!;
                    byte[] ak = entry.Proofs[0].SignerKey.AsReadOnlySpan().ToArray();

                    return ValueTask.FromResult((new ActiveLogState<TpmAttestationState>(new TpmAttestationState(ak, op.PcrDigest, 1)), (string?)null));
                },
                update: static (active, entry, _) =>
                {
                    TpmQuoteOperation op = entry.Operation!;
                    TpmAttestationState next = active.Value with { LatestPcrDigest = op.PcrDigest, QuoteCount = active.Value.QuoteCount + 1 };

                    return ValueTask.FromResult((new ActiveLogState<TpmAttestationState>(next), (string?)null));
                },
                deactivate: static (active, _, _) => ValueTask.FromResult((new DeactivatedLogState<TpmAttestationState>(active.Value), (string?)null))),
            TimeProvider = TimeProvider.System
        };

        var replayer = new LogReplayer<TpmAttestationState, TpmQuoteOperation, CryptoProof, TpmAttestationTrustContext>();
        var results = new List<LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof>>();
        await foreach(LogReplayResult<TpmAttestationState, TpmQuoteOperation, CryptoProof> result in replayer
            .ReplayAsync(AsAsync(entries, TestContext.CancellationToken), context, TestContext.CancellationToken)
            .ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }

    /// <summary>
    /// Verifies an entry's hash-chain position: its digest equals the SHA-256 of its canonical bytes, and it
    /// links to the predecessor the replayer threads forward (no predecessor for the genesis entry).
    /// </summary>
    /// <param name="entry">The entry to verify.</param>
    /// <param name="previousEntryDigest">The predecessor digest threaded by the replayer.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="null"/> when integrity holds; otherwise an error message.</returns>
    private static ValueTask<string?> VerifyIntegrity(
        LogEntry<TpmQuoteOperation, CryptoProof> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        CancellationToken cancellationToken)
    {
        Span<byte> recomputed = stackalloc byte[32];
        SHA256.HashData(entry.CanonicalBytes.Span, recomputed);
        if(!recomputed.SequenceEqual(entry.Digest.Span))
        {
            return ValueTask.FromResult<string?>("The entry digest does not match its canonical bytes.");
        }

        bool linkOk = entry.Index == 0
            ? previousEntryDigest is null && entry.PreviousDigest is null
            : previousEntryDigest is { } previous && entry.PreviousDigest is { } claimed && claimed.Span.SequenceEqual(previous.Span);

        return ValueTask.FromResult<string?>(linkOk ? null : "The entry does not chain to its predecessor.");
    }

    /// <summary>
    /// Builds a quote over the given PCRs and nonce with the given key, returning the raw attestation bytes (the
    /// canonical signed payload), the parsed operation, and the projected neutral signature.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The attestation key handle.</param>
    /// <param name="nonce">The qualifyingData nonce.</param>
    /// <returns>The canonical bytes, the parsed operation, and the projected signature (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Signature transfers to the caller.")]
    private async Task<(byte[] Canonical, TpmQuoteOperation Operation, Signature Signature)> QuoteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject signHandle, byte[] nonce)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(signHandle, nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

        using QuoteResponse quote = quoteResult.Value;
        byte[] canonical = quote.Quoted.GetRawBytes().ToArray();
        TpmsAttest attest = quote.Quoted.AttestationData;
        var operation = new TpmQuoteOperation(
            attest.Attested.Quote!.PcrDigest.AsReadOnlySpan().ToArray(),
            attest.ExtraData.Span.ToArray());

        //ToSignature copies into its own pooled buffer, so the signature outlives the disposed QuoteResponse.
        Signature signature = quote.Signature.ToSignature(P256ComponentSize, CryptoTags.P256Signature, pool);

        return (canonical, operation, signature);
    }

    /// <summary>
    /// Builds a log entry from its canonical bytes, parsed operation, and crypto proof, computing the digest as
    /// the SHA-256 of the canonical bytes.
    /// </summary>
    /// <param name="index">The zero-based entry index.</param>
    /// <param name="previousDigest">The previous entry's digest, or <see langword="null"/> for genesis.</param>
    /// <param name="canonical">The canonical signed bytes.</param>
    /// <param name="operation">The parsed quote operation.</param>
    /// <param name="proof">The crypto proof for the entry.</param>
    /// <returns>The constructed log entry.</returns>
    private static LogEntry<TpmQuoteOperation, CryptoProof> BuildEntry(
        ulong index, ReadOnlyMemory<byte>? previousDigest, byte[] canonical, TpmQuoteOperation operation, CryptoProof proof)
    {
        return new LogEntry<TpmQuoteOperation, CryptoProof>
        {
            Index = index,
            PreviousDigest = previousDigest,
            Digest = SHA256.HashData(canonical),
            CanonicalBytes = canonical,
            Operation = operation,
            Proofs = [proof]
        };
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Wraps a list of entries as an asynchronous sequence for the replayer's stream source.
    /// </summary>
    /// <param name="entries">The entries to yield in order.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>An asynchronous sequence over the entries.</returns>
    private static async IAsyncEnumerable<LogEntry<TpmQuoteOperation, CryptoProof>> AsAsync(
        IReadOnlyList<LogEntry<TpmQuoteOperation, CryptoProof>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach(LogEntry<TpmQuoteOperation, CryptoProof> entry in entries)
        {
            yield return entry;
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }
}
