using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Firewalled end-to-end coverage for a KERI Key Event Log replayed through the production
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>. An independent BouncyCastle Ed25519 minter
/// produces a real <c>icp → ixn → rot</c> log: each event is serialized as KERI JSON, its SAID computed over the
/// serialization, and the serialization signed by the authorizing private keys with no stubbed signatures. The
/// verifier then reconstructs each event from the wire bytes alone (decode the field map, read the typed event)
/// and replays the log through <see cref="KeriKeyEventLog"/>, so the chain, the SAIDs, the controller-signature
/// threshold, and the pre-rotation commitments are all verified by the shipped path. Tampering fails closed.
/// </summary>
[TestClass]
internal sealed class KeriKeyEventLogReplayTests
{
    private static readonly string Code = CesrDigestCodes.Blake3Bits256;

    /// <summary>The version string with a zeroed size, used to measure a serialization before its size is stamped.</summary>
    private const string ProbeVersion = "KERI10JSON000000_";


    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An algorithm-agile digest oracle for the SAID and pre-rotation digests: Blake3 routes to BouncyCastle,
    /// every other request to Microsoft. Constructed in the test, independent of the production registry.
    /// </summary>
    private static readonly ComputeDigestDelegate AgileDigest = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// A minted inception, interaction, and full rotation replay successfully: the final key state is at sequence
    /// two and carries the rotated-in keys.
    /// </summary>
    [TestMethod]
    public async Task ReplaysInceptionInteractionRotation()
    {
        (List<LogEntry<KeriKeyEvent, CryptoProof>> entries, List<IDisposable> disposables) =
            await BuildKelAsync(corruptInceptionSigner: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.HasCount(3, results, "Every event must produce a result.");
            foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in results)
            {
                Assert.IsTrue(result.IsSuccess, $"Every event must replay; error: '{result.Error}'.");
            }

            Assert.IsInstanceOfType<ActiveLogState<KeriKeyState>>(results[^1].State);
            KeriKeyState finalState = ((ActiveLogState<KeriKeyState>)results[^1].State).Value;
            var rotation = (KeriRotationEvent)entries[2].Operation!;

            Assert.AreEqual(2, finalState.SequenceNumber, "The log advances to sequence two.");
            Assert.AreSequenceEqual((System.Collections.ICollection)rotation.SigningKeys, (System.Collections.ICollection)finalState.SigningKeys, "The final keys are the rotated-in keys.");
            Assert.AreEqual(rotation.Said, finalState.LastEventSaid, "The last event SAID is the rotation's.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// An inception signed by a key it does not establish fails closed: the signer is not among the authorizing
    /// keys, so the signing threshold is not met and the log does not advance.
    /// </summary>
    [TestMethod]
    public async Task RejectsInceptionSignedByUnauthorizedKey()
    {
        (List<LogEntry<KeriKeyEvent, CryptoProof>> entries, List<IDisposable> disposables) =
            await BuildKelAsync(corruptInceptionSigner: true, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, TestContext.CancellationToken).ConfigureAwait(false);

            string? error = results[^1].Error;
            Assert.IsFalse(results[^1].IsSuccess, "An inception signed by an unauthorized key must fail.");
            Assert.IsInstanceOfType<EmptyLogState<KeriKeyState>>(results[^1].State, "No state may be established when the genesis signature fails.");
            Assert.IsTrue(error is not null && error.Contains("signing threshold", StringComparison.Ordinal), $"The error must report the unmet threshold; got '{error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A rotation whose prior-event digest does not chain to the verified predecessor fails closed at the
    /// chain-integrity step, after the earlier events verified.
    /// </summary>
    [TestMethod]
    public async Task RejectsBrokenPriorDigestChain()
    {
        (List<LogEntry<KeriKeyEvent, CryptoProof>> entries, List<IDisposable> disposables) =
            await BuildKelAsync(corruptInceptionSigner: false, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            //Re-point the rotation's prior digest at the inception rather than the interaction, breaking the chain.
            LogEntry<KeriKeyEvent, CryptoProof> rotation = entries[2];
            entries[2] = new LogEntry<KeriKeyEvent, CryptoProof>
            {
                Index = rotation.Index,
                PreviousDigest = entries[0].Digest,
                Digest = rotation.Digest,
                CanonicalBytes = rotation.CanonicalBytes,
                Operation = rotation.Operation,
                Proofs = rotation.Proofs
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, TestContext.CancellationToken).ConfigureAwait(false);

            string? error = results[^1].Error;
            Assert.IsTrue(results[0].IsSuccess, "The inception verifies.");
            Assert.IsTrue(results[1].IsSuccess, "The interaction verifies.");
            Assert.IsFalse(results[^1].IsSuccess, "The rotation with a broken prior digest must fail.");
            Assert.IsTrue(error is not null && error.Contains("chain", StringComparison.Ordinal), $"The error must report the broken chain; got '{error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// An inception with a weighted signing threshold (three half-weight keys) replays when two of the three keys
    /// sign — their weights reach one.
    /// </summary>
    [TestMethod]
    public async Task WeightedThresholdReplaysWhenWeightsReachOne()
    {
        await RunWeightedInceptionAsync(signerCount: 2, expectSuccess: true, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The same weighted inception fails when only one of the three half-weight keys signs — its weight is below
    /// one.
    /// </summary>
    [TestMethod]
    public async Task WeightedThresholdFailsWhenWeightsBelowOne()
    {
        await RunWeightedInceptionAsync(signerCount: 1, expectSuccess: false, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A reserve (partial) rotation replays when the exposed pre-rotated keys that sign satisfy the prior next
    /// (rotation) threshold: an inception commits three next keys under next threshold "2", the rotation exposes
    /// two of them — holding the third in reserve — as the new current keys, and both exposed keys sign.
    /// </summary>
    [TestMethod]
    public async Task ReserveRotationReplaysWhenExposedKeysMeetPriorNextThreshold()
    {
        await RunReserveRotationAsync(exposedSignerCount: 2, expectSuccess: true, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The same reserve rotation fails closed when only one of the two exposed pre-rotated keys signs: the
    /// rotation's own current signing threshold ("1" over the two new keys) is met, but the prior next (rotation)
    /// threshold ("2" over the exposed keys) is not, so rotation authority is not established. This isolates the
    /// rotation-authority gate from the signing-authority gate.
    /// </summary>
    [TestMethod]
    public async Task ReserveRotationFailsWhenExposedKeysBelowPriorNextThreshold()
    {
        await RunReserveRotationAsync(exposedSignerCount: 1, expectSuccess: false, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A key event log whose inception lists its signing key under the non-transferable Ed25519 verification-key
    /// code (<c>B</c>) — one of the two distinct CESR codes the verification-key seam maps to Ed25519 — replays
    /// successfully: the signature verifies and is matched to the key by the key's canonical identity (its algorithm
    /// and raw bytes), not by re-encoding the proof key to a single hardcoded code. A verifier that re-qualified the
    /// proof to the transferable code (<c>D</c>) would produce a string that does not equal the <c>B</c>-coded key
    /// the event lists, drop the valid signature, and wrongly reject the log; the same single-code inverse would
    /// silently drop every future non-Ed25519 algorithm the forward seam gains.
    /// </summary>
    [TestMethod]
    public async Task ReplaysInceptionWhoseSigningKeyUsesNonTransferableCode()
    {
        var disposables = new List<IDisposable>();
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signer = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

            //Qualify the current signing key under the non-transferable code B rather than the transferable code D.
            string nonTransferableKey = CesrPrimitiveCodec.EncodeText(CesrVerificationKeyCodes.Ed25519NonTransferable, signer.PublicKey.AsReadOnlyMemory().Span);
            MintedEvent inception = await MintMultiInception([nonTransferableKey], signingThreshold: "1", [await NextKeyDigest(Qualify(next.PublicKey))], nextThreshold: "1");
            disposables.Add(inception.Owner);

            Signature signature = await SignAsync(signer.PrivateKey, inception.Serialization, TestContext.CancellationToken).ConfigureAwait(false);
            disposables.Add(signature);

            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, inception, [new CryptoProof(signature, signer.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(results[^1].IsSuccess, $"An inception signed by its non-transferable-coded key must verify; error: '{results[^1].Error}'.");
            Assert.IsInstanceOfType<ActiveLogState<KeriKeyState>>(results[^1].State, "The inception establishes key state.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A delegated inception, however well-formed and validly signed, fails closed in a single-KEL replay: its
    /// validity additionally requires a delegating seal in the delegator's KEL, which this replay does not have, so
    /// the replayer rejects it rather than accepting it on its own signatures alone.
    /// </summary>
    [TestMethod]
    public async Task RejectsDelegatedEventInSingleKelReplay()
    {
        var disposables = new List<IDisposable>();
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signer = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);
            const string delegatorAid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";

            MintedEvent dip = await MintDelegatedInception(Qualify(signer.PublicKey), await NextKeyDigest(Qualify(next.PublicKey)), delegatorAid);
            disposables.Add(dip.Owner);

            Signature signature = await SignAsync(signer.PrivateKey, dip.Serialization, TestContext.CancellationToken).ConfigureAwait(false);
            disposables.Add(signature);

            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, dip, [new CryptoProof(signature, signer.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, TestContext.CancellationToken).ConfigureAwait(false);

            string? error = results[^1].Error;
            Assert.IsFalse(results[^1].IsSuccess, "A delegated event must fail closed in a single-KEL replay.");
            Assert.IsInstanceOfType<EmptyLogState<KeriKeyState>>(results[^1].State, "No state may be established for an unanchored delegated inception.");
            Assert.IsTrue(error is not null && error.Contains("delegating seal", StringComparison.Ordinal), $"The error must report the missing delegating seal; got '{error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A delegated inception replays successfully when the delegator's KEL anchors a delegating seal of it: the
    /// delegator's interaction event seals the dip's key event seal, the verifier collects the delegator's anchored
    /// seals from that verified KEL into a resolver, and the delegatee's dip then verifies — its SAID, its own
    /// signature, and the cross-log delegation seal all check out — and folds to state bound to the delegator. The
    /// same dip with a resolver that anchors nothing fails closed, isolating the delegation gate.
    /// </summary>
    [TestMethod]
    public async Task DelegatedInceptionReplaysWhenAnchoredInDelegatorKel()
    {
        var disposables = new List<IDisposable>();
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegatorCurrent = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegatorNext = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegateeCurrent = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegateeNext = Fresh(disposables);

            MintedEvent delegatorIcp = await MintInception(Qualify(delegatorCurrent.PublicKey), await NextKeyDigest(Qualify(delegatorNext.PublicKey)));
            disposables.Add(delegatorIcp.Owner);
            string delegatorAid = delegatorIcp.Said;

            MintedEvent dip = await MintDelegatedInception(Qualify(delegateeCurrent.PublicKey), await NextKeyDigest(Qualify(delegateeNext.PublicKey)), delegatorAid);
            disposables.Add(dip.Owner);
            string delegateeAid = dip.Said;

            //The delegator anchors the delegated inception with a key event seal [i, s, d] of the dip.
            string sealJson = $$"""{"i":"{{delegateeAid}}","s":"0","d":"{{dip.Said}}"}""";
            MintedEvent delegatorIxn = await MintAnchoringInteraction(delegatorAid, delegatorIcp.Said, sealJson);
            disposables.Add(delegatorIxn.Owner);

            Signature delegatorIcpSignature = await SignAsync(delegatorCurrent.PrivateKey, delegatorIcp.Serialization, TestContext.CancellationToken).ConfigureAwait(false);
            Signature delegatorIxnSignature = await SignAsync(delegatorCurrent.PrivateKey, delegatorIxn.Serialization, TestContext.CancellationToken).ConfigureAwait(false);
            Signature dipSignature = await SignAsync(delegateeCurrent.PrivateKey, dip.Serialization, TestContext.CancellationToken).ConfigureAwait(false);
            disposables.Add(delegatorIcpSignature);
            disposables.Add(delegatorIxnSignature);
            disposables.Add(dipSignature);

            //Replay and verify the delegator's KEL first.
            var delegatorEntries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, delegatorIcp, [new CryptoProof(delegatorIcpSignature, delegatorCurrent.PublicKey, CryptoAlgorithm.Ed25519)], disposables),
                Entry(1, delegatorIcp.Said, delegatorIxn, [new CryptoProof(delegatorIxnSignature, delegatorCurrent.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> delegatorResults =
                await ReplayAsync(delegatorEntries, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(delegatorResults[^1].IsSuccess, $"The delegator KEL must verify; error: '{delegatorResults[^1].Error}'.");

            //Collect the delegator's anchored seals from its verified interaction and resolve the dip's seal from them.
            IReadOnlyList<KeriSeal> anchors = KeriSealReader.ReadList(KeriEventJson.DecodeFieldMap(delegatorIxn.Serialization)[KeriMessageFields.Anchors]);
            DelegationSealResolver resolver = delegatedEvent => KeriDelegation.FindDelegationSeal(anchors, delegatedEvent);

            var delegateeEntries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, dip, [new CryptoProof(dipSignature, delegateeCurrent.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> anchored =
                await ReplayAsync(delegateeEntries, TestContext.CancellationToken, resolver).ConfigureAwait(false);
            Assert.IsTrue(anchored[^1].IsSuccess, $"The anchored delegated inception must verify; error: '{anchored[^1].Error}'.");
            Assert.IsInstanceOfType<ActiveLogState<KeriKeyState>>(anchored[^1].State);
            Assert.AreEqual(delegatorAid, ((ActiveLogState<KeriKeyState>)anchored[^1].State).Value.DelegatorPrefix, "The delegated key state is bound to its delegator.");

            //With a resolver that anchors nothing, the same delegated inception fails closed.
            DelegationSealResolver emptyResolver = _ => null;
            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> unanchored =
                await ReplayAsync(delegateeEntries, TestContext.CancellationToken, emptyResolver).ConfigureAwait(false);
            Assert.IsFalse(unanchored[^1].IsSuccess, "An unanchored delegated inception fails closed.");
            Assert.IsTrue(unanchored[^1].Error is { } error && error.Contains("not anchored", StringComparison.Ordinal), $"The error must report the missing anchor; got '{unanchored[^1].Error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    //Mints icp -> rot where the inception commits three next keys [H(A1),H(A2),H(A3)] under next threshold "2",
    //and the partial rotation exposes two of them ([A1,A2], holding A3 in reserve) as the new current keys under
    //signing threshold "1". The inception is signed by A0; the rotation is signed by the first exposedSignerCount
    //of the two exposed keys. With both signing, the prior next threshold "2" is met (rotation authority); with
    //one, only the rotation's own "1" current threshold is met, which isolates the rotation-authority gate.
    private static async Task RunReserveRotationAsync(int exposedSignerCount, bool expectSuccess, CancellationToken cancellationToken)
    {
        var disposables = new List<IDisposable>();
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> a0 = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> a1 = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> a2 = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> a3 = Fresh(disposables);
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> a4 = Fresh(disposables);

            string[] nextDigests = [await NextKeyDigest(Qualify(a1.PublicKey)), await NextKeyDigest(Qualify(a2.PublicKey)), await NextKeyDigest(Qualify(a3.PublicKey))];
            MintedEvent inception = await MintMultiInception([Qualify(a0.PublicKey)], signingThreshold: "1", nextDigests, nextThreshold: "2");
            disposables.Add(inception.Owner);
            string aid = inception.Said;

            string[] revealed = [Qualify(a1.PublicKey), Qualify(a2.PublicKey)];
            MintedEvent rotation = await MintMultiRotation(aid, inception.Said, revealed, signingThreshold: "1", [await NextKeyDigest(Qualify(a4.PublicKey))], nextThreshold: "1");
            disposables.Add(rotation.Owner);

            Signature inceptionSignature = await SignAsync(a0.PrivateKey, inception.Serialization, cancellationToken).ConfigureAwait(false);
            disposables.Add(inceptionSignature);

            PrivateKeyMemory[] exposedPrivate = [a1.PrivateKey, a2.PrivateKey];
            PublicKeyMemory[] exposedPublic = [a1.PublicKey, a2.PublicKey];
            var rotationProofs = new List<CryptoProof>();
            for(int i = 0; i < exposedSignerCount; i++)
            {
                Signature signature = await SignAsync(exposedPrivate[i], rotation.Serialization, cancellationToken).ConfigureAwait(false);
                disposables.Add(signature);
                rotationProofs.Add(new CryptoProof(signature, exposedPublic[i], CryptoAlgorithm.Ed25519));
            }

            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, inception, [new CryptoProof(inceptionSignature, a0.PublicKey, CryptoAlgorithm.Ed25519)], disposables),
                Entry(1, inception.Said, rotation, [.. rotationProofs], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, cancellationToken).ConfigureAwait(false);

            Assert.IsTrue(results[0].IsSuccess, $"The inception must verify; error: '{results[0].Error}'.");
            Assert.AreEqual(expectSuccess, results[^1].IsSuccess, $"Reserve rotation with {exposedSignerCount} of 2 exposed signers; error: '{results[^1].Error}'.");
            if(!expectSuccess)
            {
                string? error = results[^1].Error;
                Assert.IsTrue(error is not null && error.Contains("rotation", StringComparison.Ordinal), $"The failure must report the unmet rotation threshold; got '{error}'.");
            }
        }
        finally
        {
            Dispose(disposables);
        }
    }


    //Mints a single inception with three keys under a weighted threshold ["1/2","1/2","1/2"], signs it with the
    //first signerCount keys, and replays the one-entry log through the shipped path, asserting the outcome.
    private static async Task RunWeightedInceptionAsync(int signerCount, bool expectSuccess, CancellationToken cancellationToken)
    {
        var disposables = new List<IDisposable>();
        try
        {
            var keys = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>[3];
            for(int i = 0; i < keys.Length; i++)
            {
                keys[i] = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
                disposables.Add(keys[i].PublicKey);
                disposables.Add(keys[i].PrivateKey);
            }

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> nextMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
            disposables.Add(nextMaterial.PublicKey);
            disposables.Add(nextMaterial.PrivateKey);

            string[] currentKeys = [Qualify(keys[0].PublicKey), Qualify(keys[1].PublicKey), Qualify(keys[2].PublicKey)];
            string nextKeyDigest = await NextKeyDigest(Qualify(nextMaterial.PublicKey));

            MintedEvent inception = await MintWeightedInception(currentKeys, nextKeyDigest);
            disposables.Add(inception.Owner);

            var proofs = new List<CryptoProof>();
            for(int i = 0; i < signerCount; i++)
            {
                Signature signature = await SignAsync(keys[i].PrivateKey, inception.Serialization, cancellationToken).ConfigureAwait(false);
                disposables.Add(signature);
                proofs.Add(new CryptoProof(signature, keys[i].PublicKey, CryptoAlgorithm.Ed25519));
            }

            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
            {
                Entry(0, priorSaid: null, inception, [.. proofs], disposables)
            };

            List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results =
                await ReplayAsync(entries, cancellationToken).ConfigureAwait(false);

            Assert.AreEqual(expectSuccess, results[^1].IsSuccess, $"Weighted threshold with {signerCount} of 3 signers; error: '{results[^1].Error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    private static async Task<MintedEvent> MintWeightedInception(string[] currentKeys, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string keysJson = string.Join(",", Array.ConvertAll(currentKeys, key => $"\"{key}\""));
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":["1/2","1/2","1/2"],"k":[{{keysJson}}],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    //Creates a fresh Ed25519 key pair and tracks both halves for disposal.
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Fresh(List<IDisposable> disposables)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        disposables.Add(material.PublicKey);
        disposables.Add(material.PrivateKey);

        return material;
    }


    //Mints an inception with arbitrary current key and next-digest lists and their (unweighted) thresholds.
    private static async Task<MintedEvent> MintMultiInception(string[] currentKeys, string signingThreshold, string[] nextDigests, string nextThreshold)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string keysJson = JsonStringArray(currentKeys);
        string nextJson = JsonStringArray(nextDigests);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"{{signingThreshold}}","k":[{{keysJson}}],"nt":"{{nextThreshold}}","n":[{{nextJson}}],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    //Mints a rotation with arbitrary revealed key and next-digest lists and their (unweighted) thresholds.
    private static async Task<MintedEvent> MintMultiRotation(string identifier, string priorSaid, string[] revealedKeys, string signingThreshold, string[] nextDigests, string nextThreshold)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string keysJson = JsonStringArray(revealedKeys);
        string nextJson = JsonStringArray(nextDigests);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"rot","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","kt":"{{signingThreshold}}","k":[{{keysJson}}],"nt":"{{nextThreshold}}","n":[{{nextJson}}],"bt":"0","br":[],"ba":[],"c":[],"a":[]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    //Renders a list of strings as the body of a JSON string array (without the surrounding brackets).
    private static string JsonStringArray(string[] values)
    {
        return string.Join(",", Array.ConvertAll(values, value => $"\"{value}\""));
    }


    //Mints a self-addressing delegated inception (dip) naming a fixed delegator AID in its 'di' field.
    private static async Task<MintedEvent> MintDelegatedInception(string currentKey, string nextKeyDigest, string delegatorAid)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"dip","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[],"di":"{{delegatorAid}}"}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    //Mints a sequence-one interaction whose anchor list carries a single seal (the seal's JSON object body).
    private static async Task<MintedEvent> MintAnchoringInteraction(string identifier, string priorSaid, string sealJson)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"ixn","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","a":[{{sealJson}}]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    //Mints a real icp -> ixn -> rot KEL with three independent Ed25519 key pairs: the inception establishes the
    //first key and commits to the second, the interaction seals nothing under the first key, and the full
    //rotation reveals the committed second key and commits to the third. When corruptInceptionSigner is set, the
    //inception is signed by the second (unestablished) key to drive the fail-closed path.
    private static async Task<(List<LogEntry<KeriKeyEvent, CryptoProof>> Entries, List<IDisposable> Disposables)> BuildKelAsync(
        bool corruptInceptionSigner,
        CancellationToken cancellationToken)
    {
        var disposables = new List<IDisposable>();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> first = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> second = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> third = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        disposables.Add(first.PublicKey);
        disposables.Add(first.PrivateKey);
        disposables.Add(second.PublicKey);
        disposables.Add(second.PrivateKey);
        disposables.Add(third.PublicKey);
        disposables.Add(third.PrivateKey);

        string currentKey = Qualify(first.PublicKey);
        string nextKey = Qualify(second.PublicKey);
        string nextNextKey = Qualify(third.PublicKey);
        string nextKeyDigest = await NextKeyDigest(nextKey);
        string nextNextKeyDigest = await NextKeyDigest(nextNextKey);

        MintedEvent inception = await MintInception(currentKey, nextKeyDigest);
        string aid = inception.Said;
        MintedEvent interaction = await MintInteraction(aid, inception.Said);
        MintedEvent rotation = await MintRotation(aid, interaction.Said, nextKey, nextNextKeyDigest);
        disposables.Add(inception.Owner);
        disposables.Add(interaction.Owner);
        disposables.Add(rotation.Owner);

        PrivateKeyMemory inceptionSigner = corruptInceptionSigner ? second.PrivateKey : first.PrivateKey;
        PublicKeyMemory inceptionSignerPublic = corruptInceptionSigner ? second.PublicKey : first.PublicKey;

        Signature inceptionSignature = await SignAsync(inceptionSigner, inception.Serialization, cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(first.PrivateKey, interaction.Serialization, cancellationToken).ConfigureAwait(false);
        Signature rotationSignature = await SignAsync(second.PrivateKey, rotation.Serialization, cancellationToken).ConfigureAwait(false);
        disposables.Add(inceptionSignature);
        disposables.Add(interactionSignature);
        disposables.Add(rotationSignature);

        var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
        {
            Entry(0, priorSaid: null, inception, [new CryptoProof(inceptionSignature, inceptionSignerPublic, CryptoAlgorithm.Ed25519)], disposables),
            Entry(1, inception.Said, interaction, [new CryptoProof(interactionSignature, first.PublicKey, CryptoAlgorithm.Ed25519)], disposables),
            Entry(2, interaction.Said, rotation, [new CryptoProof(rotationSignature, second.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
        };

        return (entries, disposables);
    }


    private static async Task<List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>> ReplayAsync(
        List<LogEntry<KeriKeyEvent, CryptoProof>> entries,
        CancellationToken cancellationToken,
        DelegationSealResolver? resolveDelegationSeal = null)
    {
        LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> context =
            KeriKeyEventLog.CreateReplayContext(AgileDigest, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal);

        var replayer = new LogReplayer<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>();
        var results = new List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>();
        await foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in
            replayer.ReplayAsync(ToAsync(entries, cancellationToken), context, cancellationToken).ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }


    private static async Task<Signature> SignAsync(PrivateKeyMemory privateKey, ReadOnlyMemory<byte> serialization, CancellationToken cancellationToken)
    {
        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Ed25519, Purpose.Signing);

        (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), serialization, BaseMemoryPool.Shared, context: null, cancellationToken: cancellationToken).ConfigureAwait(false);

        return signature;
    }


    private static LogEntry<KeriKeyEvent, CryptoProof> Entry(ulong index, string? priorSaid, MintedEvent minted, ImmutableArray<CryptoProof> proofs, List<IDisposable> disposables) => new()
    {
        Index = index,
        PreviousDigest = priorSaid is null ? null : (ReadOnlyMemory<byte>?)Utf8(priorSaid, disposables),
        Digest = Utf8(minted.Said, disposables),
        CanonicalBytes = minted.Serialization,
        Operation = KeriEventReader.Read(KeriEventJson.DecodeFieldMap(minted.Serialization)),
        Proofs = proofs
    };


    private static string Qualify(PublicKeyMemory publicKey)
    {
        return CesrPrimitiveCodec.EncodeText("D", publicKey.AsReadOnlyMemory().Span);
    }


    //The pre-rotation commitment is the qualified digest of the qualified next key's UTF-8 bytes; the digest input
    //is rented from the pool rather than held as a naked array.
    private static async Task<string> NextKeyDigest(string qualifiedKey)
    {
        return await SaidOf(qualifiedKey).ConfigureAwait(false);
    }


    //Rents a pooled buffer for a text's UTF-8 bytes, tracks the owner for disposal, and returns a view over it -
    //the digest and prior-digest buffers a verifier reads during replay, owned and disposed like every other.
    private static ReadOnlyMemory<byte> Utf8(string text, List<IDisposable> disposables)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(text, owner.Memory.Span);
        disposables.Add(owner);

        return owner.Memory[..length];
    }


    //Computes a SAID over a serialization's bytes, renting a transient pooled buffer for the digest input.
    private static async Task<string> SaidOf(string serialization)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return await CesrSaid.ComputeAsync(owner.Memory[..length], Code, AgileDigest, BaseMemoryPool.Shared).ConfigureAwait(false);
    }


    private static async Task<MintedEvent> MintInception(string currentKey, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    private static async Task<MintedEvent> MintInteraction(string identifier, string priorSaid)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"ixn","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","a":[]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    private static async Task<MintedEvent> MintRotation(string identifier, string priorSaid, string revealedKey, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"rot","d":"{{said}}","i":"{{identifier}}","s":"2","p":"{{priorSaid}}","kt":"1","k":["{{revealedKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","br":[],"ba":[],"c":[],"a":[]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    //Mints a self-addressing event (an inception, where the identifier equals the SAID): both the SAID field and
    //the identifier are placeholdered, the SAID computed over the sized serialization, then substituted into both.
    private static async Task<MintedEvent> MintSelfAddressing(Func<string, string, string, string> build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder, placeholder));
        string dummied = build(version, placeholder, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    //Mints an event whose identifier is already fixed (an interaction or rotation): only the SAID field is
    //placeholdered, the SAID computed over the sized serialization, then substituted back.
    private static async Task<MintedEvent> MintWithFixedIdentifier(Func<string, string, string> build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder));
        string dummied = build(version, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    //Rents a pooled buffer for the final serialization a verifier replays over, owned by the returned carrier and
    //disposed by the caller once replay is complete.
    private static MintedEvent Rent(string serialization, string said)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return new MintedEvent(owner, length, said);
    }


    //The version-1 KERI JSON version string stamps the serialization's total byte length as six hex characters;
    //the size digits do not change the string's length, so a probe with zeroed digits measures the same length.
    private static string VersionFor(string probe)
    {
        return $"KERI10JSON{Encoding.UTF8.GetByteCount(probe):x6}_";
    }


    private static async IAsyncEnumerable<LogEntry<KeriKeyEvent, CryptoProof>> ToAsync(
        List<LogEntry<KeriKeyEvent, CryptoProof>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<KeriKeyEvent, CryptoProof> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }


    private static void Dispose(List<IDisposable> disposables)
    {
        foreach(IDisposable disposable in disposables)
        {
            disposable.Dispose();
        }
    }


    /// <summary>
    /// A minted event's serialization, carried in a pooled buffer the caller owns and disposes, with its SAID. The
    /// serialization is a verifier-facing input the replayer reads over the lifetime of the replay, so it is held
    /// in an <see cref="IMemoryOwner{T}"/> rather than a naked array.
    /// </summary>
    private sealed record MintedEvent(IMemoryOwner<byte> Owner, int Length, string Said)
    {
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];
    }
}
