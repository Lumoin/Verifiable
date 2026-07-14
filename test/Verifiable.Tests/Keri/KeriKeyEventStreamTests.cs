using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Firewalled end-to-end coverage for <see cref="KeriKeyEventStream.ReplayAsync"/> — verifying a KERI Key Event
/// Log served as a <c>keri.cesr</c> CESR stream (the did:webs artifact). An independent BouncyCastle Ed25519
/// minter produces a real <c>icp → ixn → rot</c> log; each event is serialized as KERI JSON, its SAID computed
/// over the serialization, and the serialization signed by the authorizing private key with no stubbed signatures.
/// The events and their controller signatures are then framed into a real CESR stream — an interleaved JSON event
/// followed by a <c>-K</c> indexed-signature group, per event — and the verifier reconstructs everything from the
/// stream bytes alone: it resolves each signature's public key from the event's own key list on the wire, so no
/// in-memory key object crosses the firewall. Tampering with a signature fails closed.
/// </summary>
[TestClass]
internal sealed class KeriKeyEventStreamTests
{
    /// <summary>The SAID derivation code the minter uses (Blake3-256).</summary>
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

    /// <summary>Decodes a KERI event's JSON bytes into a neutral field map — the per-serialization seam the stream replay is parameterized by.</summary>
    private static readonly KeriEventFieldMapDecoder JsonDecoder = (serialization, serializationKind) => KeriEventJson.DecodeFieldMap(serialization);


    /// <summary>
    /// A minted inception, interaction, and rotation, framed into a real keri.cesr stream and replayed through the
    /// shipped verifier: every event verifies from the wire bytes alone, and the final key state is at sequence
    /// two carrying the rotated-in keys.
    /// </summary>
    [TestMethod]
    public async Task ReplaysStreamedInceptionInteractionRotation()
    {
        var disposables = new List<IDisposable>();
        try
        {
            List<SignedEvent> events = await BuildSignedKelAsync(tamperInceptionSignature: false, disposables, TestContext.CancellationToken).ConfigureAwait(false);
            SignedEvent rotation = events[^1];

            KeriKeyEventStreamReplayResult result = await ReplayStreamAsync(events, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsVerified, $"Every streamed event must verify; error: '{result.Error}'.");
            Assert.AreEqual(3, result.EventCount, "The stream carries three events.");
            Assert.IsNotNull(result.KeyState, "A verified log yields a key state.");
            Assert.AreEqual(2, result.KeyState!.SequenceNumber, "The log advances to sequence two.");
            Assert.AreEqual(rotation.Said, result.KeyState.LastEventSaid, "The last event SAID is the rotation's.");
            CollectionAssert.AreEqual(
                (System.Collections.ICollection)rotation.SigningKeys,
                (System.Collections.ICollection)result.KeyState.SigningKeys,
                "The final keys are the rotation's revealed keys.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A streamed log whose inception signature has been tampered with fails closed: the reconstructed proof does
    /// not verify against the key the event's own key list names, so the genesis signing threshold is not met and
    /// the log is rejected rather than accepted on a forged signature.
    /// </summary>
    [TestMethod]
    public async Task RejectsStreamWithTamperedInceptionSignature()
    {
        var disposables = new List<IDisposable>();
        try
        {
            List<SignedEvent> events = await BuildSignedKelAsync(tamperInceptionSignature: true, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            KeriKeyEventStreamReplayResult result = await ReplayStreamAsync(events, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsVerified, "A tampered inception signature must fail closed.");
            Assert.IsNull(result.KeyState, "A rejected log yields no key state.");
            Assert.IsTrue(
                result.Error is not null && result.Error.Contains("signing threshold", StringComparison.Ordinal),
                $"The failure must report the unmet threshold; got '{result.Error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A streamed inception whose identifier (field <c>i</c>) is a victim's AID rather than its own SAID (field
    /// <c>d</c>) is rejected. A self-addressing AID is the SAID of its own inception, so <c>i == d</c>; an attacker
    /// who sets <c>i</c> to a victim's AID and recomputes <c>d</c> over a body carrying that identifier and the
    /// attacker's own keys produces an inception whose SAID still verifies — the reset touches only the SAID's own
    /// value, leaving the differing identifier in place. Without the binding the replay would return a verified key
    /// state whose prefix is the victim's AID controlled by the attacker's keys: a KEL forgery / AID substitution
    /// served as a <c>keri.cesr</c> to a did:webs resolver. It must fail closed.
    /// </summary>
    [TestMethod]
    public async Task RejectsStreamWhoseInceptionIdentifierIsNotItsSaid()
    {
        var disposables = new List<IDisposable>();
        try
        {
            //A real, well-formed AID the attacker wants to hijack: the SAID of a legitimate inception.
            string victimAid = await MintVictimAidAsync(disposables).ConfigureAwait(false);
            List<SignedEvent> forged = await BuildForgedInceptionAsync(victimAid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            KeriKeyEventStreamReplayResult result = await ReplayStreamAsync(forged, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsVerified, "An inception whose identifier is not its own SAID is an AID substitution and must fail closed.");
            Assert.IsNull(result.KeyState, "A rejected forged inception yields no key state.");
            Assert.IsTrue(
                result.Error is not null && result.Error.Contains("self-addressing", StringComparison.Ordinal),
                $"The failure must report the identifier/SAID binding; got '{result.Error}'.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A streamed inception carrying a malformed signing threshold (<c>kt</c> of <c>"0"</c>, which requires no
    /// signature and so is not a well-formed KERI threshold) is reported fail-closed as an unverified result, not
    /// thrown: a caller verifying an untrusted <c>keri.cesr</c> must not be made to crash on a crafted event it did
    /// not guard against. The verifier rejects the stream and returns the reason.
    /// </summary>
    [TestMethod]
    public async Task RejectsStreamWithMalformedThresholdWithoutThrowing()
    {
        var disposables = new List<IDisposable>();
        try
        {
            List<SignedEvent> events = await BuildMalformedThresholdInceptionAsync(disposables, TestContext.CancellationToken).ConfigureAwait(false);

            KeriKeyEventStreamReplayResult result = await ReplayStreamAsync(events, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsVerified, "A malformed-threshold event must fail closed.");
            Assert.IsNull(result.KeyState, "A rejected stream yields no key state.");
            Assert.IsNotNull(result.Error, "The rejection must carry a reason rather than surface as a thrown exception.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Mints a legitimate inception and returns its SAID — a real self-addressing AID (<c>i == d</c>) that stands
    /// in for the victim whose key event log a forged inception attempts to substitute.
    /// </summary>
    /// <param name="disposables">The list minted buffers and key material are tracked on for disposal.</param>
    /// <returns>The victim's AID.</returns>
    private static async Task<string> MintVictimAidAsync(List<IDisposable> disposables)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        MintedEvent victim = await MintInception(Qualify(current.PublicKey), await NextKeyDigest(Qualify(next.PublicKey)).ConfigureAwait(false)).ConfigureAwait(false);
        disposables.Add(victim.Owner);

        return victim.Said;
    }


    /// <summary>
    /// Mints a forged single-event log: an inception whose identifier is fixed to <paramref name="victimAid"/>
    /// while only its SAID field is dummied, so the recomputed SAID is taken over a body carrying <c>i = victim</c>
    /// and the attacker's own signing key — an inception with <c>i != d</c>, signed by the attacker at index zero.
    /// </summary>
    /// <param name="victimAid">The victim AID the forged inception claims as its identifier.</param>
    /// <param name="disposables">The list minted buffers and key material are tracked on for disposal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The forged, signed inception as a single-element log.</returns>
    private static async Task<List<SignedEvent>> BuildForgedInceptionAsync(string victimAid, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attacker = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerNext = Fresh(disposables);
        string attackerKey = Qualify(attacker.PublicKey);
        string nextKeyDigest = await NextKeyDigest(Qualify(attackerNext.PublicKey)).ConfigureAwait(false);

        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{victimAid}}","s":"0","kt":"1","k":["{{attackerKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        MintedEvent forged = await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
        disposables.Add(forged.Owner);

        Signature signature = await SignAsync(attacker.PrivateKey, forged.Serialization, cancellationToken).ConfigureAwait(false);
        disposables.Add(signature);

        return [SignEvent(forged, signature, [attackerKey], tamper: false, disposables)];
    }


    /// <summary>
    /// Mints a single-event log whose inception carries a signing threshold of <c>"0"</c> — a threshold no
    /// signature is required to satisfy, which is not a well-formed KERI threshold, so reading the event rejects it.
    /// The event is otherwise well-formed and validly signed, so the malformation is reached only when the verifier
    /// reads the threshold, exercising the fail-closed-rather-than-throw path.
    /// </summary>
    /// <param name="disposables">The list minted buffers and key material are tracked on for disposal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The malformed, signed inception as a single-element log.</returns>
    private static async Task<List<SignedEvent>> BuildMalformedThresholdInceptionAsync(List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signer = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);
        string signerKey = Qualify(signer.PublicKey);
        string nextKeyDigest = await NextKeyDigest(Qualify(next.PublicKey)).ConfigureAwait(false);

        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"0","k":["{{signerKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        MintedEvent inception = await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
        disposables.Add(inception.Owner);

        Signature signature = await SignAsync(signer.PrivateKey, inception.Serialization, cancellationToken).ConfigureAwait(false);
        disposables.Add(signature);

        return [SignEvent(inception, signature, [signerKey], tamper: false, disposables)];
    }


    /// <summary>
    /// Mints a real icp -> ixn -> rot KEL with three Ed25519 key pairs and signs each event with its authorizing
    /// key: the inception establishes the first key and commits to the second, the interaction is signed by the
    /// first key, and the rotation reveals the second key and commits to the third and is signed by the second
    /// key. When <paramref name="tamperInceptionSignature"/> is set, one bit of the inception's signature is
    /// flipped, so the reconstructed proof does not verify.
    /// </summary>
    /// <param name="tamperInceptionSignature">Whether to flip a bit of the inception signature.</param>
    /// <param name="disposables">The list minted buffers and key material are tracked on for disposal.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The signed events in log order.</returns>
    private static async Task<List<SignedEvent>> BuildSignedKelAsync(bool tamperInceptionSignature, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> first = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> second = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> third = Fresh(disposables);

        string firstKey = Qualify(first.PublicKey);
        string secondKey = Qualify(second.PublicKey);
        string thirdKey = Qualify(third.PublicKey);

        MintedEvent inception = await MintInception(firstKey, await NextKeyDigest(secondKey).ConfigureAwait(false)).ConfigureAwait(false);
        string aid = inception.Said;
        MintedEvent interaction = await MintInteraction(aid, inception.Said).ConfigureAwait(false);
        MintedEvent rotation = await MintRotation(aid, interaction.Said, secondKey, await NextKeyDigest(thirdKey).ConfigureAwait(false)).ConfigureAwait(false);
        disposables.Add(inception.Owner);
        disposables.Add(interaction.Owner);
        disposables.Add(rotation.Owner);

        Signature inceptionSignature = await SignAsync(first.PrivateKey, inception.Serialization, cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(first.PrivateKey, interaction.Serialization, cancellationToken).ConfigureAwait(false);
        Signature rotationSignature = await SignAsync(second.PrivateKey, rotation.Serialization, cancellationToken).ConfigureAwait(false);
        disposables.Add(inceptionSignature);
        disposables.Add(interactionSignature);
        disposables.Add(rotationSignature);

        return
        [
            SignEvent(inception, inceptionSignature, [firstKey], tamperInceptionSignature, disposables),
            SignEvent(interaction, interactionSignature, [firstKey], tamper: false, disposables),
            SignEvent(rotation, rotationSignature, [secondKey], tamper: false, disposables)
        ];
    }


    /// <summary>
    /// Builds a <see cref="SignedEvent"/> carrying the event's controller signature. The valid case reuses the
    /// signature carrier directly; the tampered case flips one bit in a pooled scratch buffer the pool clears on
    /// return, then wraps the result in its own tracked <see cref="Signature"/> carrier — never a naked array.
    /// </summary>
    /// <param name="minted">The minted event.</param>
    /// <param name="signature">The event's controller signature.</param>
    /// <param name="signingKeys">The qualified keys the event's signature indexes into.</param>
    /// <param name="tamper">Whether to flip one bit of the signature.</param>
    /// <param name="disposables">The list a tampered signature carrier is tracked on for disposal.</param>
    /// <returns>The signed event.</returns>
    private static SignedEvent SignEvent(MintedEvent minted, Signature signature, IReadOnlyList<string> signingKeys, bool tamper, List<IDisposable> disposables)
    {
        if(!tamper)
        {
            return new SignedEvent(minted.Serialization, signature, minted.Said, signingKeys);
        }

        ReadOnlyMemory<byte> original = signature.AsReadOnlyMemory();
        using IMemoryOwner<byte> scratch = BaseMemoryPool.Shared.Rent(original.Length);
        original.Span.CopyTo(scratch.Memory.Span);
        scratch.Memory.Span[0] ^= 0x01;
        ReadOnlySpan<byte> tamperedBytes = scratch.Memory.Span[..original.Length];
        Signature tampered = tamperedBytes.ToSignature(CryptoTags.Ed25519Signature, BaseMemoryPool.Shared);
        disposables.Add(tampered);

        return new SignedEvent(minted.Serialization, tampered, minted.Said, signingKeys);
    }


    /// <summary>
    /// Frames the signed events into a text-domain keri.cesr stream — a genus/version code then, per event, the
    /// JSON serialization followed by a <c>-K</c> controller-signature group carrying the single index-0
    /// signature — and replays it through <see cref="KeriKeyEventStream.ReplayAsync"/>.
    /// </summary>
    /// <param name="events">The signed events in log order.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The replay outcome.</returns>
    private static async Task<KeriKeyEventStreamReplayResult> ReplayStreamAsync(IReadOnlyList<SignedEvent> events, CancellationToken cancellationToken)
    {
        var pipe = new Pipe();
        CesrStreamWriter.WriteTextGenusVersion(pipe.Writer, KeriGenus.GenusCode, 2, 0);
        foreach(SignedEvent signed in events)
        {
            WriteEventFrame(pipe.Writer, signed);
        }

        await pipe.Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await pipe.Writer.CompleteAsync().ConfigureAwait(false);

        KeriKeyEventStreamReplayResult result = await KeriKeyEventStream.ReplayAsync(
            pipe.Reader, JsonDecoder, AgileDigest, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: cancellationToken).ConfigureAwait(false);

        await pipe.Reader.CompleteAsync().ConfigureAwait(false);

        return result;
    }


    /// <summary>
    /// Writes one event's frame into the stream: the JSON serialization followed by a <c>-K</c> controller-signature
    /// group carrying the single index-0 signature encoded from the event's signature carrier. The transient
    /// text-group buffer is rented from the pool (which clears it on return) rather than a naked allocation.
    /// </summary>
    /// <param name="writer">The pipe writer the frame is written into.</param>
    /// <param name="signed">The signed event to frame.</param>
    private static void WriteEventFrame(PipeWriter writer, SignedEvent signed)
    {
        writer.Write(signed.Serialization.Span);

        string indexedSignature = CesrIndexedSignatureCodec.EncodeText(WellKnownCesrSignatureCodes.Ed25519, signed.Signature.AsReadOnlyMemory().Span, index: 0);
        int byteCount = Encoding.ASCII.GetByteCount(indexedSignature);
        using IMemoryOwner<byte> groupBody = BaseMemoryPool.Shared.Rent(byteCount);
        Encoding.ASCII.GetBytes(indexedSignature, groupBody.Memory.Span);
        CesrStreamWriter.WriteTextGroup(writer, WellKnownKeriCountCodes.ControllerSignatureGroup, groupBody.Memory.Span[..byteCount]);
    }


    /// <summary>Creates a fresh Ed25519 key pair and tracks both halves for disposal.</summary>
    /// <param name="disposables">The list the key material is tracked on for disposal.</param>
    /// <returns>The fresh key material.</returns>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Fresh(List<IDisposable> disposables)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        disposables.Add(material.PublicKey);
        disposables.Add(material.PrivateKey);

        return material;
    }


    /// <summary>Qualifies an Ed25519 public key into its CESR verification-key text primitive (code <c>D</c>).</summary>
    /// <param name="publicKey">The public key.</param>
    /// <returns>The qualified key.</returns>
    private static string Qualify(PublicKeyMemory publicKey)
    {
        return CesrPrimitiveCodec.EncodeText(CesrVerificationKeyCodes.Ed25519, publicKey.AsReadOnlyMemory().Span);
    }


    /// <summary>Computes the pre-rotation commitment: the SAID of the qualified next key's UTF-8 bytes.</summary>
    /// <param name="qualifiedKey">The qualified next key.</param>
    /// <returns>The commitment SAID.</returns>
    private static async Task<string> NextKeyDigest(string qualifiedKey)
    {
        return await SaidOf(qualifiedKey).ConfigureAwait(false);
    }


    /// <summary>Signs a serialization with an Ed25519 private key through the registered signing function.</summary>
    /// <param name="privateKey">The signing key.</param>
    /// <param name="serialization">The bytes to sign.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The signature.</returns>
    private static async Task<Signature> SignAsync(PrivateKeyMemory privateKey, ReadOnlyMemory<byte> serialization, CancellationToken cancellationToken)
    {
        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Ed25519, Purpose.Signing);

        (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), serialization, BaseMemoryPool.Shared, context: null, cancellationToken: cancellationToken).ConfigureAwait(false);

        return signature;
    }


    /// <summary>Computes a SAID over a serialization's bytes, renting a transient pooled buffer for the digest input.</summary>
    /// <param name="serialization">The text to digest.</param>
    /// <returns>The SAID.</returns>
    private static async Task<string> SaidOf(string serialization)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return await CesrSaid.ComputeAsync(owner.Memory[..length], Code, AgileDigest, BaseMemoryPool.Shared).ConfigureAwait(false);
    }


    /// <summary>Mints a single-signature inception event.</summary>
    /// <param name="currentKey">The qualified current signing key.</param>
    /// <param name="nextKeyDigest">The pre-rotation commitment to the next key.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintInception(string currentKey, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    /// <summary>Mints a sequence-one interaction event that seals nothing.</summary>
    /// <param name="identifier">The AID.</param>
    /// <param name="priorSaid">The prior event SAID.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintInteraction(string identifier, string priorSaid)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"ixn","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","a":[]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    /// <summary>Mints a sequence-two single-signature rotation event revealing the pre-rotated key.</summary>
    /// <param name="identifier">The AID.</param>
    /// <param name="priorSaid">The prior event SAID.</param>
    /// <param name="revealedKey">The qualified revealed (pre-rotated) current key.</param>
    /// <param name="nextKeyDigest">The pre-rotation commitment to the next key.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintRotation(string identifier, string priorSaid, string revealedKey, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"rot","d":"{{said}}","i":"{{identifier}}","s":"2","p":"{{priorSaid}}","kt":"1","k":["{{revealedKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","br":[],"ba":[],"c":[],"a":[]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a self-addressing event (an inception, where the identifier equals the SAID): both the SAID field
    /// and the identifier are placeholdered, the SAID computed over the sized serialization, then substituted
    /// into both.
    /// </summary>
    /// <param name="build">Builds the serialization from a version string, SAID, and identifier.</param>
    /// <param name="placeholder">The SAID placeholder run.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintSelfAddressing(Func<string, string, string, string> build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder, placeholder));
        string dummied = build(version, placeholder, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    /// <summary>
    /// Mints an event whose identifier is already fixed (an interaction or rotation): only the SAID field is
    /// placeholdered, the SAID computed over the sized serialization, then substituted back.
    /// </summary>
    /// <param name="build">Builds the serialization from a version string and SAID.</param>
    /// <param name="placeholder">The SAID placeholder run.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintWithFixedIdentifier(Func<string, string, string> build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder));
        string dummied = build(version, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    /// <summary>
    /// Rents a pooled buffer for the final serialization the stream carries and the verifier replays over, owned
    /// by the returned carrier and disposed by the caller.
    /// </summary>
    /// <param name="serialization">The final event serialization.</param>
    /// <param name="said">The event SAID.</param>
    /// <returns>The minted event.</returns>
    private static MintedEvent Rent(string serialization, string said)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return new MintedEvent(owner, length, said);
    }


    /// <summary>
    /// The version-1 KERI JSON version string stamps the serialization's total byte length as six hex characters;
    /// the size digits do not change the string's length, so a probe with zeroed digits measures the same length.
    /// </summary>
    /// <param name="probe">The serialization built with a zeroed-size version string.</param>
    /// <returns>The version string with the measured size stamped.</returns>
    private static string VersionFor(string probe)
    {
        return $"KERI10JSON{Encoding.UTF8.GetByteCount(probe):x6}_";
    }


    /// <summary>Disposes every tracked disposable.</summary>
    /// <param name="disposables">The disposables to dispose.</param>
    private static void Dispose(List<IDisposable> disposables)
    {
        foreach(IDisposable disposable in disposables)
        {
            disposable.Dispose();
        }
    }


    /// <summary>
    /// A minted event's serialization, carried in a pooled buffer the caller owns and disposes, with its SAID.
    /// </summary>
    /// <param name="Owner">The pooled buffer owner.</param>
    /// <param name="Length">The number of valid serialization bytes.</param>
    /// <param name="Said">The event SAID.</param>
    private sealed record MintedEvent(IMemoryOwner<byte> Owner, int Length, string Said)
    {
        /// <summary>The event serialization as a view over the pooled buffer.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];
    }


    /// <summary>
    /// A signed event ready to frame into the stream: its serialization, the controller-signature carrier (tracked
    /// for disposal by its creator), its SAID, and the keys its signature indexes into.
    /// </summary>
    /// <param name="Serialization">The event serialization bytes.</param>
    /// <param name="Signature">The controller-signature carrier.</param>
    /// <param name="Said">The event SAID.</param>
    /// <param name="SigningKeys">The qualified keys the signature indexes into.</param>
    private sealed record SignedEvent(ReadOnlyMemory<byte> Serialization, Signature Signature, string Said, IReadOnlyList<string> SigningKeys);
}
