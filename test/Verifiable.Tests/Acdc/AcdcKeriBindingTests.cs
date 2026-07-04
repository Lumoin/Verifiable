using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Firewalled end-to-end coverage for the ACDC-to-KERI issuer binding (<see cref="AcdcKeriBinding"/>): the central
/// guarantee that an ACDC is bound to its Issuer's key state because the Issuer's KEL anchors an issuance proof seal
/// whose digest is the ACDC's SAID. An independent BouncyCastle/Microsoft minter produces a real
/// <c>icp → ixn</c> Issuer KEL where the interaction anchors a digest seal of the specification's Accreditation
/// ACDC SAID; each event is signed with no stubbed signatures. The verifier then, from wire bytes alone, verifies
/// the ACDC's own SAID over its serialization, replays the Issuer's KEL through the production
/// <see cref="KeriKeyEventLog"/> path, reads the anchored seals from the verified interaction, and confirms the
/// issuance seal binds the ACDC — the full chain with no backchannel. An unanchored ACDC and a KEL that anchors
/// nothing for it both fail closed.
/// </summary>
[TestClass]
internal sealed class AcdcKeriBindingTests
{
    /// <summary>The Blake3-256 CESR digest code the minter stamps SAIDs with.</summary>
    private static readonly string Code = CesrDigestCodes.Blake3Bits256;

    /// <summary>The KERI JSON version string with a zeroed size, used to measure a serialization before its size is stamped.</summary>
    private const string ProbeVersion = "KERI10JSON000000_";


    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An ACDC whose SAID is anchored by a digest seal in the Issuer's verified KEL binds: the ACDC's own SAID
    /// verifies over its serialization, the Issuer's KEL replays, and the issuance seal in the verified interaction
    /// commits to exactly the ACDC's SAID.
    /// </summary>
    [TestMethod]
    public async Task BindsAcdcAnchoredInIssuerKel()
    {
        var disposables = new List<IDisposable>();
        try
        {
            //The ACDC is authentic in itself: its top-level SAID verifies over its most-compact serialization,
            //independently of the Issuer's KEL.
            using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);
            Assert.IsTrue(await AcdcSaid.VerifyAsync(acdc.Memory, AcdcExampleVectors.AccreditationSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The ACDC's own SAID must verify before its anchoring is checked.");

            IReadOnlyList<KeriSeal> anchors = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.AccreditationSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            KeriDigestSeal? seal = AcdcKeriBinding.FindDirectIssuanceSeal(anchors, AcdcExampleVectors.AccreditationSaid);

            Assert.IsNotNull(seal, "The Issuer's KEL anchors an issuance seal of the ACDC.");
            Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, seal.Digest, "The issuance seal commits to exactly the ACDC's SAID.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// An ACDC whose SAID the Issuer's KEL does not anchor fails closed: the same verified KEL that anchors the
    /// Accreditation ACDC carries no issuance seal for a different ACDC SAID.
    /// </summary>
    [TestMethod]
    public async Task RejectsUnanchoredAcdc()
    {
        var disposables = new List<IDisposable>();
        try
        {
            IReadOnlyList<KeriSeal> anchors = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.AccreditationSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            //A different ACDC's SAID (the Transcript ACDC) is not anchored by this KEL.
            KeriDigestSeal? seal = AcdcKeriBinding.FindDirectIssuanceSeal(anchors, AcdcExampleVectors.TranscriptSaid);

            Assert.IsNull(seal, "An ACDC the Issuer's KEL does not anchor must not bind.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A SAID-authentic ACDC anchored in the Issuer's verified KEL mints a <see cref="Verified{T}"/> of
    /// <see cref="AcdcMessage"/> through <see cref="AcdcVerification.VerifyDirectIssuanceAsync"/> — the mint-only
    /// trust carrier a consumer requires — whose context records the Issuer AID whose key state anchored the issuance.
    /// </summary>
    [TestMethod]
    public async Task MintsVerifiedAcdcMessageFromDirectIssuance()
    {
        var disposables = new List<IDisposable>();
        try
        {
            using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdc.Memory));

            IReadOnlyList<KeriSeal> anchors = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.AccreditationSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            Verified<AcdcMessage>? verified = await AcdcVerification.VerifyDirectIssuanceAsync(
                acdc.Memory, message, anchors, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(verified, "A SAID-authentic, KEL-anchored ACDC MUST mint a Verified<AcdcMessage>.");
            Verified<AcdcMessage> trusted = verified.Value;
            Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, trusted.Value.Said, "The verified value is the ACDC whose SAID was checked over its bytes.");
            Assert.IsTrue(trusted.Context.TryGet<KeyId>(out KeyId issuer), "The verification context carries the Issuer AID.");
            Assert.AreEqual(message.Issuer, issuer.Value, "The context Issuer AID is the ACDC's issuer.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// An ACDC the Issuer's KEL does not anchor mints no <see cref="Verified{T}"/>:
    /// <see cref="AcdcVerification.VerifyDirectIssuanceAsync"/> fails closed to <see langword="null"/> even though the
    /// ACDC's own SAID is authentic, because issuer binding is not established.
    /// </summary>
    [TestMethod]
    public async Task DoesNotMintVerifiedForUnanchoredAcdc()
    {
        var disposables = new List<IDisposable>();
        try
        {
            using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);
            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdc.Memory));

            //A verified KEL for a DIFFERENT issuance: it anchors the Transcript SAID, not this ACDC's.
            IReadOnlyList<KeriSeal> anchors = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.TranscriptSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            Verified<AcdcMessage>? verified = await AcdcVerification.VerifyDirectIssuanceAsync(
                acdc.Memory, message, anchors, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(verified, "An ACDC the Issuer's KEL does not anchor MUST NOT mint a Verified<AcdcMessage>.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Mints a real <c>icp → ixn</c> Issuer KEL where the interaction anchors a digest seal of the given ACDC SAID,
    /// replays it through the production path asserting both events verify, and returns the anchored seals read from
    /// the verified interaction. This is the firewalled bridge: only the wire serializations and the ACDC SAID cross
    /// to the verifier.
    /// </summary>
    /// <param name="acdcSaid">The ACDC SAID the interaction anchors.</param>
    /// <param name="disposables">The list minted key material and events are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the signing and replay.</param>
    /// <returns>The anchored seals from the verified interaction.</returns>
    private static async Task<IReadOnlyList<KeriSeal>> BuildIssuerKelAnchoringAsync(string acdcSaid, List<IDisposable> disposables, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        MintedEvent inception = await MintInception(Qualify(current.PublicKey), await NextKeyDigest(Qualify(next.PublicKey)).ConfigureAwait(false)).ConfigureAwait(false);
        disposables.Add(inception.Owner);
        string issuerAid = inception.Said;

        string sealJson = $$"""{"d":"{{acdcSaid}}"}""";
        MintedEvent interaction = await MintAnchoringInteraction(issuerAid, inception.Said, sealJson).ConfigureAwait(false);
        disposables.Add(interaction.Owner);

        Signature inceptionSignature = await SignAsync(current.PrivateKey, inception.Serialization, cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(current.PrivateKey, interaction.Serialization, cancellationToken).ConfigureAwait(false);
        disposables.Add(inceptionSignature);
        disposables.Add(interactionSignature);

        var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>
        {
            Entry(0, priorSaid: null, inception, [new CryptoProof(inceptionSignature, current.PublicKey, CryptoAlgorithm.Ed25519)], disposables),
            Entry(1, inception.Said, interaction, [new CryptoProof(interactionSignature, current.PublicKey, CryptoAlgorithm.Ed25519)], disposables)
        };

        List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results = await ReplayAsync(entries, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(results[0].IsSuccess, $"The Issuer inception must verify; error: '{results[0].Error}'.");
        Assert.IsTrue(results[1].IsSuccess, $"The Issuer interaction must verify; error: '{results[1].Error}'.");

        return KeriSealReader.ReadList(KeriEventJson.DecodeFieldMap(interaction.Serialization)[KeriMessageFields.Anchors]);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Fresh(List<IDisposable> disposables)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        disposables.Add(material.PublicKey);
        disposables.Add(material.PrivateKey);

        return material;
    }


    private static async Task<MintedEvent> MintInception(string currentKey, string nextKeyDigest)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, placeholder).ConfigureAwait(false);
    }


    /// <summary>Mints a sequence-one interaction whose anchor list carries a single seal (the seal's JSON object body).</summary>
    /// <param name="identifier">The AID the interaction belongs to.</param>
    /// <param name="priorSaid">The prior event's SAID.</param>
    /// <param name="sealJson">The seal's JSON object body.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintAnchoringInteraction(string identifier, string priorSaid, string sealJson)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"ixn","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","a":[{{sealJson}}]}""";

        return await MintWithFixedIdentifier(Build, placeholder).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a self-addressing event (an inception, where the identifier equals the SAID): both the SAID field and
    /// the identifier are placeholdered, the SAID computed over the sized serialization, then substituted into both.
    /// </summary>
    /// <param name="build">The event-body builder.</param>
    /// <param name="placeholder">The SAID placeholder.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintSelfAddressing(SelfAddressingEventBuilder build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder, placeholder));
        string dummied = build(version, placeholder, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    /// <summary>
    /// Mints an event whose identifier is already fixed (the interaction): only the SAID field is placeholdered, the
    /// SAID computed over the sized serialization, then substituted back.
    /// </summary>
    /// <param name="build">The event-body builder.</param>
    /// <param name="placeholder">The SAID placeholder.</param>
    /// <returns>The minted event.</returns>
    private static async Task<MintedEvent> MintWithFixedIdentifier(FixedIdentifierEventBuilder build, string placeholder)
    {
        string version = VersionFor(build(ProbeVersion, placeholder));
        string dummied = build(version, placeholder);
        string said = await SaidOf(dummied).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    /// <summary>Rents a pooled buffer for the final serialization a verifier replays over, owned by the returned carrier.</summary>
    /// <param name="serialization">The serialization text.</param>
    /// <param name="said">The serialization's SAID.</param>
    /// <returns>The minted event.</returns>
    private static MintedEvent Rent(string serialization, string said)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return new MintedEvent(owner, length, said);
    }


    /// <summary>
    /// Builds the version-1 KERI JSON version string stamping the serialization's total byte length as six hex
    /// characters; the size digits do not change the string's length, so a probe with zeroed digits measures the
    /// same length.
    /// </summary>
    /// <param name="probe">The serialization built with a zeroed size.</param>
    /// <returns>The version string with the stamped size.</returns>
    private static string VersionFor(string probe)
    {
        return $"KERI10JSON{Encoding.UTF8.GetByteCount(probe):x6}_";
    }


    private static string Qualify(PublicKeyMemory publicKey)
    {
        return CesrPrimitiveCodec.EncodeText("D", publicKey.AsReadOnlyMemory().Span);
    }


    /// <summary>Computes the pre-rotation commitment: the qualified digest of the qualified next key's UTF-8 bytes.</summary>
    /// <param name="qualifiedKey">The qualified next key.</param>
    /// <returns>The next-key digest.</returns>
    private static async Task<string> NextKeyDigest(string qualifiedKey)
    {
        return await SaidOf(qualifiedKey).ConfigureAwait(false);
    }


    /// <summary>Computes a SAID over a serialization's bytes, renting a transient pooled buffer for the digest input.</summary>
    /// <param name="serialization">The serialization to digest.</param>
    /// <returns>The CESR-encoded SAID.</returns>
    private static async Task<string> SaidOf(string serialization)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return await CesrSaid.ComputeAsync(owner.Memory[..length], Code, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None).ConfigureAwait(false);
    }


    private static async Task<Signature> SignAsync(PrivateKeyMemory privateKey, ReadOnlyMemory<byte> serialization, CancellationToken cancellationToken)
    {
        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Ed25519, Purpose.Signing);

        return await sign(privateKey.AsReadOnlyMemory(), serialization, BaseMemoryPool.Shared, context: null, cancellationToken: cancellationToken).ConfigureAwait(false);
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


    /// <summary>Rents a pooled buffer for a text's UTF-8 bytes, tracks the owner for disposal, and returns a view over it.</summary>
    /// <param name="text">The text to encode.</param>
    /// <param name="disposables">The list the buffer owner is tracked on for disposal.</param>
    /// <returns>A view over the encoded bytes.</returns>
    private static ReadOnlyMemory<byte> Utf8(string text, List<IDisposable> disposables)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(text, owner.Memory.Span);
        disposables.Add(owner);

        return owner.Memory[..length];
    }


    private static async Task<List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>> ReplayAsync(List<LogEntry<KeriKeyEvent, CryptoProof>> entries, CancellationToken cancellationToken)
    {
        LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> context =
            KeriKeyEventLog.CreateReplayContext(AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, TimeProvider.System);

        var replayer = new LogReplayer<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>();
        var results = new List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>();
        await foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in replayer.ReplayAsync(ToAsync(entries, cancellationToken), context, cancellationToken).ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }


    private static async IAsyncEnumerable<LogEntry<KeriKeyEvent, CryptoProof>> ToAsync(List<LogEntry<KeriKeyEvent, CryptoProof>> entries, [EnumeratorCancellation] CancellationToken cancellationToken)
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
    /// A minted event's serialization, carried in a pooled buffer the caller owns and disposes, with its SAID.
    /// </summary>
    private sealed record MintedEvent(IMemoryOwner<byte> Owner, int Length, string Said)
    {
        /// <summary>The event's serialization bytes.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];
    }
}
