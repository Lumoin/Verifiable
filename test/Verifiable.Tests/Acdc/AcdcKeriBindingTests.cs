using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Json;
using Verifiable.Keri;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Firewalled end-to-end coverage for the ACDC-to-KERI issuer binding (<see cref="AcdcKeriBinding"/>): the central
/// guarantee that an ACDC is bound to its Issuer's key state because the Issuer's KEL anchors an issuance proof seal
/// whose digest is the ACDC's SAID, under the exact AID a mint rests on. An independent BouncyCastle/Microsoft
/// minter produces a real <c>icp → ixn</c> Issuer KEL where the interaction anchors a digest seal of the
/// specification's Accreditation ACDC SAID; each event is signed with no stubbed signatures. The verifier then,
/// from wire bytes alone, verifies the ACDC's own SAID over its serialization and replays the Issuer's RAW KEL
/// through the production <see cref="KeriIssuerAnchors.ReplayAsync"/> path — never a caller-supplied anchor set —
/// confirming the issuance seal binds the ACDC under the AID the replay itself established, the full chain with no
/// backchannel. An unanchored ACDC, a KEL that anchors nothing for it, and a genuinely-verified KEL belonging to a
/// different AID than the ACDC's claimed Issuer all fail closed.
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


    /// <summary>Decodes a KERI event's JSON bytes into a neutral field map for the production KEL replay.</summary>
    private static readonly KeriEventFieldMapDecoder JsonDecoder = (serialization, serializationKind) => KeriEventJson.DecodeFieldMap(serialization);


    /// <summary>
    /// An ACDC whose SAID is anchored by a digest seal in the Issuer's verified KEL binds: the ACDC's own SAID
    /// verifies over its serialization, the Issuer's KEL replays through the production path, and the issuance
    /// seal the replay collects commits to exactly the ACDC's SAID.
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

            (string _, List<KeriKelEvent> kel) = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.AccreditationSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);
            IReadOnlyList<KeriAnchoredSeal> anchors = await ReplayAnchorsAsync(kel, TestContext.CancellationToken).ConfigureAwait(false);

            KeriAnchoredSeal? anchor = AcdcKeriBinding.FindDirectIssuanceSeal(anchors, AcdcExampleVectors.AccreditationSaid);

            Assert.IsNotNull(anchor, "The Issuer's KEL anchors an issuance seal of the ACDC.");
            Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, ((KeriDigestSeal)anchor.Seal).Digest, "The issuance seal commits to exactly the ACDC's SAID.");
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
            (string _, List<KeriKelEvent> kel) = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.AccreditationSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);
            IReadOnlyList<KeriAnchoredSeal> anchors = await ReplayAnchorsAsync(kel, TestContext.CancellationToken).ConfigureAwait(false);

            //A different ACDC's SAID (the Transcript ACDC) is not anchored by this KEL.
            KeriAnchoredSeal? anchor = AcdcKeriBinding.FindDirectIssuanceSeal(anchors, AcdcExampleVectors.TranscriptSaid);

            Assert.IsNull(anchor, "An ACDC the Issuer's KEL does not anchor must not bind.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// A SAID-authentic ACDC anchored in the Issuer's verified KEL mints a <see cref="Verified{T}"/> of
    /// <see cref="AcdcMessage"/> through <see cref="AcdcVerification.VerifyDirectIssuanceAsync"/> — the mint-only
    /// trust carrier a consumer requires, whose context records the Issuer AID whose key state anchored the
    /// issuance. The method is handed the Issuer's RAW KEL, never a pre-vetted anchor: it replays the KEL itself.
    /// </summary>
    [TestMethod]
    public async Task MintsVerifiedAcdcMessageFromDirectIssuance()
    {
        var disposables = new List<IDisposable>();
        try
        {
            //A self-consistent scenario: the ACDC's own Issuer field IS the freshly minted AID whose KEL anchors
            //it, exactly what a real deployment looks like -- the fixed specification example vectors used above
            //name a placeholder Issuer no freshly-replayed KEL could ever legitimately match.
            (string issuerAid, AcdcFlowKit.MintedAcdc acdc, IReadOnlyList<AcdcFlowKit.SignedEvent> signedKel) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdc.Serialization));
            Assert.AreEqual(issuerAid, message.Issuer, "The minted ACDC's own Issuer field names the KEL's AID.");

            List<KeriKelEvent> kel = ToKelEvents(signedKel, disposables);

            Verified<AcdcMessage>? verified = await AcdcVerification.VerifyDirectIssuanceAsync(
                acdc.Serialization, message, kel, JsonDecoder, CesrSerializationKind.Json, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared,
                new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(verified, "A SAID-authentic ACDC whose Issuer's raw KEL genuinely replays and anchors it MUST mint a Verified<AcdcMessage>.");
            Verified<AcdcMessage> trusted = verified.Value;
            Assert.AreEqual(acdc.Said, trusted.Value.Said, "The verified value is the ACDC whose SAID was checked over its bytes.");
            Assert.AreEqual(ResolutionSource.KeriAnchor, ((BoundProvenance)trusted.Provenance!).Source, "The mint is Bound via the KERI anchor gate, not merely Asserted.");
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
            (string _, List<KeriKelEvent> kel) = await BuildIssuerKelAnchoringAsync(AcdcExampleVectors.TranscriptSaid, disposables, TestContext.CancellationToken).ConfigureAwait(false);

            Verified<AcdcMessage>? verified = await AcdcVerification.VerifyDirectIssuanceAsync(
                acdc.Memory, message, kel, JsonDecoder, CesrSerializationKind.Json, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared,
                new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(verified, "An ACDC the Issuer's KEL does not anchor MUST NOT mint a Verified<AcdcMessage>.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// The cross-AID forgery this closes: an ACDC genuinely issued by A (a real, self-certifying
    /// AID with a real minted KEL and a real ACDC anchored under it) is presented for verification together with a
    /// SECOND, independently minted, genuinely self-certifying KEL for a DIFFERENT AID (B) that -- coincidentally
    /// or by attack -- ALSO anchors A's exact ACDC SAID. B's KEL is completely real: it replays and verifies on its
    /// own terms. It is simply not A's KEL. <see cref="AcdcVerification.VerifyDirectIssuanceAsync"/> MUST NOT mint,
    /// because <see cref="BoundProvenance.TryBindByKeriAnchor"/> refuses when the replay-established AID disagrees
    /// with the ACDC's claimed Issuer -- no caller-supplied anchor and no pre-checked "expected AID" shortcut is
    /// reachable to paper over the mismatch.
    /// </summary>
    [TestMethod]
    public async Task DoesNotMintWhenSuppliedKelIsARealButDifferentIssuersKel()
    {
        var disposables = new List<IDisposable>();
        try
        {
            (string issuerA, AcdcFlowKit.MintedAcdc acdcForA, IReadOnlyList<AcdcFlowKit.SignedEvent> _) =
                await AcdcFlowKit.MintIssuerAsync(disposables, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            AcdcMessage message = AcdcReader.Read(AcdcJson.DecodeFieldMap(acdcForA.Serialization));
            Assert.AreEqual(issuerA, message.Issuer, "The minted ACDC's own Issuer field names A.");

            //B: an independently minted, genuinely self-certifying KEL that anchors the SAME ACDC SAID as A's, but
            //under B's own AID -- real signatures, real replay, just not A's KEL.
            (string issuerB, List<KeriKelEvent> kelB) = await BuildIssuerKelAnchoringAsync(acdcForA.Said, disposables, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreNotEqual(issuerA, issuerB, "A and B must be genuinely different, independently minted AIDs.");

            Verified<AcdcMessage>? verified = await AcdcVerification.VerifyDirectIssuanceAsync(
                acdcForA.Serialization, message, kelB, JsonDecoder, CesrSerializationKind.Json, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared,
                new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(verified, "A real, independently verified KEL that anchors the ACDC's SAID under a DIFFERENT AID than its claimed Issuer MUST NOT mint.");
        }
        finally
        {
            Dispose(disposables);
        }
    }


    /// <summary>
    /// Converts a minted, in-memory signed KEL (<see cref="AcdcFlowKit.MintIssuerAsync"/>'s own output) into the
    /// raw per-event form <see cref="KeriIssuerAnchors.ReplayAsync"/> takes: each event's serialization bytes
    /// paired with a <see cref="CryptoProof"/> reconstructed from its qualified signer key.
    /// </summary>
    /// <param name="kel">The minted, signed KEL events.</param>
    /// <param name="disposables">The list the reconstructed key material is tracked on for disposal.</param>
    /// <returns>The raw KEL events.</returns>
    private static List<KeriKelEvent> ToKelEvents(IReadOnlyList<AcdcFlowKit.SignedEvent> kel, List<IDisposable> disposables)
    {
        var events = new List<KeriKelEvent>(kel.Count);
        foreach(AcdcFlowKit.SignedEvent signed in kel)
        {
            using CesrParsedPrimitive parsedKey = CesrPrimitiveCodec.DecodeText(signed.SignerKeyQb64, BaseMemoryPool.Shared);
            IMemoryOwner<byte> keyOwner = BaseMemoryPool.Shared.Rent(parsedKey.RawLength);
            parsedKey.Raw.CopyTo(keyOwner.Memory.Span);
            var publicKey = new PublicKeyMemory(keyOwner, CryptoTags.Ed25519PublicKey);
            disposables.Add(publicKey);

            events.Add(new KeriKelEvent(signed.Serialization, ImmutableArray.Create(new CryptoProof(signed.Signature, publicKey, CryptoAlgorithm.Ed25519))));
        }

        return events;
    }


    /// <summary>
    /// Replays a KEL through the production <see cref="KeriIssuerAnchors.ReplayAsync"/> path and returns its
    /// collected anchors, asserting the replay itself succeeded.
    /// </summary>
    private static async Task<IReadOnlyList<KeriAnchoredSeal>> ReplayAnchorsAsync(List<KeriKelEvent> kel, CancellationToken cancellationToken)
    {
        KeriIssuerAnchorReplayResult replay = await KeriIssuerAnchors.ReplayAsync(
            kel, JsonDecoder, CesrSerializationKind.Json, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared,
            new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal: null, cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(replay.IsVerified, $"The Issuer KEL must verify; error: '{replay.Error}'.");

        return replay.Anchors!;
    }


    /// <summary>
    /// Mints a real <c>icp → ixn</c> Issuer KEL where the interaction anchors a digest seal of the given ACDC SAID:
    /// the RAW KEL (its events' own serialization bytes and proofs), not a pre-verified anchor set, so a caller
    /// exercises the exact input <see cref="AcdcVerification.VerifyDirectIssuanceAsync"/> and
    /// <see cref="KeriIssuerAnchors.ReplayAsync"/> both take.
    /// </summary>
    /// <param name="acdcSaid">The ACDC SAID the interaction anchors.</param>
    /// <param name="disposables">The list minted key material and events are tracked on for disposal.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID the inception establishes, and the raw KEL events.</returns>
    private static async Task<(string IssuerAid, List<KeriKelEvent> Kel)> BuildIssuerKelAnchoringAsync(string acdcSaid, List<IDisposable> disposables, CancellationToken cancellationToken)
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

        var kel = new List<KeriKelEvent>
        {
            new(inception.Serialization, ImmutableArray.Create(new CryptoProof(inceptionSignature, current.PublicKey, CryptoAlgorithm.Ed25519))),
            new(interaction.Serialization, ImmutableArray.Create(new CryptoProof(interactionSignature, current.PublicKey, CryptoAlgorithm.Ed25519)))
        };

        return (issuerAid, kel);
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

        (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), serialization, BaseMemoryPool.Shared, context: null, cancellationToken: cancellationToken).ConfigureAwait(false);

        return signature;
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
