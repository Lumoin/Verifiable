using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
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
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Builds the body of a self-addressing event (an inception, whose identifier equals its SAID) from the version
/// string, the SAID (or its placeholder), and the identifier (or its placeholder).
/// </summary>
/// <param name="version">The version string with the event's stamped size.</param>
/// <param name="said">The SAID, or its dummy placeholder during the two-pass mint.</param>
/// <param name="identifier">The identifier, or its dummy placeholder during the two-pass mint.</param>
/// <returns>The event's JSON serialization text.</returns>
internal delegate string SelfAddressingEventBuilder(string version, string said, string identifier);


/// <summary>
/// Builds the body of an event whose identifier is already fixed (an interaction or a registry event) from the
/// version string and the SAID (or its placeholder).
/// </summary>
/// <param name="version">The version string with the event's stamped size.</param>
/// <param name="said">The SAID, or its dummy placeholder during the two-pass mint.</param>
/// <returns>The event's JSON serialization text.</returns>
internal delegate string FixedIdentifierEventBuilder(string version, string said);


/// <summary>
/// The minting and over-the-wire (de)serialization helpers a multi-server ACDC flow test shares: an Issuer party
/// mints its KEL, its registry, and its credential and signs with real Ed25519 keys; the artifacts are serialized
/// to the bytes the Issuer publishes; and a firewalled Disclosee reconstructs the verifiable objects from those
/// bytes alone. Every minted serialization is held in pooled memory tracked for disposal, as the production code is;
/// the published wire bytes are the HTTP body the serving host owns.
/// </summary>
internal static class AcdcFlowKit
{
    /// <summary>The Blake3-256 CESR digest code SAIDs are stamped with.</summary>
    public static readonly string Code = CesrDigestCodes.Blake3Bits256;


    /// <summary>A minted, signed KEL event: its pooled serialization, its SAID, and the signature over it.</summary>
    /// <param name="Owner">The pooled buffer holding the serialization.</param>
    /// <param name="Length">The number of serialization bytes.</param>
    /// <param name="Said">The event's SAID.</param>
    /// <param name="SignerKeyQb64">The signer's qualified public key.</param>
    /// <param name="Signature">The signature over the serialization.</param>
    internal sealed record SignedEvent(IMemoryOwner<byte> Owner, int Length, string Said, string SignerKeyQb64, Signature Signature): IDisposable
    {
        /// <summary>The event's serialization bytes.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];

        /// <summary>Disposes the pooled serialization and the signature.</summary>
        public void Dispose()
        {
            Owner.Dispose();
            Signature.Dispose();
        }
    }


    /// <summary>A minted ACDC: its pooled canonical serialization, its top-level SAID, and its Issuer AID.</summary>
    /// <param name="Owner">The pooled buffer holding the serialization.</param>
    /// <param name="Length">The number of serialization bytes.</param>
    /// <param name="Said">The credential's top-level SAID.</param>
    /// <param name="Issuer">The credential's Issuer AID.</param>
    internal sealed record MintedAcdc(IMemoryOwner<byte> Owner, int Length, string Said, string Issuer): IDisposable
    {
        /// <summary>The credential's serialization bytes.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];

        /// <summary>Disposes the pooled serialization.</summary>
        public void Dispose() => Owner.Dispose();
    }


    /// <summary>
    /// A minted ACDC disclosed at two graduation levels: its most-compact form and its expanded form, both carrying
    /// the one top-level SAID the Issuer committed to. The compact variant reduces the attribute section to its SAID,
    /// disclosing no attribute values; the expanded variant discloses the attribute block; both compact to the same
    /// SAID, so one Issuer commitment covers both.
    /// </summary>
    /// <param name="Compact">The most-compact variant: the attribute section carried as its SAID.</param>
    /// <param name="Expanded">The expanded variant: the attribute section disclosed as its block.</param>
    /// <param name="Said">The one top-level SAID both variants compact to, the value the Issuer anchors.</param>
    internal sealed record GraduatedAcdc(MintedAcdc Compact, MintedAcdc Expanded, string Said);


    /// <summary>
    /// A minted aggregate ACDC presented as a selective disclosure: the credential carries a selectively disclosable
    /// aggregate section (<c>A</c>) whose blocks are each revealed (a detail block) or blinded (a SAID), the AGID that
    /// commits to the ordered set of block SAIDs, and the top-level SAID the Issuer anchors. The AGID is bound into
    /// the top-level SAID through the credential's most-compact form, so the one Issuer commitment authenticates any
    /// selective disclosure of the set.
    /// </summary>
    /// <param name="Disclosed">The selective-disclosure serialization: the aggregate section as a list of revealed and blinded blocks.</param>
    /// <param name="Said">The top-level SAID over the most-compact form (the aggregate carried as its AGID), the value the Issuer anchors.</param>
    /// <param name="Agid">The aggregate identifier committing to the ordered set of block SAIDs.</param>
    internal sealed record AggregateAcdc(MintedAcdc Disclosed, string Said, string Agid);


    /// <summary>
    /// A minted IPEX exchange (<c>exn</c>) message: a routed, self-addressing transport envelope that carries a
    /// disclosure exchange's payload. The grant message embeds the disclosed credential and routes it to a Disclosee;
    /// the admit message a Disclosee returns chains to the grant by its SAID. The envelope is SAID-integral so a
    /// receiver confirms it over its received bytes; signing the envelope is the exchange's transport-authentication
    /// layer, beyond the routed-exchange structure and the credential proofs this carries.
    /// </summary>
    /// <param name="Owner">The pooled buffer holding the serialization.</param>
    /// <param name="Length">The number of serialization bytes.</param>
    /// <param name="Said">The message's own SAID, over its serialization.</param>
    /// <param name="Route">The message's route (<c>r</c>): the exchange step it performs.</param>
    /// <param name="Sender">The message's sender AID (<c>i</c>).</param>
    /// <param name="Prior">The prior message's SAID (<c>p</c>) this message chains to, or empty when it initiates the exchange.</param>
    internal sealed record ExchangeMessage(IMemoryOwner<byte> Owner, int Length, string Said, string Route, string Sender, string Prior): IDisposable
    {
        /// <summary>The message's serialization bytes.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];

        /// <summary>Disposes the pooled serialization.</summary>
        public void Dispose() => Owner.Dispose();
    }


    /// <summary>A minted transaction-event-log registry event: its pooled serialization and its SAID.</summary>
    /// <param name="Owner">The pooled buffer holding the serialization.</param>
    /// <param name="Length">The number of serialization bytes.</param>
    /// <param name="Said">The registry event's SAID.</param>
    internal sealed record RegistryEvent(IMemoryOwner<byte> Owner, int Length, string Said): IDisposable
    {
        /// <summary>The registry event's serialization bytes.</summary>
        public ReadOnlyMemory<byte> Serialization => Owner.Memory[..Length];

        /// <summary>Disposes the pooled serialization.</summary>
        public void Dispose() => Owner.Dispose();
    }


    /// <summary>
    /// Mints a real one-party Issuer: an inception establishing the Issuer AID, a minimal ACDC issued under that AID,
    /// and an interaction anchoring the ACDC's SAID — each event signed with the Issuer's Ed25519 key.
    /// </summary>
    /// <param name="disposables">The list the minted key material, credential, and signed events are tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID, the minted ACDC, and the two signed KEL events (inception, anchoring interaction).</returns>
    public static async Task<(string IssuerAid, MintedAcdc Acdc, IReadOnlyList<SignedEvent> Kel)> MintIssuerAsync(List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        string currentKeyQb64 = Qualify(current.PublicKey);
        (IMemoryOwner<byte> inceptionOwner, int inceptionLength, string issuerAid) = await MintInception(currentKeyQb64, await NextKeyDigest(Qualify(next.PublicKey), pool), pool);

        MintedAcdc acdc = await MintAcdc(issuerAid, registryDigest: null, pool);
        disposables.Add(acdc);

        (IMemoryOwner<byte> interactionOwner, int interactionLength, string interactionSaid) = await MintAnchoringInteraction(issuerAid, issuerAid, DigestSeal(acdc.Said), pool);

        Signature inceptionSignature = await SignAsync(current.PrivateKey, inceptionOwner.Memory[..inceptionLength], cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(current.PrivateKey, interactionOwner.Memory[..interactionLength], cancellationToken).ConfigureAwait(false);

        var kel = new List<SignedEvent>
        {
            new(inceptionOwner, inceptionLength, issuerAid, currentKeyQb64, inceptionSignature),
            new(interactionOwner, interactionLength, interactionSaid, currentKeyQb64, interactionSignature)
        };
        foreach(SignedEvent signed in kel)
        {
            disposables.Add(signed);
        }

        return (issuerAid, acdc, kel);
    }


    /// <summary>
    /// Mints an Issuer of a graduated-disclosure credential: an inception establishing the Issuer AID, an
    /// attribute-bearing ACDC issued under that AID and sealed at two graduation levels (most-compact and expanded,
    /// sharing one SAID), and an interaction anchoring that one SAID — so a single Issuer commitment covers every
    /// graduation level the Discloser may present.
    /// </summary>
    /// <param name="disposables">The list the minted key material, both credential variants, and signed events are tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID, the graduated credential (both variants and their shared SAID), and the signed KEL.</returns>
    public static async Task<(string IssuerAid, GraduatedAcdc Acdc, IReadOnlyList<SignedEvent> Kel)> MintGraduatedIssuerAsync(List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        string currentKeyQb64 = Qualify(current.PublicKey);
        (IMemoryOwner<byte> inceptionOwner, int inceptionLength, string issuerAid) = await MintInception(currentKeyQb64, await NextKeyDigest(Qualify(next.PublicKey), pool), pool);

        GraduatedAcdc acdc = await MintGraduatedAcdc(issuerAid, disposables, pool);

        (IMemoryOwner<byte> interactionOwner, int interactionLength, string interactionSaid) = await MintAnchoringInteraction(issuerAid, issuerAid, DigestSeal(acdc.Said), pool);

        Signature inceptionSignature = await SignAsync(current.PrivateKey, inceptionOwner.Memory[..inceptionLength], cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(current.PrivateKey, interactionOwner.Memory[..interactionLength], cancellationToken).ConfigureAwait(false);

        var kel = new List<SignedEvent>
        {
            new(inceptionOwner, inceptionLength, issuerAid, currentKeyQb64, inceptionSignature),
            new(interactionOwner, interactionLength, interactionSaid, currentKeyQb64, interactionSignature)
        };
        foreach(SignedEvent signed in kel)
        {
            disposables.Add(signed);
        }

        return (issuerAid, acdc, kel);
    }


    /// <summary>
    /// Mints an Issuer of an aggregate-section credential presented as a selective disclosure: an inception
    /// establishing the Issuer AID, a credential whose aggregate section reveals one block and blinds another, and an
    /// interaction anchoring the credential's top-level SAID — the SAID into which the aggregate's AGID is bound, so
    /// the one Issuer commitment authenticates the disclosure.
    /// </summary>
    /// <param name="disposables">The list the minted key material, the disclosed credential, and signed events are tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID, the selectively disclosed aggregate credential, and the signed KEL.</returns>
    public static async Task<(string IssuerAid, AggregateAcdc Acdc, IReadOnlyList<SignedEvent> Kel)> MintAggregateIssuerAsync(List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        string currentKeyQb64 = Qualify(current.PublicKey);
        (IMemoryOwner<byte> inceptionOwner, int inceptionLength, string issuerAid) = await MintInception(currentKeyQb64, await NextKeyDigest(Qualify(next.PublicKey), pool), pool);

        AggregateAcdc acdc = await MintAggregateAcdc(issuerAid, disposables, pool);

        (IMemoryOwner<byte> interactionOwner, int interactionLength, string interactionSaid) = await MintAnchoringInteraction(issuerAid, issuerAid, DigestSeal(acdc.Said), pool);

        Signature inceptionSignature = await SignAsync(current.PrivateKey, inceptionOwner.Memory[..inceptionLength], cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(current.PrivateKey, interactionOwner.Memory[..interactionLength], cancellationToken).ConfigureAwait(false);

        var kel = new List<SignedEvent>
        {
            new(inceptionOwner, inceptionLength, issuerAid, currentKeyQb64, inceptionSignature),
            new(interactionOwner, interactionLength, interactionSaid, currentKeyQb64, interactionSignature)
        };
        foreach(SignedEvent signed in kel)
        {
            disposables.Add(signed);
        }

        return (issuerAid, acdc, kel);
    }


    /// <summary>
    /// Mints the IPEX grant of a disclosure exchange: an Issuer (the Discloser) with its KEL and an anchored
    /// credential, and a grant exchange message that embeds that credential and routes it to a Disclosee. The grant
    /// is the first hop of the routed grant-then-admit exchange; the credential it embeds carries the two proofs a
    /// Disclosee checks, Proof of Disclosure (the credential's SAID) and Proof of Issuance (the Issuer's KEL anchor).
    /// </summary>
    /// <param name="disposables">The list the minted key material, credential, signed events, and grant message are tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID, the grant exchange message, the embedded credential's SAID, and the Issuer's signed KEL.</returns>
    public static async Task<(string IssuerAid, ExchangeMessage Grant, string CredentialSaid, IReadOnlyList<SignedEvent> Kel)> MintIpexGrantAsync(List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (string issuerAid, MintedAcdc acdc, IReadOnlyList<SignedEvent> kel) = await MintIssuerAsync(disposables, pool, cancellationToken).ConfigureAwait(false);

        string embeddedCredentialJson = Encoding.UTF8.GetString(acdc.Serialization.Span);
        ExchangeMessage grant = await MintExchange(AcdcFlowWellKnown.IpexGrantRoute, issuerAid, prior: string.Empty, embeddedCredentialJson, pool);
        disposables.Add(grant);

        return (issuerAid, grant, acdc.Said, kel);
    }


    /// <summary>
    /// Builds the IPEX admit a Disclosee returns once it has verified a grant: an exchange message routed to admit
    /// that chains to the grant by the grant's SAID, the second hop of the routed exchange that closes it.
    /// </summary>
    /// <param name="sender">The Disclosee's AID, the admit's sender.</param>
    /// <param name="grantSaid">The grant message's SAID the admit chains to (its <c>p</c>).</param>
    /// <param name="disposables">The list the admit message is tracked on for disposal.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The admit exchange message.</returns>
    public static async Task<ExchangeMessage> BuildIpexAdmit(string sender, string grantSaid, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        ExchangeMessage admit = await MintExchange(AcdcFlowWellKnown.IpexAdmitRoute, sender, grantSaid, embeddedCredentialJson: null, pool).ConfigureAwait(false);
        disposables.Add(admit);

        return admit;
    }


    /// <summary>
    /// Mints a registry-based Issuer: an inception establishing the AID, a registry inception, a credential issued
    /// under that AID that references the registry by its SAID, an update setting the credential <c>issued</c> (and
    /// optionally a later update setting it <c>revoked</c>), and an interaction anchoring every registry event's SAID
    /// in the Issuer's KEL — the indirect binding the specification requires.
    /// </summary>
    /// <param name="includeRevocation">Whether to append a revocation update after the issuance update.</param>
    /// <param name="disposables">The list the minted key material, credential, registry events, and signed events are tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The Issuer AID, the credential (carrying its registry SAID), the registry events in order, and the signed KEL.</returns>
    public static async Task<(string IssuerAid, MintedAcdc Acdc, IReadOnlyList<RegistryEvent> Registry, IReadOnlyList<SignedEvent> Kel)> MintRegistryIssuerAsync(bool includeRevocation, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> current = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> next = Fresh(disposables);

        string currentKeyQb64 = Qualify(current.PublicKey);
        (IMemoryOwner<byte> inceptionOwner, int inceptionLength, string issuerAid) = await MintInception(currentKeyQb64, await NextKeyDigest(Qualify(next.PublicKey), pool), pool);

        string RegistryInception(string version, string said) =>
            $$"""{"v":"{{version}}","t":"rip","d":"{{said}}","u":"{{AcdcFlowWellKnown.BlockNonce}}","i":"{{issuerAid}}","n":"0","dt":"2025-07-04T17:53:00.000000+00:00"}""";

        RegistryEvent inception = await MintRegistryEvent(RegistryInception, pool);
        disposables.Add(inception);

        MintedAcdc acdc = await MintAcdc(issuerAid, inception.Said, pool);
        disposables.Add(acdc);

        string IssuedUpdate(string version, string said) =>
            $$"""{"v":"{{version}}","t":"upd","d":"{{said}}","rd":"{{inception.Said}}","n":"1","p":"{{inception.Said}}","dt":"2025-07-04T18:00:00.000000+00:00","td":"{{acdc.Said}}","ts":"issued"}""";

        RegistryEvent issued = await MintRegistryEvent(IssuedUpdate, pool);
        disposables.Add(issued);

        var registry = new List<RegistryEvent> { inception, issued };
        if(includeRevocation)
        {
            string RevokedUpdate(string version, string said) =>
                $$"""{"v":"{{version}}","t":"upd","d":"{{said}}","rd":"{{inception.Said}}","n":"2","p":"{{issued.Said}}","dt":"2025-07-04T19:00:00.000000+00:00","td":"{{acdc.Said}}","ts":"revoked"}""";

            RegistryEvent revoked = await MintRegistryEvent(RevokedUpdate, pool);
            disposables.Add(revoked);
            registry.Add(revoked);
        }

        string seals = string.Join(",", registry.ConvertAll(static registryEvent => DigestSeal(registryEvent.Said)));
        (IMemoryOwner<byte> interactionOwner, int interactionLength, string interactionSaid) = await MintAnchoringInteraction(issuerAid, issuerAid, seals, pool);

        Signature inceptionSignature = await SignAsync(current.PrivateKey, inceptionOwner.Memory[..inceptionLength], cancellationToken).ConfigureAwait(false);
        Signature interactionSignature = await SignAsync(current.PrivateKey, interactionOwner.Memory[..interactionLength], cancellationToken).ConfigureAwait(false);

        var kel = new List<SignedEvent>
        {
            new(inceptionOwner, inceptionLength, issuerAid, currentKeyQb64, inceptionSignature),
            new(interactionOwner, interactionLength, interactionSaid, currentKeyQb64, interactionSignature)
        };
        foreach(SignedEvent signed in kel)
        {
            disposables.Add(signed);
        }

        return (issuerAid, acdc, registry, kel);
    }


    /// <summary>
    /// Serializes a minted KEL to the bytes the Issuer publishes: a JSON array of <c>{ked, key, sig}</c> entries
    /// carrying each event's serialization text, its signer's qualified public key, and the Base64 signature.
    /// </summary>
    /// <param name="kel">The signed KEL events.</param>
    /// <returns>The published KEL bytes (the HTTP body the serving host owns).</returns>
    public static byte[] SerializeKel(IReadOnlyList<SignedEvent> kel)
    {
        var entries = new List<KelWireEntry>(kel.Count);
        foreach(SignedEvent signed in kel)
        {
            entries.Add(new KelWireEntry(
                Encoding.UTF8.GetString(signed.Serialization.Span),
                signed.SignerKeyQb64,
                Convert.ToBase64String(signed.Signature.AsReadOnlySpan())));
        }

        return JsonSerializer.SerializeToUtf8Bytes(entries);
    }


    /// <summary>
    /// Serializes a minted registry to the bytes the Issuer publishes: a JSON array of the registry events' canonical
    /// serializations, each as a string.
    /// </summary>
    /// <param name="registry">The registry events in order.</param>
    /// <returns>The published registry bytes (the HTTP body the serving host owns).</returns>
    public static byte[] SerializeRegistry(IReadOnlyList<RegistryEvent> registry)
    {
        var events = new List<string>(registry.Count);
        foreach(RegistryEvent registryEvent in registry)
        {
            events.Add(Encoding.UTF8.GetString(registryEvent.Serialization.Span));
        }

        return JsonSerializer.SerializeToUtf8Bytes(events);
    }


    /// <summary>
    /// Reconstructs a KEL into replayable log entries from the published bytes alone: it parses each event, rebuilds
    /// the controller signature and public key, and threads the prior-event SAID — the firewalled bridge a Disclosee
    /// crosses, with nothing shared from the Issuer but the fetched bytes.
    /// </summary>
    /// <param name="kelBytes">The published KEL bytes.</param>
    /// <param name="disposables">The list the reconstructed keys, signatures, and pooled buffers are tracked on for disposal.</param>
    /// <param name="pool">The pool the reconstructed buffers are rented from.</param>
    /// <returns>The log entries to replay through the KERI key event log.</returns>
    public static List<LogEntry<KeriKeyEvent, CryptoProof>> ReconstructKel(ReadOnlyMemory<byte> kelBytes, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        List<KelWireEntry>? entries = JsonSerializer.Deserialize<List<KelWireEntry>>(kelBytes.Span);
        if(entries is null)
        {
            throw new InvalidOperationException("The published KEL did not deserialize to entries.");
        }

        var log = new List<LogEntry<KeriKeyEvent, CryptoProof>>(entries.Count);
        string? priorSaid = null;
        for(int index = 0; index < entries.Count; index++)
        {
            KelWireEntry entry = entries[index];
            ReadOnlyMemory<byte> eventBytes = Utf8(entry.Ked, disposables, pool);
            KeriKeyEvent keyEvent = KeriEventReader.Read(KeriEventJson.DecodeFieldMap(eventBytes));

            PublicKeyMemory key = DeserializeKey(entry.Key, pool);
            Signature signature = DeserializeSignature(entry.Sig, pool);
            disposables.Add(key);
            disposables.Add(signature);

            log.Add(new LogEntry<KeriKeyEvent, CryptoProof>
            {
                Index = (ulong)index,
                PreviousDigest = priorSaid is null ? null : (ReadOnlyMemory<byte>?)Utf8(priorSaid, disposables, pool),
                Digest = Utf8(keyEvent.Said, disposables, pool),
                CanonicalBytes = eventBytes,
                Operation = keyEvent,
                Proofs = ImmutableArray.Create(new CryptoProof(signature, key, CryptoAlgorithm.Ed25519))
            });

            priorSaid = keyEvent.Said;
        }

        return log;
    }


    /// <summary>
    /// Replays a reconstructed KEL through the production KERI key event log path, returning each event's result.
    /// </summary>
    /// <param name="entries">The reconstructed log entries.</param>
    /// <param name="pool">The pool the replay's digest buffers are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the replay.</param>
    /// <returns>The replay result for each event in order.</returns>
    public static Task<List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>> ReplayKelAsync(List<LogEntry<KeriKeyEvent, CryptoProof>> entries, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        return ReplayKelAsync(entries, pool, resolveDelegationSeal: null, cancellationToken);
    }


    /// <summary>
    /// Replays a reconstructed KEL through the production KERI key event log path, supplying a resolver for a
    /// delegated event's delegating seal (built by a caller that has verified the delegator's KEL), and returns each
    /// event's result. A KEL that carries a delegated inception or rotation verifies only when the resolver finds its
    /// delegating seal in the delegator's KEL.
    /// </summary>
    /// <param name="entries">The reconstructed log entries.</param>
    /// <param name="pool">The pool the replay's digest buffers are rented from.</param>
    /// <param name="resolveDelegationSeal">The resolver for a delegated event's delegating seal, or <see langword="null"/> when the KEL carries no delegated events.</param>
    /// <param name="cancellationToken">A token to cancel the replay.</param>
    /// <returns>The replay result for each event in order.</returns>
    public static async Task<List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>> ReplayKelAsync(List<LogEntry<KeriKeyEvent, CryptoProof>> entries, MemoryPool<byte> pool, DelegationSealResolver? resolveDelegationSeal, CancellationToken cancellationToken)
    {
        LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> context =
            KeriKeyEventLog.CreateReplayContext(AcdcTestSupport.AgileDigest, pool, new FakeTimeProvider(TestClock.CanonicalEpoch), resolveDelegationSeal);

        var replayer = new LogReplayer<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>();
        var results = new List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>>();
        await foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in replayer.ReplayAsync(ToAsync(entries, cancellationToken), context, cancellationToken).ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }


    /// <summary>
    /// Reads an Issuer KEL interaction event's anchored seals from its serialization.
    /// </summary>
    /// <param name="interactionBytes">The interaction event's serialization.</param>
    /// <returns>The typed anchored seals.</returns>
    public static IReadOnlyList<KeriSeal> ReadAnchors(ReadOnlyMemory<byte> interactionBytes)
    {
        return KeriSealReader.ReadList(KeriEventJson.DecodeFieldMap(interactionBytes)[KeriMessageFields.Anchors]);
    }


    /// <summary>
    /// Verifies a fetched Issuer KEL and returns its anchored seals: it reconstructs and replays the KEL from the
    /// fetched bytes, requires every event to verify and the inception to establish the expected Issuer AID, then
    /// reads the anchored seals from the verified interaction. Returns <see langword="null"/> when the KEL does not
    /// verify or is not the expected Issuer's, so a caller can fail closed.
    /// </summary>
    /// <param name="kelBytes">The fetched KEL bytes.</param>
    /// <param name="expectedAid">The Issuer AID the KEL's inception must establish.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="pool">The pool the reconstructed buffers are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the replay.</param>
    /// <returns>The anchored seals, or <see langword="null"/> when the KEL does not verify or is not the expected Issuer's.</returns>
    public static Task<IReadOnlyList<KeriSeal>?> VerifyKelAndReadAnchorsAsync(ReadOnlyMemory<byte> kelBytes, string expectedAid, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        return VerifyKelAndReadAnchorsAsync(kelBytes, expectedAid, resolveDelegationSeal: null, disposables, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies a fetched Issuer KEL that may carry a delegated event and returns its anchored seals: as
    /// <see cref="VerifyKelAndReadAnchorsAsync(ReadOnlyMemory{byte}, string, List{IDisposable}, MemoryPool{byte}, CancellationToken)"/>,
    /// but supplying the resolver a delegated inception or rotation needs to find its delegating seal in the
    /// delegator's already-verified KEL. Returns <see langword="null"/> when the KEL does not verify (including when a
    /// delegated event's delegating seal is not found), is not the expected Issuer's, or a proof fails.
    /// </summary>
    /// <param name="kelBytes">The fetched KEL bytes.</param>
    /// <param name="expectedAid">The Issuer AID the KEL's inception must establish.</param>
    /// <param name="resolveDelegationSeal">The resolver for a delegated event's delegating seal, or <see langword="null"/> when the KEL carries no delegated events.</param>
    /// <param name="disposables">The list reconstructed buffers are tracked on for disposal.</param>
    /// <param name="pool">The pool the reconstructed buffers are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the replay.</param>
    /// <returns>The anchored seals, or <see langword="null"/> when the KEL does not verify or is not the expected Issuer's.</returns>
    public static async Task<IReadOnlyList<KeriSeal>?> VerifyKelAndReadAnchorsAsync(ReadOnlyMemory<byte> kelBytes, string expectedAid, DelegationSealResolver? resolveDelegationSeal, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        List<LogEntry<KeriKeyEvent, CryptoProof>> log = ReconstructKel(kelBytes, disposables, pool);
        List<LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof>> results = await ReplayKelAsync(log, pool, resolveDelegationSeal, cancellationToken).ConfigureAwait(false);

        foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in results)
        {
            if(!result.IsSuccess)
            {
                return null;
            }
        }

        if(!string.Equals(log[0].Operation!.Prefix, expectedAid, StringComparison.Ordinal))
        {
            return null;
        }

        return ReadAnchors(log[1].CanonicalBytes);
    }


    /// <summary>Qualifies an Ed25519 public key into its CESR text form (code <c>D</c>).</summary>
    /// <param name="publicKey">The public key to qualify.</param>
    /// <returns>The qualified key.</returns>
    public static string Qualify(PublicKeyMemory publicKey)
    {
        return CesrPrimitiveCodec.EncodeText("D", publicKey.AsReadOnlyMemory().Span);
    }


    /// <summary>Builds a digest seal JSON object committing to a SAID.</summary>
    /// <param name="said">The SAID the seal commits to.</param>
    /// <returns>The seal JSON.</returns>
    private static string DigestSeal(string said) => $$"""{"d":"{{said}}"}""";


    /// <summary>Builds a key event seal JSON object anchoring a key event by its AID, sequence number, and SAID — the delegating seal a delegator's KEL carries for a delegated inception.</summary>
    /// <param name="prefix">The anchored event's AID (<c>i</c>).</param>
    /// <param name="sequenceNumber">The anchored event's sequence number (<c>s</c>).</param>
    /// <param name="said">The anchored event's SAID (<c>d</c>).</param>
    /// <returns>The seal JSON.</returns>
    private static string KeyEventSeal(string prefix, int sequenceNumber, string said) => $$"""{"i":"{{prefix}}","s":"{{sequenceNumber}}","d":"{{said}}"}""";


    /// <summary>
    /// Mints a minimal ACDC issued under the given Issuer AID: an attribute and schema carried in compact (SAID)
    /// form, optionally a registry SAID, compacted to derive the real top-level SAID and the restamped version
    /// string, the result held in pooled memory.
    /// </summary>
    /// <param name="issuerAid">The Issuer AID the credential is issued under.</param>
    /// <param name="registryDigest">The registry SAID (<c>rd</c>), or <see langword="null"/> for a directly anchored credential.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted ACDC.</returns>
    private static async Task<MintedAcdc> MintAcdc(string issuerAid, string? registryDigest, MemoryPool<byte> pool)
    {
        var expanded = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid
        };

        if(registryDigest is not null)
        {
            expanded[AcdcMessageFields.RegistryDigest] = registryDigest;
        }

        expanded[AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid;
        expanded[AcdcMessageFields.Attribute] = AcdcFlowWellKnown.PlaceholderAttributeSaid;

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(expanded, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        var buffer = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(compact, buffer);

        IMemoryOwner<byte> owner = pool.Rent(buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(owner.Memory.Span);

        return new MintedAcdc(owner, buffer.WrittenCount, (string)compact[AcdcMessageFields.Said]!, issuerAid);
    }


    /// <summary>
    /// Mints a self-addressing ACDC-genus event (a registry event): the SAID field is placeholdered, the version
    /// string restamped to the serialization's byte count, the SAID computed over the dummied form, then
    /// substituted, the result held in pooled memory.
    /// </summary>
    /// <param name="build">The event-body builder.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted registry event.</returns>
    private static async Task<RegistryEvent> MintRegistryEvent(FixedIdentifierEventBuilder build, MemoryPool<byte> pool)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        int byteCount = Encoding.UTF8.GetByteCount(build(AcdcFlowWellKnown.AcdcProbeVersion, placeholder));
        string version = CesrVersionString.WithLength(AcdcFlowWellKnown.AcdcProbeVersion, byteCount);
        string dummied = build(version, placeholder);
        string said = await SaidOf(dummied, pool).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        (IMemoryOwner<byte> owner, int length, string _) = Rent(final, said, pool);

        return new RegistryEvent(owner, length, said);
    }


    /// <summary>
    /// Mints an IPEX exchange (<c>exn</c>) message: a routed, self-addressing KERI message whose SAID is stamped over
    /// its serialization. The grant embeds the disclosed credential under its embeds field; the admit carries no
    /// embed and chains to its grant by the grant's SAID in the prior field.
    /// </summary>
    /// <param name="route">The exchange route (<c>r</c>): the step the message performs.</param>
    /// <param name="sender">The sender AID (<c>i</c>).</param>
    /// <param name="prior">The prior message's SAID (<c>p</c>) this message chains to, or empty when it initiates the exchange.</param>
    /// <param name="embeddedCredentialJson">The disclosed credential's canonical JSON to embed, or <see langword="null"/> for a message that embeds nothing.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted exchange message.</returns>
    private static async Task<ExchangeMessage> MintExchange(string route, string sender, string prior, string? embeddedCredentialJson, MemoryPool<byte> pool)
    {
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"exn","d":"{{said}}","i":"{{sender}}","p":"{{prior}}","dt":"2025-07-04T20:00:00.000000+00:00","r":"{{route}}","a":{},"e":{{Embed(embeddedCredentialJson)}}}""";

        (IMemoryOwner<byte> owner, int length, string said) = await MintWithFixedIdentifier(Build, pool).ConfigureAwait(false);

        return new ExchangeMessage(owner, length, said, route, sender, prior);

        static string Embed(string? credentialJson) => credentialJson is null ? "{}" : $$"""{"acdc":{{credentialJson}}}""";
    }


    /// <summary>Reconstructs an Ed25519 public key from its qualified wire form into pooled memory.</summary>
    /// <param name="keyQb64">The qualified public key.</param>
    /// <param name="pool">The pool the key buffer is rented from.</param>
    /// <returns>The reconstructed public key.</returns>
    private static PublicKeyMemory DeserializeKey(string keyQb64, MemoryPool<byte> pool)
    {
        using CesrParsedPrimitive parsed = CesrPrimitiveCodec.DecodeText(keyQb64, pool);
        IMemoryOwner<byte> owner = pool.Rent(parsed.RawLength);
        parsed.Raw.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, CryptoTags.Ed25519PublicKey);
    }


    /// <summary>Reconstructs an Ed25519 signature from its Base64 wire form into pooled memory.</summary>
    /// <param name="signatureBase64">The Base64 signature.</param>
    /// <param name="pool">The pool the signature buffers are rented from.</param>
    /// <returns>The reconstructed signature.</returns>
    private static Signature DeserializeSignature(string signatureBase64, MemoryPool<byte> pool)
    {
        int maxLength = (signatureBase64.Length / 4) * 3;
        using IMemoryOwner<byte> decoded = pool.Rent(maxLength);
        if(!Convert.TryFromBase64String(signatureBase64, decoded.Memory.Span, out int written))
        {
            throw new FormatException("The published signature is not valid Base64.");
        }

        IMemoryOwner<byte> owner = pool.Rent(written);
        decoded.Memory.Span[..written].CopyTo(owner.Memory.Span);

        return new Signature(owner, CryptoTags.Ed25519Signature);
    }


    /// <summary>Creates a fresh Ed25519 key pair and tracks both halves for disposal.</summary>
    /// <param name="disposables">The list the key material is tracked on for disposal.</param>
    /// <returns>The fresh key material.</returns>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Fresh(List<IDisposable> disposables)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material = Verifiable.Tests.TestDataProviders.TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        disposables.Add(material.PublicKey);
        disposables.Add(material.PrivateKey);

        return material;
    }


    /// <summary>Mints a single-key inception event whose AID is its own SAID.</summary>
    /// <param name="currentKey">The qualified current signing key.</param>
    /// <param name="nextKeyDigest">The pre-rotation commitment to the next key.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The pooled serialization, its length, and the AID.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length, string Said)> MintInception(string currentKey, string nextKeyDigest, MemoryPool<byte> pool)
    {
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"icp","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[]}""";

        return await MintSelfAddressing(Build, pool).ConfigureAwait(false);
    }


    /// <summary>Mints a single-key delegated inception (<c>dip</c>) whose AID is its own SAID and that names its delegator (<c>di</c>).</summary>
    /// <param name="currentKey">The qualified current signing key.</param>
    /// <param name="nextKeyDigest">The pre-rotation commitment to the next key.</param>
    /// <param name="delegatorPrefix">The delegator AID the delegated inception is bound to (its <c>di</c> field).</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The pooled serialization, its length, and the delegated AID.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length, string Said)> MintDelegatedInception(string currentKey, string nextKeyDigest, string delegatorPrefix, MemoryPool<byte> pool)
    {
        string Build(string version, string said, string identifier) =>
            $$"""{"v":"{{version}}","t":"dip","d":"{{said}}","i":"{{identifier}}","s":"0","kt":"1","k":["{{currentKey}}"],"nt":"1","n":["{{nextKeyDigest}}"],"bt":"0","b":[],"c":[],"a":[],"di":"{{delegatorPrefix}}"}""";

        return await MintSelfAddressing(Build, pool).ConfigureAwait(false);
    }


    /// <summary>Mints a sequence-one interaction event whose anchor list carries the given seals.</summary>
    /// <param name="identifier">The AID the interaction belongs to.</param>
    /// <param name="priorSaid">The prior event's SAID.</param>
    /// <param name="seals">The anchor list body (comma-separated seal objects, without the brackets).</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The pooled serialization, its length, and the event SAID.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length, string Said)> MintAnchoringInteraction(string identifier, string priorSaid, string seals, MemoryPool<byte> pool)
    {
        string Build(string version, string said) =>
            $$"""{"v":"{{version}}","t":"ixn","d":"{{said}}","i":"{{identifier}}","s":"1","p":"{{priorSaid}}","a":[{{seals}}]}""";

        return await MintWithFixedIdentifier(Build, pool).ConfigureAwait(false);
    }


    /// <summary>Mints a self-addressing event by stamping its KERI version size, computing its SAID, and substituting it into both the SAID and identifier slots.</summary>
    /// <param name="build">The event-body builder.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The pooled serialization, its length, and the SAID.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length, string Said)> MintSelfAddressing(SelfAddressingEventBuilder build, MemoryPool<byte> pool)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string version = KeriVersionFor(build(AcdcFlowWellKnown.KeriProbeVersion, placeholder, placeholder));
        string dummied = build(version, placeholder, placeholder);
        string said = await SaidOf(dummied, pool).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said, pool);
    }


    /// <summary>Mints a fixed-identifier event by stamping its KERI version size, computing its SAID, and substituting it into the SAID slot.</summary>
    /// <param name="build">The event-body builder.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The pooled serialization, its length, and the SAID.</returns>
    private static async Task<(IMemoryOwner<byte> Owner, int Length, string Said)> MintWithFixedIdentifier(FixedIdentifierEventBuilder build, MemoryPool<byte> pool)
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string version = KeriVersionFor(build(AcdcFlowWellKnown.KeriProbeVersion, placeholder));
        string dummied = build(version, placeholder);
        string said = await SaidOf(dummied, pool).ConfigureAwait(false);
        string final = dummied.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said, pool);
    }


    /// <summary>Rents a pooled buffer for a serialization's UTF-8 bytes.</summary>
    /// <param name="serialization">The serialization text.</param>
    /// <param name="said">The serialization's SAID.</param>
    /// <param name="pool">The pool the buffer is rented from.</param>
    /// <returns>The pooled buffer, its length, and the SAID.</returns>
    private static (IMemoryOwner<byte> Owner, int Length, string Said) Rent(string serialization, string said, MemoryPool<byte> pool)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = pool.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return (owner, length, said);
    }


    /// <summary>Builds the version-1 KERI JSON version string stamping a probe serialization's byte length.</summary>
    /// <param name="probe">The serialization built with a zeroed size.</param>
    /// <returns>The version string with the stamped size.</returns>
    private static string KeriVersionFor(string probe)
    {
        return $"KERI10JSON{Encoding.UTF8.GetByteCount(probe):x6}_";
    }


    /// <summary>Computes the pre-rotation commitment: the SAID of the qualified next key's text.</summary>
    /// <param name="qualifiedKey">The qualified next key.</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <returns>The next-key digest.</returns>
    private static async Task<string> NextKeyDigest(string qualifiedKey, MemoryPool<byte> pool)
    {
        return await SaidOf(qualifiedKey, pool).ConfigureAwait(false);
    }


    /// <summary>Computes the SAID over a serialization's UTF-8 bytes, renting a pooled digest input buffer.</summary>
    /// <param name="serialization">The serialization to digest.</param>
    /// <param name="pool">The pool the digest input buffer is rented from.</param>
    /// <returns>The CESR-encoded SAID.</returns>
    private static async Task<string> SaidOf(string serialization, MemoryPool<byte> pool)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return await CesrSaid.ComputeAsync(owner.Memory[..length], Code, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);
    }


    /// <summary>Signs a serialization with an Ed25519 private key through the production signing function.</summary>
    /// <param name="privateKey">The signing key.</param>
    /// <param name="serialization">The bytes to sign.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The signature.</returns>
    private static async Task<Signature> SignAsync(PrivateKeyMemory privateKey, ReadOnlyMemory<byte> serialization, CancellationToken cancellationToken)
    {
        var sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Ed25519, Purpose.Signing);

        (Signature signature, CryptoEvent? _) = await sign(privateKey.AsReadOnlyMemory(), serialization, BaseMemoryPool.Shared, context: null, cancellationToken: cancellationToken).ConfigureAwait(false);

        return signature;
    }


    /// <summary>Rents a pooled buffer for a text's UTF-8 bytes, tracking the owner for disposal.</summary>
    /// <param name="text">The text to encode.</param>
    /// <param name="disposables">The list the buffer owner is tracked on for disposal.</param>
    /// <param name="pool">The pool the buffer is rented from.</param>
    /// <returns>A view over the encoded bytes.</returns>
    private static ReadOnlyMemory<byte> Utf8(string text, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        IMemoryOwner<byte> owner = pool.Rent(length);
        Encoding.UTF8.GetBytes(text, owner.Memory.Span);
        disposables.Add(owner);

        return owner.Memory[..length];
    }


    /// <summary>Adapts the entry list to the async stream the replayer consumes.</summary>
    /// <param name="entries">The log entries.</param>
    /// <param name="cancellationToken">A token to cancel the enumeration.</param>
    /// <returns>The entries as an async stream.</returns>
    private static async IAsyncEnumerable<LogEntry<KeriKeyEvent, CryptoProof>> ToAsync(List<LogEntry<KeriKeyEvent, CryptoProof>> entries, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<KeriKeyEvent, CryptoProof> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }


    /// <summary>One party in a minted edge chain: its AID, its disclosed ACDC, and its signed KEL.</summary>
    /// <param name="Aid">The party's AID.</param>
    /// <param name="Acdc">The party's disclosed (expanded) ACDC.</param>
    /// <param name="Kel">The party's signed KEL (inception and anchoring interaction).</param>
    internal sealed record EdgeChainParty(string Aid, MintedAcdc Acdc, IReadOnlyList<SignedEvent> Kel);


    /// <summary>
    /// Mints a two-issuer chain-of-authority: a far Issuer (A) issues a targeted credential whose Issuee is the near
    /// Issuer (B), and B issues a near credential with an edge pointing to the far credential. Each Issuer anchors
    /// its credential's SAID in its own KEL. The near credential's default <c>I2I</c> edge therefore holds — B is the
    /// Issuee of the credential its edge points to — so the chain authorizes B's issuance, unless
    /// <paramref name="brokenChain"/> sets the far credential's Issuee to a different AID.
    /// </summary>
    /// <param name="brokenChain">When <see langword="true"/>, the far credential's Issuee is not the near Issuer, breaking the <c>I2I</c> chain.</param>
    /// <param name="disposables">The list the minted material is tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The near party (B and its edge credential) and the far party (A and its targeted credential).</returns>
    public static async Task<(EdgeChainParty Near, EdgeChainParty Far)> MintEdgeChainAsync(bool brokenChain, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> farCurrent = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> farNext = Fresh(disposables);
        string farKeyQb64 = Qualify(farCurrent.PublicKey);
        (IMemoryOwner<byte> farIcpOwner, int farIcpLength, string farAid) = await MintInception(farKeyQb64, await NextKeyDigest(Qualify(farNext.PublicKey), pool), pool);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> nearCurrent = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> nearNext = Fresh(disposables);
        string nearKeyQb64 = Qualify(nearCurrent.PublicKey);
        (IMemoryOwner<byte> nearIcpOwner, int nearIcpLength, string nearAid) = await MintInception(nearKeyQb64, await NextKeyDigest(Qualify(nearNext.PublicKey), pool), pool);

        string issuee = brokenChain ? AcdcFlowWellKnown.UnrelatedIssueeAid : nearAid;
        MintedAcdc far = await MintTargetedAcdc(farAid, issuee, pool);
        disposables.Add(far);
        (IMemoryOwner<byte> farIxnOwner, int farIxnLength, string farIxnSaid) = await MintAnchoringInteraction(farAid, farAid, DigestSeal(far.Said), pool);

        MintedAcdc near = await MintEdgeAcdc(nearAid, far.Said, edgeOperator: null, pool);
        disposables.Add(near);
        (IMemoryOwner<byte> nearIxnOwner, int nearIxnLength, string nearIxnSaid) = await MintAnchoringInteraction(nearAid, nearAid, DigestSeal(near.Said), pool);

        Signature farIcpSignature = await SignAsync(farCurrent.PrivateKey, farIcpOwner.Memory[..farIcpLength], cancellationToken).ConfigureAwait(false);
        Signature farIxnSignature = await SignAsync(farCurrent.PrivateKey, farIxnOwner.Memory[..farIxnLength], cancellationToken).ConfigureAwait(false);
        Signature nearIcpSignature = await SignAsync(nearCurrent.PrivateKey, nearIcpOwner.Memory[..nearIcpLength], cancellationToken).ConfigureAwait(false);
        Signature nearIxnSignature = await SignAsync(nearCurrent.PrivateKey, nearIxnOwner.Memory[..nearIxnLength], cancellationToken).ConfigureAwait(false);

        var farKel = new List<SignedEvent>
        {
            new(farIcpOwner, farIcpLength, farAid, farKeyQb64, farIcpSignature),
            new(farIxnOwner, farIxnLength, farIxnSaid, farKeyQb64, farIxnSignature)
        };
        var nearKel = new List<SignedEvent>
        {
            new(nearIcpOwner, nearIcpLength, nearAid, nearKeyQb64, nearIcpSignature),
            new(nearIxnOwner, nearIxnLength, nearIxnSaid, nearKeyQb64, nearIxnSignature)
        };
        foreach(SignedEvent signed in farKel)
        {
            disposables.Add(signed);
        }

        foreach(SignedEvent signed in nearKel)
        {
            disposables.Add(signed);
        }

        return (new EdgeChainParty(nearAid, near, nearKel), new EdgeChainParty(farAid, far, farKel));
    }


    /// <summary>
    /// Mints a DI2I chain-of-authority across a delegator and its delegate. The delegator (X) self-issues a targeted
    /// far-node credential whose Issuee is X and anchors, in its KEL, both that credential and the delegating seal for
    /// the delegate's delegated inception. The delegate (B) is a delegated AID whose inception (<c>dip</c>) names X as
    /// its delegator; B issues a near credential with a DI2I edge pointing to X's far credential and anchors it in its
    /// own KEL. The DI2I edge holds because B — the near Issuer — is an AID X (the far credential's Issuee) delegated;
    /// I2I would not hold because B is not X itself. When <paramref name="brokenDelegation"/> is set, X does not anchor
    /// B's delegating seal, so the delegation cannot be confirmed and the edge is invalid.
    /// </summary>
    /// <param name="brokenDelegation">When <see langword="true"/>, the delegator's KEL omits the delegate's delegating seal, so the delegation is unverifiable.</param>
    /// <param name="disposables">The list the minted material is tracked on for disposal.</param>
    /// <param name="pool">The pool the minted serializations are rented from.</param>
    /// <param name="cancellationToken">A token to cancel the signing.</param>
    /// <returns>The delegate party (B and its DI2I-edge credential) and the delegator party (X and its far credential).</returns>
    public static async Task<(EdgeChainParty Delegate, EdgeChainParty Delegator)> MintDi2iChainAsync(bool brokenDelegation, List<IDisposable> disposables, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegatorCurrent = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegatorNext = Fresh(disposables);
        string delegatorKeyQb64 = Qualify(delegatorCurrent.PublicKey);
        (IMemoryOwner<byte> delegatorIcpOwner, int delegatorIcpLength, string delegatorAid) = await MintInception(delegatorKeyQb64, await NextKeyDigest(Qualify(delegatorNext.PublicKey), pool), pool);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegateCurrent = Fresh(disposables);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> delegateNext = Fresh(disposables);
        string delegateKeyQb64 = Qualify(delegateCurrent.PublicKey);
        (IMemoryOwner<byte> delegateDipOwner, int delegateDipLength, string delegateAid) = await MintDelegatedInception(delegateKeyQb64, await NextKeyDigest(Qualify(delegateNext.PublicKey), pool), delegatorAid, pool);

        //The far node is a targeted credential the delegator self-issues, so its Issuee is the delegator; the near
        //node the delegate issues carries a DI2I edge pointing to it.
        MintedAcdc far = await MintTargetedAcdc(delegatorAid, delegatorAid, pool);
        disposables.Add(far);
        MintedAcdc near = await MintEdgeAcdc(delegateAid, far.Said, AcdcEdgeOperators.DelegatedIssuerToIssuee, pool);
        disposables.Add(near);

        //The delegator anchors its far credential and, unless the delegation is broken, the delegating seal for the
        //delegate's delegated inception; the delegate anchors its near credential.
        string delegatorSeals = brokenDelegation
            ? DigestSeal(far.Said)
            : DigestSeal(far.Said) + "," + KeyEventSeal(delegateAid, 0, delegateAid);
        (IMemoryOwner<byte> delegatorIxnOwner, int delegatorIxnLength, string delegatorIxnSaid) = await MintAnchoringInteraction(delegatorAid, delegatorAid, delegatorSeals, pool);
        (IMemoryOwner<byte> delegateIxnOwner, int delegateIxnLength, string delegateIxnSaid) = await MintAnchoringInteraction(delegateAid, delegateAid, DigestSeal(near.Said), pool);

        Signature delegatorIcpSignature = await SignAsync(delegatorCurrent.PrivateKey, delegatorIcpOwner.Memory[..delegatorIcpLength], cancellationToken).ConfigureAwait(false);
        Signature delegatorIxnSignature = await SignAsync(delegatorCurrent.PrivateKey, delegatorIxnOwner.Memory[..delegatorIxnLength], cancellationToken).ConfigureAwait(false);
        Signature delegateDipSignature = await SignAsync(delegateCurrent.PrivateKey, delegateDipOwner.Memory[..delegateDipLength], cancellationToken).ConfigureAwait(false);
        Signature delegateIxnSignature = await SignAsync(delegateCurrent.PrivateKey, delegateIxnOwner.Memory[..delegateIxnLength], cancellationToken).ConfigureAwait(false);

        var delegatorKel = new List<SignedEvent>
        {
            new(delegatorIcpOwner, delegatorIcpLength, delegatorAid, delegatorKeyQb64, delegatorIcpSignature),
            new(delegatorIxnOwner, delegatorIxnLength, delegatorIxnSaid, delegatorKeyQb64, delegatorIxnSignature)
        };
        var delegateKel = new List<SignedEvent>
        {
            new(delegateDipOwner, delegateDipLength, delegateAid, delegateKeyQb64, delegateDipSignature),
            new(delegateIxnOwner, delegateIxnLength, delegateIxnSaid, delegateKeyQb64, delegateIxnSignature)
        };
        foreach(SignedEvent signed in delegatorKel)
        {
            disposables.Add(signed);
        }

        foreach(SignedEvent signed in delegateKel)
        {
            disposables.Add(signed);
        }

        return (new EdgeChainParty(delegateAid, near, delegateKel), new EdgeChainParty(delegatorAid, far, delegatorKel));
    }


    /// <summary>
    /// Mints a graduated-disclosure credential: a credential whose attribute section is a block carrying an Issuee
    /// AID and a disclosed attribute field, sealed at two graduation levels. The expanded variant discloses the
    /// attribute values; the compact variant blinds them behind the attribute section's SAID; both compact to the one
    /// committed SAID.
    /// </summary>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="disposables">The list both minted variant serializations are tracked on for disposal.</param>
    /// <param name="pool">The pool the serializations are rented from.</param>
    /// <returns>The minted credential at both graduation levels.</returns>
    private static async Task<GraduatedAcdc> MintGraduatedAcdc(string issuerAid, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        var attribute = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            [AcdcMessageFields.Issuer] = AcdcFlowWellKnown.GraduatedSubjectAid,
            [AcdcFlowWellKnown.GraduatedNameLabel] = AcdcFlowWellKnown.GraduatedSubjectName
        };
        attribute[AcdcMessageFields.Said] = await AcdcCompaction.DeriveSectionSaidAsync(attribute, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        var top = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid,
            [AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid,
            [AcdcMessageFields.Attribute] = attribute
        };

        return await SealGraduatedAcdc(top, issuerAid, disposables, pool).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints an aggregate-section credential presented as a selective disclosure: two blinded attribute blocks (an
    /// Issuee block and a score block) whose SAIDs aggregate into the AGID, the AGID bound into the top-level SAID
    /// through the credential's most-compact form, and a disclosed serialization that reveals the Issuee block and
    /// blinds the score block to its SAID. A Disclosee verifies the revealed block is a member of the AGID and that
    /// the AGID is committed by the top-level SAID, without learning the blinded block's value.
    /// </summary>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="disposables">The list the minted disclosed serialization is tracked on for disposal as it is rented.</param>
    /// <param name="pool">The pool the serializations are rented from.</param>
    /// <returns>The minted, selectively disclosed aggregate credential.</returns>
    private static async Task<AggregateAcdc> MintAggregateAcdc(string issuerAid, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        var issuee = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            [AcdcMessageFields.Issuer] = AcdcFlowWellKnown.AggregateSubjectAid
        };
        issuee[AcdcMessageFields.Said] = await SealBlock(issuee, pool).ConfigureAwait(false);

        var score = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            [AcdcFlowWellKnown.AggregateScoreLabel] = AcdcFlowWellKnown.AggregateScoreValue
        };
        score[AcdcMessageFields.Said] = await SealBlock(score, pool).ConfigureAwait(false);

        string scoreSaid = (string)score[AcdcMessageFields.Said]!;
        var blockSaids = new List<string> { (string)issuee[AcdcMessageFields.Said]!, scoreSaid };
        string agid = await AcdcAggregate.DeriveAgidAsync(blockSaids, Code, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        //The top-level SAID is taken over the most-compact form, whose aggregate section is the AGID alone, so the
        //one Issuer commitment binds the AGID and authenticates any selective disclosure of the set.
        var compactTop = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid,
            [AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid,
            [AcdcMessageFields.AttributeAggregate] = agid
        };
        string topSaid = (string)(await AcdcCompaction.ToCompactFormAsync(compactTop, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false))[AcdcMessageFields.Said]!;

        //The selective disclosure reveals the Issuee block and blinds the score block to its SAID; its top-level SAID
        //is the same committed SAID, restamped to the disclosed byte count.
        var disclosedAggregate = new List<object?> { agid, issuee, scoreSaid };
        var disclosedTop = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid,
            [AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid,
            [AcdcMessageFields.AttributeAggregate] = disclosedAggregate
        };

        MintedAcdc disclosed = SerializeExpanded(disclosedTop, topSaid, issuerAid, pool);
        disposables.Add(disclosed);

        return new AggregateAcdc(disclosed, topSaid, agid);

        static async Task<string> SealBlock(MessageFieldMap block, MemoryPool<byte> pool) =>
            await AcdcCompaction.DeriveSectionSaidAsync(block, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a targeted credential disclosed in expanded form: its attribute section is a block carrying the Issuee
    /// AID, so a Disclosee can read the Issuee an <c>I2I</c> edge checks against.
    /// </summary>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="issueeAid">The credential's Issuee AID (the attribute block's <c>i</c>).</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted, expanded credential.</returns>
    private static async Task<MintedAcdc> MintTargetedAcdc(string issuerAid, string issueeAid, MemoryPool<byte> pool)
    {
        var attribute = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            [AcdcMessageFields.Issuer] = issueeAid,
            ["name"] = "Sunspot College"
        };
        attribute[AcdcMessageFields.Said] = await AcdcCompaction.DeriveSectionSaidAsync(attribute, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        var top = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid,
            [AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid,
            [AcdcMessageFields.Attribute] = attribute
        };

        return await SealExpandedAcdc(top, issuerAid, pool).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a credential disclosed in expanded form whose edge section carries one edge pointing to a far node, so
    /// a Disclosee can read the edge and evaluate the chain-of-authority. The edge carries the given unary operator,
    /// or a far-node schema constraint when none is given.
    /// </summary>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="farNodeSaid">The SAID of the far node the edge points to.</param>
    /// <param name="edgeOperator">The edge's unary operator (<c>o</c>), for example <c>DI2I</c>; <see langword="null"/> for a default-operator edge carrying a far-node schema constraint (<c>s</c>).</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted, expanded credential.</returns>
    private static async Task<MintedAcdc> MintEdgeAcdc(string issuerAid, string farNodeSaid, string? edgeOperator, MemoryPool<byte> pool)
    {
        var edge = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            [AcdcMessageFields.Node] = farNodeSaid
        };

        //An edge carries either its unary operator (o) or a far-node schema constraint (s), both after the node
        //field in canonical order; the DI2I chain uses the operator, the default I2I chain the schema constraint.
        if(edgeOperator is not null)
        {
            edge[AcdcMessageFields.Operator] = edgeOperator;
        }
        else
        {
            edge[AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid;
        }

        edge[AcdcMessageFields.Said] = await AcdcCompaction.DeriveSectionSaidAsync(edge, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        var edgeSection = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Uuid] = AcdcFlowWellKnown.BlockNonce,
            ["accreditation"] = edge
        };
        edgeSection[AcdcMessageFields.Said] = await AcdcCompaction.DeriveSectionSaidAsync(edgeSection, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        var top = new MessageFieldMap(StringComparer.Ordinal)
        {
            [AcdcMessageFields.Version] = AcdcFlowWellKnown.AcdcProbeVersion,
            [AcdcMessageFields.MessageType] = AcdcMessageTypes.Acdc,
            [AcdcMessageFields.Said] = AcdcFlowWellKnown.SaidPlaceholder,
            [AcdcMessageFields.Issuer] = issuerAid,
            [AcdcMessageFields.Schema] = AcdcFlowWellKnown.PlaceholderSchemaSaid,
            [AcdcMessageFields.Edge] = edgeSection
        };

        return await SealExpandedAcdc(top, issuerAid, pool).ConfigureAwait(false);
    }


    /// <summary>
    /// Seals an expanded ACDC for disclosure: compacts it to derive its top-level SAID, substitutes that SAID into
    /// the disclosed expanded form, restamps the version string to the expanded byte count, and serializes the
    /// result into pooled memory. The disclosed form compacts to the same SAID, so a Disclosee verifies it by
    /// compaction.
    /// </summary>
    /// <param name="top">The expanded ACDC field map, its section blocks' SAIDs already filled.</param>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted, expanded credential.</returns>
    private static async Task<MintedAcdc> SealExpandedAcdc(MessageFieldMap top, string issuerAid, MemoryPool<byte> pool)
    {
        return SerializeExpanded(top, await DeriveTopSaid(top, pool).ConfigureAwait(false), issuerAid, pool);
    }


    /// <summary>
    /// Seals an ACDC for graduated disclosure: derives the one top-level SAID the Issuer commits to, then serializes
    /// the credential at two graduation levels from that single derivation — the most-compact form (each section
    /// reduced to its SAID) and the expanded form (the attribute block disclosed). Both forms carry the same SAID and
    /// compact to it, so the one Issuer commitment to that SAID covers every graduation level, as the specification's
    /// most-compact-form SAID derivation requires.
    /// </summary>
    /// <param name="top">The expanded ACDC field map, its section blocks' SAIDs already filled.</param>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="disposables">The list both minted variant serializations are tracked on for disposal as they are rented.</param>
    /// <param name="pool">The pool the serializations are rented from.</param>
    /// <returns>The minted credential at both graduation levels, sharing the one committed SAID.</returns>
    private static async Task<GraduatedAcdc> SealGraduatedAcdc(MessageFieldMap top, string issuerAid, List<IDisposable> disposables, MemoryPool<byte> pool)
    {
        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(top, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);
        string topSaid = (string)compact[AcdcMessageFields.Said]!;

        MintedAcdc compactAcdc = SerializeMap(compact, topSaid, issuerAid, pool);
        disposables.Add(compactAcdc);
        MintedAcdc expandedAcdc = SerializeExpanded(top, topSaid, issuerAid, pool);
        disposables.Add(expandedAcdc);

        return new GraduatedAcdc(compactAcdc, expandedAcdc, topSaid);
    }


    /// <summary>
    /// Derives the top-level SAID of an expanded ACDC: compacts it to its most-compact form and reads the SAID taken
    /// over that form, the value the Issuer commits to.
    /// </summary>
    /// <param name="top">The expanded ACDC field map, its section blocks' SAIDs already filled.</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <returns>The top-level SAID over the most-compact form.</returns>
    private static async Task<string> DeriveTopSaid(MessageFieldMap top, MemoryPool<byte> pool)
    {
        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(top, AcdcJson.Encode, AcdcTestSupport.AgileDigest, pool).ConfigureAwait(false);

        return (string)compact[AcdcMessageFields.Said]!;
    }


    /// <summary>
    /// Serializes an expanded ACDC to pooled memory: fills the disclosed expanded form's top-level SAID, restamps its
    /// version string to the expanded byte count, and serializes the result. The disclosed form compacts to the same
    /// SAID, so a Disclosee verifies it by compaction.
    /// </summary>
    /// <param name="top">The expanded ACDC field map, its section blocks' SAIDs already filled.</param>
    /// <param name="topSaid">The top-level SAID over the most-compact form, filled into the disclosed expanded form.</param>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted, expanded credential.</returns>
    private static MintedAcdc SerializeExpanded(MessageFieldMap top, string topSaid, string issuerAid, MemoryPool<byte> pool)
    {
        top[AcdcMessageFields.Said] = topSaid;

        var probeBuffer = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(top, probeBuffer);
        top[AcdcMessageFields.Version] = CesrVersionString.WithLength(AcdcFlowWellKnown.AcdcProbeVersion, probeBuffer.WrittenCount);

        return SerializeMap(top, topSaid, issuerAid, pool);
    }


    /// <summary>
    /// Serializes a ready ACDC field map (its version string and SAID already stamped) into pooled memory as a minted
    /// credential carrying the given SAID and Issuer.
    /// </summary>
    /// <param name="map">The ready ACDC field map to serialize.</param>
    /// <param name="said">The credential's top-level SAID.</param>
    /// <param name="issuerAid">The credential's Issuer AID.</param>
    /// <param name="pool">The pool the serialization is rented from.</param>
    /// <returns>The minted credential.</returns>
    private static MintedAcdc SerializeMap(MessageFieldMap map, string said, string issuerAid, MemoryPool<byte> pool)
    {
        var buffer = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(map, buffer);

        IMemoryOwner<byte> owner = pool.Rent(buffer.WrittenCount);
        buffer.WrittenSpan.CopyTo(owner.Memory.Span);

        return new MintedAcdc(owner, buffer.WrittenCount, said, issuerAid);
    }


    /// <summary>The over-the-wire envelope for one signed KEL event: the event JSON, the signer's qualified key, and the Base64 signature.</summary>
    /// <param name="Ked">The event's JSON serialization text.</param>
    /// <param name="Key">The signer's qualified public key.</param>
    /// <param name="Sig">The Base64 signature.</param>
    private sealed record KelWireEntry(string Ked, string Key, string Sig);
}
