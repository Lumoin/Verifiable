using Lumoin.Base;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Keri;

namespace Verifiable.Acdc;

/// <summary>
/// Verifies an ACDC message and, on success, mints a <see cref="Verified{T}"/> of
/// <see cref="AcdcMessage"/> — the mint-only trust carrier that separates the authenticated value from a
/// freely-constructible wire one, exactly as the credential and DIDComm verify paths mint a
/// <see cref="Verified{T}"/>. A trusted consumer that requires a <see cref="Verified{AcdcMessage}"/> therefore
/// cannot be handed an unverified ACDC: the distinction is enforced by the compiler, not by convention.
/// </summary>
/// <remarks>
/// <para>
/// This is the direct-issuance case (no issuance/revocation registry). Establishing an ACDC's authenticity has two
/// parts, both required before a <see cref="Verified{AcdcMessage}"/> is minted:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Content integrity</strong> — the ACDC's top-level SAID MUST verify over its received bytes
/// (<see cref="AcdcSaid.VerifyAsync"/>), so the decoded <paramref name="message">message</paramref> is bound to
/// <paramref name="acdcBytes">acdcBytes</paramref>: a tampered body cannot reproduce the claimed SAID.
/// </description></item>
/// <item><description>
/// <strong>Issuer binding</strong> — the Issuer's KEL, replayed and verified HERE from <paramref name="issuerKel">issuerKel</paramref>
/// (<see cref="KeriIssuerAnchors.ReplayAsync"/>), MUST anchor a direct issuance proof digest seal of that SAID
/// (<see cref="AcdcKeriBinding.FindDirectIssuanceSeal"/>) under exactly <paramref name="message">message</paramref>'s
/// claimed <see cref="AcdcMessage.Issuer"/> — the Issuer's nonrepudiable commitment to the ACDC that survives later
/// key rotation (ACDC specification,
/// <see href="https://trustoverip.github.io/kswg-acdc-specification/#binding-to-key-state-at-time-of-acdc-state-change">
/// binding to key state</see>).
/// </description></item>
/// </list>
/// <para>
/// This method takes the Issuer's RAW KEL — never a pre-vetted set of anchors — and replays it itself, so the AID a
/// mint rests on is always the product of a KEL that verified inside this call, not a caller's own assertion: a
/// caller cannot shortcut the replay by handing in an anchor it hand-built (<see cref="KeriAnchoredSeal"/>'s own
/// construction boundary makes that unrepresentable) or by claiming an Issuer AID a KEL it supplies does not
/// actually establish (<see cref="BoundProvenance.TryBindByKeriAnchor"/> refuses the mint when the two disagree).
/// The verification context carried by the minted value records the Issuer AID whose key state anchored the
/// issuance, so provenance is visible at the decision point.
/// </para>
/// </remarks>
public static class AcdcVerification
{
    /// <summary>
    /// Verifies an ACDC's direct issuance and mints a <see cref="Verified{AcdcMessage}"/> when it is both
    /// internally authentic (its SAID verifies over its received bytes) and anchored in the Issuer's verified key
    /// state (a direct issuance proof seal of its SAID appears among the Issuer's verified KEL anchors, under the
    /// exact AID <paramref name="message"/> claims as its Issuer).
    /// </summary>
    /// <param name="acdcBytes">The ACDC's received serialization bytes, in the most-compact form its top-level SAID is taken over.</param>
    /// <param name="message">The ACDC message decoded from <paramref name="acdcBytes"/> (the serialization-specific bytes-to-message decode is the caller's; the SAID check binds this message to the bytes).</param>
    /// <param name="issuerKel">The Issuer's raw KEL, in log order: each event's own serialization bytes and its proofs. Replayed and verified inside this call — never taken on faith.</param>
    /// <param name="decodeIssuerKelEvent">The per-serialization decoder for one KEL event's bytes.</param>
    /// <param name="issuerKelSerializationKind">The serialization <paramref name="issuerKel"/> is encoded in.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="timeProvider">The clock the KEL replay consults for any time-bounded check.</param>
    /// <param name="resolveDelegationSeal">Resolves a delegated event's delegating seal from the delegator's KEL, or <see langword="null"/> when <paramref name="issuerKel"/> carries no delegated events.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS) or the KEL replay.</param>
    /// <returns>A <see cref="Verified{AcdcMessage}"/> when content integrity, the KEL replay, and issuer binding all hold; otherwise <see langword="null"/>.</returns>
    /// <exception cref="CesrFormatException">The ACDC's claimed SAID does not begin with a supported digest code.</exception>
    public static async ValueTask<Verified<AcdcMessage>?> VerifyDirectIssuanceAsync(
        ReadOnlyMemory<byte> acdcBytes,
        AcdcMessage message,
        IReadOnlyList<KeriKelEvent> issuerKel,
        KeriEventFieldMapDecoder decodeIssuerKelEvent,
        CesrSerializationKind issuerKelSerializationKind,
        ComputeDigestDelegate computeDigest,
        BaseMemoryPool pool,
        TimeProvider timeProvider,
        DelegationSealResolver? resolveDelegationSeal = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(issuerKel);
        ArgumentNullException.ThrowIfNull(decodeIssuerKelEvent);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        //Content integrity: verify before trusting the value. The SAID recomputes over the received bytes with the
        //field reset to its placeholder, binding the decoded message to those exact bytes.
        if(!await AcdcSaid.VerifyAsync(acdcBytes, message.Said, computeDigest, pool, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        //Issuer binding, part one: replay the Issuer's raw KEL. Only a KEL that verifies end to end yields anchors
        //at all -- there is no caller-supplied shortcut around this replay.
        KeriIssuerAnchorReplayResult replay = await KeriIssuerAnchors.ReplayAsync(
            issuerKel, decodeIssuerKelEvent, issuerKelSerializationKind, computeDigest, pool, timeProvider, resolveDelegationSeal, cancellationToken).ConfigureAwait(false);

        if(!replay.IsVerified || replay.Anchors is null)
        {
            return null;
        }

        //Issuer binding, part two: the replayed KEL must anchor a direct issuance proof seal of this ACDC's SAID.
        KeriAnchoredSeal? matchedAnchor = AcdcKeriBinding.FindDirectIssuanceSeal(replay.Anchors, message.Said);
        if(matchedAnchor is null)
        {
            return null;
        }

        //Issuer binding, part three: the seal's own verified AID must be exactly the AID message claims as its
        //Issuer -- refuses a KEL that genuinely verified but for a different (or substituted) Issuer.
        BoundProvenance? provenance = BoundProvenance.TryBindByKeriAnchor(message.Issuer, matchedAnchor.Aid, message);
        if(provenance is null)
        {
            return null;
        }

        return Verified<AcdcMessage>.TryCreateBound(message, provenance);
    }
}
