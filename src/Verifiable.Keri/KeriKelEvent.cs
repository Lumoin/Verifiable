using System;
using System.Collections.Immutable;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Keri;

/// <summary>
/// One key event's serialization bytes and its attached proofs, in key event log order — the per-event input a
/// caller reconstructs from an issuer's published KEL before <see cref="KeriIssuerAnchors.ReplayAsync"/> replays
/// it.
/// </summary>
/// <remarks>
/// The event's typed <see cref="KeriKeyEvent"/> (its <see cref="KeriKeyEvent.Prefix"/>, signing keys, and anchors)
/// is never taken from the caller: <see cref="KeriIssuerAnchors.ReplayAsync"/> decodes it itself from
/// <see cref="EventBytes"/>, exactly as the event's own SAID (field <c>d</c>) is recomputed over those same
/// bytes — so a caller cannot supply an AID independent of the bytes the replay actually verifies.
/// </remarks>
/// <param name="EventBytes">The event's own serialization bytes, in the exact form its SAID is taken over.</param>
/// <param name="Proofs">The proofs over <paramref name="EventBytes"/> — conventionally the controller proof first, any witness proofs after.</param>
public sealed record KeriKelEvent(ReadOnlyMemory<byte> EventBytes, ImmutableArray<CryptoProof> Proofs);
