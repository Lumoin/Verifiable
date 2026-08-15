using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The outcome of replaying an issuer's KERI Key Event Log and collecting the seals it anchors.
/// </summary>
/// <remarks>
/// A KEL is accepted only when every event verifies; a single failure makes the whole log invalid, so
/// <see cref="IssuerAid"/> and <see cref="Anchors"/> are populated only when <see cref="IsVerified"/> is
/// <see langword="true"/> — a partially verified log is not handed back as if it were valid.
/// </remarks>
/// <param name="IsVerified">Whether every event in the KEL verified.</param>
/// <param name="IssuerAid">
/// The AID the replay itself established for the KEL — self-certifying at the inception and chain-verified at
/// every later event — when <paramref name="IsVerified"/> is <see langword="true"/>; otherwise <see langword="null"/>.
/// </param>
/// <param name="Anchors">
/// The anchored seals collected from every verified event, each paired with that event's own verified AID
/// (<see cref="KeriAnchoredSeal.Aid"/>), when <paramref name="IsVerified"/> is <see langword="true"/>; otherwise
/// <see langword="null"/>.
/// </param>
/// <param name="EventCount">The number of events processed.</param>
/// <param name="Error">The first verification error, or <see langword="null"/> when every event verified.</param>
public sealed record KeriIssuerAnchorReplayResult(bool IsVerified, string? IssuerAid, IReadOnlyList<KeriAnchoredSeal>? Anchors, long EventCount, string? Error);
