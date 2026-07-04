namespace Verifiable.Keri;

/// <summary>
/// The outcome of replaying a KERI Key Event Log served as a CESR stream (a <c>keri.cesr</c>): whether every
/// event verified through the shipped replayer, the final verified key state, how many events were read, and the
/// first verification error when one occurred.
/// </summary>
/// <remarks>
/// A KEL is accepted only when every event verifies; a single failure makes the whole log invalid, so
/// <see cref="KeyState"/> is the final key state only when <see cref="IsVerified"/> is <see langword="true"/> and
/// is <see langword="null"/> otherwise — a partially verified log is not handed back as if it were valid.
/// </remarks>
/// <param name="IsVerified">Whether every event in the stream verified.</param>
/// <param name="KeyState">The final verified key state when <paramref name="IsVerified"/> is <see langword="true"/>; otherwise <see langword="null"/>.</param>
/// <param name="EventCount">The number of events read from the stream.</param>
/// <param name="Error">The first verification error, or <see langword="null"/> when every event verified.</param>
public sealed record KeriKeyEventStreamReplayResult(bool IsVerified, KeriKeyState? KeyState, long EventCount, string? Error);
