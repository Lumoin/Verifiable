namespace Verifiable.OAuth.Server;

/// <summary>
/// How long a replay store keeps the record of a <c>jti</c>'s first use: "for the length of time for which the JWT would be
/// considered valid" (RFC 7523 Section 3 item 7). A window that ends at an instant the clock represents keeps the record until
/// that instant, exclusive (<see cref="ReplayRecordKeptUntil"/>); a window that reaches past the clock's last instant keeps it
/// to the clock's end (<see cref="ReplayRecordKeptToTheClocksEnd"/>), which no instant represents, so a store that drops a
/// record once the instant it was kept until is reached is told the two apart rather than handed a last instant that would
/// drop, at that very instant, the record of a token still accepted then. A store drops a record when
/// <see cref="IsDueAt"/> holds, and keeps it otherwise.
/// </summary>
public abstract record ReplayRecordRetention
{
    /// <summary>Whether the record may be dropped at an instant: whether the window it is kept for has ended by then.</summary>
    /// <param name="instant">The instant, by the store's clock.</param>
    /// <returns><see langword="true"/> when the record is no longer kept.</returns>
    public abstract bool IsDueAt(DateTimeOffset instant);
}


/// <summary>
/// The record is kept until an instant the clock represents, exclusive: from <paramref name="End"/> on, the token it records is no
/// longer accepted, and the record may be dropped.
/// </summary>
/// <param name="End">The first instant the record is no longer kept at.</param>
public sealed record ReplayRecordKeptUntil(DateTimeOffset End) : ReplayRecordRetention
{
    /// <inheritdoc/>
    public override bool IsDueAt(DateTimeOffset instant) => instant >= End;
}


/// <summary>
/// The record is kept to the clock's end: the window it is kept for reaches past the latest instant a
/// <see cref="DateTimeOffset"/> represents, so no instant the clock holds lets it be dropped, the clock's last instant included.
/// </summary>
public sealed record ReplayRecordKeptToTheClocksEnd : ReplayRecordRetention
{
    /// <inheritdoc/>
    public override bool IsDueAt(DateTimeOffset instant) => false;
}
