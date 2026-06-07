using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The parsed, typed view of a Security Event Token's claims, as defined by
/// <see href="https://www.rfc-editor.org/rfc/rfc8417">RFC 8417</see> and the
/// subject-identifier extension of
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see>.
/// </summary>
/// <remarks>
/// This is a projection of the verified JWT payload — produced only after the
/// SET's signature has been verified. Optional claims are <see langword="null"/>
/// when absent; <see cref="Events"/> is never null but may be empty if the
/// <c>events</c> claim was missing or malformed (a condition the verification
/// pipeline flags separately).
/// </remarks>
public sealed record SecurityEventToken
{
    /// <summary>The <c>iss</c> claim — the SET issuer (Transmitter). <see langword="null"/> if absent.</summary>
    public string? Issuer { get; init; }

    /// <summary>The <c>iat</c> claim as a timestamp. <see langword="null"/> if absent or unparseable.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>The <c>jti</c> claim — the per-token unique identifier. <see langword="null"/> if absent.</summary>
    public string? JwtId { get; init; }

    /// <summary>The <c>aud</c> claim values (a SET may carry one or many). Never null; may be empty.</summary>
    public IReadOnlyList<string> Audiences { get; init; } = [];

    /// <summary>The <c>toe</c> (time of event) claim as a timestamp. <see langword="null"/> if absent.</summary>
    public DateTimeOffset? TimeOfEvent { get; init; }

    /// <summary>The <c>txn</c> (transaction) claim. <see langword="null"/> if absent.</summary>
    public string? Transaction { get; init; }

    /// <summary>The <c>sub_id</c> subject identifier. <see langword="null"/> if absent or malformed.</summary>
    public SubjectIdentifier? SubjectId { get; init; }

    /// <summary>The events carried in the <c>events</c> claim. Never null; may be empty.</summary>
    public IReadOnlyList<SecurityEvent> Events { get; init; } = [];
}
