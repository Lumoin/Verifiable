namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The body of an Add Subject request (POST to the Add Subject Endpoint), per
/// OpenID Shared Signals Framework 1.0 §8.1.3.2.
/// </summary>
public sealed record SsfAddSubjectRequest
{
    /// <summary>The <c>stream_id</c> (REQUIRED) of the stream the subject is added to.</summary>
    public required string StreamId { get; init; }

    /// <summary>The <c>subject</c> (REQUIRED) Subject Identifier to add.</summary>
    public required SubjectIdentifier Subject { get; init; }

    /// <summary>
    /// The <c>verified</c> flag (OPTIONAL): whether the Receiver has verified the subject.
    /// <see langword="null"/> when omitted — Transmitters SHOULD then assume verified.
    /// </summary>
    public bool? Verified { get; init; }
}


/// <summary>
/// The body of a Remove Subject request (POST to the Remove Subject Endpoint), per
/// OpenID Shared Signals Framework 1.0 §8.1.3.3.
/// </summary>
public sealed record SsfRemoveSubjectRequest
{
    /// <summary>The <c>stream_id</c> (REQUIRED) of the stream the subject is removed from.</summary>
    public required string StreamId { get; init; }

    /// <summary>The <c>subject</c> (REQUIRED) Subject Identifier to remove.</summary>
    public required SubjectIdentifier Subject { get; init; }
}


/// <summary>
/// The body of a Trigger Verification request (POST to the Verification Endpoint),
/// per OpenID Shared Signals Framework 1.0 §8.1.4.2.
/// </summary>
public sealed record SsfVerificationRequest
{
    /// <summary>The <c>stream_id</c> (REQUIRED) of the stream to verify.</summary>
    public required string StreamId { get; init; }

    /// <summary>
    /// The <c>state</c> (OPTIONAL) opaque value the Transmitter MUST echo back in the
    /// Verification Event's <c>state</c>. <see langword="null"/> when omitted.
    /// </summary>
    public string? State { get; init; }
}
