namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of the Subject-management and Verification request bodies of
/// the Stream Management API, per OpenID Shared Signals Framework 1.0 §8.1.3 /
/// §8.1.4. Shared by Receiver (which sends them) and Transmitter (which reads them).
/// </summary>
public static class SsfStreamManagementParameterNames
{
    /// <summary><c>stream_id</c> — REQUIRED stream identifier (all stream-management requests).</summary>
    public static readonly string StreamId = "stream_id";

    /// <summary><c>subject</c> — REQUIRED Subject Identifier (Add/Remove Subject, §8.1.3).</summary>
    public static readonly string Subject = "subject";

    /// <summary>
    /// <c>verified</c> — OPTIONAL boolean (Add Subject, §8.1.3.2): whether the Receiver has verified
    /// the subject. If omitted, Transmitters SHOULD assume verified.
    /// </summary>
    public static readonly string Verified = "verified";

    /// <summary>
    /// <c>state</c> — OPTIONAL opaque string (Trigger Verification, §8.1.4.2) the Transmitter MUST
    /// echo back in the Verification Event payload.
    /// </summary>
    public static readonly string State = "state";
}
