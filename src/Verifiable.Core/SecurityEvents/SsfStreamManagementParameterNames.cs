using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of the Subject-management and Verification request bodies of
/// the Stream Management API, per OpenID Shared Signals Framework 1.0 §8.1.3 /
/// §8.1.4. Shared by Receiver (which sends them) and Transmitter (which reads them).
/// </summary>
public static class SsfStreamManagementParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="StreamId"/>.</summary>
    public static ReadOnlySpan<byte> StreamIdUtf8 => "stream_id"u8;

    /// <summary><c>stream_id</c> — REQUIRED stream identifier (all stream-management requests).</summary>
    public static readonly string StreamId = Utf8Constants.ToInternedString(StreamIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Subject"/>.</summary>
    public static ReadOnlySpan<byte> SubjectUtf8 => "subject"u8;

    /// <summary><c>subject</c> — REQUIRED Subject Identifier (Add/Remove Subject, §8.1.3).</summary>
    public static readonly string Subject = Utf8Constants.ToInternedString(SubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Verified"/>.</summary>
    public static ReadOnlySpan<byte> VerifiedUtf8 => "verified"u8;

    /// <summary>
    /// <c>verified</c> — OPTIONAL boolean (Add Subject, §8.1.3.2): whether the Receiver has verified
    /// the subject. If omitted, Transmitters SHOULD assume verified.
    /// </summary>
    public static readonly string Verified = Utf8Constants.ToInternedString(VerifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="State"/>.</summary>
    public static ReadOnlySpan<byte> StateUtf8 => "state"u8;

    /// <summary>
    /// <c>state</c> — OPTIONAL opaque string (Trigger Verification, §8.1.4.2) the Transmitter MUST
    /// echo back in the Verification Event payload.
    /// </summary>
    public static readonly string State = Utf8Constants.ToInternedString(StateUtf8);
}
