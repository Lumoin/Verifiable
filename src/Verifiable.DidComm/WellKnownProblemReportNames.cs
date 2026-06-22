using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm;

/// <summary>
/// The well-known names of the DIDComm Report Problem Protocol 2.0 — the <c>problem-report</c> Message Type
/// URI and the <c>body</c> member names — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-reports">DIDComm Messaging v2.1 §Problem Reports</see>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and
/// derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="WellKnownRoutingNames"/> and <see cref="WellKnownDidCommMemberNames"/>. The body member
/// names are the keys of the problem report's <c>body</c> object; like
/// <see cref="WellKnownRoutingNames.Next"/> they are used as dictionary keys when building and reading the
/// body (the message converter treats <c>body</c> as opaque JSON, so these need no allocation-free
/// converter matching, but they follow the same idiom for consistency).
/// </remarks>
public static class WellKnownProblemReportNames
{
    /// <summary>The UTF-8 source literal of <see cref="ProblemReportType"/>.</summary>
    public static ReadOnlySpan<byte> ProblemReportTypeUtf8 => "https://didcomm.org/report-problem/2.0/problem-report"u8;

    /// <summary>
    /// The problem-report Message Type URI — the value of the <c>type</c> header that identifies a message
    /// as a Report Problem Protocol 2.0 problem report (DIDComm v2.1 §Problem Reports).
    /// </summary>
    public static readonly string ProblemReportType = Utf8Constants.ToInternedString(ProblemReportTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Code"/>.</summary>
    public static ReadOnlySpan<byte> CodeUtf8 => "code"u8;

    /// <summary>The problem report <c>body.code</c> member — REQUIRED, the problem code (DIDComm v2.1 §Problem Reports).</summary>
    public static readonly string Code = Utf8Constants.ToInternedString(CodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Comment"/>.</summary>
    public static ReadOnlySpan<byte> CommentUtf8 => "comment"u8;

    /// <summary>The problem report <c>body.comment</c> member — OPTIONAL human-friendly text with <c>{n}</c> interpolation over <see cref="Args"/> (DIDComm v2.1 §Problem Reports).</summary>
    public static readonly string Comment = Utf8Constants.ToInternedString(CommentUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Args"/>.</summary>
    public static ReadOnlySpan<byte> ArgsUtf8 => "args"u8;

    /// <summary>The problem report <c>body.args</c> member — OPTIONAL situation values interpolated into <see cref="Comment"/> (DIDComm v2.1 §Problem Reports).</summary>
    public static readonly string Args = Utf8Constants.ToInternedString(ArgsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EscalateTo"/>.</summary>
    public static ReadOnlySpan<byte> EscalateToUtf8 => "escalate_to"u8;

    /// <summary>The problem report <c>body.escalate_to</c> member — OPTIONAL URI for more help on the issue (DIDComm v2.1 §Problem Reports).</summary>
    public static readonly string EscalateTo = Utf8Constants.ToInternedString(EscalateToUtf8);
}
