using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm.ProblemReports;

/// <summary>
/// Build and interpret for the DIDComm Report Problem Protocol 2.0 <c>problem-report</c> message — turning
/// a semantic <see cref="ProblemReport"/> into a wire <see cref="DidCommMessage"/> and recovering one from
/// a received message, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-reports">DIDComm Messaging v2.1 §Problem Reports</see>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CreateProblemReport"/> is producer-side and MAY throw on bad caller arguments;
/// <see cref="TryInterpretProblemReport"/> reads attacker-controlled wire input and is fail-closed — it
/// never throws, returning <see langword="false"/> for any non-conformant message. The dictionary
/// <c>body</c> is only the wire intermediate: callers operate on the typed <see cref="ProblemReport"/>.
/// </para>
/// <para>
/// Interpretation establishes no trust on its own — the message's authenticity came from the envelope
/// unpack that produced it; this is pure data shaping. So, unlike the proof-bearing from_prior and forward
/// results, the read path is a plain <c>bool TryInterpret… + out</c>.
/// </para>
/// </remarks>
public static class DidCommProblemReportExtensions
{
    //The problem-report Message Type URI, parsed once for semver-compatible handler dispatch.
    private static readonly MessageTypeUri ProblemReportMessageType = MessageTypeUri.Parse(WellKnownProblemReportNames.ProblemReportType);


    /// <summary>
    /// Whether <paramref name="message"/> is a problem report — its <c>type</c> names the problem-report
    /// Message Type URI (DIDComm v2.1 §Problem Reports). The comparison is the spec-mandated MTURI dispatch
    /// match (<see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/>): protocol and message names
    /// ignoring case and punctuation, same major version, under the same documentation URI.
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message type is the problem-report Message Type URI.</returns>
    public static bool IsProblemReport(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(ProblemReportMessageType);
    }


    /// <summary>
    /// Builds a problem-report message from <paramref name="report"/>: <c>type</c> is the problem-report
    /// Message Type URI, <c>pthid</c> is the report's <see cref="ProblemReport.ParentThreadId"/>, the
    /// message-level <c>ack</c> header carries <see cref="ProblemReport.Ack"/>, and the <c>body</c> carries
    /// <c>code</c> (and <c>comment</c>, <c>args</c>, <c>escalate_to</c> when present) (DIDComm v2.1
    /// §Problem Reports).
    /// </summary>
    /// <param name="report">The semantic problem report.</param>
    /// <param name="id">REQUIRED. The problem report's own message id, unique to the sender (DIDComm v2.1 §Message Headers).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <param name="threadId">
    /// OPTIONAL. The thread this report continues. Omit for the first message of the report's own thread
    /// (its <c>id</c> seeds the <c>thid</c>); set it when replying within an existing thread — e.g. a
    /// warning-to-error escalation, which MUST be part of the original warning's thread (DIDComm v2.1
    /// §Replying to Warnings).
    /// </param>
    /// <returns>The problem-report message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty, or the report's <c>pthid</c> is null or empty.</exception>
    public static DidCommMessage CreateProblemReport(this ProblemReport report, string id, string? from = null, string? threadId = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(report.Code);
        ArgumentException.ThrowIfNullOrEmpty(id);

        if(string.IsNullOrEmpty(report.ParentThreadId))
        {
            throw new ArgumentException(
                "A problem report MUST carry a non-empty 'pthid' (DIDComm v2.1 §Problem Reports).",
                nameof(report));
        }

        var body = new Dictionary<string, object>
        {
            [WellKnownProblemReportNames.Code] = report.Code.Value
        };

        if(report.Comment is not null)
        {
            body[WellKnownProblemReportNames.Comment] = report.Comment;
        }

        if(report.Args is not null)
        {
            //A null arg is preserved as a JSON null so the missing-or-null '?' rule is recoverable on the
            //other side (DIDComm v2.1 §Problem Reports). The element type is object? to carry the nulls.
            var args = new List<object?>(report.Args.Count);
            foreach(string? arg in report.Args)
            {
                args.Add(arg);
            }

            body[WellKnownProblemReportNames.Args] = args;
        }

        if(report.EscalateTo is not null)
        {
            body[WellKnownProblemReportNames.EscalateTo] = report.EscalateTo;
        }

        IList<string>? ack = null;
        if(report.Ack is not null)
        {
            ack = [.. report.Ack];
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownProblemReportNames.ProblemReportType,
            From = from,
            ThreadId = threadId,
            ParentThreadId = report.ParentThreadId,
            Ack = ack,
            Body = body
        };
    }


    /// <summary>
    /// Interprets <paramref name="message"/> as a problem report, recovering its semantic
    /// <see cref="ProblemReport"/> — fail-closed: returns <see langword="false"/> without throwing for any
    /// message that is not a conformant problem report (DIDComm v2.1 §Problem Reports).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="report">The recovered problem report when interpretation succeeds.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="message"/> is a problem report with a non-empty
    /// <c>pthid</c> and a <c>body.code</c> that is a string parsing to a well-formed
    /// <see cref="ProblemCode"/>; otherwise <see langword="false"/>. A present-but-non-string
    /// <c>comment</c>/<c>escalate_to</c>, a non-array <c>args</c>, or a non-string <c>args</c> element is a
    /// malformation that fails closed.
    /// </returns>
    public static bool TryInterpretProblemReport(this DidCommMessage message, [NotNullWhen(true)] out ProblemReport? report)
    {
        ArgumentNullException.ThrowIfNull(message);

        report = null;

        if(!message.IsProblemReport())
        {
            return false;
        }

        //pthid is REQUIRED on a problem report (DIDComm v2.1 §Problem Reports).
        if(string.IsNullOrEmpty(message.ParentThreadId))
        {
            return false;
        }

        if(message.Body is not { } body)
        {
            return false;
        }

        //code is REQUIRED, a string, and a well-formed problem code.
        if(!body.TryGetValue(WellKnownProblemReportNames.Code, out object? codeValue)
            || codeValue is not string codeText
            || !ProblemCode.TryParse(codeText, out ProblemCode? code))
        {
            return false;
        }

        if(!TryReadOptionalString(body, WellKnownProblemReportNames.Comment, out string? comment))
        {
            return false;
        }

        if(!TryReadOptionalString(body, WellKnownProblemReportNames.EscalateTo, out string? escalateTo))
        {
            return false;
        }

        if(!TryReadOptionalArgs(body, out IReadOnlyList<string?>? args))
        {
            return false;
        }

        IReadOnlyList<string>? ack = message.Ack is { Count: > 0 } ? [.. message.Ack] : null;

        report = new ProblemReport
        {
            Code = code,
            ParentThreadId = message.ParentThreadId,
            Comment = comment,
            Args = args,
            EscalateTo = escalateTo,
            Ack = ack
        };

        return true;
    }


    //Reads an optional string body member: absent or JSON-null yields null with success; a present
    //non-string value is a malformation and fails.
    private static bool TryReadOptionalString(IDictionary<string, object> body, string member, out string? value)
    {
        value = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return true;
        }

        if(raw is string text)
        {
            value = text;

            return true;
        }

        return false;
    }


    //Reads the optional args array: absent or JSON-null yields null with success; a present value that is
    //not a JSON array, or that holds a non-string, non-null element, is a malformation and fails. JSON
    //null elements are preserved as null slots for the '?' interpolation rule.
    private static bool TryReadOptionalArgs(IDictionary<string, object> body, out IReadOnlyList<string?>? args)
    {
        args = null;
        if(!body.TryGetValue(WellKnownProblemReportNames.Args, out object? raw) || raw is null)
        {
            return true;
        }

        //A string is IEnumerable but is not a JSON array; reject it explicitly.
        if(raw is string || raw is not System.Collections.IEnumerable elements)
        {
            return false;
        }

        var collected = new List<string?>();
        foreach(object? element in elements)
        {
            switch(element)
            {
                case null:
                {
                    collected.Add(null);

                    break;
                }
                case string text:
                {
                    collected.Add(text);

                    break;
                }
                default:
                {
                    return false;
                }
            }
        }

        args = collected;

        return true;
    }
}
