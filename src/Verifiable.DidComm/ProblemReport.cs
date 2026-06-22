using System.Collections.Generic;
using System.Text;

namespace Verifiable.DidComm;

/// <summary>
/// The semantic content of a DIDComm problem report — the typed view of its <c>body</c> plus the
/// correlation headers an application constructs and reads, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-reports">DIDComm Messaging v2.1 §Problem Reports</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the operate-on form: an application builds a <see cref="ProblemReport"/> with a typed
/// <see cref="ProblemCode"/> and turns it into a wire <see cref="DidCommMessage"/> via
/// <see cref="DidCommProblemReportExtensions.CreateProblemReport"/>, or recovers one from a received
/// message via <see cref="DidCommProblemReportExtensions.TryInterpretProblemReport"/>. The dictionary
/// <c>body</c> is only the wire intermediate inside those operations and is never exposed here.
/// </para>
/// <para>
/// A problem report begins a new CHILD thread of the context in which the problem occurred, so
/// <see cref="ParentThreadId"/> (the <c>pthid</c>) is REQUIRED and references the parent's thread id
/// (DIDComm v2.1 §Problem Reports). Recovering this type carries no cryptographic proof — authenticity was
/// established by the envelope unpack that produced the <see cref="DidCommMessage"/>; interpretation is
/// purely shaping wire data into the typed view, which is why the read path is a plain
/// <c>bool TryInterpret…</c> rather than a proof-bearing result.
/// </para>
/// </remarks>
public sealed record ProblemReport
{
    /// <summary>REQUIRED. The problem code categorizing what went wrong (DIDComm v2.1 §Problem Codes).</summary>
    public required ProblemCode Code { get; init; }

    /// <summary>
    /// REQUIRED. The <c>pthid</c> — the thread id of the thread in which the problem occurred. The report
    /// begins a child thread of that parent (DIDComm v2.1 §Problem Reports).
    /// </summary>
    public required string ParentThreadId { get; init; }

    /// <summary>
    /// OPTIONAL. Human-friendly text describing the problem, statically associated with <see cref="Code"/>
    /// and supporting <c>{n}</c> interpolation over <see cref="Args"/> (DIDComm v2.1 §Problem Reports).
    /// </summary>
    public string? Comment { get; init; }

    /// <summary>
    /// OPTIONAL. Situation-specific values interpolated into <see cref="Comment"/>. A null element is
    /// preserved so it renders as <c>?</c> during interpolation, per the spec's missing-or-null rule
    /// (DIDComm v2.1 §Problem Reports).
    /// </summary>
    public IReadOnlyList<string?>? Args { get; init; }

    /// <summary>OPTIONAL. A URI where additional help on the issue can be received (DIDComm v2.1 §Problem Reports).</summary>
    public string? EscalateTo { get; init; }

    /// <summary>
    /// OPTIONAL. The ids of messages this report acknowledges. SHOULD be set when the problem was triggered
    /// directly by a preceding message (DIDComm v2.1 §Problem Reports). Conveyed as the message-level
    /// <c>ack</c> header, not in the body.
    /// </summary>
    public IReadOnlyList<string>? Ack { get; init; }


    /// <summary>
    /// Renders <see cref="Comment"/> with <see cref="Args"/> interpolated, per
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#problem-reports">DIDComm Messaging v2.1 §Problem Reports</see>:
    /// each <c>{n}</c> token (1-based) is replaced by <see cref="Args"/>[n-1], a missing or null arg is
    /// replaced by <c>?</c>, and any arg not referenced by a token is appended to the text as a
    /// comma-separated value.
    /// </summary>
    /// <returns>The rendered comment, or <see langword="null"/> when <see cref="Comment"/> is <see langword="null"/>.</returns>
    public string? InterpolateComment()
    {
        if(Comment is null)
        {
            return null;
        }

        string comment = Comment;
        IReadOnlyList<string?> args = Args ?? [];
        var builder = new StringBuilder(comment.Length);
        var referencedIndexes = new HashSet<int>();

        int i = 0;
        while(i < comment.Length)
        {
            //A '{' followed by one or more ASCII digits and a '}' is a 1-based argument placeholder;
            //anything else (including a literal '{' or '{0}') passes through verbatim.
            if(comment[i] == '{')
            {
                int j = i + 1;
                while(j < comment.Length && char.IsAsciiDigit(comment[j]))
                {
                    ++j;
                }

                if(j > i + 1 && j < comment.Length && comment[j] == '}'
                    && int.TryParse(comment.AsSpan(i + 1, j - i - 1), out int oneBasedIndex)
                    && oneBasedIndex >= 1)
                {
                    referencedIndexes.Add(oneBasedIndex);
                    builder.Append(ResolveArgument(args, oneBasedIndex - 1));
                    i = j + 1;

                    continue;
                }
            }

            builder.Append(comment[i]);
            ++i;
        }

        //Extra args — every arg no placeholder referenced — are appended in order as comma-separated
        //values so no supplied detail is lost; a null value renders as '?' (DIDComm v2.1 §Problem Reports:
        //"extra args MUST be appended to the main text as comma-separated values").
        for(int index = 1; index <= args.Count; ++index)
        {
            if(!referencedIndexes.Contains(index))
            {
                builder.Append(", ");
                builder.Append(ResolveArgument(args, index - 1));
            }
        }

        return builder.ToString();
    }


    /// <summary>
    /// Produces the reply problem report a recipient sends when it decides this warning is actually an
    /// error, per
    /// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#replying-to-warnings">DIDComm Messaging v2.1 §Replying to Warnings</see>.
    /// The reply carries the same <see cref="ParentThreadId"/> as this warning; the caller places it in
    /// this warning's thread (sets the reply message's <c>thid</c>) when building the message, since the
    /// two MUST be part of the same thread. The escalated report's <see cref="Comment"/>, <see cref="Args"/>,
    /// <see cref="EscalateTo"/>, and <see cref="Ack"/> come from the arguments and are NOT inherited from
    /// this warning — omitting them clears them (the spec permits the escalated text to differ; pass the
    /// originals to retain them).
    /// </summary>
    /// <param name="escalatedCode">The error code. MUST begin with <c>e.</c> and its scope MUST be at least as broad as this warning's scope.</param>
    /// <param name="comment">OPTIONAL. The escalated comment; MAY differ from this warning's.</param>
    /// <param name="args">OPTIONAL. The escalated args.</param>
    /// <param name="escalateTo">OPTIONAL. A URI for more help.</param>
    /// <param name="acknowledgedMessageIds">OPTIONAL. The ids the reply acknowledges (e.g. this warning's message id).</param>
    /// <returns>The escalated error problem report.</returns>
    /// <exception cref="InvalidOperationException">Thrown when this report is not a warning.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="escalatedCode"/> is not an error code, or its scope is narrower than this warning's scope.</exception>
    public ProblemReport EscalateWarningToError(
        ProblemCode escalatedCode,
        string? comment = null,
        IReadOnlyList<string?>? args = null,
        string? escalateTo = null,
        IReadOnlyList<string>? acknowledgedMessageIds = null)
    {
        ArgumentNullException.ThrowIfNull(escalatedCode);

        if(!Code.IsWarning)
        {
            throw new InvalidOperationException(
                "Only a warning problem report can be escalated to an error (DIDComm v2.1 §Replying to Warnings).");
        }

        if(!escalatedCode.IsError)
        {
            throw new ArgumentException(
                "The escalated code MUST be an error code beginning with 'e.' (DIDComm v2.1 §Replying to Warnings).",
                nameof(escalatedCode));
        }

        if(!ProblemScope.IsAtLeastAsBroadAs(escalatedCode.Scope, Code.Scope))
        {
            throw new ArgumentException(
                $"The escalated scope '{escalatedCode.Scope}' MUST be at least as broad as the original " +
                $"scope '{Code.Scope}' (DIDComm v2.1 §Replying to Warnings).",
                nameof(escalatedCode));
        }

        return this with
        {
            Code = escalatedCode,
            Comment = comment,
            Args = args,
            EscalateTo = escalateTo,
            Ack = acknowledgedMessageIds
        };
    }


    //Resolves a 1-based argument position to its value, rendering a missing or null arg as '?'
    //(DIDComm v2.1 §Problem Reports: "Missing or null args MUST be replaced with a question mark").
    private static string ResolveArgument(IReadOnlyList<string?> args, int zeroBasedIndex)
    {
        if(zeroBasedIndex < 0 || zeroBasedIndex >= args.Count)
        {
            return "?";
        }

        return args[zeroBasedIndex] ?? "?";
    }
}
