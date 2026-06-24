using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Verifiable.DidComm;
using Verifiable.DidComm.ProblemReports;
using Verifiable.Foundation;
using Verifiable.Json;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm v2.1 message conventions in chunk F: the <c>please_ack</c>/<c>ack</c> headers and
/// the Empty Message (<see cref="DidCommAckExtensions"/>), the problem code taxonomy
/// (<see cref="ProblemCode"/>/<see cref="ProblemScope"/>), and the problem report semantic model and
/// build/interpret (<see cref="ProblemReport"/>/<see cref="DidCommProblemReportExtensions"/>).
/// </summary>
/// <remarks>
/// The plaintext round-trip exercises the leaf serializer/parser (<see cref="DidCommMessageJson"/>) and the
/// converter additions, so the ACK headers prove they serialize as top-level arrays and land on the typed
/// members, and a problem report proves <c>pthid</c>/<c>ack</c> sit at the message level while
/// <c>code</c>/<c>comment</c>/<c>args</c>/<c>escalate_to</c> sit in the body.
/// </remarks>
[TestClass]
internal sealed class DidCommAckProblemReportTests
{
    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    private const string Alice = "did:example:alice";
    private const string ProblemReportType = "https://didcomm.org/report-problem/2.0/problem-report";


    private static DidCommMessage RoundTrip(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return packed.UnpackPlaintext(DidCommMessageJson.Parser);
    }


    private static string PackToJson(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return Encoding.UTF8.GetString(packed.AsReadOnlySpan());
    }


    //Joins a sequence for order-sensitive equality, rendering a null element as <null> so a preserved null
    //slot is distinguishable from an absent one.
    private static string Joined<T>(IEnumerable<T>? source)
    {
        Assert.IsNotNull(source);

        return string.Join("|", source!.Select(static x => x?.ToString() ?? "<null>"));
    }


    // ---- ACK headers + Empty Message ------------------------------------------------------------

    [TestMethod]
    public void AckHeadersRoundTripOntoTypedMembers()
    {
        var message = new DidCommMessage
        {
            Id = "xyz",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = Alice,
            ThreadId = "thread-1",
            PleaseAck = ["abc", "def"],
            Ack = ["abc", "def", "xyz"],
            Body = new Dictionary<string, object> { ["k"] = "v" }
        };

        string json = PackToJson(message);
        Assert.Contains("\"please_ack\":[\"abc\",\"def\"]", json, "please_ack MUST serialize as a top-level string array.");
        Assert.Contains("\"ack\":[\"abc\",\"def\",\"xyz\"]", json, "ack MUST serialize as a top-level string array.");

        DidCommMessage roundTripped = RoundTrip(message);

        Assert.AreEqual("abc|def", Joined(roundTripped.PleaseAck), "please_ack MUST land on the typed member.");
        Assert.AreEqual("abc|def|xyz", Joined(roundTripped.Ack), "ack MUST land on the typed member.");

        //The recognized headers must not also leak into the extension-header bag (asserted unconditionally
        //so the check cannot be silently skipped when the bag happens to be null).
        IDictionary<string, object>? extras = roundTripped.AdditionalHeaders;
        Assert.IsTrue(
            extras is null || (!extras.ContainsKey("please_ack") && !extras.ContainsKey("ack")),
            "Recognized please_ack/ack headers MUST NOT fall into AdditionalHeaders.");

        Assert.IsTrue(roundTripped.IsExplicitAck(), "A message carrying ack is an explicit ACK.");
        Assert.IsTrue(roundTripped.RequestsAcknowledgment(), "A message carrying please_ack requests acknowledgment.");
    }


    [TestMethod]
    public void ResolveRequestedAcksExpandsEmptyStringToCurrentId()
    {
        var message = new DidCommMessage
        {
            Id = "msg-1",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            PleaseAck = ["", "abc"]
        };

        Assert.AreEqual("msg-1|abc", Joined(message.ResolveRequestedAcks()), "\"\" MUST expand to the current message id.");

        var multiEmpty = new DidCommMessage { Id = "m9", Type = "https://example.com/x/1.0/y", PleaseAck = ["", "x", ""] };
        Assert.AreEqual("m9|x|m9", Joined(multiEmpty.ResolveRequestedAcks()), "Each \"\" entry expands independently to the current id.");

        var noId = new DidCommMessage { Type = "https://example.com/x/1.0/y", PleaseAck = [""] };
        Assert.IsEmpty(noId.ResolveRequestedAcks(), "An \"\" entry is dropped when the message has no id.");

        var none = new DidCommMessage { Id = "m", Type = "https://example.com/x/1.0/y" };
        Assert.IsEmpty(none.ResolveRequestedAcks(), "No please_ack yields an empty list.");
        Assert.IsFalse(none.RequestsAcknowledgment());
        Assert.IsFalse(none.IsExplicitAck());
    }


    [TestMethod]
    public void EmptyMessageRoundTrips()
    {
        DidCommMessage empty = DidCommAckExtensions.CreateEmptyMessage("empty-1", from: Alice);

        Assert.AreEqual(WellKnownEmptyMessageNames.EmptyType, empty.Type);
        Assert.IsNotNull(empty.Body);
        Assert.IsEmpty(empty.Body!, "The empty message body is the empty object {}.");

        string json = PackToJson(empty);
        Assert.Contains("\"body\":{}", json, "The empty message MUST serialize body as {}.");

        DidCommMessage roundTripped = RoundTrip(empty);
        Assert.AreEqual(WellKnownEmptyMessageNames.EmptyType, roundTripped.Type);
        Assert.IsNotNull(roundTripped.Body);
        Assert.IsEmpty(roundTripped.Body!, "The empty {} body survives the round trip.");
    }


    [TestMethod]
    public void AckOrderIsPreservedThroughRoundTrip()
    {
        //A deliberately out-of-order ack: a serializer/parser that sorted or reversed would be caught here,
        //unlike the already-sorted fixtures (DIDComm v2.1 §ACKs: values MUST appear oldest → most recent).
        var message = new DidCommMessage
        {
            Id = "ack-order",
            Type = "https://example.com/x/1.0/y",
            ThreadId = "t",
            Ack = ["zzz", "aaa", "mmm"]
        };

        Assert.AreEqual("zzz|aaa|mmm", Joined(RoundTrip(message).Ack), "ack order MUST be preserved verbatim.");
    }


    [TestMethod]
    public void CreateAcknowledgmentBuildsPureAck()
    {
        DidCommMessage ack = DidCommAckExtensions.CreateAcknowledgment(["a", "b"], "ack-1", "thread-7", from: Alice);

        Assert.AreEqual(WellKnownEmptyMessageNames.EmptyType, ack.Type, "A pure ACK is an empty message.");
        Assert.AreEqual("thread-7", ack.ThreadId, "An ACK MUST continue the acknowledged thread (thid).");
        Assert.AreEqual("a|b", Joined(ack.Ack));
        Assert.IsNull(ack.PleaseAck, "A pure ACK MUST NOT request an ACK in turn.");
        Assert.IsTrue(ack.IsExplicitAck());
        Assert.IsFalse(ack.RequestsAcknowledgment());

        DidCommMessage roundTripped = RoundTrip(ack);
        Assert.AreEqual("a|b", Joined(roundTripped.Ack));
    }


    [TestMethod]
    public void CreateAcknowledgmentGuardsRejectBadInput()
    {
        Assert.ThrowsExactly<ArgumentException>(() => DidCommAckExtensions.CreateAcknowledgment([], "id", "thid"));
        Assert.ThrowsExactly<ArgumentException>(() => DidCommAckExtensions.CreateAcknowledgment(["a", ""], "id", "thid"));
        Assert.ThrowsExactly<ArgumentException>(() => DidCommAckExtensions.CreateAcknowledgment(["a"], "", "thid"));
        Assert.ThrowsExactly<ArgumentException>(() => DidCommAckExtensions.CreateAcknowledgment(["a"], "id", ""));
        Assert.ThrowsExactly<ArgumentException>(() => DidCommAckExtensions.CreateEmptyMessage(""));
    }


    // ---- Problem code taxonomy -----------------------------------------------------------------

    [TestMethod]
    public void ProblemCodeParsesStructure()
    {
        Assert.IsTrue(ProblemCode.TryParse("e.p.xfer.cant-use-endpoint", out ProblemCode? code));
        Assert.AreEqual(ProblemSorter.Error, code!.Sorter);
        Assert.IsTrue(code.IsError);
        Assert.IsFalse(code.IsWarning);
        Assert.AreEqual("p", code.Scope);
        Assert.AreEqual("xfer|cant-use-endpoint", Joined(code.Descriptors));
        Assert.HasCount(4, code.Tokens);

        Assert.IsTrue(ProblemCode.TryParse("w.m", out ProblemCode? warning), "A two-token code (sorter+scope, no descriptor) is valid.");
        Assert.AreEqual(ProblemSorter.Warning, warning!.Sorter);
        Assert.AreEqual("m", warning.Scope);
        Assert.IsEmpty(warning.Descriptors);

        //An interior doubled hyphen is accepted — the spec names no grammar beyond "lower kebab-case", so
        //the receiver does not fail an otherwise-recoverable code closed over an interior detail.
        Assert.IsTrue(ProblemCode.TryParse("e.p.fo--o", out _), "An interior doubled hyphen is accepted.");
    }


    [TestMethod]
    public void MaxErrorsExceededIsTheSpecCode()
    {
        Assert.AreEqual("e.p.req.max-errors-exceeded", WellKnownProblemCodes.MaxErrorsExceeded);

        ProblemCode code = ProblemCode.Parse(WellKnownProblemCodes.MaxErrorsExceeded);
        Assert.IsTrue(code.IsError);
        Assert.AreEqual("p", code.Scope);
        Assert.IsTrue(code.StartsWith("e.p.req"));
    }


    [TestMethod]
    public void ProblemCodeStartsWithMatchesTokenBoundary()
    {
        ProblemCode code = ProblemCode.Parse("e.p.xfer.cant-use-endpoint");

        Assert.IsTrue(code.StartsWith("e.p.xfer"), "Token-prefix match.");
        Assert.IsTrue(code.StartsWith("e"), "Single-token prefix.");
        Assert.IsTrue(code.StartsWith("e.p.xfer.cant-use-endpoint"), "Full code is its own prefix.");
        Assert.IsFalse(code.StartsWith("e.p.x"), "A non-token-boundary substring MUST NOT match.");
        Assert.IsFalse(code.StartsWith("w"), "A different sorter MUST NOT match.");
        Assert.IsFalse(code.StartsWith("e.p.xfer.cant-use-endpoint.more"), "A longer prefix than the code MUST NOT match.");
        Assert.IsFalse(code.StartsWith(""), "An empty prefix does not match.");
    }


    [TestMethod]
    [DataRow("E.p.x")]          //Uppercase sorter.
    [DataRow("e..x")]           //Empty scope token.
    [DataRow("x.p.foo")]        //Undefined sorter.
    [DataRow("e")]              //Too few tokens (no scope).
    [DataRow("e.p.Foo")]        //Uppercase descriptor.
    [DataRow("e.p.foo-")]       //Trailing hyphen (a token cannot end with a separator).
    [DataRow("e.p.-foo")]       //Leading hyphen (a token cannot begin with a separator).
    [DataRow("e.p.-")]          //A bare separator is not a token.
    [DataRow("e.p.")]           //Trailing dot (empty last token).
    [DataRow("")]               //Empty.
    [DataRow((string?)null)]    //Null.
    public void ProblemCodeRejectsMalformed(string? value)
    {
        Assert.IsFalse(ProblemCode.TryParse(value, out _), $"'{value}' MUST be rejected as malformed.");
    }


    // ---- Comment interpolation -----------------------------------------------------------------

    [TestMethod]
    public void InterpolateCommentReplacesPlaceholders()
    {
        var report = new ProblemReport
        {
            Code = ProblemCode.Parse("e.p.xfer.cant-use-endpoint"),
            ParentThreadId = "parent",
            Comment = "Unable to use the {1} endpoint for {2}.",
            Args = ["https://agents.r.us/inbox", "did:sov:C805sNYhMrjHiqZDTUASHg"]
        };

        Assert.AreEqual(
            "Unable to use the https://agents.r.us/inbox endpoint for did:sov:C805sNYhMrjHiqZDTUASHg.",
            report.InterpolateComment());
    }


    [TestMethod]
    public void InterpolateCommentHandlesMissingNullAndExtraArgs()
    {
        //A referenced index with no arg is rendered as '?'; the supplied-but-unreferenced arg is appended.
        Assert.AreEqual("a ? b, x", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "a {3} b", Args = ["x"] }.InterpolateComment());

        //A null arg is rendered as '?'.
        Assert.AreEqual("v=?", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "v={1}", Args = [null] }.InterpolateComment());

        //An extra (unreferenced) arg is appended as a comma-separated value.
        Assert.AreEqual("got one=one, two", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "got {1}={1}", Args = ["one", "two"] }.InterpolateComment());

        //A gap arg — supplied but referenced by no placeholder — MUST still be appended, never dropped.
        Assert.AreEqual("a and c, b", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "{1} and {3}", Args = ["a", "b", "c"] }.InterpolateComment());

        //No placeholders, no args: the comment passes through verbatim.
        Assert.AreEqual("plain text", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "plain text" }.InterpolateComment());

        //A placeholder with no args at all is a missing arg → '?'.
        Assert.AreEqual("?", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "{1}" }.InterpolateComment());

        //A null comment interpolates to null.
        Assert.IsNull(new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = null }.InterpolateComment());

        //A literal brace that is not a {digit} token passes through.
        Assert.AreEqual("a {x} {0} b", new ProblemReport { Code = Warn(), ParentThreadId = "p", Comment = "a {x} {0} b" }.InterpolateComment());
    }


    // ---- Problem report build / interpret ------------------------------------------------------

    [TestMethod]
    public void ProblemReportRoundTrips()
    {
        var report = new ProblemReport
        {
            Code = ProblemCode.Parse("e.p.xfer.cant-use-endpoint"),
            ParentThreadId = "1e513ad4-48c9-444e-9e7e-5b8b45c5e325",
            Comment = "Unable to use the {1} endpoint for {2}.",
            Args = ["https://agents.r.us/inbox", null],
            EscalateTo = "mailto:admin@foo.org",
            Ack = ["1e513ad4-48c9-444e-9e7e-5b8b45c5e325"]
        };

        DidCommMessage message = report.CreateProblemReport("7c9de639-c51c-4d60-ab95-103fa613c805", from: Alice);
        Assert.IsTrue(message.IsProblemReport());
        Assert.AreEqual(report.ParentThreadId, message.ParentThreadId, "pthid sits at the message level.");
        Assert.IsTrue(message.IsExplicitAck(), "The report's ack sits at the message level.");

        string json = PackToJson(message);
        Assert.Contains("\"code\":\"e.p.xfer.cant-use-endpoint\"", json, "code sits in the body.");
        Assert.Contains("\"args\":[\"https://agents.r.us/inbox\",null]", json, "A null arg is preserved as JSON null.");

        DidCommMessage parsed = RoundTrip(message);
        Assert.IsTrue(parsed.TryInterpretProblemReport(out ProblemReport? recovered));

        Assert.AreEqual(report.Code.Value, recovered!.Code.Value);
        Assert.AreEqual(report.Comment, recovered.Comment);
        Assert.AreEqual(report.EscalateTo, recovered.EscalateTo);
        Assert.AreEqual(report.ParentThreadId, recovered.ParentThreadId);
        Assert.AreEqual("https://agents.r.us/inbox|<null>", Joined(recovered.Args), "Args incl. the null slot survive the round trip.");
        Assert.AreEqual("1e513ad4-48c9-444e-9e7e-5b8b45c5e325", Joined(recovered.Ack));
    }


    [TestMethod]
    public void MinimalProblemReportRoundTrips()
    {
        //Only the REQUIRED code + pthid; no comment/args/escalate_to/ack. Exercises the absent-optional
        //branches of CreateProblemReport and the null-on-absence reads of TryInterpretProblemReport.
        var report = new ProblemReport
        {
            Code = ProblemCode.Parse("e.m.msg.bad-format"),
            ParentThreadId = "parent-7"
        };

        DidCommMessage message = report.CreateProblemReport("min-1");
        Assert.IsFalse(message.IsExplicitAck(), "A report with no ack is not an explicit ACK.");

        string json = PackToJson(message);
        Assert.DoesNotContain("\"comment\"", json, "An absent comment MUST NOT be emitted.");
        Assert.DoesNotContain("\"args\"", json, "Absent args MUST NOT be emitted.");
        Assert.DoesNotContain("\"escalate_to\"", json, "An absent escalate_to MUST NOT be emitted.");
        Assert.DoesNotContain("\"ack\"", json, "An absent ack MUST NOT be emitted.");

        Assert.IsTrue(RoundTrip(message).TryInterpretProblemReport(out ProblemReport? recovered));
        Assert.AreEqual("e.m.msg.bad-format", recovered!.Code.Value);
        Assert.AreEqual("parent-7", recovered.ParentThreadId);
        Assert.IsNull(recovered.Comment);
        Assert.IsNull(recovered.Args);
        Assert.IsNull(recovered.EscalateTo);
        Assert.IsNull(recovered.Ack);
    }


    [TestMethod]
    public void TryInterpretProblemReportFailsClosed()
    {
        //Wrong type.
        Assert.IsFalse(Message("https://example.com/x/1.0/y", "p", Body(("code", "e.p.x"))).TryInterpretProblemReport(out _));

        //Missing code.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("comment", "no code"))).TryInterpretProblemReport(out _));

        //Non-string code.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", 7))).TryInterpretProblemReport(out _));

        //Unparseable code.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", "X.bad"))).TryInterpretProblemReport(out _));

        //Missing pthid.
        Assert.IsFalse(Message(ProblemReportType, null, Body(("code", "e.p.x"))).TryInterpretProblemReport(out _));

        //Non-string comment.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", "e.p.x"), ("comment", 1))).TryInterpretProblemReport(out _));

        //Non-string escalate_to.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", "e.p.x"), ("escalate_to", 1))).TryInterpretProblemReport(out _));

        //args not an array.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", "e.p.x"), ("args", "not-an-array"))).TryInterpretProblemReport(out _));

        //args with a non-string element.
        Assert.IsFalse(Message(ProblemReportType, "p", Body(("code", "e.p.x"), ("args", new List<object?> { "ok", 5 }))).TryInterpretProblemReport(out _));

        //Missing body.
        var noBody = new DidCommMessage { Id = "i", Type = ProblemReportType, ParentThreadId = "p" };
        Assert.IsFalse(noBody.TryInterpretProblemReport(out _));
    }


    [TestMethod]
    public void EscalateWarningToErrorEnforcesScopeBreadth()
    {
        var warning = new ProblemReport
        {
            Code = ProblemCode.Parse("w.p.msg.bad-lang"),
            ParentThreadId = "parent-thread"
        };

        ProblemReport escalated = warning.EscalateWarningToError(ProblemCode.Parse("e.p.msg.bad-lang"), comment: "Now an error.");
        Assert.IsTrue(escalated.Code.IsError);
        Assert.AreEqual("parent-thread", escalated.ParentThreadId, "The escalation stays under the same parent thread.");

        //Narrowing the scope (p → m) MUST be rejected.
        Assert.ThrowsExactly<ArgumentException>(() => warning.EscalateWarningToError(ProblemCode.Parse("e.m.msg.bad-lang")));

        //A non-error escalated code MUST be rejected.
        Assert.ThrowsExactly<ArgumentException>(() => warning.EscalateWarningToError(ProblemCode.Parse("w.p.msg.bad-lang")));

        //An equally-broad state-name scope (rank 1 → 1) is allowed; widening (state → p) is allowed.
        var stateWarning = new ProblemReport { Code = ProblemCode.Parse("w.get-pay-details.payment-failed"), ParentThreadId = "t" };
        Assert.IsTrue(stateWarning.EscalateWarningToError(ProblemCode.Parse("e.p.payment-failed")).Code.IsError, "state-name → p widens the scope.");
        Assert.ThrowsExactly<ArgumentException>(() => stateWarning.EscalateWarningToError(ProblemCode.Parse("e.m.payment-failed")), "state-name → m narrows the scope.");

        //Escalating a non-warning report MUST be rejected.
        var error = new ProblemReport { Code = ProblemCode.Parse("e.p.x"), ParentThreadId = "t" };
        Assert.ThrowsExactly<InvalidOperationException>(() => error.EscalateWarningToError(ProblemCode.Parse("e.p.y")));
    }


    // ---- helpers -------------------------------------------------------------------------------

    private static ProblemCode Warn() => ProblemCode.Parse("w.p.msg");


    private static Dictionary<string, object> Body(params (string Key, object? Value)[] members)
    {
        var body = new Dictionary<string, object>();
        foreach((string key, object? value) in members)
        {
            body[key] = value!;
        }

        return body;
    }


    private static DidCommMessage Message(string type, string? parentThreadId, Dictionary<string, object> body)
    {
        return new DidCommMessage
        {
            Id = "message-id",
            Type = type,
            ParentThreadId = parentThreadId,
            Body = body
        };
    }
}
