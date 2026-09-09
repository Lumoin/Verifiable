using System;
using System.Collections.Generic;
using Verifiable.Core.Transport;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests for <see cref="HttpHeaderSet"/>, the transport-neutral header set every outbound and
/// inbound header lookup in the library reads through. Each case pins one RFC 9110 field
/// sentence: names compare case-insensitively, a name's repeated field lines keep their received
/// order and are never comma-joined, a sender composing a set cannot emit a second field line for
/// a name unless it declares the field a list, a name must be a token, and a value may carry no
/// CR, LF, or NUL. The set is immutable, so every composing call is proved to leave its receiver
/// untouched.
/// </summary>
[TestClass]
internal sealed class HttpHeaderSetTests
{
    private const string JsonMediaType = "application/json";
    private const string RedirectTarget = "https://relying-party.example/next";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5">RFC 9110, Section 5</see>: "HTTP
    /// uses "fields" to provide data in the form of extensible name/value pairs with a registered key
    /// namespace. Fields are sent and received within the header and trailer sections of messages".
    /// A section that carries no field line yields no name and no count.
    /// </summary>
    [TestMethod]
    public void EmptySetCarriesNoFields()
    {
        HttpHeaderSet headers = HttpHeaderSet.Empty;

        Assert.AreEqual(0, headers.Count, "RFC 9110 Section 5: a header section with no field line carries no name/value pair.");
        Assert.IsEmpty(headers.Names, "RFC 9110 Section 5: the empty section names no field.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5">RFC 9110, Section 5</see>: "HTTP
    /// uses "fields" to provide data in the form of extensible name/value pairs with a registered key
    /// namespace." Two field lines with differing names are two such pairs.
    /// </summary>
    [TestMethod]
    public void EachDistinctFieldNameIsOneEntry()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs(
            (WellKnownHttpHeaderNames.ContentType, JsonMediaType),
            (WellKnownHttpHeaderNames.Location, RedirectTarget));

        Assert.AreEqual(2, headers.Count, "RFC 9110 Section 5: two field lines with differing names are two name/value pairs.");
        Assert.IsTrue(headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType), "Content-Type was composed onto the set and must be present.");
        Assert.AreEqual(JsonMediaType, contentType, "The Content-Type field value is carried verbatim.");
        Assert.IsTrue(headers.TryGetValue(WellKnownHttpHeaderNames.Location, out string? location), "Location was composed onto the set and must be present.");
        Assert.AreEqual(RedirectTarget, location, "The Location field value is carried verbatim.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>:
    /// "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer
    /// Protocol (HTTP) Field Name Registry"". A lookup therefore matches whatever casing the caller
    /// spells, not the casing the set stored.
    /// </summary>
    /// <param name="spelling">A casing of the <c>Content-Type</c> field name.</param>
    [TestMethod]
    [DataRow("content-type")]
    [DataRow("CONTENT-TYPE")]
    [DataRow("Content-Type")]
    [DataRow("cOnTeNt-TyPe")]
    public void FieldNameLookupIsCaseInsensitive(string spelling)
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, JsonMediaType));

        Assert.IsTrue(headers.Contains(spelling), $"RFC 9110 Section 5.1: field names are case-insensitive, so '{spelling}' must be found.");
        Assert.IsTrue(headers.TryGetValue(spelling, out string? value), $"RFC 9110 Section 5.1: '{spelling}' must read the stored field value.");
        Assert.AreEqual(JsonMediaType, value, "The value read through a differently cased name is the same value.");
        Assert.HasCount(1, headers.GetValues(spelling), "RFC 9110 Section 5.1: the case-insensitive name reads the same single field line.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>:
    /// "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer
    /// Protocol (HTTP) Field Name Registry"". Because the received casing carries no meaning, a
    /// registered name is named by the canonical spelling its defining specification uses; a name
    /// outside the library's table is named exactly as first received.
    /// </summary>
    [TestMethod]
    public void ARegisteredNameIsNamedByItsCanonicalSpelling()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs(
            ("content-type", JsonMediaType),
            ("X-Relying-Party-Trace", "abc"));

        Assert.AreEqual(WellKnownHttpHeaderNames.ContentType, headers.Names[0], "RFC 9110 Section 5.1: a registered field name is named by its canonical spelling.");
        Assert.AreEqual("X-Relying-Party-Trace", headers.Names[1], "An unregistered field name keeps the casing it was first received under.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "The
    /// order in which field lines with differing field names are received in a section is not
    /// significant. However, it is good practice to send header fields that contain additional control
    /// data first, such as Host on requests and Date on responses, so that implementations can decide
    /// when not to handle a message as early as possible." The set never reorders names, so a sender
    /// keeps the ordering it chose.
    /// </summary>
    [TestMethod]
    public void NamesKeepFirstAppearanceOrder()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs(
            (WellKnownHttpHeaderNames.Date, "Tue, 15 Nov 1994 08:12:31 GMT"),
            (WellKnownHttpHeaderNames.ContentType, JsonMediaType),
            (WellKnownHttpHeaderNames.Location, RedirectTarget));

        Assert.AreEqual(WellKnownHttpHeaderNames.Date, headers.Names[0], "RFC 9110 Section 5.3: the control-data field the sender put first stays first.");
        Assert.AreEqual(WellKnownHttpHeaderNames.ContentType, headers.Names[1], "RFC 9110 Section 5.3: first-appearance order is preserved.");
        Assert.AreEqual(WellKnownHttpHeaderNames.Location, headers.Names[2], "RFC 9110 Section 5.3: first-appearance order is preserved.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name
    /// into one field line". That combinable list is what <see cref="HttpHeaderSet.GetValues(string)"/>
    /// hands back, so a field the section never carried has an empty list of field lines, never a
    /// missing one.
    /// </summary>
    [TestMethod]
    public void AnAbsentFieldHasAnEmptyValueList()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, JsonMediaType));

        IReadOnlyList<string> values = headers.GetValues(WellKnownHttpHeaderNames.Location);

        Assert.IsNotNull(values, "RFC 9110 Section 5.3: an absent field's list of field lines is empty, not null.");
        Assert.IsEmpty(values, "RFC 9110 Section 5.3: a field section that carried no Location field line has no Location value.");
        Assert.IsFalse(headers.Contains(WellKnownHttpHeaderNames.Location), "A field never composed onto the set is not present.");
        Assert.IsFalse(headers.TryGetValue(WellKnownHttpHeaderNames.Location, out string? first), "An absent field has no first value.");
        Assert.IsNull(first, "An absent field yields a null first value.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "The
    /// order in which field lines with the same name are received is therefore significant to the
    /// interpretation of the field value; a proxy MUST NOT change the order of these field line values
    /// when forwarding a message." Combining them is only a recipient's MAY — "A recipient MAY combine
    /// multiple field lines … by appending each subsequent field line value to the initial field line
    /// value in order, separated by a comma" — so the set hands back the separate values and never
    /// joins them on the caller's behalf.
    /// </summary>
    [TestMethod]
    public void RepeatedFieldLinesKeepOrderAndAreNeverJoined()
    {
        HttpHeaderSet headers = new HttpHeaderSet.Builder()
            .AddValues("Via", ["1.1 a", "1.1 b"])
            .Build();

        Assert.AreEqual(1, headers.Count, "Repeated field lines with the same name are one field, not two.");
        Assert.IsTrue(headers.TryGetValue("Via", out string? first), "The Via field is present.");
        Assert.AreEqual("1.1 a", first, "RFC 9110 Section 5.3: the first received field line stays first.");

        IReadOnlyList<string> values = headers.GetValues("Via");

        Assert.HasCount(2, values, "RFC 9110 Section 5.3: both field lines are carried.");
        Assert.AreEqual("1.1 a", values[0], "RFC 9110 Section 5.3: a proxy MUST NOT change the order of these field line values.");
        Assert.AreEqual("1.1 b", values[1], "RFC 9110 Section 5.3: a proxy MUST NOT change the order of these field line values.");

        foreach(string value in values)
        {
            Assert.DoesNotContain(",", value, StringComparison.Ordinal, "RFC 9110 Section 5.3: combining the field lines with a comma is a recipient MAY, so the set never does it for the caller.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "a
    /// sender MUST NOT generate multiple field lines with the same name in a message (whether in the
    /// headers or trailers) or append a field line when a field line of the same name already exists in
    /// the message, unless that field's definition allows multiple field line values to be recombined as
    /// a comma-separated list". Composing a second single field line for a name already present is that
    /// prohibited generation and is refused.
    /// </summary>
    [TestMethod]
    public void ASecondFieldLineForAPresentNameIsRefused()
    {
        var builder = new HttpHeaderSet.Builder().Add(WellKnownHttpHeaderNames.Accept, JsonMediaType);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => _ = builder.Add(WellKnownHttpHeaderNames.Accept, "application/jwt"),
            "RFC 9110 Section 5.3: a sender MUST NOT append a field line when a field line of the same name already exists.");

        Assert.Contains(WellKnownHttpHeaderNames.Accept, exception.Message, StringComparison.Ordinal, "The refusal names the field whose second line was refused.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: the
    /// same prohibition's escape clause — a sender MUST NOT generate multiple field lines with the same
    /// name "unless that field's definition allows multiple field line values to be recombined as a
    /// comma-separated list". A caller declares the field a list in one call, which is the only way a
    /// second value reaches a name. RFC 9110 Section 5.3 also notes that "In practice, the "Set-Cookie"
    /// header field ([COOKIE]) often appears in a response message across multiple field lines and does
    /// not use the list syntax, violating the above requirements on multiple field lines with the same
    /// field name": that exception is composed the same declared way, never as two single field lines.
    /// </summary>
    [TestMethod]
    public void AListValuedFieldIsDeclaredAsSuchWhenComposed()
    {
        var builder = new HttpHeaderSet.Builder().AddValues("Set-Cookie", ["a=1", "b=2"]);
        HttpHeaderSet headers = builder.Build();

        Assert.HasCount(2, headers.GetValues("Set-Cookie"), "RFC 9110 Section 5.3: a field composed as a list carries every field line the caller declared.");
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = builder.AddValues("Set-Cookie", ["c=3"]),
            "RFC 9110 Section 5.3: even a list-valued field is declared once; a second declaration would append field lines behind the caller's back.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name
    /// into one field line, without changing the semantics of the message, by appending each subsequent
    /// field line value to the initial field line value in order". Received field lines are what
    /// <see cref="HttpHeaderSet.FromPairs"/> models, so repeated names group into one field whose values
    /// keep the received order — the recipient's MAY taken as far as grouping and no further.
    /// </summary>
    [TestMethod]
    public void ReceivedRepeatedFieldLinesGroupUnderOneName()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs(
            ("Via", "1.1 a"),
            (WellKnownHttpHeaderNames.ContentType, JsonMediaType),
            ("via", "1.1 b"));

        Assert.AreEqual(2, headers.Count, "RFC 9110 Section 5.3: two field lines with the same name are one field.");
        Assert.AreEqual("Via", headers.Names[0], "RFC 9110 Section 5.3: the grouped field keeps the position of its first received line.");
        Assert.HasCount(2, headers.GetValues("Via"), "RFC 9110 Section 5.3: both received field lines are kept.");
        Assert.AreEqual("1.1 a", headers.GetValues("Via")[0], "RFC 9110 Section 5.3: the order in which field lines with the same name are received is significant.");
        Assert.AreEqual("1.1 b", headers.GetValues("Via")[1], "RFC 9110 Section 5.3: the order in which field lines with the same name are received is significant.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "a
    /// sender MUST NOT generate multiple field lines with the same name in a message … or append a field
    /// line when a field line of the same name already exists in the message". A composed set is
    /// therefore never edited in place: <see cref="HttpHeaderSet.With(string, string)"/> yields a second
    /// set, and a message already composed from the first keeps exactly the field lines it had.
    /// </summary>
    [TestMethod]
    public void WithYieldsANewSetAndLeavesTheOriginalUntouched()
    {
        HttpHeaderSet original = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, JsonMediaType));

        HttpHeaderSet extended = original.With(WellKnownHttpHeaderNames.Accept, "application/jwt");

        Assert.AreEqual(1, original.Count, "The original set is unchanged: it still carries exactly its one field.");
        Assert.IsFalse(original.Contains(WellKnownHttpHeaderNames.Accept), "The original set never gained the field added to the new one.");
        Assert.AreEqual(JsonMediaType, original.ContentType, "The original set's field value is unchanged.");
        Assert.AreEqual(2, extended.Count, "The new set carries the original field plus the added one.");
        Assert.AreEqual(JsonMediaType, extended.ContentType, "The new set carries the original field forward.");
        Assert.AreEqual("application/jwt", extended.Accept, "The new set carries the added field.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "The
    /// order in which field lines with the same name are received is therefore significant to the
    /// interpretation of the field value". Restating a list-valued field therefore states the whole
    /// ordered list at once — <see cref="HttpHeaderSet.WithValues(string, IReadOnlyList{string})"/>
    /// replaces the name's field lines on the new set and never appends to the original's.
    /// </summary>
    [TestMethod]
    public void WithValuesReplacesOnTheNewSetOnly()
    {
        HttpHeaderSet original = new HttpHeaderSet.Builder().AddValues("Via", ["1.1 a"]).Build();

        HttpHeaderSet replaced = original.WithValues("Via", ["1.1 b", "1.1 c"]);

        Assert.HasCount(1, original.GetValues("Via"), "The original set keeps exactly the field lines it was built with.");
        Assert.AreEqual("1.1 a", original.GetValues("Via")[0], "The original set's field value is unchanged.");
        Assert.HasCount(2, replaced.GetValues("Via"), "The new set carries the restated field lines, not the sum of both.");
        Assert.AreEqual("1.1 b", replaced.GetValues("Via")[0], "RFC 9110 Section 5.3: the restated field lines keep the order the caller gave.");
        Assert.AreEqual("1.1 c", replaced.GetValues("Via")[1], "RFC 9110 Section 5.3: the restated field lines keep the order the caller gave.");
        Assert.AreEqual(1, replaced.Count, "Restating a field does not add a second entry for the same name.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>: "The
    /// "Content-Type" header field indicates the media type of the associated representation".
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.2">RFC 9110, Section 10.2.2</see>:
    /// "The "Location" header field is used in some responses to refer to a specific resource in relation
    /// to the response." The conveniences read those two, and <c>Accept</c>, through the registered names
    /// rather than through a caller-spelled literal, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>'s
    /// case-insensitivity holds for them too.
    /// </summary>
    [TestMethod]
    public void TheConveniencesReadThroughTheRegisteredNames()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromPairs(
            ("content-type", JsonMediaType),
            ("ACCEPT", "application/jwt"),
            ("location", RedirectTarget));

        Assert.AreEqual(JsonMediaType, headers.ContentType, "RFC 9110 Section 8.3: the Content-Type convenience reads the media type of the associated representation.");
        Assert.AreEqual("application/jwt", headers.Accept, "RFC 9110 Section 5.1: the Accept convenience matches the field regardless of the received casing.");
        Assert.AreEqual(RedirectTarget, headers.Location, "RFC 9110 Section 10.2.2: the Location convenience reads the referred resource.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>: "If a
    /// Content-Type header field is not present, the recipient MAY either assume a media type of
    /// "application/octet-stream" ([RFC2046], Section 4.5.1) or examine the data to determine its type."
    /// The set therefore reports the field's absence rather than inventing a default: the convenience is
    /// null, leaving that MAY with the caller.
    /// </summary>
    [TestMethod]
    public void TheConveniencesAreNullWhenTheFieldIsAbsent()
    {
        HttpHeaderSet headers = HttpHeaderSet.Empty;

        Assert.IsNull(headers.ContentType, "RFC 9110 Section 8.3: an absent Content-Type is reported absent, not defaulted by the set.");
        Assert.IsNull(headers.Accept, "An absent Accept field is reported absent.");
        Assert.IsNull(headers.Location, "An absent Location field is reported absent.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>:
    /// "field-name = token", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110, Section 5.6.2</see>:
    /// "Tokens are short textual identifiers that do not include whitespace or delimiters", over "tchar
    /// = "!" / "#" / "$" / "%" / "&amp;" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" /
    /// DIGIT / ALPHA ; any VCHAR, except delimiters". A name carrying a space, a delimiter, or nothing at
    /// all is not a field name and is refused rather than composed onto a message.
    /// </summary>
    /// <param name="name">A candidate field name that is not an RFC 9110 token.</param>
    [TestMethod]
    [DataRow("Content Type")]
    [DataRow("Content-Type:")]
    [DataRow("")]
    [DataRow("Accept/Json")]
    public void AFieldNameThatIsNotATokenIsRefused(string name)
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = HttpHeaderSet.FromPairs((name, JsonMediaType)),
            $"RFC 9110 Section 5.6.2: '{name}' is not a token, so it is not a field name.");
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new HttpHeaderSet.Builder().Add(name, JsonMediaType),
            $"RFC 9110 Section 5.6.2: '{name}' is not a token, so the builder refuses it too.");
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = HttpHeaderSet.Empty.With(name, JsonMediaType),
            $"RFC 9110 Section 5.6.2: '{name}' is not a token, so it cannot be composed onto an existing set.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.5">RFC 9110, Section 5.5</see>: "Field
    /// values containing CR, LF, or NUL characters are invalid and dangerous, due to the varying ways
    /// that implementations might parse and interpret those characters; a recipient of CR, LF, or NUL
    /// within a field value MUST either reject the message or replace each of those characters with SP
    /// before further processing or forwarding of that message." Every value on this set is composed by
    /// a caller, so the set takes the reject arm: a transport that serialises the set can never be made
    /// to emit an injected field line.
    /// </summary>
    /// <param name="value">A candidate field value carrying CR, LF, or NUL.</param>
    [TestMethod]
    [DataRow("application/json\r\nX-Injected: yes")]
    [DataRow("application/json\nX-Injected: yes")]
    [DataRow("application/json\rX-Injected: yes")]
    [DataRow("application/json\0")]
    public void AFieldValueCarryingCarriageReturnLineFeedOrNulIsRefused(string value)
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, value)),
            "RFC 9110 Section 5.5: a field value containing CR, LF, or NUL is invalid and dangerous and is rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new HttpHeaderSet.Builder().Add(WellKnownHttpHeaderNames.ContentType, value),
            "RFC 9110 Section 5.5: the builder rejects such a value at every composition point.");
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = HttpHeaderSet.Empty.WithValues(WellKnownHttpHeaderNames.ContentType, [value]),
            "RFC 9110 Section 5.5: a list-valued composition rejects such a value too.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name
    /// into one field line". A receiving transport that surfaces an ordinal-keyed map can hand
    /// <see cref="HttpHeaderSet.FromReceived"/> the same name under two castings (<c>X-Foo</c> and
    /// <c>x-foo</c>); the recipient's case-insensitive grouping still folds them into one field.
    /// </summary>
    [TestMethod]
    public void FromReceivedGroupsACasingCollidingNameIntoOneField()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromReceived(
        [
            ("X-Foo", "first"),
            ("x-foo", "second"),
        ]);

        Assert.AreEqual(1, headers.Count, "RFC 9110 Section 5.3: a recipient MAY combine field lines with the same name (case-insensitively) into one field.");
        IReadOnlyList<string> values = headers.GetValues("X-Foo");
        Assert.HasCount(2, values, "Both differently-cased field lines are kept as separate values of the one field.");
        Assert.AreEqual("first", values[0], "Received order is preserved across the casing collision.");
        Assert.AreEqual("second", values[1], "Received order is preserved across the casing collision.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.5">RFC 9110, Section 5.5</see>: "a
    /// recipient of CR, LF, or NUL within a field value MUST either reject the message or replace each
    /// of those characters with SP before further processing or forwarding of that message."
    /// <see cref="HttpHeaderSet.FromReceived"/> is the recipient side of that sentence and takes the
    /// replace arm, unlike every composing-side entry point, which rejects.
    /// </summary>
    [TestMethod]
    public void FromReceivedReplacesCarriageReturnLineFeedAndNulWithSpace()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromReceived(
        [
            (WellKnownHttpHeaderNames.ContentType, "application/json\r\nX-Injected:\nyes\0"),
        ]);

        Assert.IsTrue(headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? value), "The received field is present, not rejected.");
        Assert.AreEqual("application/json  X-Injected: yes ", value, "RFC 9110 Section 5.5: every CR, LF, or NUL is replaced with SP rather than rejecting the message.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110, Section 5.6.2</see>:
    /// "field-name = token". A field line whose name is not a token cannot have been a well-formed field
    /// line, so <see cref="HttpHeaderSet.FromReceived"/> drops it rather than throwing out of the whole
    /// receive path the way the composing-side entry points do.
    /// </summary>
    [TestMethod]
    public void FromReceivedDropsAFieldLineWhoseNameIsNotAToken()
    {
        HttpHeaderSet headers = HttpHeaderSet.FromReceived(
        [
            ("Content Type", JsonMediaType),
            (WellKnownHttpHeaderNames.Accept, "application/jwt"),
        ]);

        Assert.AreEqual(1, headers.Count, "RFC 9110 Section 5.6.2: the non-token name names no field and is dropped.");
        Assert.IsFalse(headers.Contains("Content Type"), "The dropped field line is not present under any spelling.");
        Assert.AreEqual("application/jwt", headers.Accept, "The well-formed field line survives the drop of its neighbour.");
    }
}
