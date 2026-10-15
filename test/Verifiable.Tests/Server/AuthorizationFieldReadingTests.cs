namespace Verifiable.Tests.Server;

/// <summary>
/// <see cref="AuthorizationFieldReading.Read"/> over the field lines a request carries: absent, one line
/// read by the <c>credentials</c> grammar of
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>, or
/// repeated.
/// </summary>
[TestClass]
internal sealed class AuthorizationFieldReadingTests
{
    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>: a
    /// request without an <c>Authorization</c> field line reads as absent, with no scheme and no
    /// credentials.
    /// </summary>
    [TestMethod]
    public void ARequestWithoutTheFieldReadsAsAbsent()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(RequestHeaders.Empty);

        Assert.IsTrue(reading.IsAbsent);
        Assert.IsFalse(reading.IsRepeated);
        Assert.IsNull(reading.Scheme);
        Assert.IsNull(reading.Credentials);
        Assert.IsFalse(reading.IsWellFormed);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]". One line <c>Basic Y2xpZW50OnNlY3JldA==</c>
    /// reads as well-formed with the scheme <c>Basic</c> and the token68 credentials.
    /// </summary>
    [TestMethod]
    public void OneLineOfTheToken68FormIsWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Basic Y2xpZW50OnNlY3JldA=="));

        Assert.IsFalse(reading.IsAbsent);
        Assert.IsFalse(reading.IsRepeated);
        Assert.IsTrue(reading.IsWellFormed);
        Assert.AreEqual("Basic", reading.Scheme);
        Assert.AreEqual("Y2xpZW50OnNlY3JldA==", reading.Credentials);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "auth-param     = token BWS "=" BWS ( token / quoted-string )". One line of a comma-separated list of
    /// parameters, a token value and a quoted-string value with a quoted-pair, reads as well-formed.
    /// </summary>
    [TestMethod]
    public void OneLineOfTheAuthParamFormIsWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(
            HeadersOf("Example name=value, other = \"quoted \\\" text\""));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.AreEqual("Example", reading.Scheme);
        Assert.AreEqual("name=value, other = \"quoted \\\" text\"", reading.Credentials);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme:", followed by "auth-scheme    = token". A
    /// line whose scheme is written
    /// <c>bearer</c> is the <c>Bearer</c> scheme.
    /// </summary>
    [TestMethod]
    public void ALowerCaseSchemeMatchesCaseInsensitively()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("bearer an-access-token"));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.IsTrue(reading.IsScheme("Bearer"));
        Assert.IsFalse(reading.IsScheme("Basic"));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> forbids a sender
    /// to generate a second field line of a name already in the message unless the field's definition is a
    /// list, and <c>Authorization = credentials</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) is not.
    /// Two field lines read as repeated, with no scheme.
    /// </summary>
    [TestMethod]
    public void TwoLinesReadAsRepeated()
    {
        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Basic Y2xpZW50OnNlY3JldA==", "Basic Y2xpZW50OnNlY3JldA=="]
        });

        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(headers);

        Assert.IsTrue(reading.IsRepeated);
        Assert.IsFalse(reading.IsAbsent);
        Assert.IsFalse(reading.IsWellFormed);
        Assert.IsNull(reading.Scheme);
        Assert.IsFalse(reading.IsScheme("Basic"));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18).", over two field lines that
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>'s
    /// <c>Authorization = credentials</c> does not make a list, each line's scheme compared case-insensitively ("It uses
    /// a case-insensitive token to identify the authentication scheme", Section 11.1). The scheme every line names is
    /// read as the first line sends it: <c>Bearer a</c> and <c>Bearer b</c> name <c>Bearer</c>; <c>DPoP a</c> and
    /// <c>dpop b</c> name <c>DPoP</c>; <c>Bearer a</c> and <c>DPoP b</c> name no one scheme; <c>Bearer a</c> and a line
    /// holding no scheme token, <c>=a</c>, name no one scheme. The reading is in process: the field lines are its input.
    /// </summary>
    /// <param name="first">The first field line.</param>
    /// <param name="second">The second field line.</param>
    /// <param name="expectedScheme">The scheme every line names, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DataRow("Bearer a", "Bearer b", "Bearer", DisplayName = "two Bearer lines")]
    [DataRow("DPoP a", "dpop b", "DPoP", DisplayName = "DPoP and dpop")]
    [DataRow("Bearer a", "DPoP b", null, DisplayName = "Bearer and DPoP")]
    [DataRow("Bearer a", "=a", null, DisplayName = "a line with no scheme token")]
    public void RepeatedLinesNameTheirOneScheme(string first, string second, string? expectedScheme)
    {
        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = [first, second]
        });

        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(headers);

        Assert.IsTrue(reading.IsRepeated);
        Assert.IsNull(reading.Scheme);
        Assert.AreEqual(expectedScheme, reading.RepeatedScheme);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>: a value
    /// whose credentials are neither a token68 nor a list of auth-params, here a token68 followed by a
    /// second word, is outside the grammar.
    /// </summary>
    [TestMethod]
    public void AValueOutsideTheGrammarIsNotWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Bearer one two"));

        Assert.IsFalse(reading.IsAbsent);
        Assert.IsFalse(reading.IsRepeated);
        Assert.IsFalse(reading.IsWellFormed);
        Assert.AreEqual("Bearer", reading.Scheme);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>:
    /// "auth-scheme    = token", and a token holds at least one character. One empty field line carries no
    /// scheme token: it is present, not repeated, and not well-formed, with an empty scheme.
    /// </summary>
    [TestMethod]
    public void AnEmptyLineIsNotWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf(string.Empty));

        Assert.IsFalse(reading.IsAbsent);
        Assert.IsFalse(reading.IsRepeated);
        Assert.IsFalse(reading.IsWellFormed);
        Assert.AreEqual(string.Empty, reading.Scheme);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", the separator one or more SP. A line
    /// whose scheme and token68 are separated by HTAB, <c>Basic</c> HTAB <c>Y2xpZW50OnNlY3JldA==</c>, is not
    /// well-formed, and the reading's text names that and holds no part of the value, neither the scheme nor
    /// the credential.
    /// </summary>
    [TestMethod]
    public void ALineSeparatedByATabRendersNoPartOfItsValue()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Basic\tY2xpZW50OnNlY3JldA=="));

        Assert.IsFalse(reading.IsWellFormed);
        Assert.AreEqual("AuthorizationFieldReading(NotWellFormed)", reading.ToString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>:
    /// "auth-scheme    = token". The reading bounds the scheme it accepts at 20 characters, a policy of this
    /// library: the longest name in the <see href="https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml">IANA HTTP
    /// Authentication Scheme Registry</see> is <c>SCRAM-SHA-256</c>, 13 characters, and a refused scheme
    /// is written back in a challenge. A line whose scheme is 20 characters long is well-formed.
    /// </summary>
    [TestMethod]
    public void ASchemeOfTwentyCharactersIsWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("abcdefghijklmnopqrst a-token"));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.AreEqual("abcdefghijklmnopqrst", reading.Scheme);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>:
    /// "auth-scheme    = token". The reading bounds the scheme it accepts at 20 characters, a policy of this
    /// library: the longest name in the <see href="https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml">IANA HTTP
    /// Authentication Scheme Registry</see> is <c>SCRAM-SHA-256</c>, 13 characters, and a refused scheme
    /// is written back in a challenge. A line whose scheme is 21 characters long is not well-formed.
    /// </summary>
    [TestMethod]
    public void ASchemeOfTwentyOneCharactersIsNotWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("abcdefghijklmnopqrstu a-token"));

        Assert.IsFalse(reading.IsWellFormed);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>: "In other
    /// words, a recipient MUST accept lists that satisfy the following syntax:", followed by
    /// "#element => [ element ] *( OWS "," OWS [ element ] )". A line whose auth-param list starts with an empty
    /// element, white space before its comma, <c>Basic</c> SP HTAB <c>, a=b</c>, is well-formed.
    /// </summary>
    [TestMethod]
    public void AnEmptyFirstListElementBeforeOptionalWhiteSpaceIsWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Basic \t, a=b"));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.AreEqual("Basic", reading.Scheme);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>:
    /// "#element => [ element ] *( OWS "," OWS [ element ] )", so optional white space stands before a list's comma,
    /// not before its first element. A line whose first auth-param follows
    /// HTAB with no comma, <c>Basic</c> SP HTAB <c>a=b</c>, is not well-formed.
    /// </summary>
    [TestMethod]
    public void WhiteSpaceBeforeTheFirstParameterWithoutACommaIsNotWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Basic \ta=b"));

        Assert.IsFalse(reading.IsWellFormed);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", the scheme followed by one or more SP. A
    /// line whose empty first list element follows the scheme with HTAB and no SP, <c>Basic</c> HTAB
    /// <c>, a=b</c>, is not well-formed.
    /// </summary>
    [TestMethod]
    public void AnEmptyFirstListElementWithoutTheSpaceAfterTheSchemeIsNotWellFormed()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Basic\t, a=b"));

        Assert.IsFalse(reading.IsWellFormed);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "credentials = "Bearer" 1*SP b64token". The line <c>Bearer mF_9.B5f-4.1JqM</c>, the section's own example,
    /// is well-formed and its credentials are a token68.
    /// </summary>
    [TestMethod]
    public void ABearerLineOfTheToken68FormHasToken68Credentials()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Bearer mF_9.B5f-4.1JqM"));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.IsTrue(reading.HasToken68Credentials);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "credentials = "Bearer" 1*SP b64token". The line <c>Bearer a=b</c> is well-formed by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>'s
    /// <c>#auth-param</c> alternative, and its credentials are not a token68, so it carries no access token.
    /// </summary>
    [TestMethod]
    public void ABearerLineOfTheAuthParamFormHasNoToken68Credentials()
    {
        AuthorizationFieldReading reading = AuthorizationFieldReading.Read(HeadersOf("Bearer a=b"));

        Assert.IsTrue(reading.IsWellFormed);
        Assert.IsFalse(reading.HasToken68Credentials);
    }


    /// <summary>The request headers of one <c>Authorization</c> field line holding <paramref name="value"/>.</summary>
    /// <param name="value">The field line's value.</param>
    /// <returns>The headers.</returns>
    private static RequestHeaders HeadersOf(string value) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = [value]
        });
}
