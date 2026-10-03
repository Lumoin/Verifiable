using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// <see cref="ClientCredentialReading.Read"/> over a request's <c>Authorization</c> field and its form
/// fields: the client authentication mechanisms presented, and the one reason a request whose credential
/// is malformed is refused before any authentication seam
/// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>).
/// </summary>
[TestClass]
internal sealed class ClientCredentialReadingTests
{
    /// <summary>
    /// The <c>Authorization</c> value of a <c>Basic</c> credential. It is a constant because a <c>DataRow</c>
    /// argument must be one.
    /// </summary>
    private const string BasicCredential = "Basic Y2xpZW50OnNlY3JldA==";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 Section 2.3</see>: "The client
    /// MUST NOT use more than one authentication method in each request." A request presenting exactly one
    /// mechanism, a <c>Basic</c> field, a field of another scheme, a form secret or a form assertion, reads
    /// as that one mechanism and is not malformed.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> value, or <see langword="null"/> for none.</param>
    /// <param name="fieldName">The one credential form field, or <see langword="null"/> for none.</param>
    /// <param name="mechanism">The mechanism the reading names.</param>
    [TestMethod]
    [DataRow(BasicCredential, null, "basic")]
    [DataRow("Bearer an-access-token", null, "other")]
    [DataRow(null, "client_secret", "secret")]
    [DataRow(null, "client_assertion", "assertion")]
    public void EachMechanismAloneIsOneMechanism(string? authorization, string? fieldName, string mechanism)
    {
        RequestFields fields = new();
        if(fieldName is not null)
        {
            fields.Add(fieldName, "a-value");
        }

        ClientCredentialReading reading = ClientCredentialReading.Read(HeadersOf(authorization), fields);

        Assert.IsFalse(reading.IsMalformed);
        Assert.IsTrue(reading.HasCredentials);
        Assert.AreEqual(mechanism == "basic", reading.HasBasicAuthorization);
        Assert.AreEqual(mechanism == "other", reading.HasOtherAuthorization);
        Assert.AreEqual(mechanism == "secret", reading.HasClientSecret);
        Assert.AreEqual(mechanism == "assertion", reading.HasClientAssertion);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Request and
    /// response parameters MUST NOT be included more than once." Each client authentication field carrying
    /// two values reads as a repeated parameter, and its value is not read.
    /// </summary>
    /// <param name="fieldName">The repeated form field.</param>
    [TestMethod]
    [DataRow("client_id")]
    [DataRow("client_secret")]
    [DataRow("client_assertion")]
    [DataRow("client_assertion_type")]
    public void EachRepeatedFieldIsARepeatedParameter(string fieldName)
    {
        RequestFields fields = new();
        fields.Add(fieldName, "first");
        fields.Add(fieldName, "second");

        ClientCredentialReading reading = ClientCredentialReading.Read(RequestHeaders.Empty, fields);

        Assert.IsTrue(reading.IsMalformed);
        Assert.IsTrue(reading.IsParameterRepeated);
        Assert.IsFalse(reading.IsAuthorizationRepeated);
        Assert.IsFalse(reading.IsAuthorizationMalformed);
        Assert.IsFalse(reading.IsMoreThanOneMechanism);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 Section 2.3</see>: "The client
    /// MUST NOT use more than one authentication method in each request." A <c>Basic</c> field beside a form
    /// secret reads as more than one mechanism.
    /// </summary>
    [TestMethod]
    public void TwoMechanismsAreMoreThanOneMechanism()
    {
        RequestFields fields = new();
        fields.Add("client_secret", "a-secret");

        ClientCredentialReading reading = ClientCredentialReading.Read(HeadersOf(BasicCredential), fields);

        Assert.IsTrue(reading.IsMalformed);
        Assert.IsTrue(reading.IsMoreThanOneMechanism);
        Assert.IsFalse(reading.IsParameterRepeated);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." <c>client_secret=</c>
    /// reads as no secret, and beside a second occurrence with a value it is the omitted occurrence, so the
    /// value is read once and is not a repeat.
    /// </summary>
    [TestMethod]
    public void AnEmptyValueIsTheOmittedParameter()
    {
        RequestFields emptyOnly = new();
        emptyOnly.Add("client_secret", string.Empty);
        ClientCredentialReading omitted = ClientCredentialReading.Read(RequestHeaders.Empty, emptyOnly);

        RequestFields emptyBesideValue = new();
        emptyBesideValue.Add("client_secret", string.Empty);
        emptyBesideValue.Add("client_secret", "a-secret");
        ClientCredentialReading once = ClientCredentialReading.Read(RequestHeaders.Empty, emptyBesideValue);

        Assert.IsFalse(omitted.IsMalformed);
        Assert.IsFalse(omitted.HasCredentials);
        Assert.IsNull(omitted.ClientSecret);
        Assert.IsFalse(once.IsMalformed);
        Assert.AreEqual("a-secret", once.ClientSecret);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see> forbids a sender
    /// to generate a second field line of a name already in the message unless the field's definition is a
    /// list, and <c>Authorization = credentials</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) is not.
    /// Two <c>Authorization</c> field lines read as a repeated field, and neither line is read as a mechanism.
    /// </summary>
    [TestMethod]
    public void TwoAuthorizationLinesAreARepeatedField()
    {
        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = [BasicCredential, BasicCredential]
        });

        ClientCredentialReading reading = ClientCredentialReading.Read(headers, new RequestFields());

        Assert.IsTrue(reading.IsMalformed);
        Assert.IsTrue(reading.IsAuthorizationRepeated);
        Assert.IsTrue(reading.Authorization.IsRepeated);
        Assert.IsFalse(reading.HasBasicAuthorization);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]". An <c>Authorization</c> value
    /// outside that grammar reads as a malformed field, and is not read as a mechanism.
    /// </summary>
    [TestMethod]
    public void AnAuthorizationValueOutsideTheGrammarIsMalformed()
    {
        ClientCredentialReading reading = ClientCredentialReading.Read(HeadersOf("Basic one two"), new RequestFields());

        Assert.IsTrue(reading.IsMalformed);
        Assert.IsTrue(reading.IsAuthorizationMalformed);
        Assert.IsFalse(reading.HasBasicAuthorization);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", with "auth-scheme    = token" of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>, a token of one
    /// or more characters. A present <c>Authorization</c> field line that is empty or holds white space only
    /// carries no scheme, so it reads as a malformed field, and no mechanism is read. The parameter rule of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see> for a value sent
    /// empty governs form parameters, not header fields.
    /// </summary>
    /// <param name="authorization">The value of the one field line.</param>
    [TestMethod]
    [DataRow("", DisplayName = "an empty Authorization value")]
    [DataRow(" ", DisplayName = "an Authorization value of white space")]
    public void AnAuthorizationLineWithoutASchemeIsMalformed(string authorization)
    {
        ClientCredentialReading reading = ClientCredentialReading.Read(HeadersOf(authorization), new RequestFields());

        Assert.IsTrue(reading.IsMalformed);
        Assert.IsTrue(reading.IsAuthorizationMalformed);
        Assert.IsFalse(reading.HasCredentials);
    }


    /// <summary>The request headers of one <c>Authorization</c> field line, or none.</summary>
    /// <param name="value">The field line's value, or <see langword="null"/> for no field.</param>
    /// <returns>The headers.</returns>
    private static RequestHeaders HeadersOf(string? value) =>
        value is null
            ? RequestHeaders.Empty
            : new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = [value]
            });
}
