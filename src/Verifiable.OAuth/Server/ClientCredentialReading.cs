using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The one reading of the client credentials a request presents: its <c>Authorization</c> field, read
/// through <see cref="AuthorizationFieldReading"/>, and its <c>client_id</c>, <c>client_secret</c>,
/// <c>client_assertion</c> and <c>client_assertion_type</c> form fields, read with every value they carry.
/// The library reads it once per request, before any client authentication seam, refuses a malformed
/// reading itself at every client-authenticating site, and hands the reading to
/// <see cref="ValidateClientCredentialsDelegate"/>, so the seam judges exactly the credential the library read
/// and never one the library refused. At the bearer resources and at Global Token Revocation a present
/// <c>Authorization</c> line that is empty or white space only is read as a request without a credential, not
/// refused, and Global Token Revocation hands that reading on to the seam, marked
/// <see cref="IsAuthorizationMalformed"/> and naming no mechanism.
/// </summary>
/// <remarks>
/// <para>
/// The mechanisms a request may present are a <c>Basic</c> field
/// (<see cref="HasBasicAuthorization"/>), a field of another scheme (<see cref="HasOtherAuthorization"/>), a
/// form secret (<see cref="HasClientSecret"/>) and a form assertion (<see cref="HasClientAssertion"/>). A
/// bare <c>client_id</c> identifies the client and authenticates nothing, so it is no mechanism.
/// </para>
/// <para>
/// A reading is malformed for one reason, judged in this order, and a malformed reading names no
/// mechanism a seam may judge:
/// </para>
/// <list type="number">
///   <item><description>
///     <see cref="IsParameterRepeated"/>: one of the four form fields carries two values.
///     <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Request
///     and response parameters MUST NOT be included more than once."
///   </description></item>
///   <item><description>
///     <see cref="IsAuthorizationRepeated"/>: the <c>Authorization</c> field is sent on two field lines
///     (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see>;
///     <see cref="AuthorizationFieldReading.IsRepeated"/>).
///   </description></item>
///   <item><description>
///     <see cref="IsAuthorizationMalformed"/>: the one field line's value is outside
///     <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>'s
///     <c>credentials</c> grammar (<see cref="AuthorizationFieldReading.IsWellFormed"/>), an empty line and a
///     line of white space only included.
///   </description></item>
///   <item><description>
///     <see cref="IsMoreThanOneMechanism"/>: two or more mechanisms are presented.
///     <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 Section 2.3</see>: "The
///     client MUST NOT use more than one authentication method in each request."
///   </description></item>
/// </list>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> names the
/// answer to each, <c>invalid_request</c>: "The request is missing a required parameter, includes an
/// unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials,
/// utilizes more than one mechanism for authenticating the client, or is otherwise malformed."
/// </para>
/// <para>
/// An empty value is the omitted parameter: "Parameters sent without a value MUST be treated as if they
/// were omitted from the request." (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749
/// Section 3.2</see>). An empty occurrence of a form field is not counted, so <c>client_secret=</c> beside
/// <c>client_secret=x</c> reads as the one secret <c>x</c>, and <c>client_id=</c> beside <c>client_id=x</c> as
/// the one identifier <c>x</c>, which every site that decides the client's identity reads through
/// <see cref="ClientId"/>.
/// </para>
/// <para>
/// That rule governs request parameters, not header fields. A present <c>Authorization</c> field line that is
/// empty or holds white space only has no <c>auth-scheme</c>, the token
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see> requires, so it is
/// read as the malformed field (<see cref="IsAuthorizationMalformed"/>), as every other value outside the
/// grammar is: one grammar reading with no exception.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ClientCredentialReading
{
    /// <summary>The reading of the request's <c>Authorization</c> field.</summary>
    public AuthorizationFieldReading Authorization { get; private init; }

    /// <summary>
    /// The one non-empty <c>client_id</c> form value, or <see langword="null"/> when the field is omitted,
    /// empty or repeated.
    /// </summary>
    public string? ClientId { get; private init; }

    /// <summary>
    /// The one non-empty <c>client_secret</c> form value, or <see langword="null"/> when the field is
    /// omitted, empty or repeated.
    /// </summary>
    public string? ClientSecret { get; private init; }

    /// <summary>
    /// The one non-empty <c>client_assertion</c> form value, or <see langword="null"/> when the field is
    /// omitted, empty or repeated.
    /// </summary>
    public string? ClientAssertion { get; private init; }

    /// <summary>
    /// The one non-empty <c>client_assertion_type</c> form value, or <see langword="null"/> when the field
    /// is omitted, empty or repeated.
    /// </summary>
    public string? ClientAssertionType { get; private init; }

    /// <summary>
    /// Whether the request presents one well-formed <c>Authorization</c> field line of the <c>Basic</c>
    /// scheme (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 Section
    /// 2.3.1</see>), its credentials in <see cref="AuthorizationFieldReading.Credentials"/>.
    /// </summary>
    public bool HasBasicAuthorization { get; private init; }

    /// <summary>
    /// Whether the request presents one well-formed <c>Authorization</c> field line of a scheme other than
    /// <c>Basic</c>, named by <see cref="AuthorizationFieldReading.Scheme"/>.
    /// </summary>
    public bool HasOtherAuthorization { get; private init; }

    /// <summary>Whether the request presents a <c>client_secret</c> form value, <see cref="ClientSecret"/>.</summary>
    public bool HasClientSecret => ClientSecret is not null;

    /// <summary>Whether the request presents a <c>client_assertion</c> form value, <see cref="ClientAssertion"/>.</summary>
    public bool HasClientAssertion => ClientAssertion is not null;

    /// <summary>Whether the request presents at least one client authentication mechanism.</summary>
    public bool HasCredentials => HasBasicAuthorization || HasOtherAuthorization || HasClientSecret || HasClientAssertion;

    /// <summary>Whether one of the four client authentication form fields carries two non-empty values.</summary>
    public bool IsParameterRepeated { get; private init; }

    /// <summary>Whether the <c>Authorization</c> field is sent on two or more field lines.</summary>
    public bool IsAuthorizationRepeated { get; private init; }

    /// <summary>Whether the one <c>Authorization</c> field line's value is outside the <c>credentials</c> grammar.</summary>
    public bool IsAuthorizationMalformed { get; private init; }

    /// <summary>Whether the request presents two or more client authentication mechanisms.</summary>
    public bool IsMoreThanOneMechanism { get; private init; }

    /// <summary>Whether the reading is malformed for one of the four reasons, and the library refuses the request.</summary>
    public bool IsMalformed => IsParameterRepeated || IsAuthorizationRepeated || IsAuthorizationMalformed || IsMoreThanOneMechanism;

    /// <summary>The text the debugger shows for the reading; no credential value is shown.</summary>
    private string DebuggerDisplay =>
        $"ClientCredentialReading(Basic={HasBasicAuthorization}, Other={HasOtherAuthorization}, Secret={HasClientSecret}, Assertion={HasClientAssertion}, Malformed={IsMalformed})";


    /// <summary>Creates an empty reading; <see cref="Read"/> is the one caller.</summary>
    private ClientCredentialReading()
    {
    }


    /// <summary>
    /// The mechanisms and the malformation of the reading, never a credential value, so a reading written
    /// to a log or a trace carries no secret.
    /// </summary>
    /// <returns>The reading's text.</returns>
    public override string ToString() => DebuggerDisplay;


    /// <summary>
    /// Reads the client credentials of a request from its <paramref name="headers"/> and its form
    /// <paramref name="fields"/>, once, before any client authentication seam.
    /// </summary>
    /// <param name="headers">The request headers as received.</param>
    /// <param name="fields">The request's form fields, every value of each.</param>
    /// <returns>The reading.</returns>
    public static ClientCredentialReading Read(RequestHeaders headers, RequestFields fields)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(fields);

        AuthorizationFieldReading authorization = AuthorizationFieldReading.Read(headers);

        (string? clientId, bool isClientIdRepeated) = ReadField(fields, OAuthRequestParameterNames.ClientId);
        (string? clientSecret, bool isClientSecretRepeated) = ReadField(fields, OAuthRequestParameterNames.ClientSecret);
        (string? clientAssertion, bool isClientAssertionRepeated) = ReadField(fields, OAuthRequestParameterNames.ClientAssertion);
        (string? clientAssertionType, bool isClientAssertionTypeRepeated) = ReadField(fields, OAuthRequestParameterNames.ClientAssertionType);

        bool isParameterRepeated = isClientIdRepeated || isClientSecretRepeated || isClientAssertionRepeated || isClientAssertionTypeRepeated;
        bool isAuthorizationRepeated = !isParameterRepeated && authorization.IsRepeated;
        bool isAuthorizationMalformed = !isParameterRepeated
            && !isAuthorizationRepeated
            && !authorization.IsAbsent
            && !authorization.IsWellFormed;

        bool isFieldUsable = authorization.IsWellFormed && !isParameterRepeated;
        bool hasBasicAuthorization = isFieldUsable && authorization.IsScheme(WellKnownAuthenticationSchemes.Basic);
        bool hasOtherAuthorization = isFieldUsable && !hasBasicAuthorization;
        string? usableSecret = isParameterRepeated ? null : clientSecret;
        string? usableAssertion = isParameterRepeated ? null : clientAssertion;

        int mechanismCount = (hasBasicAuthorization ? 1 : 0) + (hasOtherAuthorization ? 1 : 0)
            + (usableSecret is not null ? 1 : 0) + (usableAssertion is not null ? 1 : 0);
        bool isMoreThanOneMechanism = !isParameterRepeated && !isAuthorizationRepeated && !isAuthorizationMalformed
            && mechanismCount > 1;
        bool isMalformed = isParameterRepeated || isAuthorizationRepeated || isAuthorizationMalformed || isMoreThanOneMechanism;

        return new ClientCredentialReading
        {
            Authorization = authorization,
            ClientId = isMalformed ? null : clientId,
            ClientSecret = isMalformed ? null : usableSecret,
            ClientAssertion = isMalformed ? null : usableAssertion,
            ClientAssertionType = isMalformed ? null : clientAssertionType,
            HasBasicAuthorization = !isMalformed && hasBasicAuthorization,
            HasOtherAuthorization = !isMalformed && hasOtherAuthorization,
            IsParameterRepeated = isParameterRepeated,
            IsAuthorizationRepeated = isAuthorizationRepeated,
            IsAuthorizationMalformed = isAuthorizationMalformed,
            IsMoreThanOneMechanism = isMoreThanOneMechanism
        };
    }


    /// <summary>
    /// The one non-empty <c>client_id</c> value of <paramref name="fields"/> by the field's own rule alone, read
    /// through the body <see cref="Read"/> reads every field with: an empty occurrence is the omitted parameter, and
    /// two non-empty values name no client. Unlike <see cref="ClientId"/>, it does not depend on the other fields or
    /// on the <c>Authorization</c> field, so a request that authenticates no client is identified by its
    /// <c>client_id</c> as its endpoint identifies it, whatever else it carries (the Client ID Metadata Document
    /// materialization, <see cref="Pipeline.ClientIdMetadataMaterialization.Build"/>, reads it so).
    /// </summary>
    /// <param name="fields">The request's form fields, every value of each.</param>
    /// <returns>The one non-empty <c>client_id</c> value, or <see langword="null"/>.</returns>
    internal static string? ReadClientIdentifier(RequestFields fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        return ReadField(fields, OAuthRequestParameterNames.ClientId).Value;
    }


    /// <summary>
    /// Reads one form field with every value it carries: its one non-empty value, and whether two or more
    /// non-empty values were sent. Empty values are the omitted parameter and are not counted.
    /// </summary>
    /// <param name="fields">The request's form fields.</param>
    /// <param name="name">The field name.</param>
    /// <returns>The one non-empty value, or <see langword="null"/>, and whether the field is repeated.</returns>
    private static (string? Value, bool IsRepeated) ReadField(RequestFields fields, string name)
    {
        if(!fields.TryGetValues(name, out IReadOnlyList<string>? values))
        {
            return (null, false);
        }

        string? value = null;
        foreach(string candidate in values)
        {
            if(string.IsNullOrEmpty(candidate))
            {
                continue;
            }

            if(value is not null)
            {
                return (null, true);
            }

            value = candidate;
        }

        return (value, false);
    }
}
