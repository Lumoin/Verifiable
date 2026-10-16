using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// The fixed <c>error_description</c> texts the library answers with where the reason for a
/// refusal must not reach the wire.
/// </summary>
/// <remarks>
/// Every value lies inside the character set
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> fixes for
/// the parameter: "Values for the "error_description" parameter MUST NOT include characters
/// outside the set %x20-21 / %x23-5B / %x5D-7E." An application that refuses a request in the
/// library's own shape reads the text from here and refuses through
/// <see cref="Server.Pipeline.ClientIdMetadataMaterialization.Refuse"/>, so the status, the body
/// and the challenge are the same either way.
/// </remarks>
public static class WellKnownOAuthErrorDescriptions
{
    /// <summary>The UTF-8 source literal of <see cref="ClientAuthenticationFailed"/>.</summary>
    public static ReadOnlySpan<byte> ClientAuthenticationFailedUtf8 => "Client authentication failed."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.InvalidClient"/>
    /// when client authentication fails at the token endpoint family, per the
    /// <c>invalid_client</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>, and
    /// beside <see cref="OAuthErrors.InvalidToken"/> when the Global Token Revocation endpoint's
    /// authentication seam refuses the credential a request carried, per the <c>invalid_token</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>. The
    /// text names no client, registration or internal cause.
    /// </summary>
    public static string ClientAuthenticationFailed { get; } =
        Utf8Constants.ToInternedString(ClientAuthenticationFailedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestNotProcessed"/>.</summary>
    public static ReadOnlySpan<byte> RequestNotProcessedUtf8 => "The request could not be processed."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.InvalidRequest"/>
    /// when the server aborts a request before a usable registration exists, per the
    /// <c>invalid_request</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>. The
    /// text names no client, document or internal cause.
    /// </summary>
    public static string RequestNotProcessed { get; } =
        Utf8Constants.ToInternedString(RequestNotProcessedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ServerNotReady"/>.</summary>
    public static ReadOnlySpan<byte> ServerNotReadyUtf8 => "The server is not ready to serve this request."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.ServerError"/> when the
    /// server's own wiring, not the request, is the cause of the failure, per the
    /// <c>server_error</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1</see>.
    /// The text names no seam, configuration or internal cause.
    /// </summary>
    public static string ServerNotReady { get; } =
        Utf8Constants.ToInternedString(ServerNotReadyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RepeatedClientAuthenticationParameter"/>.</summary>
    public static ReadOnlySpan<byte> RepeatedClientAuthenticationParameterUtf8 => "The request repeats a client authentication parameter."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.InvalidRequest"/> when a
    /// request carries <c>client_id</c>, <c>client_secret</c>, <c>client_assertion</c> or
    /// <c>client_assertion_type</c> twice (<see cref="Server.ClientCredentialReading.IsParameterRepeated"/>):
    /// "Request and response parameters MUST NOT be included more than once."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>), a request
    /// that repeats a parameter, which the <c>invalid_request</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">Section 5.2</see> names: "The request is
    /// missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a
    /// parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client,
    /// or is otherwise malformed." The text names neither the parameter nor its values.
    /// </summary>
    public static string RepeatedClientAuthenticationParameter { get; } =
        Utf8Constants.ToInternedString(RepeatedClientAuthenticationParameterUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MoreThanOneClientAuthenticationMethod"/>.</summary>
    public static ReadOnlySpan<byte> MoreThanOneClientAuthenticationMethodUtf8 => "The request authenticates the client by more than one method."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.InvalidRequest"/> when a
    /// request presents two or more client authentication mechanisms
    /// (<see cref="Server.ClientCredentialReading.IsMoreThanOneMechanism"/>): "The client MUST NOT use more
    /// than one authentication method in each request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 Section 2.3</see>), a request
    /// that uses more than one mechanism for authenticating the client, which the <c>invalid_request</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">Section 5.2</see> names. The text names no
    /// mechanism.
    /// </summary>
    public static string MoreThanOneClientAuthenticationMethod { get; } =
        Utf8Constants.ToInternedString(MoreThanOneClientAuthenticationMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MalformedAuthorizationField"/>.</summary>
    public static ReadOnlySpan<byte> MalformedAuthorizationFieldUtf8 => "The Authorization header is not a single well-formed credential."u8;

    /// <summary>
    /// The description the library answers with beside <see cref="OAuthErrors.InvalidRequest"/> when the
    /// <c>Authorization</c> field is sent on two field lines or outside its grammar
    /// (<see cref="Server.ClientCredentialReading.IsAuthorizationRepeated"/>,
    /// <see cref="Server.ClientCredentialReading.IsAuthorizationMalformed"/>):
    /// "Authorization = credentials" (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC
    /// 9110 Section 11.6.2</see>) is one credential, and a request carrying more includes multiple credentials,
    /// and one carrying a value outside the grammar is otherwise malformed, both under the <c>invalid_request</c>
    /// code of <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>. The
    /// text carries no part of the field's value.
    /// </summary>
    public static string MalformedAuthorizationField { get; } =
        Utf8Constants.ToInternedString(MalformedAuthorizationFieldUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialOutsideToken68"/>.</summary>
    internal static ReadOnlySpan<byte> CredentialOutsideToken68Utf8 => "The Authorization header credentials are not a token68."u8;

    /// <summary>
    /// The description the library's resources answer with beside <see cref="OAuthErrors.InvalidRequest"/> when the one
    /// <c>Authorization</c> field line names the <c>Bearer</c> or <c>DPoP</c> scheme with credentials outside its grammar:
    /// "credentials = "Bearer" 1*SP b64token" (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750
    /// Section 2.1</see>) and "credentials = "DPoP" 1*SP token68"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>), a request that is
    /// otherwise malformed under the <c>invalid_request</c> code of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>. The text carries no
    /// part of the field's value.
    /// </summary>
    internal static string CredentialOutsideToken68 { get; } =
        Utf8Constants.ToInternedString(CredentialOutsideToken68Utf8);
}
