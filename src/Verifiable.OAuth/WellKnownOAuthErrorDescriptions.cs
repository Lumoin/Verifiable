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
}
