namespace Verifiable.OAuth.Server;

/// <summary>
/// The server-side issuer-identifier shape validation applied wherever
/// <see cref="ClientRecord.IssuerUri"/> or the request-scoped
/// <see cref="ExchangeContextServerExtensions.Issuer"/> becomes the value emitted as
/// the discovery <c>issuer</c> field or the Authorize-redirect <c>iss</c> parameter.
/// The sibling of the client-side
/// <see cref="Verifiable.OAuth.Client.AuthorizationServerMetadataValidation"/>.
/// </summary>
public static class IssuerIdentifierValidation
{
    /// <summary>
    /// Whether <paramref name="issuer"/> satisfies
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207#section-2">RFC 9207 §2</see>:
    /// "Its value MUST be a URL that uses the &quot;https&quot; scheme without any
    /// query or fragment components" — the same issuer-identifier shape
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see>
    /// requires of every authorization server issuer identifier.
    /// </summary>
    /// <param name="issuer">The candidate issuer identifier.</param>
    public static bool IsValidIssuerShape(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        //A relative URI has no scheme, query or fragment components to inspect
        //(System.Uri throws on those accessors), and it cannot be "a URL that
        //uses the https scheme" — it fails the shape rather than the caller.
        return issuer.IsAbsoluteUri
            && string.Equals(issuer.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            && issuer.Query.Length == 0
            && issuer.Fragment.Length == 0;
    }
}
