using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Encodes an issued JWT Response Document into the response-mode-specific wire forms of
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.3">JARM §2.3</see>:
/// the <c>response</c> parameter in the redirect URI's query (<c>query.jwt</c>) or
/// fragment (<c>fragment.jwt</c>) component, or an auto-submitting HTML form POST
/// (<c>form_post.jwt</c>).
/// </summary>
[DebuggerDisplay("JarmResponseEncoding")]
public static class JarmResponseEncoding
{
    /// <summary>The UTF-8 source literal of <see cref="ResponseParameterName"/>.</summary>
    public static ReadOnlySpan<byte> ResponseParameterNameUtf8 => "response"u8;

    /// <summary>
    /// The <c>response</c> authorization response parameter that carries the JWT
    /// Response Document in every JARM encoding.
    /// </summary>
    public static readonly string ResponseParameterName = Utf8Constants.ToInternedString(ResponseParameterNameUtf8);


    /// <summary>
    /// Resolves the <see cref="JarmResponseModes.Jwt"/> shortcut to the concrete
    /// default encoding for <paramref name="responseType"/> per §2.3.4:
    /// <see cref="JarmResponseModes.QueryJwt"/> for <c>code</c> (and <c>none</c>,
    /// whose RFC 6749-family default encoding is likewise the query), otherwise
    /// <see cref="JarmResponseModes.FragmentJwt"/>. Concrete JARM modes pass through
    /// unchanged.
    /// </summary>
    /// <param name="responseMode">The requested JARM response mode.</param>
    /// <param name="responseType">The <c>response_type</c> of the Authorization Request.</param>
    /// <returns>The concrete encoding mode: <c>query.jwt</c>, <c>fragment.jwt</c>, or <c>form_post.jwt</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="responseMode"/> is not a JARM response mode.</exception>
    public static string ResolveEncodingMode(string responseMode, string responseType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(responseMode);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseType);

        return responseMode switch
        {
            _ when JarmResponseModes.IsQueryJwt(responseMode) => JarmResponseModes.QueryJwt,
            _ when JarmResponseModes.IsFragmentJwt(responseMode) => JarmResponseModes.FragmentJwt,
            _ when JarmResponseModes.IsFormPostJwt(responseMode) => JarmResponseModes.FormPostJwt,
            _ when JarmResponseModes.IsJwt(responseMode) =>
                string.Equals(responseType, "code", StringComparison.Ordinal)
                    || string.Equals(responseType, "none", StringComparison.Ordinal)
                    ? JarmResponseModes.QueryJwt
                    : JarmResponseModes.FragmentJwt,
            _ => throw new ArgumentException(
                $"'{responseMode}' is not a JARM response mode.", nameof(responseMode))
        };
    }


    /// <summary>
    /// Composes the §2.3.1 <c>query.jwt</c> redirect location: the <c>response</c>
    /// parameter appended to the query component of the client's redirect URI.
    /// </summary>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="responseJwt">The compact JWT Response Document.</param>
    /// <returns>The redirect location for the HTTP 302 <c>Location</c> header.</returns>
    public static string ToQueryRedirectLocation(Uri redirectUri, string responseJwt)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseJwt);

        string uri = redirectUri.OriginalString;
        char separator = uri.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        return $"{uri}{separator}{ResponseParameterName}={Uri.EscapeDataString(responseJwt)}";
    }


    /// <summary>
    /// Composes the §2.3.2 <c>fragment.jwt</c> redirect location: the <c>response</c>
    /// parameter in the fragment component of the client's redirect URI.
    /// </summary>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="responseJwt">The compact JWT Response Document.</param>
    /// <returns>The redirect location for the HTTP 302 <c>Location</c> header.</returns>
    public static string ToFragmentRedirectLocation(Uri redirectUri, string responseJwt)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseJwt);

        return $"{redirectUri.OriginalString}#{ResponseParameterName}={Uri.EscapeDataString(responseJwt)}";
    }


    /// <summary>
    /// Composes the form body the User Agent POSTs to the client's redirect URI in the
    /// §2.3.3 <c>form_post.jwt</c> mode, in <c>application/x-www-form-urlencoded</c>
    /// format — also the body shape the client receives and hands to
    /// <see cref="JarmResponseValidation"/> after extracting the parameter.
    /// </summary>
    /// <param name="responseJwt">The compact JWT Response Document.</param>
    /// <returns>The form-urlencoded body.</returns>
    public static string ToFormPostBody(string responseJwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(responseJwt);

        return $"{ResponseParameterName}={Uri.EscapeDataString(responseJwt)}";
    }


    /// <summary>
    /// Composes the §2.3.3 auto-submitting HTML page the Authorization Server returns
    /// to the User Agent in the <c>form_post.jwt</c> mode, mirroring the OAuth 2.0 Form
    /// Post Response Mode technique.
    /// </summary>
    /// <param name="redirectUri">The client's redirect URI the form POSTs to.</param>
    /// <param name="responseJwt">The compact JWT Response Document.</param>
    /// <returns>The HTML document for a <c>200 OK</c> <c>text/html</c> response.</returns>
    public static string ToFormPostHtml(Uri redirectUri, string responseJwt)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseJwt);

        //The redirect URI is HTML-attribute-escaped; the JWT is base64url material
        //plus '.' separators and needs no escaping, but is escaped anyway so the
        //document stays well-formed whatever the input.
        string action = System.Net.WebUtility.HtmlEncode(redirectUri.OriginalString);
        string value = System.Net.WebUtility.HtmlEncode(responseJwt);

        return
            "<html><head><title>Submit This Form</title></head>"
            + "<body onload=\"javascript:document.forms[0].submit()\">"
            + $"<form method=\"post\" action=\"{action}\">"
            + $"<input type=\"hidden\" name=\"{ResponseParameterName}\" value=\"{value}\"/>"
            + "</form></body></html>";
    }
}
