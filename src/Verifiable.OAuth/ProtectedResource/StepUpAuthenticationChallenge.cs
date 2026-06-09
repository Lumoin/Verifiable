using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The RFC 9470 §3 step-up authentication challenge: a protected resource that finds the
/// access token's authentication event insufficient returns HTTP 401 with a
/// <c>WWW-Authenticate</c> header carrying <c>error="insufficient_user_authentication"</c>
/// and the requirements the client must satisfy — a stronger authentication context
/// (<c>acr_values</c>) and/or a more recent authentication (<c>max_age</c>). The client
/// re-runs authorization carrying those values to step the user up, then retries
/// (<see href="https://www.rfc-editor.org/rfc/rfc9470">RFC 9470</see>).
/// </summary>
/// <remarks>
/// <para>
/// The challenge rides any OAuth authentication scheme — <c>Bearer</c> (RFC 6750) or
/// <c>DPoP</c> (RFC 9449) — through that scheme's <c>error</c> parameter (§3). Values are
/// quoted-strings per the RFC 9110 §11.2 <c>auth-param</c> grammar; <c>acr_values</c> is a
/// space-separated list in order of preference (§3), and <c>max_age</c> is the allowable
/// elapsed seconds since the last active authentication event.
/// </para>
/// <para>
/// This builds the server-side <em>output</em>. Composing the request the client sends back
/// (the <c>acr_values</c>/<c>max_age</c> authorization parameters) and deciding when a token's
/// <c>acr</c>/<c>auth_time</c> is insufficient are the authorization-flow's and the resource
/// server's concerns layered on top — not part of this primitive.
/// </para>
/// </remarks>
public static class StepUpAuthenticationChallenge
{
    /// <summary>The <c>acr_values</c> challenge parameter name (RFC 9470 §3).</summary>
    public static readonly string AcrValuesParameter = "acr_values";

    /// <summary>The <c>max_age</c> challenge parameter name (RFC 9470 §3).</summary>
    public static readonly string MaxAgeParameter = "max_age";

    /// <summary>The <c>error</c> challenge parameter name (RFC 6750 §3 / RFC 9470 §3).</summary>
    private const string ErrorParameter = "error";

    /// <summary>The <c>error_description</c> challenge parameter name (RFC 6750 §3).</summary>
    private const string ErrorDescriptionParameter = "error_description";

    /// <summary>The <c>scope</c> challenge parameter name (RFC 6750 §3.1).</summary>
    private const string ScopeParameter = "scope";


    /// <summary>
    /// Builds a <c>WWW-Authenticate</c> step-up challenge:
    /// <c>{scheme} error="insufficient_user_authentication"</c> followed by the supplied
    /// requirements. <paramref name="acrValues"/> and <paramref name="maxAgeSeconds"/> are
    /// both optional (a caller normally supplies at least one so the client has something to
    /// act on); <paramref name="errorDescription"/> is an optional human-readable note.
    /// </summary>
    /// <param name="scheme">The authentication scheme, e.g. <see cref="WellKnownAuthenticationSchemes.Bearer"/>.</param>
    /// <param name="acrValues">The requested <c>acr</c> values, in order of preference; joined space-separated (§3).</param>
    /// <param name="maxAgeSeconds">The allowable elapsed seconds since the last active authentication event (§3).</param>
    /// <param name="errorDescription">An optional human-readable description of the requirement.</param>
    /// <param name="scopes">
    /// Optional <c>scope</c> attribute (RFC 6750 §3.1) — the scopes the resource also requires, joined
    /// space-separated. §3 allows the challenge to carry this when the request is <em>also</em> lacking scope.
    /// </param>
    /// <returns>The <c>WWW-Authenticate</c> header value.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxAgeSeconds"/> is negative.</exception>
    public static string BuildChallenge(
        string scheme,
        IReadOnlyList<string>? acrValues = null,
        int? maxAgeSeconds = null,
        string? errorDescription = null,
        IReadOnlyList<string>? scopes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);

        if(maxAgeSeconds is < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxAgeSeconds), maxAgeSeconds, "max_age cannot be negative (RFC 9470 §3).");
        }

        StringBuilder builder = new();
        builder.Append(scheme).Append(' ');
        AppendQuotedParameter(builder, ErrorParameter, OAuthErrors.InsufficientUserAuthentication);

        if(!string.IsNullOrEmpty(errorDescription))
        {
            builder.Append(", ");
            AppendQuotedParameter(builder, ErrorDescriptionParameter, errorDescription);
        }

        if(acrValues is { Count: > 0 })
        {
            builder.Append(", ");
            AppendQuotedParameter(builder, AcrValuesParameter, string.Join(' ', acrValues));
        }

        if(maxAgeSeconds is int maxAge)
        {
            builder.Append(", ");
            AppendQuotedParameter(builder, MaxAgeParameter, maxAge.ToString(CultureInfo.InvariantCulture));
        }

        if(scopes is { Count: > 0 })
        {
            builder.Append(", ");
            AppendQuotedParameter(builder, ScopeParameter, string.Join(' ', scopes));
        }

        return builder.ToString();
    }


    /// <summary>
    /// Appends <c>{name}="{value}"</c> with RFC 9110 §5.6.4 quoted-string escaping of
    /// <c>"</c> and <c>\</c> in <paramref name="value"/>.
    /// </summary>
    private static void AppendQuotedParameter(StringBuilder builder, string name, string value)
    {
        string escaped = value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);

        builder.Append(name).Append("=\"").Append(escaped).Append('"');
    }
}
