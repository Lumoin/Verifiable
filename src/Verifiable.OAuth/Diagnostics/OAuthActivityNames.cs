using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Activity (span) names of the OAuth operations the library traces through an application's
/// <see cref="Verifiable.Core.Diagnostics.StartTraceActivityDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Names follow the pattern <c>{domain}.{operation}</c>. Each names one operation boundary whose span the application
/// starts and the library completes and stops; the spans are <see cref="System.Diagnostics.ActivityKind.Internal"/>, the
/// HTTP server and client spans being the application's host's and transport's.
/// </para>
/// </remarks>
public static class OAuthActivityNames
{
    /// <summary>The UTF-8 source literal of <see cref="DecideResourceAccess"/>.</summary>
    public static ReadOnlySpan<byte> DecideResourceAccessUtf8 => "oauth.resource.decide"u8;

    /// <summary>
    /// The span of <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/>, an application's protected resource
    /// deciding on one presentation of an access token by the checks of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, started through
    /// <see cref="ResourceServerIntegration.StartTraceActivity"/>. It carries
    /// <see cref="OAuthTagNames.DpopResourceDecision"/>, <see cref="OAuthTagNames.DpopResourceCheck"/> when a check
    /// refused, and the answer's error code.
    /// </summary>
    public static string DecideResourceAccess { get; } = Utf8Constants.ToInternedString(DecideResourceAccessUtf8);
}
