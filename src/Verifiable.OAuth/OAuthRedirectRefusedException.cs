using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// Thrown by a client flow that reports a refused answer by throwing — the RFC 7591 registration and the
/// RFC 7592 read, update and deregistration handlers, and the OpenID for Verifiable Presentations
/// wallet's posts — when the endpoint answered a request carrying a credential with a redirect, an HTTP
/// status of the 3xx class. The flow did not follow the redirect and sent nothing further;
/// <see cref="Refusal"/> carries the typed refusal.
/// </summary>
/// <remarks>
/// It derives from <see cref="InvalidOperationException"/>, the type those flows raise for every other
/// answer they refuse, so a caller that catches that type for a failed answer catches this one too.
/// </remarks>
[SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "This exception always carries the typed refusal it reports; the parameterless and message-only constructors would violate that invariant.")]
public sealed class OAuthRedirectRefusedException: InvalidOperationException
{
    /// <summary>The refusal: the endpoint, the 3xx status and the <c>Location</c> value it sent.</summary>
    public OAuthRedirectRefused Refusal { get; }


    /// <summary>Creates the exception for <paramref name="refusal"/>.</summary>
    /// <param name="refusal">The typed refusal the flow made.</param>
    public OAuthRedirectRefusedException(OAuthRedirectRefused refusal)
        : base(refusal?.Support.Summary)
    {
        ArgumentNullException.ThrowIfNull(refusal);

        Refusal = refusal;
    }
}
