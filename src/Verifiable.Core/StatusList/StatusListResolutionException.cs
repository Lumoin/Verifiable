using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Thrown by a <see cref="ResolveVerifiedStatusListTokenDelegate"/> implementation, or raised by
/// <see cref="CredentialStatusGate"/> on the delegate's behalf, when the Status List Token itself could
/// not be obtained — a fetch failure, an untrusted or unresolvable issuer, or an unparseable list.
/// </summary>
/// <remarks>
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token
/// Status List §8.3</see> step 2, "Resolve the Status List Token from the provided URI", is one of the
/// validation steps step 8.3's closing sentence covers: "If any of these checks fails, no statement
/// about the status of the Referenced Token can be made and the Referenced Token SHOULD be rejected."
/// Deriving from <see cref="StatusListValidationException"/> routes a resolution failure through the
/// same undeterminable-status classification a caller already catches that type for, rather than
/// escaping as the resolver's own transport exception (a genuine, unclassified fault).
/// </remarks>
[SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "This exception always carries the Status List Token uri that could not be resolved; the parameterless and message-only constructors would violate that invariant.")]
public sealed class StatusListResolutionException: StatusListValidationException
{
    /// <summary>The Status List Token <c>uri</c> the resolver could not obtain a verified token for.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "The specification defines status_list.uri as a string claim value, the same type StatusListReference.Uri carries; System.Uri would round-trip it inexactly.")]
    public string Uri { get; }

    /// <summary>
    /// Creates a resolution exception.
    /// </summary>
    /// <param name="uri">The Status List Token <c>uri</c> the resolver could not obtain a verified token for.</param>
    /// <param name="message">A description of the resolution failure.</param>
    /// <param name="innerException">The underlying exception (a transport failure, a trust-verification failure), or <see langword="null"/>.</param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "The specification defines status_list.uri as a string claim value, the same type StatusListReference.Uri carries; System.Uri would round-trip it inexactly.")]
    public StatusListResolutionException(string uri, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);

        Uri = uri;
    }
}
