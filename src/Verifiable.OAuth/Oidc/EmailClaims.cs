using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>email</c> scope.
/// </summary>
[DebuggerDisplay("EmailClaims Email={Email,nq} Verified={EmailVerified}")]
public sealed record EmailClaims
{
    /// <summary>The end-user's email address. REQUIRED when constructing this record.</summary>
    public required string Email { get; init; }

    /// <summary>
    /// Whether the email address has been verified by the OP. Omitted on the
    /// wire when <see langword="null"/>.
    /// </summary>
    public bool? EmailVerified { get; init; }
}
