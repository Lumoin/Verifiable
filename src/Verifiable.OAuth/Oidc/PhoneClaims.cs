using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>phone</c> scope.
/// </summary>
[DebuggerDisplay("PhoneClaims {PhoneNumber,nq}")]
public sealed record PhoneClaims
{
    /// <summary>The end-user's phone number. REQUIRED when constructing this record.</summary>
    public required string PhoneNumber { get; init; }

    /// <summary>
    /// Whether the phone number has been verified by the OP. Omitted on the
    /// wire when <see langword="null"/>.
    /// </summary>
    public bool? PhoneNumberVerified { get; init; }
}
