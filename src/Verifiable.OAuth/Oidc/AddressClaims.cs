using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>address</c>
/// scope. Serialized as a structured JSON object per OIDC Core §5.1.1.
/// </summary>
[DebuggerDisplay("AddressClaims {Locality,nq} {Country,nq}")]
public sealed record AddressClaims
{
    public string? Formatted { get; init; }
    public string? StreetAddress { get; init; }
    public string? Locality { get; init; }
    public string? Region { get; init; }
    public string? PostalCode { get; init; }
    public string? Country { get; init; }
}
