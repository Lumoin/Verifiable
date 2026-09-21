using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>address</c>
/// scope. Serialized as a structured JSON object per OIDC Core §5.1.1.
/// </summary>
[DebuggerDisplay("AddressClaims {Locality,nq} {Country,nq}")]
public sealed record AddressClaims
{
    /// <summary>The full mailing address, formatted for display or use on a mailing label, with newlines as <c>\r\n</c> or <c>\n</c> (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? Formatted { get; init; }

    /// <summary>The full street address, which MAY include house number, street name, PO box, and multi-line extended address information, with newlines as <c>\r\n</c> or <c>\n</c> (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? StreetAddress { get; init; }

    /// <summary>The city or locality component (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? Locality { get; init; }

    /// <summary>The state, province, prefecture, or region component (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? Region { get; init; }

    /// <summary>The zip code or postal code component (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? PostalCode { get; init; }

    /// <summary>The country name component (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">OpenID Connect Core 1.0 §5.1.1</see>).</summary>
    public string? Country { get; init; }
}
