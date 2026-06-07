using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The claim set of a DPoP proof JWS per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
/// </summary>
/// <remarks>
/// All required claims are populated by the construction helper.
/// <see cref="Nonce"/> and <see cref="Ath"/> are populated conditionally —
/// <see cref="Nonce"/> when a server nonce is in flight, <see cref="Ath"/>
/// only on resource-server calls where an access token is being presented.
/// </remarks>
[DebuggerDisplay("DpopProofClaims htm={Htm,nq} htu={Htu,nq} jti={Jti,nq}")]
public sealed record DpopProofClaims
{
    /// <summary>The HTTP method of the request the proof authorizes, uppercase.</summary>
    public required string Htm { get; init; }

    /// <summary>
    /// The HTTP URI the proof authorizes — origin + path, no query and no
    /// fragment per RFC 9449 §4.2. The receiver computes the same
    /// normalization on its inbound URI and compares for equality.
    /// </summary>
    public required string Htu { get; init; }

    /// <summary>The proof's issuance time.</summary>
    public required DateTimeOffset Iat { get; init; }

    /// <summary>
    /// A unique identifier for this proof, used by the receiver's replay
    /// cache. Per RFC 9449 §4.2 the value SHOULD be a high-entropy
    /// identifier (UUID, base64-encoded CSPRNG bytes).
    /// </summary>
    public required string Jti { get; init; }

    /// <summary>
    /// The server-issued nonce being echoed in this proof, or
    /// <see langword="null"/> if no nonce is in flight.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Base64url-encoded SHA-256 of the access token being presented, per
    /// RFC 9449 §4.3. Set on resource-server calls; <see langword="null"/>
    /// for token-endpoint proofs (where the access token is being requested,
    /// not presented).
    /// </summary>
    public string? Ath { get; init; }
}
