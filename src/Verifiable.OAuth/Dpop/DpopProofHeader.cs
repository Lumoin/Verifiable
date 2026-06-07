using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The JWS protected header of a DPoP proof per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
/// </summary>
[DebuggerDisplay("DpopProofHeader alg={Alg,nq} typ={Typ,nq}")]
public sealed record DpopProofHeader
{
    /// <summary>
    /// The signing algorithm, e.g. <c>ES256</c>. Must match the type of
    /// the embedded <see cref="Jwk"/>.
    /// </summary>
    public required string Alg { get; init; }

    /// <summary>
    /// The type — always <c>dpop+jwt</c> per RFC 9449 §4.2.
    /// </summary>
    public string Typ { get; init; } = WellKnownDpopValues.ProofTypeHeader;

    /// <summary>
    /// The public key used to verify the proof, serialised as a JWK. The
    /// AS / RS extracts this, computes its RFC 7638 thumbprint, and
    /// compares to the access token's <c>cnf.jkt</c> binding.
    /// </summary>
    public required IReadOnlyDictionary<string, string> Jwk { get; init; }
}
