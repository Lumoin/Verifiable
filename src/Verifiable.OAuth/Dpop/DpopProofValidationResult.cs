using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The result of validating a DPoP proof.
/// </summary>
[DebuggerDisplay("DpopProofValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record DpopProofValidationResult
{
    /// <summary>The validated claims if the proof is valid; otherwise <see langword="null"/>.</summary>
    public DpopProofClaims? Claims { get; init; }

    /// <summary>
    /// The base64url-encoded RFC 7638 thumbprint of the proof's embedded
    /// JWK, if validation succeeded. This is the value the receiver
    /// compares against an access token's <c>cnf.jkt</c> binding.
    /// </summary>
    public string? JwkThumbprint { get; init; }

    /// <summary>
    /// The failure reason if the proof was rejected. <see langword="null"/>
    /// on success.
    /// </summary>
    public DpopProofValidationFailureReason? FailureReason { get; init; }

    /// <summary>
    /// The reading's own refusal of the proof's part, carried whole beside <see cref="FailureReason"/> when the reading of the
    /// protected header or the claims set refused it (<see cref="DpopProofPartRefused{TPart}"/>): the JSON reader's refusal of
    /// the part's document (<see cref="JwsPartDocumentRefusal"/>) or the member the part was refused for
    /// (<see cref="DpopProofMemberRefusal"/>), so a receiver records the reason without reading the proof again.
    /// <see langword="null"/> on success and for a failure no reading refused.
    /// </summary>
    public JwsPartRefusal? PartRefusal { get; init; }

    /// <summary><see langword="true"/> when the proof is valid.</summary>
    public bool IsSuccess => FailureReason is null;

    /// <summary>Builds a success result.</summary>
    public static DpopProofValidationResult Success(DpopProofClaims claims, string jwkThumbprint) =>
        new() { Claims = claims, JwkThumbprint = jwkThumbprint };

    /// <summary>Builds a failure result.</summary>
    public static DpopProofValidationResult Failure(DpopProofValidationFailureReason reason) =>
        new() { FailureReason = reason };


    /// <summary>Builds the failure of a proof whose part its reading refused, carrying the reading's refusal.</summary>
    /// <param name="reason">The coarse category the refusal is answered under.</param>
    /// <param name="partRefusal">The reading's refusal of the part.</param>
    /// <returns>The failure.</returns>
    public static DpopProofValidationResult PartRefused(DpopProofValidationFailureReason reason, JwsPartRefusal partRefusal)
    {
        ArgumentNullException.ThrowIfNull(partRefusal);

        return new() { FailureReason = reason, PartRefusal = partRefusal };
    }
}
