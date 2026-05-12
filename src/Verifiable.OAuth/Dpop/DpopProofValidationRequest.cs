using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// All inputs needed to validate a DPoP proof. Threaded into
/// <see cref="ValidateDpopProofDelegate"/> as a single record so adding
/// new check inputs (audience policy, custom nonce policy, etc.) doesn't
/// re-shape the delegate signature.
/// </summary>
[DebuggerDisplay("DpopProofValidationRequest method={HttpMethod,nq} url={HttpUrl,nq}")]
public sealed record DpopProofValidationRequest
{
    /// <summary>The compact-serialised proof from the request's <c>DPoP</c> header.</summary>
    public required string Proof { get; init; }

    /// <summary>The HTTP method of the inbound request, uppercase.</summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// The receiver's inbound request URI, normalised to origin + path
    /// (no query, no fragment) per RFC 9449 §4.2. Compared by ordinal
    /// equality against the proof's <c>htu</c> claim, which is itself a
    /// wire-form string per the same section — keeping this as a string
    /// avoids re-parsing on every call and surfaces the spec's
    /// already-normalised form directly.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "RFC 9449 §4.2 specifies htu as a normalised string compared by ordinal equality; promoting to System.Uri would require re-normalising on every comparison.")]
    public required string HttpUrl { get; init; }

    /// <summary>
    /// The access token presented alongside the proof, or
    /// <see langword="null"/> for token-endpoint validation (where the
    /// access token is being requested, not presented).
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// The nonce the receiver expects to find in the proof's <c>nonce</c>
    /// claim. <see langword="null"/> when no nonce challenge is in flight;
    /// validation behaviour depends on <see cref="NonceRequired"/>.
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// When <see langword="true"/>, validation fails if the proof has no
    /// <c>nonce</c> claim or the value doesn't match
    /// <see cref="ExpectedNonce"/>. When <see langword="false"/>, an
    /// absent <c>nonce</c> is accepted; a present but mismatched
    /// <c>nonce</c> still fails when an <see cref="ExpectedNonce"/> is
    /// supplied.
    /// </summary>
    public required bool NonceRequired { get; init; }
}
