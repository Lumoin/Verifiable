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

    /// <summary>
    /// The JWS <c>alg</c> values the receiver accepts for this proof, or <see langword="null"/> to hold
    /// the proof only to the identifiers a DPoP proof may be signed under
    /// (<see cref="Verifiable.JCose.WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(string)"/>). An
    /// empty list accepts no proof.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5:
    /// "The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm
    /// [IANA.JOSE.ALGS], is not none, is supported by the application, and is acceptable per local
    /// policy." The structural half (an asymmetric JWS signature identifier of the JOSE catalogue,
    /// <see cref="Verifiable.JCose.WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(string)"/>, never <c>none</c> or a
    /// MAC) is the validator's own; this list is the application's half, the identifiers it supports and
    /// its local policy accepts. The library's authorization server fills it from
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServerCryptography.ResolveSupportedSigningAlgorithmsAsync"/>
    /// for <see cref="Verifiable.Cryptography.Context.KeyUsageContext.DpopProof"/>, the list whose identifiers of the
    /// structural half its metadata publishes as <c>dpop_signing_alg_values_supported</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5.1">RFC 9449 Section 5.1</see>). Each
    /// entry is compared with the proof's <c>alg</c> exactly, as a JWS <c>alg</c> value is case-sensitive
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>).
    /// An identifier this list names is accepted only where <see cref="DpopProofValidator"/> binds a public
    /// key family to it (P-256, P-384, P-521, secp256k1, Ed25519 and RSA, through the identifiers of those
    /// families); a proof under a Brainpool ECDSA or an ML-DSA identifier is refused
    /// <see cref="DpopProofValidationFailureReason.InvalidAlg"/> for want of a binding, whatever this list names.
    /// The list accepts; it does not verify: the signature of an accepted proof is verified by the provider the host's
    /// registry serves for the family of the proof's public key, or by the primitive the host bound, and a family
    /// neither serves is refused <see cref="DpopProofValidationFailureReason.SignatureFailed"/>. An RSA public key is
    /// tagged by the proof's <c>alg</c>, so the registry verifies an accepted RSA identifier under the scheme it names.
    /// </remarks>
    public IReadOnlyList<string>? AcceptedAlgorithms { get; init; }
}
