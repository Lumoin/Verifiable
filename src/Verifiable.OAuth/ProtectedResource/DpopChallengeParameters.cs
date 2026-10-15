using System.Diagnostics;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The authentication parameters read from a <c>WWW-Authenticate: DPoP</c> challenge by
/// <see cref="DpopChallenge.TryParse"/> and <see cref="DpopChallenge.TryRead"/>, the parameters
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> names for the scheme.
/// Every parameter is optional in the challenge, so any may be <see langword="null"/>.
/// </summary>
/// <remarks>
/// <see cref="ErrorDescription"/> is read because a server MAY send one (Section 7.1: "An error_description parameter
/// ([RFC6750], Section 3) MAY be included along with the error parameter to provide developers a human-readable
/// explanation that is not meant to be displayed to end-users."); the library's own builder,
/// <see cref="DpopChallenge.BuildChallenge"/>, never writes it, the response body carrying the description.
/// </remarks>
/// <param name="Realm">
/// The protection-space identifier. Section 7.1: "The authentication parameter realm MAY be included to indicate the
/// scope of protection in the manner described in [RFC9110], Section 11.5."
/// </param>
/// <param name="Error">
/// The error code. Section 7.1: "An error parameter ([RFC6750], Section 3) SHOULD be included to indicate the reason why
/// the request was declined, if the request included an access token but failed authentication.", among them
/// <c>use_dpop_nonce</c> and <c>invalid_dpop_proof</c>.
/// </param>
/// <param name="ErrorDescription">The developer-readable explanation of the error (Section 7.1, RFC 6750 Section 3).</param>
/// <param name="Scope">
/// The space-delimited scopes the resource requires. Section 7.1: "A scope authentication parameter MAY be included as
/// defined in [RFC6750], Section 3."
/// </param>
/// <param name="Algorithms">
/// The names of the <c>algs</c> value, in the order written, or <see langword="null"/> when the challenge carries no
/// <c>algs</c>. Section 7.1: "An algs parameter SHOULD be included to signal to the client the JWS algorithms that are
/// acceptable for the DPoP proof JWT. The value of the parameter is a space-delimited list of JWS alg (Algorithm)
/// header values ([RFC7515], Section 4.1.1)."
/// </param>
/// <param name="ResourceMetadata">
/// The <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>
/// <c>resource_metadata</c> URL: "This parameter MAY also be used in WWW-Authenticate responses using authorization
/// schemes other than "Bearer" [RFC6750], such as the DPoP scheme defined by [RFC9449]." Per RFC 9728 Section 3.3 the
/// fetched document's <c>resource</c> value MUST be identical to the URL the client used to make the resource request;
/// verify with <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> before using the document.
/// </param>
[DebuggerDisplay("DpopChallengeParameters Error={Error} Scope={Scope}")]
public sealed record DpopChallengeParameters(
    string? Realm,
    string? Error,
    string? ErrorDescription,
    string? Scope,
    IReadOnlyList<string>? Algorithms,
    Uri? ResourceMetadata);
