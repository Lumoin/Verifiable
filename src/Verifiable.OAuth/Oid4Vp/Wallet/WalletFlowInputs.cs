using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// A <c>request_uri</c> has been received by the Wallet, typically by scanning a QR
/// code or following a deep link. Drives <c>RequestUriReceived</c> → <c>JarParsed</c>.
/// </summary>
/// <param name="RequestUri">
/// The <c>request_uri</c> from which the Wallet fetches the JAR JWT.
/// </param>
/// <param name="Request">
/// The typed Authorization Request Object parsed from the JAR JWT fetched at
/// <paramref name="RequestUri"/>. Signature verification must be completed by
/// the caller before constructing this input.
/// </param>
/// <param name="FetchedAt">The UTC instant at which the JAR was fetched and parsed.</param>
public sealed record JarReceived(
    Uri RequestUri,
    AuthorizationRequestObject Request,
    DateTimeOffset FetchedAt): OAuthFlowInput;


/// <summary>
/// The DCQL query has been evaluated against the Wallet's held credentials and at least
/// one match has been found. Drives <c>JarParsed</c> → <c>DcqlEvaluated</c>.
/// </summary>
/// <param name="PreparedQuery">The prepared DCQL query ready for disclosure strategy computation.</param>
/// <param name="MatchedCredentialIds">
/// Held credential identifiers that satisfy the query, keyed by DCQL credential query ID.
/// </param>
/// <param name="EvaluatedAt">The UTC instant at which evaluation completed.</param>
public sealed record DcqlMatched(
    PreparedDcqlQuery PreparedQuery,
    IReadOnlyDictionary<string, string> MatchedCredentialIds,
    DateTimeOffset EvaluatedAt): OAuthFlowInput;


/// <summary>
/// Minimum disclosures have been selected and the VP token payload has been assembled.
/// Drives <c>DcqlEvaluated</c> → <c>PresentationBuilt</c>.
/// </summary>
/// <param name="VpTokenJson">
/// The VP token as UTF-8 JSON, keyed by DCQL credential query identifier per OID4VP 1.0 §7.
/// </param>
/// <param name="SelectedAt">The UTC instant at which disclosures were selected.</param>
public sealed record PresentationSelected(
    string VpTokenJson,
    DateTimeOffset SelectedAt): OAuthFlowInput;


/// <summary>
/// The encrypted Authorization Response has been POSTed to <c>response_uri</c> and the
/// server has acknowledged receipt. Drives <c>PresentationBuilt</c> → <c>ResponseSent</c>.
/// </summary>
/// <param name="ResponseUri">The <c>response_uri</c> that received the POST.</param>
/// <param name="State">The opaque state value echoed from the Authorization Request, if present.</param>
/// <param name="SentAt">The UTC instant at which the POST was acknowledged.</param>
public sealed record ResponsePostedByWallet(
    Uri ResponseUri,
    string? State,
    DateTimeOffset SentAt): OAuthFlowInput;


/// <summary>
/// The Verifier's HTTP response to the <c>direct_post.jwt</c> POST contained a
/// <c>redirect_uri</c> that the Wallet must follow to return the user to the browser
/// session. Drives <c>ResponseSent</c> → <see cref="BrowserRedirectIssued"/>.
/// </summary>
/// <remarks>
/// This input is only produced in the same-device flow. In the cross-device flow the
/// Verifier's POST response carries no redirect URI and the flow ends at
/// <see cref="ResponseSent"/>. The application must read the <c>redirect_uri</c> from the
/// Verifier's HTTP 200 response body and construct this input before feeding it to the
/// Wallet PDA.
/// </remarks>
/// <param name="RedirectUri">
/// The URI from the Verifier's HTTP response body to which the Wallet redirects the
/// user's browser session per OID4VP 1.0 §8.2.
/// </param>
/// <param name="ReceivedAt">
/// The UTC instant at which the Verifier's response containing the redirect URI was
/// received.
/// </param>
public sealed record RedirectReceived(
    Uri RedirectUri,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
