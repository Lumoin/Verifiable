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
    DateTimeOffset FetchedAt): FlowInput;


/// <summary>
/// The Wallet has POSTed <c>wallet_nonce</c> (and optionally <c>wallet_metadata</c>)
/// to the Verifier's <c>request_uri</c> per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// Drives <c>RequestUriReceived</c> → <c>WalletNonceSent</c>.
/// </summary>
/// <param name="RequestUri">The <c>request_uri</c> that received the POST.</param>
/// <param name="WalletNonce">
/// The fresh Wallet-issued nonce included in the POST body. The Verifier must
/// echo it in the served JAR's <c>wallet_nonce</c> claim.
/// </param>
/// <param name="SentAt">The UTC instant at which the POST was acknowledged.</param>
public sealed record WalletPostSent(
    Uri RequestUri,
    string WalletNonce,
    DateTimeOffset SentAt): FlowInput;


/// <summary>
/// The DCQL query has been evaluated against the Wallet's held credentials and at least
/// one match has been found and presented. Drives <c>JarParsed</c> → <c>DcqlEvaluated</c>.
/// </summary>
/// <param name="PreparedQuery">The prepared DCQL query ready for disclosure strategy computation.</param>
/// <param name="MatchedPresentationsByQueryId">
/// The wire-form presentation produced per matched credential query, keyed by DCQL
/// credential query ID. The values are opaque presentation strings (format-neutral),
/// retained for traceability.
/// </param>
/// <param name="EvaluatedAt">The UTC instant at which evaluation completed.</param>
public sealed record DcqlMatched(
    PreparedDcqlQuery PreparedQuery,
    IReadOnlyDictionary<string, string> MatchedPresentationsByQueryId,
    DateTimeOffset EvaluatedAt): FlowInput;


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
    DateTimeOffset SelectedAt): FlowInput;


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
    DateTimeOffset SentAt): FlowInput;


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
    DateTimeOffset ReceivedAt): FlowInput;
