using System.Diagnostics;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Parses an <see cref="AuthorizationRequestObject"/> from form-encoded or
/// query-string parameters — the wire shape used by OID4VP 1.0 §5.10 when the
/// Verifier sends the Authorization Request directly (not via the
/// <c>request_uri</c> indirection) with the <c>redirect_uri</c> client
/// identifier prefix per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>redirect_uri</c> prefix mandates an UNSIGNED request (spec text:
/// "the Authorization Request MUST NOT be signed"). The Verifier MAY omit
/// the <c>request_uri</c> parameter and send the Authorization Request
/// parameters inline as URL query parameters (e.g. on an <c>openid4vp://</c>
/// deep link) — this factory is the wallet-side parser for that shape.
/// </para>
/// <para>
/// Trust in this shape comes from the wallet POSTing the Authorization
/// Response back to <see cref="AuthorizationRequestObject.ResponseUri"/>,
/// which the <c>redirect_uri:</c> prefix asserts equals
/// <see cref="AuthorizationRequestObject.ClientId"/> (modulo the prefix
/// marker). Any attacker that successfully steered the wallet to a
/// different URL would have to also receive the wallet's POST — and if they
/// can, the deployment has a bigger problem than this validation can solve.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationRequestObjectFormFields")]
public static class AuthorizationRequestObjectFormFields
{
    /// <summary>
    /// Builds an <see cref="AuthorizationRequestObject"/> from the parameter
    /// values the Verifier sent inline. Required parameters per OID4VP 1.0 §5
    /// are validated; the timing claims <c>iat</c> / <c>nbf</c> / <c>exp</c>
    /// are stamped at <paramref name="now"/> if absent from the inline
    /// parameters (typical for the unsigned URL-parameter shape — there's no
    /// signed envelope to bind them to).
    /// </summary>
    /// <param name="fields">
    /// The inline parameters, e.g. <c>client_id</c>, <c>response_type</c>,
    /// <c>response_mode</c>, <c>response_uri</c>, <c>nonce</c>, <c>state</c>,
    /// and optionally <c>dcql_query</c> (JSON), <c>client_metadata</c> (JSON),
    /// <c>transaction_data</c> (one or more entries — joined by spaces is
    /// not supported here; pass via <paramref name="transactionDataEntries"/>
    /// directly when present).
    /// </param>
    /// <param name="dcqlQueryDeserializer">
    /// Deserialises the <c>dcql_query</c> form value (JSON text) into a
    /// <see cref="DcqlQuery"/>. Required when the inline parameters carry a
    /// <c>dcql_query</c>; ignored otherwise.
    /// </param>
    /// <param name="clientMetadataDeserializer">
    /// Deserialises the <c>client_metadata</c> form value (JSON text) into a
    /// <see cref="VerifierClientMetadata"/>. Required when the inline
    /// parameters carry a <c>client_metadata</c>; ignored otherwise.
    /// </param>
    /// <param name="now">UTC instant used to stamp the timing claims when absent.</param>
    /// <param name="requestObjectLifetime">
    /// Window applied as <c>exp = now + requestObjectLifetime</c> when the
    /// <c>exp</c> claim is absent from the inline parameters.
    /// </param>
    /// <param name="transactionDataEntries">
    /// Optional pre-split <c>transaction_data</c> entries (each a base64url-
    /// encoded JSON descriptor per OID4VP 1.0 §8.4). Inline URL parameters
    /// cannot carry an array natively; callers that need transaction-data
    /// binding parse the descriptors out of their deployment-specific shape
    /// and pass them here. <see langword="null"/> omits the claim.
    /// </param>
    public static AuthorizationRequestObject Parse(
        IReadOnlyDictionary<string, string> fields,
        JarClaimDeserializer<DcqlQuery> dcqlQueryDeserializer,
        JarClaimDeserializer<VerifierClientMetadata> clientMetadataDeserializer,
        DateTimeOffset now,
        TimeSpan requestObjectLifetime,
        StateParameterPolicy statePolicy,
        IReadOnlyList<string>? transactionDataEntries = null)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(dcqlQueryDeserializer);
        ArgumentNullException.ThrowIfNull(clientMetadataDeserializer);

        if(requestObjectLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(requestObjectLifetime),
                requestObjectLifetime,
                "Inline-parameter request-object lifetime must be positive.");
        }

        string clientId = Require(fields, OAuthRequestParameterNames.ClientId);
        string responseType = Require(fields, OAuthRequestParameterNames.ResponseType);
        string responseMode = Require(fields, OAuthRequestParameterNames.ResponseMode);
        string responseUriValue = Require(
            fields, Oid4VpAuthorizationRequestParameterNames.ResponseUri);
        string nonce = Require(fields, WellKnownJwtClaimNames.Nonce);

        //OID4VP 1.0 §5 / RFC 6749 §4.1.1 — state is OPTIONAL; the caller decides per call.
        string? state = statePolicy == StateParameterPolicy.Required
            ? Require(fields, OAuthRequestParameterNames.State)
            : (fields.TryGetValue(OAuthRequestParameterNames.State, out string? stateValue)
                && !string.IsNullOrWhiteSpace(stateValue) ? stateValue : null);

        if(!Uri.TryCreate(responseUriValue, UriKind.Absolute, out Uri? responseUri))
        {
            throw new FormatException(
                $"Inline '{Oid4VpAuthorizationRequestParameterNames.ResponseUri}' " +
                $"is not an absolute URI: '{responseUriValue}'.");
        }

        DcqlQuery? dcqlQuery = null;
        if(fields.TryGetValue(
                Oid4VpAuthorizationRequestParameterNames.DcqlQuery,
                out string? dcqlJson)
            && !string.IsNullOrWhiteSpace(dcqlJson))
        {
            dcqlQuery = dcqlQueryDeserializer(dcqlJson);
        }

        VerifierClientMetadata? clientMetadata = null;
        if(fields.TryGetValue(
                Oid4VpAuthorizationRequestParameterNames.ClientMetadata,
                out string? clientMetadataJson)
            && !string.IsNullOrWhiteSpace(clientMetadataJson))
        {
            clientMetadata = clientMetadataDeserializer(clientMetadataJson);
        }

        return new AuthorizationRequestObject
        {
            ClientId = clientId,
            ResponseType = responseType,
            ResponseMode = responseMode,
            ResponseUri = responseUri,
            Nonce = nonce,
            State = state,
            Iat = now,
            Nbf = now,
            Exp = now + requestObjectLifetime,
            DcqlQuery = dcqlQuery,
            ClientMetadata = clientMetadata,
            TransactionData = transactionDataEntries
        };
    }


    private static string Require(IReadOnlyDictionary<string, string> fields, string key)
    {
        if(!fields.TryGetValue(key, out string? value)
            || string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException(
                $"Inline Authorization Request is missing required parameter '{key}'.");
        }

        return value;
    }
}
