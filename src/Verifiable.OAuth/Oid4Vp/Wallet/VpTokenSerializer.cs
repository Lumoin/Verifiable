using System.Diagnostics;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Builds the OID4VP <c>vp_token</c> JSON object that the Wallet sends to the
/// Verifier per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#response-parameters">OID4VP 1.0 §8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The VP Token is a JSON-encoded object whose keys are the <c>id</c> values
/// from the DCQL query's <c>credentials</c> list and whose values are arrays
/// of one or more Presentations matching the respective Credential Query.
/// When the Credential Query's <c>multiple</c> is omitted or <see langword="false"/>,
/// the array contains exactly one Presentation; the wire shape is the array
/// regardless of cardinality.
/// </para>
/// <para>
/// The presentation string is opaque to this serializer and is placed verbatim
/// in the wire array, so the same shape carries every credential format: an
/// SD-JWT VC presentation (issuer JWS + selected disclosures + KB-JWT joined by
/// <c>~</c>), a base64url mdoc DeviceResponse, or an SD-CWT presentation.
/// </para>
/// </remarks>
[DebuggerDisplay("VpTokenSerializer")]
public static class VpTokenSerializer
{
    /// <summary>
    /// Serialises a single Presentation as the OID4VP <c>vp_token</c>
    /// JSON object: <c>{"&lt;credentialQueryId&gt;": ["&lt;compactPresentation&gt;"]}</c>.
    /// </summary>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier (the <c>id</c> field of the
    /// matched <see cref="Verifiable.Core.Model.Dcql.CredentialQuery"/>) used
    /// as the JSON object key.
    /// </param>
    /// <param name="compactPresentation">
    /// The full wire-form presentation produced by the credential's
    /// <see cref="ProduceVpTokenPresentationsDelegate"/>. The string is placed verbatim
    /// in the wire array — do not append additional separators.
    /// </param>
    /// <param name="payloadSerializer">
    /// Serialises a <see cref="JwtPayload"/> to UTF-8 JSON bytes. Reused here as
    /// the project's standard JSON-from-string-keyed-dict mechanism so number
    /// formatting, escaping, and culture invariants stay aligned across every
    /// JSON-producing step in the OID4VP flow.
    /// </param>
    /// <returns>The UTF-8-decoded JSON object as a string, ready to be carried in <see cref="States.PresentationBuilt.VpTokenJson"/>.</returns>
    public static string SerializeSingle(
        string credentialQueryId,
        string compactPresentation,
        JwtPayloadSerializer payloadSerializer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialQueryId);
        ArgumentException.ThrowIfNullOrWhiteSpace(compactPresentation);
        ArgumentNullException.ThrowIfNull(payloadSerializer);

        JwtPayload payload = new(capacity: 1)
        {
            [credentialQueryId] = new[] { compactPresentation }
        };

        ReadOnlySpan<byte> bytes = payloadSerializer(payload);
        return Encoding.UTF8.GetString(bytes);
    }


    /// <summary>
    /// Serialises multiple presentations as the OID4VP
    /// <c>vp_token</c> JSON object:
    /// <c>{"&lt;qid1&gt;": ["&lt;presentation1&gt;"], "&lt;qid2&gt;": ["&lt;presentation2&gt;"], ...}</c>.
    /// Each entry's array still carries exactly one presentation under the
    /// single-presentation-per-query default; the
    /// <see cref="Verifiable.Core.Model.Dcql.CredentialQuery.Multiple"/>
    /// extension for multiple presentations under one query id is a future
    /// extension beyond this slice.
    /// </summary>
    /// <param name="presentationsByQueryId">
    /// Map from DCQL credential query id to the full wire-form presentation for
    /// that query, the way <see cref="SerializeSingle"/> documents.
    /// </param>
    /// <param name="payloadSerializer">As on <see cref="SerializeSingle"/>.</param>
    /// <returns>The UTF-8-decoded JSON object as a string.</returns>
    public static string SerializeMultiple(
        IReadOnlyDictionary<string, string> presentationsByQueryId,
        JwtPayloadSerializer payloadSerializer)
    {
        ArgumentNullException.ThrowIfNull(presentationsByQueryId);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        if(presentationsByQueryId.Count == 0)
        {
            throw new ArgumentException(
                "At least one credential-query presentation is required.",
                nameof(presentationsByQueryId));
        }

        JwtPayload payload = new(capacity: presentationsByQueryId.Count);
        foreach(KeyValuePair<string, string> entry in presentationsByQueryId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.Key, nameof(presentationsByQueryId));
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.Value, nameof(presentationsByQueryId));
            payload[entry.Key] = new[] { entry.Value };
        }

        ReadOnlySpan<byte> bytes = payloadSerializer(payload);

        return Encoding.UTF8.GetString(bytes);
    }


    /// <summary>
    /// Serialises the OID4VP 1.0 §8.3.1 <c>direct_post.jwt</c> Authorization
    /// Response payload — the JSON object that becomes the JWE plaintext — with the
    /// response parameters as NAMED CLAIMS: <c>{"vp_token": {...}, "state": "..."}</c>.
    /// The <c>vp_token</c> claim is the §8.1 DCQL-keyed object (the same shape
    /// <see cref="SerializeMultiple"/> produces), nested under the <c>vp_token</c>
    /// member rather than placed at the top level.
    /// </summary>
    /// <remarks>
    /// This is distinct from the §8.2 plaintext <c>direct_post</c> path, where
    /// <c>vp_token</c> and <c>state</c> are separate <c>application/x-www-form-urlencoded</c>
    /// fields (the bare object from <see cref="SerializeSingle"/>/<see cref="SerializeMultiple"/>).
    /// For <c>direct_post.jwt</c> the spec requires them inside the response JWT, so
    /// <c>state</c> is integrity-protected by the JWE rather than carried as an outer
    /// form field.
    /// </remarks>
    /// <param name="presentationsByQueryId">DCQL-query-id → wire presentation, as on <see cref="SerializeMultiple"/>.</param>
    /// <param name="state">The <c>state</c> echoed from the Authorization Request; omitted when <see langword="null"/>/empty.</param>
    /// <param name="payloadSerializer">As on <see cref="SerializeSingle"/>.</param>
    /// <returns>The UTF-8-decoded response-JWT payload JSON, ready to be the JWE plaintext.</returns>
    public static string SerializeDirectPostJwtResponse(
        IReadOnlyDictionary<string, string> presentationsByQueryId,
        string? state,
        JwtPayloadSerializer payloadSerializer)
    {
        ArgumentNullException.ThrowIfNull(presentationsByQueryId);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        if(presentationsByQueryId.Count == 0)
        {
            throw new ArgumentException(
                "At least one credential-query presentation is required.",
                nameof(presentationsByQueryId));
        }

        JwtPayload vpToken = new(capacity: presentationsByQueryId.Count);
        foreach(KeyValuePair<string, string> entry in presentationsByQueryId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.Key, nameof(presentationsByQueryId));
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.Value, nameof(presentationsByQueryId));
            vpToken[entry.Key] = new[] { entry.Value };
        }

        JwtPayload response = new(capacity: 2)
        {
            [AuthorizationResponseParameters.VpToken] = vpToken
        };

        if(!string.IsNullOrEmpty(state))
        {
            response[AuthorizationResponseParameters.State] = state;
        }

        ReadOnlySpan<byte> bytes = payloadSerializer(response);

        return Encoding.UTF8.GetString(bytes);
    }
}
