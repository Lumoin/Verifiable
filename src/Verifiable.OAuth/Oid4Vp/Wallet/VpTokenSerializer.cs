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
/// For SD-JWT VC the Presentation is the compact serialisation of the SD-JWT
/// with the selected disclosures appended, optionally followed by a KB-JWT, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("VpTokenSerializer")]
public static class VpTokenSerializer
{
    /// <summary>
    /// Serialises a single SD-JWT VC Presentation as the OID4VP <c>vp_token</c>
    /// JSON object: <c>{"&lt;credentialQueryId&gt;": ["&lt;compactPresentation&gt;"]}</c>.
    /// </summary>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier (the <c>id</c> field of the
    /// matched <see cref="Verifiable.Core.Model.Dcql.CredentialQuery"/>) used
    /// as the JSON object key.
    /// </param>
    /// <param name="compactPresentation">
    /// The full SD-JWT VC presentation: issuer-signed SD-JWT, selected disclosures,
    /// and KB-JWT, concatenated by <c>~</c>. Produced by
    /// <c>SdJwtSerializer.SerializeToken</c> on a token that already carries the
    /// KB-JWT via <c>SdToken&lt;string&gt;.WithKeyBinding</c>. The string is
    /// placed verbatim in the wire array — do not append additional separators.
    /// </param>
    /// <param name="payloadSerializer">
    /// Serialises a <see cref="JwtPayload"/> to UTF-8 JSON bytes. Reused here as
    /// the project's standard JSON-from-string-keyed-dict mechanism so number
    /// formatting, escaping, and culture invariants stay aligned across every
    /// JSON-producing step in the OID4VP flow.
    /// </param>
    /// <returns>The UTF-8-decoded JSON object as a string, ready to be carried in <see cref="States.PresentationBuilt.VpTokenJson"/>.</returns>
    public static string SerializeSingleSdJwtVc(
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
}
