using System.Diagnostics;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Builds the OID4VP <c>vp_token</c> JSON object that the Wallet sends to the
/// Verifier per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7">OID4VP 1.0 §7</see>.
/// </summary>
/// <remarks>
/// <para>
/// The VP token is a JSON object whose keys are credential format identifiers
/// (e.g. <see cref="WellKnownMediaTypes.Jwt.DcSdJwt"/>) and whose values are
/// the credentials themselves (or arrays thereof). For the single-credential
/// SD-JWT VC case driven by HAIP §6, the value is a one-element array
/// containing the issuer-signed SD-JWT, its selected disclosures, and the
/// holder-signed KB-JWT, all concatenated by <c>~</c>:
/// </para>
/// <code>
/// {
///   "dc+sd-jwt": ["<sd-jwt>~<disclosure1>~<disclosure2>~<kb-jwt>"]
/// }
/// </code>
/// <para>
/// The output is the <c>VpTokenJson</c> string that
/// <see cref="States.PresentationBuilt"/> carries forward into the Wallet's
/// response phase.
/// </para>
/// </remarks>
[DebuggerDisplay("VpTokenSerializer")]
public static class VpTokenSerializer
{
    /// <summary>
    /// Serialises a single SD-JWT VC presentation as the OID4VP <c>vp_token</c>
    /// JSON object.
    /// </summary>
    /// <param name="sdJwtCompactWithDisclosuresAndKbJwt">
    /// The full presentation: issuer-signed SD-JWT, the selected disclosures, and
    /// the holder-signed KB-JWT, concatenated by <c>~</c> in that order.
    /// </param>
    /// <param name="payloadSerializer">
    /// Serialises a <see cref="JwtPayload"/> to UTF-8 JSON bytes. Reused here as
    /// the project's standard JSON-from-string-keyed-dict mechanism — the same
    /// instance the Wallet's KB-JWT issuance and the Verifier's pipeline use, so
    /// number formatting, escaping, and culture invariants stay aligned across
    /// every JSON-producing step in the OID4VP flow.
    /// </param>
    /// <returns>The UTF-8-decoded JSON object as a string, ready to be carried in <see cref="States.PresentationBuilt.VpTokenJson"/>.</returns>
    public static string SerializeSingleSdJwtVc(
        string sdJwtCompactWithDisclosuresAndKbJwt,
        JwtPayloadSerializer payloadSerializer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sdJwtCompactWithDisclosuresAndKbJwt);
        ArgumentNullException.ThrowIfNull(payloadSerializer);

        JwtPayload payload = new(capacity: 1)
        {
            [WellKnownMediaTypes.Jwt.DcSdJwt] = new[] { sdJwtCompactWithDisclosuresAndKbJwt }
        };

        ReadOnlySpan<byte> bytes = payloadSerializer(payload);
        return Encoding.UTF8.GetString(bytes);
    }
}
