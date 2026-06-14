using System.Diagnostics;
using System.Text;
using Verifiable.Server;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Serializes a <see cref="SiopProviderMetadata"/> to its canonical JSON document — the
/// Self-Issued OpenID Provider Discovery Metadata an RP obtains via Dynamic Discovery
/// (§6.1) or the static-configuration document of §15.1, per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-6.1">SIOPv2 §6.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Built on <see cref="JsonAppender"/> to honour the <c>Verifiable.OAuth</c> serialization
/// firewall, mirroring <see cref="SiopRequestSerializer.ToJson"/> and the OID4VP
/// <see cref="Oid4Vp.Wallet.WalletMetadataWriter"/> on the inverse OP-side surface. Member
/// names reuse the existing parameter-name constants
/// (<see cref="AuthorizationServerMetadataParameterNames"/>,
/// <see cref="OpenIdProviderMetadataParameterNames"/>,
/// <see cref="SiopClientMetadataParameterNames"/>).
/// </para>
/// <para>
/// The §6.1 security invariant is enforced structurally: <see cref="SiopProviderMetadata"/>
/// has no <c>jwks_uri</c> member, so the writer cannot emit one — "contrary to
/// [OpenID.Discovery], <c>jwks_uri</c> parameter MUST NOT be present in Self-Issued OP
/// Metadata" (§6.1). The RP obtains the signing key from the ID Token's <c>sub</c> Claim
/// (<c>sub_jwk</c> for the JWK Thumbprint subject syntax type, or the resolved DID).
/// </para>
/// </remarks>
[DebuggerDisplay("SiopProviderMetadataWriter")]
public static class SiopProviderMetadataWriter
{
    /// <summary>
    /// Serializes the Self-Issued OP Discovery Metadata to its JSON document — the value an
    /// OP publishes at <c>/.well-known/openid-configuration</c> for Dynamic Discovery (§6.1),
    /// or the §15.1 static-configuration document. Fields are emitted in §6.1 document order;
    /// the OPTIONAL <c>issuer</c>, <c>vp_formats_supported</c>, and
    /// <c>id_token_types_supported</c> members are omitted when unset. No <c>jwks_uri</c>
    /// member is ever emitted (§6.1 MUST NOT).
    /// </summary>
    /// <param name="metadata">The Self-Issued OP metadata to serialize.</param>
    /// <returns>The JSON-encoded Self-Issued OP Discovery Metadata document.</returns>
    public static string ToJson(SiopProviderMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            //§6.1 authorization_endpoint (REQUIRED) — first member, matching the §6.1 and
            //§15.1 example ordering.
            JsonAppender.AppendStringField(
                sb, AuthorizationServerMetadataParameterNames.AuthorizationEndpoint,
                metadata.AuthorizationEndpoint, ref first);

            //§6.1 issuer — REQUIRED for Dynamic Discovery, absent from the §15.1 static sets.
            if(metadata.Issuer is not null)
            {
                JsonAppender.AppendStringField(
                    sb, AuthorizationServerMetadataParameterNames.Issuer,
                    metadata.Issuer, ref first);
            }

            //§6.1 response_types_supported (REQUIRED, MUST include id_token).
            JsonAppender.AppendStringArrayField(
                sb, AuthorizationServerMetadataParameterNames.ResponseTypesSupported,
                metadata.ResponseTypesSupported, ref first);

            //§15.1.3 vp_formats_supported — present only in the openid:// static set and when
            //the OP advertises Verifiable Presentation support (§12); a raw JSON object value.
            if(metadata.VpFormatsSupportedJson is not null)
            {
                JsonAppender.AppendRawField(
                    sb, Oid4Vp.Oid4VpClientMetadataParameterNames.VpFormatsSupported,
                    metadata.VpFormatsSupportedJson, ref first);
            }

            //§6.1 scopes_supported (REQUIRED, MUST support openid).
            JsonAppender.AppendStringArrayField(
                sb, AuthorizationServerMetadataParameterNames.ScopesSupported,
                metadata.ScopesSupported, ref first);

            //§6.1 subject_types_supported (REQUIRED; pairwise and public are valid values).
            JsonAppender.AppendStringArrayField(
                sb, OpenIdProviderMetadataParameterNames.SubjectTypesSupported,
                metadata.SubjectTypesSupported, ref first);

            //§6.1 id_token_signing_alg_values_supported (REQUIRED).
            JsonAppender.AppendStringArrayField(
                sb, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported,
                metadata.IdTokenSigningAlgValuesSupported, ref first);

            //§6.1 request_object_signing_alg_values_supported (REQUIRED).
            JsonAppender.AppendStringArrayField(
                sb, SiopClientMetadataParameterNames.RequestObjectSigningAlgValuesSupported,
                metadata.RequestObjectSigningAlgValuesSupported, ref first);

            //§6.1 subject_syntax_types_supported (REQUIRED).
            JsonAppender.AppendStringArrayField(
                sb, SiopClientMetadataParameterNames.SubjectSyntaxTypesSupported,
                metadata.SubjectSyntaxTypesSupported, ref first);

            //§6.1 id_token_types_supported (OPTIONAL; default attester_signed_id_token).
            if(metadata.IdTokenTypesSupported is not null)
            {
                JsonAppender.AppendStringArrayField(
                    sb, SiopClientMetadataParameterNames.IdTokenTypesSupported,
                    metadata.IdTokenTypesSupported, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
