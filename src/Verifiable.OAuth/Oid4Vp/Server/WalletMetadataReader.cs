using System.Diagnostics;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Span-based reader for the subset of <c>wallet_metadata</c> the OID4VP
/// 1.0 §5.10 Verifier consults when deciding whether to JWE-wrap the JAR.
/// </summary>
/// <remarks>
/// <para>
/// The Wallet POSTs <c>wallet_metadata</c> alongside <c>wallet_nonce</c> on the
/// <c>request_uri_method=post</c> body per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// The Verifier reads <c>jwks</c> to learn the Wallet's public exchange key
/// for JAR encryption and (optionally)
/// <c>authorization_encrypted_response_enc</c> to learn which content
/// encryption algorithm to use.
/// </para>
/// <para>
/// Parsing builds on <see cref="JwkJsonReader"/> primitives — span-based,
/// no JSON serialisation library dependency. Returned values are
/// <see langword="null"/> when their respective member is absent or malformed.
/// </para>
/// </remarks>
[DebuggerDisplay("WalletMetadataReader")]
public static class WalletMetadataReader
{
    /// <summary>
    /// Parses the two members of <c>wallet_metadata</c> the JAR-encryption
    /// branch consumes: the <c>jwks</c> object (returned as JSON text with
    /// outer braces) and the <c>authorization_encrypted_response_enc</c>
    /// string. Either tuple slot is <see langword="null"/> when the
    /// corresponding member is absent or malformed. Empty/whitespace input
    /// returns <c>(null, null)</c>.
    /// </summary>
    /// <param name="walletMetadataJson">
    /// The raw wallet_metadata JSON text. <see langword="null"/> or whitespace
    /// is treated as no metadata.
    /// </param>
    public static (string? WalletEncryptionJwksJson, string? JarEncryptionEnc) ParseForJarEncryption(
        string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return (null, null);
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        string? jwksJson = JwkJsonReader.ExtractObjectAsString(bytes, "jwks"u8);
        string? enc = JwkJsonReader.ExtractStringValue(
            bytes, "authorization_encrypted_response_enc"u8);

        return (jwksJson, enc);
    }


    /// <summary>
    /// Strict-validation helper: returns a human-readable description of the first
    /// conformance defect in the posted <c>wallet_metadata</c>, or
    /// <see langword="null"/> when it is acceptable. The Wallet's
    /// <c>wallet_metadata</c> is its Authorization Server metadata (OID4VP 1.0 §10,
    /// layered on RFC 8414), so a conformant Verifier validates the full document
    /// rather than reading only the encryption subset. Checked, in order:
    /// <c>vp_formats_supported</c> present (OID4VP 1.0 §10 REQUIRED),
    /// <c>response_types_supported</c> present (the Wallet declares <c>vp_token</c>),
    /// <c>client_id_prefixes_supported</c> present (OID4VP 1.0 final — renamed from
    /// the draft <c>client_id_schemes_supported</c>),
    /// <c>issuer</c> present and an <c>https</c> URL (RFC 8414 §2 REQUIRED), and
    /// <c>authorization_endpoint</c> present and a custom invocation scheme ending
    /// with <c>://</c>. Empty/whitespace input returns <see langword="null"/> —
    /// "no metadata" is the caller's decision, distinct from "incomplete metadata".
    /// </summary>
    public static string? DescribeWalletPostDefect(string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        if(JwkJsonReader.ExtractObjectAsString(bytes, "vp_formats_supported"u8) is null)
        {
            return "the required member 'vp_formats_supported' is absent";
        }

        if(JwkJsonReader.ExtractStringArrayProperty(bytes, "response_types_supported"u8) is null)
        {
            return "the required member 'response_types_supported' is absent";
        }

        if(JwkJsonReader.ExtractStringArrayProperty(bytes, "client_id_prefixes_supported"u8) is null)
        {
            return "the required member 'client_id_prefixes_supported' is absent";
        }

        string? issuer = JwkJsonReader.ExtractStringValue(bytes, "issuer"u8);
        if(issuer is null)
        {
            return "the required member 'issuer' is absent";
        }

        if(!issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return $"issuer '{issuer}' must be an https URL (RFC 8414 §2) — it is the " +
                "Authorization Server's identity, not the custom invocation scheme";
        }

        string? authorizationEndpoint = JwkJsonReader.ExtractStringValue(bytes, "authorization_endpoint"u8);
        if(authorizationEndpoint is null)
        {
            return "the required member 'authorization_endpoint' is absent";
        }

        if(!authorizationEndpoint.EndsWith("://", StringComparison.Ordinal))
        {
            return $"authorization_endpoint '{authorizationEndpoint}' must be a custom " +
                "invocation scheme ending with '://'";
        }

        return null;
    }


    /// <summary>
    /// Reads the wallet's advertised <c>client_id_prefixes_supported</c>
    /// array per OID4VP 1.0 §10 — the client identifier prefixes (e.g.
    /// <c>redirect_uri</c>, <c>x509_san_dns</c>, <c>verifier_attestation</c>)
    /// the Wallet will accept on inbound Authorization Requests. Returns
    /// <see langword="null"/> when the member is absent or malformed;
    /// the empty array is returned as an empty list. Application code uses
    /// the result to choose a compatible prefix before signing the JAR.
    /// </summary>
    public static List<string>? ParseClientIdPrefixesSupported(string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        return JwkJsonReader.ExtractStringArrayProperty(
            bytes, "client_id_prefixes_supported"u8);
    }


    /// <summary>
    /// Reads the wallet's advertised <c>request_object_signing_alg_values_supported</c>
    /// array per OID4VP 1.0 §10. The Verifier consults this to pick a
    /// signing algorithm the Wallet will accept on the JAR. Returns
    /// <see langword="null"/> when absent or malformed.
    /// </summary>
    public static List<string>? ParseRequestObjectSigningAlgValuesSupported(string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        return JwkJsonReader.ExtractStringArrayProperty(
            bytes, "request_object_signing_alg_values_supported"u8);
    }


    /// <summary>
    /// Reads the wallet's <c>authorization_endpoint</c> per OID4VP 1.0 §10 —
    /// the URL scheme the Wallet listens on for Authorization Requests
    /// (e.g. <c>openid4vp://</c>). Returns <see langword="null"/> when
    /// absent. Application code typically does not need to act on this
    /// because the Wallet drives request fetching itself, but the value
    /// surfaces here for diagnostic completeness.
    /// </summary>
    public static string? ParseAuthorizationEndpoint(string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        return JwkJsonReader.ExtractStringValue(bytes, "authorization_endpoint"u8);
    }


    /// <summary>
    /// Returns the JSON text of <c>vp_formats_supported</c> (HAIP 1.0 §5.2 /
    /// OID4VP 1.0 §10) — a nested object keyed by credential format
    /// identifier (<c>dc+sd-jwt</c>, <c>mso_mdoc</c>, …) with per-format
    /// algorithm/curve hints. Returned as raw JSON text (braces included)
    /// so deployments parse the structure with their own JSON library; the
    /// shape is too nested to flatten into a single typed return.
    /// </summary>
    public static string? ParseVpFormatsSupportedJson(string? walletMetadataJson)
    {
        if(string.IsNullOrWhiteSpace(walletMetadataJson))
        {
            return null;
        }

        ReadOnlySpan<byte> bytes = Encoding.UTF8.GetBytes(walletMetadataJson);

        return JwkJsonReader.ExtractObjectAsString(bytes, "vp_formats_supported"u8);
    }
}
