using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Claim NAMES for the <c>transaction_data</c> mechanism per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
/// </summary>
/// <remarks>
/// <para>
/// Each <c>transaction_data</c> Authorization Request parameter entry is a
/// base64url-encoded JSON object that the Wallet decodes, inspects for type
/// support and credential-id binding, and hashes (in its original base64url
/// ASCII form) into <see cref="Hashes"/> on the KB-JWT.
/// </para>
/// <para>
/// The descriptor object fields (<see cref="Type"/>, <see cref="CredentialIds"/>,
/// <see cref="HashesAlg"/>) live inside the decoded JSON; the KB-JWT claim
/// names (<see cref="Hashes"/>, <see cref="HashesAlg"/>) live in the
/// emitted KB-JWT payload. The names overlap because the spec ties the
/// algorithm choice to the descriptor itself.
/// </para>
/// </remarks>
[DebuggerDisplay("TransactionDataClaimNames")]
public static class TransactionDataClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>The <c>type</c> field inside a decoded transaction_data
    /// descriptor — identifies the transaction semantic the Wallet must
    /// understand to consent (e.g. <c>qes_authorization</c>).</summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialIds"/>.</summary>
    public static ReadOnlySpan<byte> CredentialIdsUtf8 => "credential_ids"u8;

    /// <summary>The <c>credential_ids</c> field inside a decoded
    /// transaction_data descriptor — the DCQL credential identifiers the
    /// transaction is bound to. Each value must reference a credential the
    /// Verifier requested in <c>dcql_query</c>.</summary>
    public static readonly string CredentialIds = Utf8Constants.ToInternedString(CredentialIdsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HashesAlg"/>.</summary>
    public static ReadOnlySpan<byte> HashesAlgUtf8 => "transaction_data_hashes_alg"u8;

    /// <summary>The <c>transaction_data_hashes_alg</c> field — used both as
    /// an optional field inside a transaction_data descriptor (Verifier-
    /// permitted hash algorithms; defaults to <c>["sha-256"]</c>) and as
    /// an optional claim on the KB-JWT (Wallet-selected algorithm).</summary>
    public static readonly string HashesAlg = Utf8Constants.ToInternedString(HashesAlgUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Hashes"/>.</summary>
    public static ReadOnlySpan<byte> HashesUtf8 => "transaction_data_hashes"u8;

    /// <summary>The <c>transaction_data_hashes</c> claim emitted on the
    /// KB-JWT — an array of base64url-encoded digests of the original
    /// base64url-encoded transaction_data entries, positionally aligned
    /// with the <c>transaction_data</c> array the Verifier sent.</summary>
    public static readonly string Hashes = Utf8Constants.ToInternedString(HashesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DefaultHashesAlg"/>.</summary>
    public static ReadOnlySpan<byte> DefaultHashesAlgUtf8 => "sha-256"u8;

    /// <summary>The default hash algorithm identifier used when a
    /// transaction_data descriptor does not specify
    /// <see cref="HashesAlg"/>, per OID4VP 1.0 §8.4.</summary>
    public static readonly string DefaultHashesAlg = Utf8Constants.ToInternedString(DefaultHashesAlgUtf8);
}
