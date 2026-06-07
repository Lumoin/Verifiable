using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The output of the application's <see cref="ProduceVpTokenPresentationsDelegate"/>:
/// the wire-form presentation per DCQL credential query, plus any binding the
/// chosen format needs carried on the response envelope rather than inside the
/// <c>vp_token</c>.
/// </summary>
/// <remarks>
/// The wallet client owns the OID4VP protocol mechanics — it assembles these
/// per-query presentations into the spec-shaped <c>vp_token</c> JSON, sets the
/// response JWE <c>apu</c> from <see cref="ResponseEncryptionApu"/>, encrypts,
/// and POSTs. The application owns everything format-specific behind the
/// delegate (DCQL evaluation, disclosure computation, key binding), so this
/// carrier stays format-neutral.
/// </remarks>
[DebuggerDisplay("Oid4VpPresentationSet Count={PresentationsByQueryId.Count} Apu={ResponseEncryptionApu is not null}")]
public sealed record Oid4VpPresentationSet
{
    /// <summary>
    /// The compact presentation per DCQL credential query id — placed verbatim
    /// under its query id in the wire <c>vp_token</c> JSON array. Values are
    /// opaque to the wallet client (SD-JWT VC presentation, base64url mdoc
    /// DeviceResponse, or SD-CWT presentation).
    /// </summary>
    public required IReadOnlyDictionary<string, string> PresentationsByQueryId { get; init; }

    /// <summary>
    /// Optional pre-base64url value the wallet client sets as the response JWE's
    /// <c>apu</c> (Agreement PartyUInfo) header. mdoc presentations carry the
    /// wallet's <c>mdoc_generated_nonce</c> here per ISO/IEC 18013-7 §B.4.4;
    /// <see langword="null"/> for formats that need no response-envelope binding
    /// (SD-JWT VC, SD-CWT). The wallet client rejects a non-null value on a
    /// response mode that emits no JWE.
    /// </summary>
    public string? ResponseEncryptionApu { get; init; }
}
