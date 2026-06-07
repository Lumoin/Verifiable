namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the embedded presentation SD-CWT from the <c>kcwt</c> parameter
/// (label 13 = <c>CoseHeaderParameters.Kcwt</c>) of an SD-CWT Key Binding Token's
/// protected header, per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse seam — it locates and returns the encoded <c>kcwt</c> value
/// (the embedded COSE_Sign1 wire bytes) without performing any cryptographic
/// validation. Wired by the application to a <c>Verifiable.Cbor</c> implementation —
/// typically <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractKcwt</c>.
/// </para>
/// </remarks>
/// <param name="kbtProtectedHeader">The CBOR-encoded KBT protected header map.</param>
/// <returns>The embedded SD-CWT COSE_Sign1 wire bytes carried under <c>kcwt</c>.</returns>
public delegate System.ReadOnlyMemory<byte> ExtractKcwtFromKbtDelegate(System.ReadOnlyMemory<byte> kbtProtectedHeader);
