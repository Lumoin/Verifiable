namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Reads the session-binding CWT claims (<c>aud</c> = 3, <c>iat</c> = 6,
/// <c>cnonce</c> = 39) from an SD-CWT Key Binding Token payload per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse seam — it walks the KBT payload claims map without any
/// cryptographic validation. Wired by the application to a <c>Verifiable.Cbor</c>
/// implementation — typically <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ReadKbtClaims</c>.
/// </para>
/// </remarks>
/// <param name="kbtPayload">The CBOR-encoded KBT payload claims map.</param>
/// <returns>The parsed <c>aud</c>/<c>iat</c>/<c>cnonce</c> claims.</returns>
public delegate KbtCwtClaims ReadKbtCwtClaimsDelegate(System.ReadOnlyMemory<byte> kbtPayload);
