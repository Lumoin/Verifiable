namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The session-binding CWT claims read from an SD-CWT Key Binding Token (KBT)
/// payload per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>: <c>aud</c> (claim 3), <c>iat</c> (claim 6),
/// and the optional <c>cnonce</c> (claim 39). The CBOR analogue of the SD-JWT
/// KB-JWT's <c>aud</c>/<c>iat</c>/<c>nonce</c> fields.
/// </summary>
/// <remarks>
/// <para>
/// Produced by a <see cref="ReadKbtCwtClaimsDelegate"/> implementation reading the
/// KBT payload bytes; consumed by <c>KbCwtVerification</c> to populate the session
/// fields of <see cref="SdCwtKbtVerificationResult"/>.
/// </para>
/// </remarks>
public sealed record KbtCwtClaims
{
    /// <summary>The <c>aud</c> claim (CWT claim 3) identifying the Verifier.</summary>
    public string? Aud { get; init; }

    /// <summary>The <c>iat</c> claim (CWT claim 6), or <see langword="null"/> when absent.</summary>
    public DateTimeOffset? Iat { get; init; }

    /// <summary>The <c>cnonce</c> claim (CWT claim 39), or <see langword="null"/> when omitted.</summary>
    public string? Cnonce { get; init; }
}
