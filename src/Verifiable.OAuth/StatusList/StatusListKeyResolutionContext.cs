using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// Everything a <see cref="ResolveStatusListIssuerKeyDelegate"/> is told when it decides which public
/// key a Status List Token's signature is checked under: the URI the token was fetched for, the token's
/// own not-yet-verified protected header, and the Referenced Token's verified issuer facts.
/// </summary>
/// <remarks>
/// <para>
/// This is the input to
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
/// Status List, Section 8.3</see> step 3.a's key resolution. Carrying the Referenced Token's issuer
/// identity and key is what makes
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
/// 11.3</see> implementable behind the seam rather than a resolver having to bind its trust to the
/// list URI's authority.
/// </para>
/// </remarks>
public sealed record StatusListKeyResolutionContext
{
    /// <summary>
    /// The <c>uri</c> the Status List Token was fetched for — the same value
    /// <see cref="StatusListTokenVerification.VerifyAsync"/> checks the verified <c>sub</c> claim against.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "The specification defines this as a string claim value that is compared ordinally against the token's own 'sub' claim in both JWT and CWT formats, mirroring StatusListReference.Uri.")]
    public required string StatusListUri { get; init; }

    /// <summary>
    /// The Status List Token's protected header, decoded from the compact JWS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 §7.2</see> reads the JOSE
    /// header (steps 1 through 5) before the signature is verified (step 8) — the header is the token's own
    /// self-description and is exactly what selects the key the signature will be checked under, so it
    /// cannot be trusted at the moment it is read. The type says so: unchecked wire data rides an
    /// <see cref="UnverifiedJwtHeader"/>, and only verification promotes data to a verified carrier. A
    /// resolver reads <c>kid</c>, <c>x5c</c>, <c>x5t#S256</c> here to select which key to <em>try</em>,
    /// and treats nothing in it as a trust statement — mirroring
    /// <see cref="Verifiable.Cryptography.Context.JoseKeyContext"/>'s role in the generic
    /// resolver/binder verification path.
    /// </para>
    /// </remarks>
    public required UnverifiedJwtHeader Header { get; init; }

    /// <summary>
    /// The Referenced Token's verified issuer identifier — the <c>iss</c> claim for SD-JWT and SD-CWT
    /// credentials, <see langword="null"/> for an mdoc, which carries no issuer claim, and on a context
    /// built without a verified credential. Section 11.3's second recommendation — "Alternatively, the
    /// Status Issuer may use the same web-based key resolution that is used for the Referenced Token." —
    /// is keyed on this.
    /// </summary>
    public string? ReferencedTokenIssuer { get; init; }

    /// <summary>
    /// The public key the Referenced Token's own issuer signature verified under, borrowed for the
    /// duration of the resolution call and never disposed or retained by a resolver. Answering it as the
    /// Status List Token's key is Section 11.3's first recommendation, shipped as
    /// <see cref="StatusListIssuerKeys.FromReferencedToken"/>.
    /// </summary>
    /// <remarks>
    /// Read it inside the resolution call; the seat releases it the moment the flow step ends, so a
    /// context kept past that step answers this member with a key whose buffer has already gone back
    /// to its pool.
    /// </remarks>
    public PublicKeyMemory? ReferencedTokenIssuerKey { get; init; }
}
