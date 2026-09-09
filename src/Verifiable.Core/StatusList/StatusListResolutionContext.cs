using Verifiable.Cryptography;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Everything a <see cref="ResolveVerifiedStatusListTokenDelegate"/> is told about the Referenced
/// Token whose status is being read: the <c>status_list</c> reference itself and the Referenced
/// Token's own verified issuer facts.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
/// Status List, Section 8.3</see> step 3.a — "Validate the Status List Token by following the rules
/// defined in Section 7.2 of [RFC7519] for JWTs and Section 7.2 of [RFC8392] for CWTs. This step might
/// require the resolution of a public key as described in Section 11.3." — makes key resolution the
/// resolver's own step. This record is what the verifier seat hands that step: without the Referenced
/// Token's issuer identity and the key its issuer signature verified under, Section 11.3's same-key
/// recommendation cannot be evaluated behind the seam at all, leaving a resolver to bind its trust to
/// the list URI's authority instead.
/// </para>
/// <para>
/// <see cref="ReferencedTokenIssuerKey"/> is a <em>borrowed</em> reference for the duration of the
/// resolution call. A resolver reads it, and never disposes or retains it — the seat that resolved it
/// owns its lifetime and releases it when the verification step it belongs to ends.
/// </para>
/// </remarks>
public sealed record StatusListResolutionContext
{
    /// <summary>
    /// The Referenced Token's <c>status_list</c> reference — the <c>idx</c> the status bit is read at and
    /// the <c>uri</c> the Status List Token is obtained from.
    /// </summary>
    /// <remarks>
    /// <see cref="StatusListReference.Uri"/> is read out of a presented, not-yet-status-checked credential,
    /// so it is untrusted input the credential's holder controls. An implementation that fetches it MUST
    /// run it through <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/> (or an equivalent
    /// SSRF policy) before dereferencing it.
    /// </remarks>
    public required StatusListReference Reference { get; init; }

    /// <summary>
    /// The Referenced Token's verified issuer identifier — the <c>iss</c> claim for SD-JWT and SD-CWT
    /// credentials, <see langword="null"/> for an mdoc, which carries no issuer claim (its issuer identity
    /// is the IssuerAuth <c>x5chain</c> leaf certificate's own subject). Also <see langword="null"/> on a
    /// context built without a verified credential.
    /// </summary>
    /// <remarks>
    /// A resolver that follows
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
    /// 11.3</see>'s second recommendation — "Alternatively, the Status Issuer may use the same web-based key
    /// resolution that is used for the Referenced Token." — keys that resolution on this identifier.
    /// </remarks>
    public string? ReferencedTokenIssuer { get; init; }

    /// <summary>
    /// The public key the Referenced Token's own issuer signature verified under, borrowed for the duration
    /// of the resolution call and never disposed or retained by a resolver.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On the status path this key is present for every credential format — SD-JWT, SD-CWT and mdoc alike.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section
    /// 8.3</see> orders the two steps — "Upon receiving a Referenced Token, a Relying Party MUST first
    /// perform the validation of the Referenced Token" and only "If the validation was successful" evaluate
    /// its status — so a seat reaches status resolution only after the credential's issuer signature
    /// verified under a key its own issuer-key seam returned, whatever trust path (a tenant record, a trust
    /// list, <c>did:web</c>, an IACA chain) produced it. The nullable type serves the record's other
    /// constructions — a context built before or without a verified credential — not any one format.
    /// </para>
    /// <para>
    /// It is what makes
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
    /// 11.3</see>'s first recommendation reachable behind the seam: "If the Issuer of the Referenced Token
    /// is the same entity as the Status Issuer, then the same key that is embedded into the Referenced Token
    /// may be used for the Status List Token."
    /// </para>
    /// <para>
    /// Read it inside the resolution call; the seat releases it the moment the flow step ends, so a
    /// context kept past that step answers this member with a key whose buffer has already gone back
    /// to its pool.
    /// </para>
    /// </remarks>
    public PublicKeyMemory? ReferencedTokenIssuerKey { get; init; }
}
