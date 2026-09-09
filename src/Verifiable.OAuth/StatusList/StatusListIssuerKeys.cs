using System;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// Compositions of <see cref="ResolveStatusListIssuerKeyDelegate"/> that ship the Token Status List
/// key-resolution recommendations rather than leaving every application to re-derive them.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
/// Status List, Section 11.3</see>: "This specification does not mandate specific methods for key
/// resolution and trust management, however the following recommendations are made for specifications,
/// profiles, or ecosystems that are planning to make use of the Status List mechanism". The two
/// recommendations differ in what the library can supply: the first is a decision the verifier can make
/// from facts it already holds, so it is shipped here; the second is the application's own key
/// resolution, so it stays the application's delegate, keyed on
/// <see cref="StatusListKeyResolutionContext.ReferencedTokenIssuer"/>.
/// </para>
/// </remarks>
public static class StatusListIssuerKeys
{
    /// <summary>
    /// Answers the Referenced Token's own issuer key as the Status List Token's key, deferring to
    /// <paramref name="whenAbsent"/> when the context carries none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
    /// 11.3</see>'s first recommendation: "If the Issuer of the Referenced Token is the same entity as
    /// the Status Issuer, then the same key that is embedded into the Referenced Token may be used for
    /// the Status List Token. In this case the Status List Token may use: the same x5c value or an x5t,
    /// x5t#S256 or kid parameter referencing to the same key as used in the Referenced Token for JOSE."
    /// </para>
    /// <para>
    /// Why that key is a defensible trust decision: it is the key the credential whose status is being
    /// read <em>already</em> verified under, on the seat's own trust path. A Status List Token that
    /// verifies under it is therefore the credential issuer's own signed statement about its own
    /// credential — the narrowest possible trust step, and one that needs no second trust source, no
    /// second fetch, and no inference from the list URI's authority (which is a DNS fact, not a
    /// cryptographic one).
    /// </para>
    /// <para>
    /// Its limit, and why the limit is safe: an ecosystem whose Status Issuer is a separate entity, or
    /// whose lists are signed by a different key of the same issuer, fails CLOSED under this composition
    /// — the Status List Token's signature does not verify under the answered key, the resolution raises
    /// <see cref="Verifiable.Core.StatusList.StatusListResolutionException"/>, and the seat refuses the
    /// presentation as an undeterminable status rather than accepting it. Such an ecosystem resolves
    /// through its own delegate instead, which is what <paramref name="whenAbsent"/> is for; the
    /// composition never widens what is accepted, only removes a resolution step where the same key
    /// already answers.
    /// </para>
    /// </remarks>
    /// <param name="whenAbsent">
    /// The delegate consulted when <see cref="StatusListKeyResolutionContext.ReferencedTokenIssuerKey"/>
    /// is <see langword="null"/> — a context built without a verified credential. Its own answer,
    /// including <see langword="null"/> for "no key this application trusts", is passed through unchanged.
    /// </param>
    /// <returns>The composed resolver.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="whenAbsent"/> is <see langword="null"/>.</exception>
    public static ResolveStatusListIssuerKeyDelegate FromReferencedToken(ResolveStatusListIssuerKeyDelegate whenAbsent)
    {
        ArgumentNullException.ThrowIfNull(whenAbsent);

        return (context, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(context);

            //The referenced key is borrowed: the seat that verified the credential under it owns its
            //lifetime for the whole flow step, so the verification reads it and never releases it.
            return context.ReferencedTokenIssuerKey is PublicKeyMemory referencedKey
                ? ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(referencedKey))
                : whenAbsent(context, cancellationToken);
        };
    }
}
