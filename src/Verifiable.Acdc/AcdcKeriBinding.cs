using System.Collections.Generic;
using Verifiable.Keri;

namespace Verifiable.Acdc;

/// <summary>
/// The binding between an ACDC and the key state of its Issuer: an ACDC is bound to its Issuer's KEL when that KEL
/// anchors an issuance proof seal whose digest is the ACDC's top-level SAID. This holds the pure matching of an
/// ACDC SAID to such a seal; locating the Issuer's KEL and replaying it to obtain its verified anchored seals is a
/// cross-log step a validator performs, exactly as <see cref="KeriDelegation"/> separates the delegation-seal match
/// from the cross-log replay.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#binding-to-key-state-at-time-of-acdc-state-change">
/// binding to key state</see>: to protect against later forgery if the Issuer's signing keys are compromised, the
/// Issuer MUST anchor an issuance proof digest seal to the ACDC in its KEL. In the direct case, no
/// issuance/revocation registry is used and the issuance proof seal digest is the SAID of the ACDC itself, anchored
/// in a key event of the Issuer's KEL. Because key events are nonrepudiably signed by the Issuer, the seal is a
/// verifiable commitment by the Issuer to the ACDC that survives changes to the Issuer's key state — the binding is
/// to the key state at the anchoring event, not to a signature over the ACDC. This is why an ACDC is not signed
/// directly: the Issuer's key state may rotate independently of the ACDC's state.
/// </para>
/// <para>
/// This models the direct case, where the anchored seal is a digest seal (<see cref="KeriDigestSeal"/>) of the
/// ACDC's SAID. In the indirect case, the ACDC's state is held by a Transaction Event Log (TEL) registry and the
/// anchored seal commits to a registry event rather than to the ACDC directly; that path binds through the registry
/// and lands with the TEL registry support. A full verification additionally checks the ACDC's own SAID over its
/// received bytes (with <see cref="AcdcSaid"/>) and verifies the Issuer's KEL (with the KERI replayer) before
/// matching the seal here, so the ACDC is both internally authentic and anchored in the Issuer's verified key state.
/// </para>
/// </remarks>
public static class AcdcKeriBinding
{
    /// <summary>
    /// Whether a digest seal is the direct issuance proof seal for an ACDC: its digest (field <c>d</c>) MUST equal
    /// the ACDC's top-level SAID.
    /// </summary>
    /// <param name="seal">A digest seal taken from the Issuer's verified KEL anchors.</param>
    /// <param name="acdcSaid">The ACDC's top-level SAID (its <c>d</c> field value).</param>
    /// <returns><see langword="true"/> when the seal anchors exactly this ACDC.</returns>
    public static bool IsDirectIssuanceSealFor(KeriDigestSeal seal, string acdcSaid)
    {
        ArgumentNullException.ThrowIfNull(seal);
        ArgumentNullException.ThrowIfNull(acdcSaid);

        return string.Equals(seal.Digest, acdcSaid, StringComparison.Ordinal);
    }


    /// <summary>
    /// Finds the direct issuance proof seal for an ACDC among an Issuer key event's anchored seals: the first digest
    /// seal whose digest is the ACDC's SAID, or <see langword="null"/> when none does.
    /// </summary>
    /// <param name="issuerAnchors">The seals anchored in a verified Issuer key event (its <c>a</c> field, read by <see cref="KeriSealReader"/>).</param>
    /// <param name="acdcSaid">The ACDC's top-level SAID to find an issuance seal for.</param>
    /// <returns>The direct issuance proof digest seal, or <see langword="null"/> when the anchors carry none for this ACDC.</returns>
    public static KeriDigestSeal? FindDirectIssuanceSeal(IEnumerable<KeriSeal> issuerAnchors, string acdcSaid)
    {
        ArgumentNullException.ThrowIfNull(issuerAnchors);
        ArgumentNullException.ThrowIfNull(acdcSaid);

        foreach(KeriSeal anchor in issuerAnchors)
        {
            if(anchor is KeriDigestSeal seal && IsDirectIssuanceSealFor(seal, acdcSaid))
            {
                return seal;
            }
        }

        return null;
    }
}
