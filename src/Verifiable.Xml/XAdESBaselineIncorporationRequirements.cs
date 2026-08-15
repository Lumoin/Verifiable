using System.Collections.Generic;

namespace Verifiable.Xml;

/// <summary>
/// Clause 6.3's own two opening structural requirements, applying to every XAdES baseline signature regardless
/// of level, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: XA-6.3-02's direct-incorporation-only mechanism and XA-6.3-04's RFC 3161-only
/// time-stamp container content. Both are plain structural facts computed over already-read leaf output —
/// reused from the discovery surface (<see cref="XAdESQualifyingPropertiesDiscovery"/>) and the shared
/// time-stamp entry model (<see cref="XAdESTimeStampEntry"/>) — never a re-read or a re-implementation of
/// either engine, the same "recognize a fact over an existing read" posture
/// <see cref="XAdESCountersignatureIdentification"/> already takes for clause 5.2.7.1.
/// </summary>
public static class XAdESBaselineIncorporationRequirements
{
    /// <summary>
    /// Tells whether a discovered signature's XAdES content uses ONLY the direct incorporation mechanism —
    /// XA-6.3-02: "The XAdES qualifying properties specified in clause 5 shall be incorporated into the
    /// signature using only the direct incorporation mechanism specified in clause 4.4," restated by NOTE 1 as
    /// "no <c>QualifyingPropertiesReference</c> element is present." A baseline signature carrying even one
    /// indirectly-incorporated <c>QualifyingPropertiesReference</c> — modeled at read,
    /// never itself refused there since indirect incorporation is legal outside the baseline profile —
    /// fails this baseline-specific requirement.
    /// </summary>
    /// <param name="discovery">The clause 4.4.1 discovery outcome for the signature under test.</param>
    /// <returns><see langword="true"/> when <paramref name="discovery"/> carries zero <c>QualifyingPropertiesReference</c> instances.</returns>
    public static bool IsDirectIncorporationOnly(XAdESQualifyingPropertiesDiscoveryResult discovery)
    {
        return discovery.QualifyingPropertiesReferences.Count == 0;
    }


    /// <summary>
    /// Tells whether a time-stamp container's entries are ALL RFC 3161 tokens — XA-6.3-04: "In XAdES baseline
    /// signatures the qualifying properties that act as electronic time-stamps containers shall encapsulate
    /// only IETF RFC 3161 [7] updated by IETF RFC 5816 [16] electronic time-stamps." Any
    /// <see cref="XAdESTimeStampEntryKind.XmlTimeStamp"/> entry — carried unmodeled,
    /// never itself refused at read since an <c>XMLTimeStamp</c> is schema-legal outside the baseline profile —
    /// fails this baseline-specific requirement.
    /// </summary>
    /// <param name="timeStamps">A time-stamp container's own entries, e.g. <see cref="XAdESTimeStamp.TimeStamps"/> or <see cref="XAdESOtherTimeStamp.TimeStamp"/> wrapped as a single-element list.</param>
    /// <returns><see langword="true"/> when every entry's <see cref="XAdESTimeStampEntry.Kind"/> is <see cref="XAdESTimeStampEntryKind.EncapsulatedTimeStamp"/>.</returns>
    public static bool ContainsOnlyRfc3161TimeStamps(IReadOnlyList<XAdESTimeStampEntry> timeStamps)
    {
        ArgumentNullException.ThrowIfNull(timeStamps);
        foreach(XAdESTimeStampEntry entry in timeStamps)
        {
            if(entry.Kind != XAdESTimeStampEntryKind.EncapsulatedTimeStamp)
            {
                return false;
            }
        }

        return true;
    }
}
