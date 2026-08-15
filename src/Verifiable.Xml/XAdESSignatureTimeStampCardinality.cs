namespace Verifiable.Xml;

/// <summary>
/// Clause 6.3 letter n)'s <c>SignatureTimeStamp</c> cardinality narrowing, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — XA-6.3-n: "Each <c>SignatureTimeStamp</c> element shall contain only one
/// electronic time-stamp." <c>XAdESTimeStampType</c>'s own grammar (clause 5.1.4.4.1) permits one-or-more
/// <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries for every property built on it
/// (<see cref="XAdESTimeStamp"/>); letter n) narrows that shared cardinality down to exactly one for THIS
/// property alone — distinct from letter z)'s explicit multi-token ALLOWANCE for <c>ArchiveTimeStamp</c>, the
/// shared grammar's own unnarrowed default.
/// </summary>
public static class XAdESSignatureTimeStampCardinality
{
    /// <summary>
    /// Tells whether a <c>SignatureTimeStamp</c> carries exactly one electronic time-stamp, per XA-6.3-n.
    /// </summary>
    /// <param name="signatureTimeStamp">The already-read <c>SignatureTimeStamp</c> property.</param>
    /// <returns><see langword="true"/> when <see cref="XAdESTimeStamp.TimeStamps"/> carries exactly one entry.</returns>
    public static bool HasExactlyOneTimeStamp(XAdESSignatureTimeStamp signatureTimeStamp)
    {
        ArgumentNullException.ThrowIfNull(signatureTimeStamp);

        return signatureTimeStamp.TimeStamp.TimeStamps.Count == 1;
    }
}
