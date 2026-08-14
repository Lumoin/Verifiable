namespace Verifiable.Xml;

/// <summary>
/// Clause 6.3 letter m)'s <c>SignaturePolicyStore</c> conditioned-presence rule, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — XA-6.3-m1/-m2: "This qualifying property may be incorporated into the
/// XAdES signature only if the <c>SignaturePolicyIdentifier</c> is also incorporated and it contains the
/// <c>SigPolicyHash</c> element with the digest value of the signature policy document[. O]therwise the
/// <c>SignaturePolicyStore</c> shall not be incorporated into the XAdES signature." — the reconciliation
/// <see cref="XAdESSignaturePolicyStore"/>'s own remarks point to this type for.
/// <see cref="XAdESSignaturePolicyId.TryRead"/> already
/// makes <c>SigPolicyHash</c> a mandatory child (clause 5.2.9.1) of every successfully-read
/// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/> arm, so letter m)'s "contains
/// <c>SigPolicyHash</c>" clause collapses to the choice arm itself: the
/// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied"/> arm never carries a
/// <c>SigPolicyHash</c>, structurally.
/// </summary>
public static class XAdESSignaturePolicyStoreLegality
{
    /// <summary>
    /// Tells whether a <c>SignaturePolicyStore</c> is legal per XA-6.3-m1/-m2: present only alongside a
    /// <c>SignaturePolicyIdentifier</c> whose choice is the explicit <c>SignaturePolicyId</c> arm.
    /// </summary>
    /// <param name="signaturePolicyIdentifier">The signature's own <c>SignaturePolicyIdentifier</c>, or
    /// <see langword="null"/> when the signature carries none.</param>
    /// <returns><see langword="true"/> when <paramref name="signaturePolicyIdentifier"/> is not
    /// <see langword="null"/> and its <see cref="XAdESSignaturePolicyIdentifier.Choice"/> is
    /// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/>.</returns>
    public static bool IsSignaturePolicyStoreLegal(XAdESSignaturePolicyIdentifier? signaturePolicyIdentifier)
    {
        return signaturePolicyIdentifier is not null && signaturePolicyIdentifier.Choice == XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId;
    }
}
