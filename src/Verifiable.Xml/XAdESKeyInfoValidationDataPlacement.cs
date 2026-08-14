namespace Verifiable.Xml;

/// <summary>
/// Letter u) of clause 6.3, Table 2, <c>RevocationValues</c> (XA-6.3-t32) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: "Certificate status values SHOULD be included in RevocationValues or
/// AnyValidationData elements. Certificate status values SHOULD NOT be included in <c>ds:KeyInfo</c> element."
/// This is the SHOULD-NOT-observable half — whether a signature's own <c>ds:KeyInfo</c> carries an
/// <c>X509CRL</c> member at all — reported without this leaf performing any trust decision or crypto of its
/// own.
/// </summary>
public static class XAdESKeyInfoValidationDataPlacement
{
    /// <summary>
    /// Tells whether <paramref name="keyInfo"/> carries at least one <c>ds:X509Data/ds:X509CRL</c> member.
    /// </summary>
    /// <param name="keyInfo">The signature's own <c>KeyInfo</c> (<see cref="XmlSignature.KeyInfo"/>), or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when at least one <c>X509Data</c> child carries an <c>X509CRL</c> member.</returns>
    public static bool HasCertificateRevocationListMember(XmlKeyInfo? keyInfo)
    {
        if(keyInfo is not XmlKeyInfo value)
        {
            return false;
        }

        for(int i = 0; i < value.Children.Count; ++i)
        {
            XmlKeyInfoChild child = value.Children[i];
            if(child.Kind != XmlKeyInfoChildKind.X509Data || child.X509DataMembers is null)
            {
                continue;
            }

            for(int m = 0; m < child.X509DataMembers.Count; ++m)
            {
                if(child.X509DataMembers[m].Kind == XmlX509DataMemberKind.CertificateRevocationList)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
