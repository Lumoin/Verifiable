using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignerRoleV2.TryRead"/> against clause 5.2.6's <c>SignerRoleV2</c> qualifying
/// property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSignerRoleV2Tests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, a <c>ClaimedRoles</c>-only
    /// instance — "The <c>ClaimedRoles</c> element shall contain a non-empty sequence of roles claimed by the
    /// signer" — reads, and that custody balances to zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void ClaimedRolesAloneReadsAndCustodyBalancesAfterDispose()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
            </SignerRoleV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignerRoleV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasClaimedRoles);
            Assert.HasCount(1, value.ClaimedRoles);
            Assert.IsFalse(value.HasCertifiedRolesV2);
            Assert.IsFalse(value.HasSignedAssertions);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "ClaimedRole carries no pooled content, so nothing should have been rented at all.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, a <c>CertifiedRolesV2</c> entry
    /// choosing the <c>X509AttributeCertificate</c> arm — "the base-64 encoding of DER-encoded X509 attribute
    /// certificates ... within the <c>X509AttributeCertificate</c> element" — decodes its DER content, and
    /// custody balances to zero once disposed.
    /// </summary>
    [TestMethod]
    public void CertifiedRoleWithX509AttributeCertificateDecodesAndCustodyBalances()
    {
        byte[] der = [0x30, 0x03, 0x02, 0x01, 0x2A];
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2>
                <CertifiedRole><X509AttributeCertificate>{Convert.ToBase64String(der)}</X509AttributeCertificate></CertifiedRole>
              </CertifiedRolesV2>
            </SignerRoleV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignerRoleV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasCertifiedRolesV2);
            Assert.HasCount(1, value.CertifiedRoles);
            Assert.AreEqual(XAdESCertifiedRoleKind.X509AttributeCertificate, value.CertifiedRoles[0].Kind);
            Assert.AreSequenceEqual(der, value.CertifiedRoles[0].X509AttributeCertificate.Content.AsReadOnlySpan().ToArray());

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded X509AttributeCertificate buffer must be released on Dispose.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, a <c>CertifiedRolesV2</c> entry
    /// choosing the <c>OtherAttributeCertificate</c> arm — "attribute certificates ... in different syntax ...
    /// within the <c>OtherAttributeCertificate</c> element. The definition of specific
    /// <c>OtherAttributeCertificate</c> is outside of the scope of the present document" — is carried
    /// unmodeled, with no pooled content decoded at all.
    /// </summary>
    [TestMethod]
    public void CertifiedRoleWithOtherAttributeCertificateIsCarriedUnmodeled()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2>
                <CertifiedRole><OtherAttributeCertificate><Foreign>content</Foreign></OtherAttributeCertificate></CertifiedRole>
              </CertifiedRolesV2>
            </SignerRoleV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignerRoleV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.CertifiedRoles);
            Assert.AreEqual(XAdESCertifiedRoleKind.OtherAttributeCertificate, value.CertifiedRoles[0].Kind);
            Assert.HasCount(1, value.CertifiedRoles[0].OtherAttributeCertificate.ContentNodeIndices);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "OtherAttributeCertificate carries no pooled content.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, mixed
    /// <c>X509AttributeCertificate</c>/<c>OtherAttributeCertificate</c> entries within one <c>CertifiedRolesV2</c>
    /// list read together, in document order.
    /// </summary>
    [TestMethod]
    public void MixedCertifiedRoleKindsPreserveDocumentOrder()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2>
                <CertifiedRole><OtherAttributeCertificate><Foreign/></OtherAttributeCertificate></CertifiedRole>
                <CertifiedRole><X509AttributeCertificate>AQ==</X509AttributeCertificate></CertifiedRole>
              </CertifiedRolesV2>
            </SignerRoleV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignerRoleV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.CertifiedRoles);
            Assert.AreEqual(XAdESCertifiedRoleKind.OtherAttributeCertificate, value.CertifiedRoles[0].Kind);
            Assert.AreEqual(XAdESCertifiedRoleKind.X509AttributeCertificate, value.CertifiedRoles[1].Kind);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, a <c>SignedAssertions</c>-only
    /// instance — "The <c>SignedAssertions</c> element shall contain a non-empty sequence of assertions signed
    /// by a third party" — reads.
    /// </summary>
    [TestMethod]
    public void SignedAssertionsAloneReads()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SignedAssertions><SignedAssertion>content</SignedAssertion></SignedAssertions>
            </SignerRoleV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignerRoleV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasSignedAssertions);
            Assert.HasCount(1, value.SignedAssertions);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's acquired v132
    /// <c>SignerRoleV2Type</c> schema, all three children, in their fixed schema order (<c>ClaimedRoles,
    /// CertifiedRolesV2, SignedAssertions</c>), read together.
    /// </summary>
    [TestMethod]
    public void AllThreeChildrenInFixedOrderRead()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
              <CertifiedRolesV2><CertifiedRole><X509AttributeCertificate>AQ==</X509AttributeCertificate></CertifiedRole></CertifiedRolesV2>
              <SignedAssertions><SignedAssertion>content</SignedAssertion></SignedAssertions>
            </SignerRoleV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignerRoleV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasClaimedRoles);
            Assert.IsTrue(value.HasCertifiedRolesV2);
            Assert.IsTrue(value.HasSignedAssertions);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's "Empty <c>SignerRoleV2</c>
    /// qualifying properties shall not be generated" — an entirely empty element is refused, even though every
    /// one of the three children is individually schema-optional.
    /// </summary>
    [TestMethod]
    public void NoChildrenAtAllIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An entirely empty SignerRoleV2 must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptySignerRoleV2, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's "non-empty sequence" rule, a
    /// present-but-empty <c>ClaimedRoles</c> element is refused, despite the schema's own
    /// <c>maxOccurs="unbounded"</c> <c>ClaimedRole</c> already defaulting to <c>minOccurs="1"</c> — this reader
    /// enforces it explicitly rather than relying on that default alone.
    /// </summary>
    [TestMethod]
    public void EmptyClaimedRolesListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <ClaimedRoles/>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty ClaimedRoles element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's "non-empty sequence" rule for
    /// <c>CertifiedRolesV2</c>, a present-but-empty element is refused.
    /// </summary>
    [TestMethod]
    public void EmptyCertifiedRolesV2ListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2/>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty CertifiedRolesV2 element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's "non-empty sequence" rule for
    /// <c>SignedAssertions</c>, a present-but-empty element is refused.
    /// </summary>
    [TestMethod]
    public void EmptySignedAssertionsListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SignedAssertions/>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty SignedAssertions element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's fixed sequence, a child
    /// out of order — <c>CertifiedRolesV2</c> before <c>ClaimedRoles</c> — is refused.
    /// </summary>
    [TestMethod]
    public void OutOfOrderChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2><CertifiedRole><X509AttributeCertificate>AQ==</X509AttributeCertificate></CertifiedRole></CertifiedRolesV2>
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's fixed at-most-once
    /// sequence, a repeated child — two <c>ClaimedRoles</c> elements — is refused as a duplicate.
    /// </summary>
    [TestMethod]
    public void DuplicateChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
              <ClaimedRoles><ClaimedRole>Director</ClaimedRole></ClaimedRoles>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, a <c>CertifiedRole</c> carrying
    /// neither <c>X509AttributeCertificate</c> nor <c>OtherAttributeCertificate</c> — an element the schema's
    /// exhaustive <c>xsd:choice</c> does not permit — is refused.
    /// </summary>
    [TestMethod]
    public void CertifiedRoleWithNeitherChoiceMemberIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2><CertifiedRole><Unexpected/></CertifiedRole></CertifiedRolesV2>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CertifiedRole with an unrecognized choice member must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6's exhaustive, single-member
    /// <c>xsd:choice</c>, a <c>CertifiedRole</c> carrying BOTH choice members (trailing content after the
    /// first) is refused.
    /// </summary>
    [TestMethod]
    public void CertifiedRoleWithTrailingSecondChoiceMemberIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2>
                <CertifiedRole>
                  <X509AttributeCertificate>AQ==</X509AttributeCertificate>
                  <OtherAttributeCertificate><Foreign/></OtherAttributeCertificate>
                </CertifiedRole>
              </CertifiedRolesV2>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CertifiedRole with two choice members must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6, an unrecognized attribute on the
    /// <c>SignerRoleV2</c> element itself is refused — <c>SignerRoleV2Type</c> declares no attribute of its
    /// own.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnWrappingElementIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value">
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
            </SignerRoleV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6 and the pooling discipline,
    /// custody is balanced even on a refusal path: when the first <c>CertifiedRole</c>'s <c>X509AttributeCertificate</c> already decoded successfully before a second, malformed <c>CertifiedRole</c>
    /// causes the whole read to refuse, <see cref="XAdESSignerRoleV2.TryRead"/>'s own outer <c>try</c>/<c>finally</c> releases every buffer already rented, leaving nothing outstanding.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string document = $"""
            <SignerRoleV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CertifiedRolesV2>
                <CertifiedRole><X509AttributeCertificate>AQ==</X509AttributeCertificate></CertifiedRole>
                <CertifiedRole><Unexpected/></CertifiedRole>
              </CertifiedRolesV2>
            </SignerRoleV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignerRoleV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignerRoleV2? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A malformed second CertifiedRole must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined must already be released.");
            }
        }
    }
}
