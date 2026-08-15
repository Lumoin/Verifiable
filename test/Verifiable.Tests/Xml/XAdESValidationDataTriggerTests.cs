using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESValidationDataTrigger.TryDetermine"/> against Annex A.1.1/A.1.2/A.1.3/A.1.4's
/// closing conditional-<c>shall</c> paragraph of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — the "if at least one of [...] is incorporated" antecedent, structural half
/// only (the consequent's digest-matching half is performed above the leaf, per
/// <see cref="XAdESValidationDataTriggerResult"/>'s own remarks).
/// </summary>
[TestClass]
internal sealed class XAdESValidationDataTriggerTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";


    private static (XmlNodeTable Table, XAdESUnsignedSignatureProperties Container) ReadFixture(string innerXml, BaseMemoryPool pool)
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}">{innerXml}</UnsignedSignatureProperties>""";
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table!, table!.DocumentElementIndex, out XAdESUnsignedSignatureProperties container, out XAdESReadError containerError);
        Assert.IsTrue(isRead, $"The fixture UnsignedSignatureProperties must read but was refused with {containerError.Failure}.");

        return (table, container);
    }


    /// <summary>
    /// Proves Annex A.1.1's first trigger alternative — an incorporated <c>CertificateValues</c> — sets
    /// <see cref="XAdESValidationDataTriggerResult.HasValuesProperty"/> for
    /// <see cref="XAdESValidationDataFamily.Certificate"/> only, never for
    /// <see cref="XAdESValidationDataFamily.Revocation"/> (proving family selectivity). Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void CertificateValuesTriggersCertificateFamilyOnly()
    {
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture("<CertificateValues/>", BaseMemoryPool.Shared);
        using(table)
        {
            bool isCertDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certResult, out XAdESProcessingError certError);
            Assert.IsTrue(isCertDetermined, $"Must determine but was refused with {certError.Failure}.");
            Assert.IsTrue(certResult.HasValuesProperty);
            Assert.IsTrue(certResult.IsTriggered);

            bool isRevDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revResult, out XAdESProcessingError revError);
            Assert.IsTrue(isRevDetermined, $"Must determine but was refused with {revError.Failure}.");
            Assert.IsFalse(revResult.HasValuesProperty);
            Assert.IsFalse(revResult.IsTriggered);
        }
    }


    /// <summary>
    /// Proves Annex A.1.3's attribute-certificate trigger alternative — an incorporated
    /// <c>AttrAuthoritiesCertValues</c> — sets
    /// <see cref="XAdESValidationDataTriggerResult.HasAttributeValuesProperty"/> for the certificate family.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.3.
    /// </summary>
    [TestMethod]
    public void AttrAuthoritiesCertValuesTriggersAttributeValuesFlag()
    {
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture("<AttrAuthoritiesCertValues/>", BaseMemoryPool.Shared);
        using(table)
        {
            bool isDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult result, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.IsTrue(result.HasAttributeValuesProperty);
            Assert.IsFalse(result.HasValuesProperty);
            Assert.IsTrue(result.IsTriggered);
        }
    }


    /// <summary>
    /// Proves Annex A.1.2's/A.1.4's revocation-side trigger alternatives — <c>RevocationValues</c> and
    /// <c>AttributeRevocationValues</c> — set the revocation family's own flags, and never the certificate
    /// family's. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2/A.1.4.
    /// </summary>
    [TestMethod]
    public void RevocationValuesAndAttributeRevocationValuesTriggerRevocationFamilyOnly()
    {
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture("<RevocationValues/><AttributeRevocationValues/>", BaseMemoryPool.Shared);
        using(table)
        {
            bool isRevDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revResult, out XAdESProcessingError revError);
            Assert.IsTrue(isRevDetermined, $"Must determine but was refused with {revError.Failure}.");
            Assert.IsTrue(revResult.HasValuesProperty);
            Assert.IsTrue(revResult.HasAttributeValuesProperty);

            bool isCertDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certResult, out XAdESProcessingError certError);
            Assert.IsTrue(isCertDetermined, $"Must determine but was refused with {certError.Failure}.");
            Assert.IsFalse(certResult.HasValuesProperty);
            Assert.IsFalse(certResult.HasAttributeValuesProperty);
            Assert.IsFalse(certResult.IsTriggered);
        }
    }


    /// <summary>
    /// Proves Annex A.1.1/A.1.2/A.1.3/A.1.4's shared fourth trigger alternative — "the <c>ArchiveTimeStamp</c>
    /// defined in the namespace whose URI is [v1.4.1]" — sets
    /// <see cref="XAdESValidationDataTriggerResult.HasArchiveTimeStamp"/> for BOTH families, since the
    /// paragraph names the same trigger identically in every one of the four clauses. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1/A.1.2/A.1.3/A.1.4.
    /// </summary>
    [TestMethod]
    public void ArchiveTimeStampV141TriggersBothFamilies()
    {
        string archiveTimeStamp = $"""<ArchiveTimeStamp xmlns="{V141}"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ArchiveTimeStamp>""";
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(archiveTimeStamp, BaseMemoryPool.Shared);
        using(table)
        {
            bool isCertDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certResult, out XAdESProcessingError certError);
            Assert.IsTrue(isCertDetermined, $"Must determine but was refused with {certError.Failure}.");
            Assert.IsTrue(certResult.HasArchiveTimeStamp);
            Assert.IsTrue(certResult.IsTriggered);

            bool isRevDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revResult, out XAdESProcessingError revError);
            Assert.IsTrue(isRevDetermined, $"Must determine but was refused with {revError.Failure}.");
            Assert.IsTrue(revResult.HasArchiveTimeStamp);
            Assert.IsTrue(revResult.IsTriggered);
        }
    }


    /// <summary>
    /// Proves Annex A.1.1's third trigger alternative — "<c>AnyValidationData</c> with a non empty
    /// <c>CertificateValues</c> child element" — fires only when the matching child is BOTH present and
    /// structurally non-empty, for the certificate family. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void AnyValidationDataWithNonEmptyCertificateValuesChildTriggersCertificateFamily()
    {
        string anyValidationData = $"""
            <AnyValidationData xmlns="{V141}">
              <CertificateValues xmlns="{V132}"><EncapsulatedX509Certificate>AQ==</EncapsulatedX509Certificate></CertificateValues>
            </AnyValidationData>
            """;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(anyValidationData, BaseMemoryPool.Shared);
        using(table)
        {
            bool isCertDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certResult, out XAdESProcessingError certError);
            Assert.IsTrue(isCertDetermined, $"Must determine but was refused with {certError.Failure}.");
            Assert.IsTrue(certResult.HasNonEmptyAnyValidationDataChild);
            Assert.IsTrue(certResult.IsTriggered);

            bool isRevDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revResult, out XAdESProcessingError revError);
            Assert.IsTrue(isRevDetermined, $"Must determine but was refused with {revError.Failure}.");
            Assert.IsFalse(revResult.HasNonEmptyAnyValidationDataChild, "A non-empty CertificateValues child must not trigger the revocation family.");
            Assert.IsFalse(revResult.IsTriggered);
        }
    }


    /// <summary>
    /// Proves the "non empty" qualifier is load-bearing: an <c>AnyValidationData</c> whose <c>CertificateValues</c>
    /// child is present but structurally EMPTY (no entries) does NOT trigger — Annex A's own text distinguishes
    /// "with a non empty <c>CertificateValues</c> child element" from mere presence, per
    /// <see cref="XAdESValidationDataTriggerResult.HasNonEmptyAnyValidationDataChild"/>'s own remarks. Anchored
    /// to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void AnyValidationDataWithEmptyCertificateValuesChildDoesNotTrigger()
    {
        string anyValidationData = $"""
            <AnyValidationData xmlns="{V141}">
              <CertificateValues xmlns="{V132}"/>
            </AnyValidationData>
            """;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(anyValidationData, BaseMemoryPool.Shared);
        using(table)
        {
            bool isDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult result, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.IsFalse(result.HasNonEmptyAnyValidationDataChild);
            Assert.IsFalse(result.IsTriggered);
        }
    }


    /// <summary>
    /// Proves the revocation-side mirror: <c>AnyValidationData</c> with a non-empty <c>RevocationValues</c>
    /// child triggers the revocation family per Annex A.1.2's own closing paragraph. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void AnyValidationDataWithNonEmptyRevocationValuesChildTriggersRevocationFamily()
    {
        string anyValidationData = $"""
            <AnyValidationData xmlns="{V141}">
              <RevocationValues xmlns="{V132}"><CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues></RevocationValues>
            </AnyValidationData>
            """;
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(anyValidationData, BaseMemoryPool.Shared);
        using(table)
        {
            bool isDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult result, out XAdESProcessingError error);
            Assert.IsTrue(isDetermined, $"Must determine but was refused with {error.Failure}.");
            Assert.IsTrue(result.HasNonEmptyAnyValidationDataChild);
        }
    }


    /// <summary>
    /// Proves the "at least one of" disjunction's negative case: an <c>UnsignedSignatureProperties</c> whose
    /// only entry is unrelated to every trigger alternative (a <c>CounterSignature</c>-shaped filler) leaves
    /// every flag false and <see cref="XAdESValidationDataTriggerResult.IsTriggered"/> false, for both families.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void UnrelatedContentLeavesEveryFlagFalse()
    {
        string filler = $"""<Filler xmlns="{V141}"/>""";
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture(filler, BaseMemoryPool.Shared);
        using(table)
        {
            bool isCertDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certResult, out XAdESProcessingError certError);
            Assert.IsTrue(isCertDetermined, $"Must determine but was refused with {certError.Failure}.");
            Assert.IsFalse(certResult.IsTriggered);

            bool isRevDetermined = XAdESValidationDataTrigger.TryDetermine(table, container, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revResult, out XAdESProcessingError revError);
            Assert.IsTrue(isRevDetermined, $"Must determine but was refused with {revError.Failure}.");
            Assert.IsFalse(revResult.IsTriggered);
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a <paramref name="table"/> argument that is not the identical instance the fixture's <see
    /// cref="XAdESUnsignedSignatureProperties"/> was read from refuses with <see cref="XAdESProcessingFailure.TableMismatch"/> rather than being silently
    /// processed against the wrong document. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        (XmlNodeTable table, XAdESUnsignedSignatureProperties container) = ReadFixture("<CertificateValues/>", BaseMemoryPool.Shared);
        using(table)
        {
            bool isOtherParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes($"""<UnsignedSignatureProperties xmlns="{V132}"><CertificateValues/></UnsignedSignatureProperties>"""), BaseMemoryPool.Shared, out XmlNodeTable? otherTable, out XmlReadError readError);
            Assert.IsTrue(isOtherParsed, $"The second fixture document must parse but was refused with {readError.Failure}.");
            using(otherTable)
            {
                bool isDetermined = XAdESValidationDataTrigger.TryDetermine(otherTable!, container, XAdESValidationDataFamily.Certificate, out _, out XAdESProcessingError error);
                Assert.IsFalse(isDetermined, "A table argument foreign to the container must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
            }
        }
    }
}
