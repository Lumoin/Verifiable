using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESObjectIdentifier.TryRead"/> against clause 5.1.2's <c>ObjectIdentifierType</c>
/// data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>. This type carries no pooled content of its own (every field is a span
/// computed from the node table), so there is no custody to prove — unlike
/// <see cref="XAdESEncapsulatedPkiDataTests"/>/<see cref="XAdESDigestAlgAndValueTests"/>, which decode
/// base64.
/// </summary>
[TestClass]
internal sealed class XAdESObjectIdentifierTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2's minimal shape: a bare URI-identified object — <c>Identifier</c> only, no
    /// <c>Qualifier</c>, no <c>Description</c>, no <c>DocumentationReferences</c> — reads, per XA-5.1.2-6's
    /// first arm ("if a URI identifies the object ... the Qualifier attribute shall not be present").
    /// </summary>
    [TestMethod]
    public void UriIdentifiedObjectWithoutQualifierReads()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>http://example.com/policy/1</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out XAdESObjectIdentifier value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual("http://example.com/policy/1", Encoding.UTF8.GetString(value.Identifier));
        Assert.IsFalse(value.HasQualifier);
        Assert.IsFalse(value.HasDescription);
        Assert.IsFalse(value.HasDocumentationReferences);
        Assert.AreEqual(0, value.DocumentationReferenceCount);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2's OID-as-URI arm (XA-5.1.2-6): <c>Qualifier="OIDAsURI"</c> reads and is recognized
    /// as <see cref="XAdESObjectIdentifierQualifier.OIDAsURI"/> — the schema's own spelling, matching the
    /// prose's spelling for this arm too (no defect on this value, contrast <c>OIDAsURN</c>).
    /// </summary>
    [TestMethod]
    public void OidAsUriQualifierReads()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier Qualifier="OIDAsURI">http://example.com/oid/1.2.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out XAdESObjectIdentifier value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasQualifier);
        Assert.AreEqual(XAdESObjectIdentifierQualifier.OIDAsURI, value.Qualifier);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2's OID-as-URN arm (XA-5.1.2-6): <c>Qualifier="OIDAsURN"</c> — the schema
    /// <c>QualifierType</c> enumeration's exact casing — reads and is recognized as
    /// <see cref="XAdESObjectIdentifierQualifier.OIDAsURN"/>.
    /// </summary>
    [TestMethod]
    public void OidAsUrnQualifierWithSchemaCasingReads()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier Qualifier="OIDAsURN">urn:oid:1.2.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out XAdESObjectIdentifier value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasQualifier);
        Assert.AreEqual(XAdESObjectIdentifierQualifier.OIDAsURN, value.Qualifier);
    }


    /// <summary>
    /// Proves a genuine specification defect: the specification's own prose restates the URN qualifier value as <c>"OIDASURN"</c> (upper-case <c>S</c>), but the schema's <c>QualifierType</c> enumeration — which <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.2's XA-4.2-4 precedence rule makes authoritative — spells it <c>"OIDAsURN"</c>. This reader
    /// applies the schema's casing: the prose's literal string is refused as an unrecognized qualifier value, proving the precedence rule is actually enforced rather than merely documented.
    /// </summary>
    [TestMethod]
    public void ProseCasingOfUrnQualifierIsRefusedBecauseTheSchemaCasingGoverns()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier Qualifier="OIDASURN">urn:oid:1.2.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The prose's mis-cased 'OIDASURN' must be refused: the schema enumeration, not the prose, governs.");
        Assert.AreEqual(XAdESReadFailure.UnrecognizedObjectIdentifierQualifier, error.Failure);
    }


    /// <summary>
    /// Proves an entirely unrecognized <c>Qualifier</c> value (neither schema literal) refuses, per the
    /// schema's closed two-value <c>QualifierType</c> enumeration (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2).
    /// </summary>
    [TestMethod]
    public void UnrecognizedQualifierValueIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier Qualifier="NotARealQualifier">urn:oid:1.2.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized Qualifier value must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnrecognizedObjectIdentifierQualifier, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2's full shape: <c>Identifier</c>, an optional <c>Description</c> (XA-5.1.2-8: "shall
    /// contain an informal text describing the object"), and an optional <c>DocumentationReferences</c> with
    /// more than one <c>DocumentationReference</c> (XA-5.1.2-9: "an arbitrary number of references") — all
    /// three read in the schema's fixed order.
    /// </summary>
    [TestMethod]
    public void FullShapeWithDescriptionAndMultipleDocumentationReferencesReads()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <Description>An example signature policy</Description>
              <DocumentationReferences>
                <DocumentationReference>http://example.com/policy.pdf</DocumentationReference>
                <DocumentationReference>http://example.com/policy.txt</DocumentationReference>
              </DocumentationReferences>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out XAdESObjectIdentifier value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual("urn:oid:1.2.3.4", Encoding.UTF8.GetString(value.Identifier));
        Assert.IsTrue(value.HasDescription);
        Assert.AreEqual("An example signature policy", Encoding.UTF8.GetString(value.Description));
        Assert.IsTrue(value.HasDocumentationReferences);
        Assert.AreEqual(2, value.DocumentationReferenceCount);
        Assert.AreEqual("http://example.com/policy.pdf", Encoding.UTF8.GetString(value.DocumentationReferenceAt(0)));
        Assert.AreEqual("http://example.com/policy.txt", Encoding.UTF8.GetString(value.DocumentationReferenceAt(1)));
    }


    /// <summary>
    /// Proves the mandatory <c>Identifier</c> element's absence (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, "instances ... shall contain a
    /// unique and permanent identifier") is refused, not silently accepted as an empty object.
    /// </summary>
    [TestMethod]
    public void MissingIdentifierIsRefused()
    {
        using XmlNodeTable table = Parse("""<ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#"/>""");

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An ObjectIdentifier without an Identifier child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, an empty <c>DocumentationReferences</c> element (zero <c>DocumentationReference</c> children)
    /// is refused: the schema's <c>xsd:sequence maxOccurs="unbounded"</c> carries a default
    /// <c>minOccurs="1"</c>, so at least one reference is mandatory whenever the container is present.
    /// </summary>
    [TestMethod]
    public void EmptyDocumentationReferencesIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <DocumentationReferences/>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty DocumentationReferences element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, an unrecognized child of <c>DocumentationReferences</c> — anything other than
    /// <c>DocumentationReference</c> — is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownChildOfDocumentationReferencesIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <DocumentationReferences>
                <NotADocumentationReference>http://example.com</NotADocumentationReference>
              </DocumentationReferences>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized DocumentationReferences child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves a repeated <c>Identifier</c> element is refused as a duplicate — <c>Identifier</c> is
    /// unconditionally consumed exactly once by the fixed-order content model (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2), so a second
    /// one is always a repeat, never merely "unexpected."
    /// </summary>
    [TestMethod]
    public void DuplicateIdentifierIsRefusedAsDuplicate()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <Identifier>urn:oid:5.6.7.8</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A repeated Identifier must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves a repeated <c>Description</c> element is refused as a duplicate, not merely "unknown" — the
    /// fixed-order content model (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2) permits <c>Description</c> at most once.
    /// </summary>
    [TestMethod]
    public void DuplicateDescriptionIsRefusedAsDuplicate()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <Description>First</Description>
              <Description>Second</Description>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A repeated Description must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, a repeated <c>DocumentationReferences</c> element is refused as a duplicate.
    /// </summary>
    [TestMethod]
    public void DuplicateDocumentationReferencesIsRefusedAsDuplicate()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <DocumentationReferences><DocumentationReference>http://example.com/a</DocumentationReference></DocumentationReferences>
              <DocumentationReferences><DocumentationReference>http://example.com/b</DocumentationReference></DocumentationReferences>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A repeated DocumentationReferences must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, <c>DocumentationReferences</c> appearing before <c>Description</c> — violating the schema's
    /// fixed <c>Identifier, Description?, DocumentationReferences?</c> sequence — is refused as an unknown
    /// element at that position, not mislabelled a duplicate (<c>Description</c> was never consumed).
    /// </summary>
    [TestMethod]
    public void OutOfOrderDescriptionAfterDocumentationReferencesIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2.3.4</Identifier>
              <DocumentationReferences><DocumentationReference>http://example.com/a</DocumentationReference></DocumentationReferences>
              <Description>Out of order</Description>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Description appearing after DocumentationReferences must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, an unrecognized attribute on the outer <c>ObjectIdentifierType</c>-typed element is refused
    /// fail-closed — the type declares no attribute of its own.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnOuterElementIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#" unexpected="value">
              <Identifier>urn:oid:1.2.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute on the outer element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, a comment splitting the <c>Identifier</c> element's simple content is refused — the same
    /// comment-smuggling closure applies to <c>ds:DigestValue</c>, reused unchanged here.
    /// </summary>
    [TestMethod]
    public void CommentSplittingIdentifierContentIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#">
              <Identifier>urn:oid:1.2<!--x-->.3.4</Identifier>
            </ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A comment splitting Identifier's simple content must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.2, non-whitespace text between <c>Identifier</c> and <c>Description</c> is refused as unexpected
    /// element content, not silently skipped.
    /// </summary>
    [TestMethod]
    public void StrayTextBetweenChildrenIsRefused()
    {
        using XmlNodeTable table = Parse("""
            <ObjectIdentifier xmlns="http://uri.etsi.org/01903/v1.3.2#"><Identifier>urn:oid:1.2.3.4</Identifier>stray<Description>Text</Description></ObjectIdentifier>
            """);

        bool isRead = XAdESObjectIdentifier.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Stray non-whitespace text between children must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }
}
