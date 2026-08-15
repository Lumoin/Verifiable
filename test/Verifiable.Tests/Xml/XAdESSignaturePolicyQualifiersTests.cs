using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSigPolicyQualifierEntry.TryRead"/>, <see cref="XAdESSPUserNotice.TryRead"/> and
/// <see cref="XAdESSPDocSpecification.TryRead"/> against clause 5.2.9.2's three signature-policy qualifiers of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: <c>SPURI</c>, <c>SPUserNotice</c> and <c>SPDocSpecification</c>, plus the
/// open-content tolerance the <c>SigPolicyQualifier</c> element's own <c>AnyType</c> content model requires.
/// </summary>
[TestClass]
internal sealed class XAdESSignaturePolicyQualifiersTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static (XmlNodeTable Table, XAdESSigPolicyQualifierEntry Entry) ReadEntry(string sigPolicyQualifierXml)
    {
        XmlNodeTable table = Parse(sigPolicyQualifierXml, BaseMemoryPool.Shared);
        bool isRead = XAdESSigPolicyQualifierEntry.TryRead(table, table.DocumentElementIndex, out XAdESSigPolicyQualifierEntry entry, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");

        return (table, entry);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's <c>"The SPURI
    /// element shall contain a URL value where a copy of the signature policy document can be obtained"</c>:
    /// a <c>SigPolicyQualifier</c> wrapping exactly one <c>SPURI</c> child is recognized, with its
    /// <c>anyURI</c> content captured exact-character.
    /// </summary>
    [TestMethod]
    public void SPURIQualifierIsRecognized()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPURI>http://example.com/policy.pdf</SPURI>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPURI, entry.Kind);
            Assert.AreEqual("http://example.com/policy.pdf", Encoding.UTF8.GetString(entry.SPURI));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's <c>"The
    /// SPUserNotice element shall contain information that is intended for being displayed whenever the
    /// signature is validated"</c>: a full <c>SPUserNotice</c> — <c>NoticeRef</c> (<c>Organization</c> plus
    /// two <c>NoticeNumbers/int</c> entries) and <c>ExplicitText</c> — reads with every value captured, per
    /// <c>"The NoticeRef element shall name an organization and shall identify by numbers (NoticeNumbers
    /// element) a group of textual statements"</c> and <c>"The ExplicitText element shall contain the text
    /// of the notice to be displayed."</c>
    /// </summary>
    [TestMethod]
    public void SPUserNoticeQualifierWithFullContentIsRecognized()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPUserNotice>
                <NoticeRef>
                  <Organization>Example Org</Organization>
                  <NoticeNumbers><int>1</int><int>2</int></NoticeNumbers>
                </NoticeRef>
                <ExplicitText>Please read carefully.</ExplicitText>
              </SPUserNotice>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPUserNotice, entry.Kind);
            Assert.IsTrue(entry.SPUserNotice.HasNoticeRef);
            Assert.AreEqual("Example Org", Encoding.UTF8.GetString(entry.SPUserNotice.Organization));
            Assert.AreEqual(2, entry.SPUserNotice.NoticeNumberCount);
            Assert.AreEqual("1", Encoding.UTF8.GetString(entry.SPUserNotice.NoticeNumberAt(0)));
            Assert.AreEqual("2", Encoding.UTF8.GetString(entry.SPUserNotice.NoticeNumberAt(1)));
            Assert.IsTrue(entry.SPUserNotice.HasExplicitText);
            Assert.AreEqual("Please read carefully.", Encoding.UTF8.GetString(entry.SPUserNotice.ExplicitText));
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2, an
    /// <c>SPUserNotice</c> with neither <c>NoticeRef</c> nor <c>ExplicitText</c> reads: the clause states no
    /// "empty ... shall not be generated" floor for this qualifier the way clauses 5.2.4/5.2.5/5.2.6 do for
    /// their own elements, so the schema's individually-optional children stand unmodified.
    /// </summary>
    [TestMethod]
    public void FullyEmptySPUserNoticeIsNotRefused()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPUserNotice/>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPUserNotice, entry.Kind);
            Assert.IsFalse(entry.SPUserNotice.HasNoticeRef);
            Assert.IsFalse(entry.SPUserNotice.HasExplicitText);
        }
    }


    /// <summary>
    /// Proves, against the <c>IntegerListType</c> fragment of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN
    /// 319 132-1 V1.3.1</see> clause 5.2.9.2, <c>NoticeNumbers</c>' own list can be empty — its <c>int</c>
    /// child is individually <c>minOccurs="0"</c> — distinct from <c>NoticeRef</c> itself, whose
    /// <c>Organization</c> and <c>NoticeNumbers</c> are each mandatory once <c>NoticeRef</c> is present.
    /// </summary>
    [TestMethod]
    public void EmptyNoticeNumbersListIsNotRefused()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPUserNotice>
                <NoticeRef>
                  <Organization>Example Org</Organization>
                  <NoticeNumbers/>
                </NoticeRef>
              </SPUserNotice>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.IsTrue(entry.SPUserNotice.HasNoticeRef);
            Assert.AreEqual(0, entry.SPUserNotice.NoticeNumberCount);
        }
    }


    /// <summary>
    /// Proves, against the <c>NoticeReferenceType</c> fragment of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN
    /// 319 132-1 V1.3.1</see> clause 5.2.9.2, <c>Organization</c> is mandatory once <c>NoticeRef</c> is
    /// present: its absence is a structural refusal, not silently tolerated.
    /// </summary>
    [TestMethod]
    public void NoticeRefWithoutOrganizationIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPUserNotice>
                <NoticeRef>
                  <NoticeNumbers><int>1</int></NoticeNumbers>
                </NoticeRef>
              </SPUserNotice>
            </SigPolicyQualifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigPolicyQualifierEntry.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "NoticeRef without Organization must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against the <c>NoticeReferenceType</c> fragment of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN
    /// 319 132-1 V1.3.1</see> clause 5.2.9.2, <c>NoticeNumbers</c> is mandatory once <c>NoticeRef</c> is
    /// present: its absence is a structural refusal, not silently tolerated.
    /// </summary>
    [TestMethod]
    public void NoticeRefWithoutNoticeNumbersIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPUserNotice>
                <NoticeRef>
                  <Organization>Example Org</Organization>
                </NoticeRef>
              </SPUserNotice>
            </SigPolicyQualifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigPolicyQualifierEntry.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "NoticeRef without NoticeNumbers must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's <c>"The
    /// SPDocSpecification shall identify the technical specification that defines the syntax used for
    /// producing the signature policy document"</c> and its URI-identified branch
    /// (<c>"If the technical specification is identified using a URI, then the Identifier child shall contain
    /// this URI and its QualifierType attribute shall not be present"</c>): a <c>SPDocSpecification</c> — in
    /// its own <see cref="XAdESIdentifiers.XAdESNamespaceV141"/> namespace — with no <c>Qualifier</c> reads.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationQualifierUriIdentifiedIsRecognized()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPDocSpecification xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
                <Identifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">http://example.com/policy-spec</Identifier>
              </SPDocSpecification>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPDocSpecification, entry.Kind);
            Assert.IsFalse(entry.SPDocSpecification.HasQualifier);
            Assert.AreEqual("http://example.com/policy-spec", Encoding.UTF8.GetString(entry.SPDocSpecification.Identifier));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's OID-identified
    /// branch (<c>"If the technical specification is identified using an OID, then the Identifier child shall
    /// contain a URN encoding this OID ..., and its QualifierType attribute shall be present with its value
    /// set to 'OIDAsURN'"</c>): <c>Qualifier="OIDAsURN"</c> reads.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationQualifierOidIdentifiedIsRecognized()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPDocSpecification xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
                <Identifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Qualifier="OIDAsURN">urn:oid:1.2.3.4</Identifier>
              </SPDocSpecification>
            </SigPolicyQualifier>
            """);
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPDocSpecification, entry.Kind);
            Assert.IsTrue(entry.SPDocSpecification.HasQualifier);
            Assert.AreEqual(XAdESObjectIdentifierQualifier.OIDAsURN, entry.SPDocSpecification.Qualifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's narrower,
    /// directional Qualifier rule refuses the one value <c>ObjectIdentifierType</c>'s own general schema
    /// (clause 5.1.2) would otherwise permit here: <c>Qualifier="OIDAsURI"</c> satisfies neither the OID
    /// branch (which demands <c>OIDAsURN</c>) nor the URI branch (which forbids <c>Qualifier</c> outright).
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationQualifierOIDAsURIIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SPDocSpecification xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              <Identifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Qualifier="OIDAsURI">http://example.com/oid-as-uri</Identifier>
            </SPDocSpecification>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSPDocSpecification.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Qualifier=\"OIDAsURI\" on SPDocSpecification must be refused.");
        Assert.AreEqual(XAdESReadFailure.SPDocSpecificationQualifierNotOIDAsURN, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's namespace
    /// split matters for identity: an element locally named <c>SPDocSpecification</c> but declared in
    /// <see cref="XAdESIdentifiers.XAdESNamespaceV132"/> — the
    /// namespace <c>SPURI</c>/<c>SPUserNotice</c> use, NOT the one clause 5.2.9.2's own preamble states for
    /// this qualifier — is not recognized as <see cref="XAdESSigPolicyQualifierKind.SPDocSpecification"/>; it
    /// falls to <see cref="XAdESSigPolicyQualifierKind.Unrecognized"/> and its raw content stays available via
    /// <see cref="XAdESSigPolicyQualifierEntry.Content"/>, per this reader's own open-qualifier tolerance.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationInTheWrongNamespaceIsUnrecognizedNotRefused()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""<SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"><SPDocSpecification><Identifier>http://example.com/policy-spec</Identifier></SPDocSpecification></SigPolicyQualifier>""");
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.Unrecognized, entry.Kind);
            Assert.HasCount(1, entry.Content.ContentNodeIndices);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's
    /// <c>SigPolicyQualifier</c> declaration, this reader's own open-qualifier tolerance directly: a
    /// <c>SigPolicyQualifier</c> wrapping content that is none of the three clause 5.2.9.2 qualifiers is
    /// never refused — <c>SigPolicyQualifier</c>'s own schema type is <c>AnyType</c> (clause 5.1.1), and this
    /// reader carries the content unmodeled rather than rejecting it.
    /// </summary>
    [TestMethod]
    public void GenuinelyUnknownQualifierContentIsUnrecognizedNotRefused()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""<SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"><FutureQualifier xmlns="urn:example:future">some content</FutureQualifier></SigPolicyQualifier>""");
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.Unrecognized, entry.Kind);
            Assert.HasCount(1, entry.Content.ContentNodeIndices);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.1's
    /// <c>AnyType</c> content model that clause 5.2.9.1's <c>SigPolicyQualifier</c> instantiates, the
    /// open-qualifier tolerance extends to a <c>SigPolicyQualifier</c> with no element child at all (bare
    /// text or nothing) — never refused, always <see cref="XAdESSigPolicyQualifierKind.Unrecognized"/>.
    /// </summary>
    [TestMethod]
    public void EmptyQualifierContentIsUnrecognizedNotRefused()
    {
        (XmlNodeTable table, XAdESSigPolicyQualifierEntry entry) = ReadEntry($"""<SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""");
        using(table)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.Unrecognized, entry.Kind);
            Assert.HasCount(0, entry.Content.ContentNodeIndices);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's
    /// <c>SPURI</c> declaration (no attribute of its own), a recognized qualifier name whose own inner shape
    /// is malformed propagates a genuine structural refusal rather than silently falling back to
    /// <see cref="XAdESSigPolicyQualifierKind.Unrecognized"/> — an unrecognized NAME is tolerated by design,
    /// but a recognized name this reader has committed to parsing is held to its own type's shape.
    /// </summary>
    [TestMethod]
    public void RecognizedQualifierWithMalformedInnerContentIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigPolicyQualifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SPURI unexpected="value">http://example.com/policy.pdf</SPURI>
            </SigPolicyQualifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigPolicyQualifierEntry.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A recognized SPURI with an unexpected attribute must be refused, not silently downgraded to Unrecognized.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }
}
