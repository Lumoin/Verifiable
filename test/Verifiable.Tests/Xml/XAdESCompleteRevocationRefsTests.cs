using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs"/>/
/// <see cref="XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs"/> against Annex A.1.2's
/// <c>CompleteRevocationRefs</c> qualifying property and Annex A.1.4's <c>AttributeRevocationRefs</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — both bound to the SAME <c>CompleteRevocationRefsType</c> schema type.
/// </summary>
[TestClass]
internal sealed class XAdESCompleteRevocationRefsTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Document(string elementName, string content, string? id = null)
    {
        string idAttribute = id is null ? string.Empty : $" Id=\"{id}\"";

        return $"""
            <{elementName} xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}"{idAttribute}>
              {content}
            </{elementName}>
            """;
    }


    private static string DigestAlgAndValue(byte[] digest) => $"""
        <DigestAlgAndValue>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
        </DigestAlgAndValue>
        """;


    private static string CrlRef(byte[] digest, string? crlIdentifier = null) => $"""
        <CRLRef>
          {DigestAlgAndValue(digest)}
          {crlIdentifier ?? string.Empty}
        </CRLRef>
        """;


    private static string CrlIdentifier(string issuer, string issueTime, string? number = null, string? uri = null)
    {
        string uriAttribute = uri is null ? string.Empty : $" URI=\"{uri}\"";
        string numberElement = number is null ? string.Empty : $"<Number>{number}</Number>";

        return $"""
            <CRLIdentifier{uriAttribute}>
              <Issuer>{issuer}</Issuer>
              <IssueTime>{issueTime}</IssueTime>
              {numberElement}
            </CRLIdentifier>
            """;
    }


    private static string OcspRefByName(string responderName, string producedAt, byte[]? digest = null)
    {
        string digestElement = digest is null ? string.Empty : DigestAlgAndValue(digest);

        return $"""
            <OCSPRef>
              <OCSPIdentifier>
                <ResponderID><ByName>{responderName}</ByName></ResponderID>
                <ProducedAt>{producedAt}</ProducedAt>
              </OCSPIdentifier>
              {digestElement}
            </OCSPRef>
            """;
    }


    private static string OcspRefByKey(byte[] keyDigest, string producedAt) => $"""
        <OCSPRef>
          <OCSPIdentifier>
            <ResponderID><ByKey>{Convert.ToBase64String(keyDigest)}</ByKey></ResponderID>
            <ProducedAt>{producedAt}</ProducedAt>
          </OCSPIdentifier>
        </OCSPRef>
        """;


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's "Each
    /// <c>CRLRef</c> child of <c>CRLRefs</c> shall contain one reference to one CRL" — a <c>CRLRefs</c>-only
    /// instance with the minimal <c>DigestAlgAndValue</c>-only <c>CRLRef</c> shape reads, and custody balances
    /// to zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void CrlRefsAloneWithMinimalCrlRefReadsAndCustodyBalances()
    {
        byte[] digest = [0x01, 0x02, 0x03];
        string document = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef(digest)}</CRLRefs>");

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasCrlRefs);
            Assert.HasCount(1, value.CrlRefs);
            Assert.AreSequenceEqual(digest, value.CrlRefs[0].DigestAlgAndValue.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.IsFalse(value.CrlRefs[0].HasCrlIdentifier);
            Assert.IsFalse(value.HasOcspRefs);
            Assert.IsFalse(value.HasOtherRefs);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's
    /// <c>CRLIdentifier</c> reads its mandatory <c>Issuer</c>/<c>IssueTime</c>, optional <c>Number</c> and
    /// optional <c>URI</c> hint attribute.
    /// </summary>
    [TestMethod]
    public void CrlIdentifierReadsIssuerIssueTimeNumberAndUri()
    {
        string identifier = CrlIdentifier("CN=Test CA", "2024-01-01T00:00:00Z", number: "42", uri: "http://example.com/crl1.crl");
        string document = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], identifier)}</CRLRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.CrlRefs[0].HasCrlIdentifier);
            XAdESCrlIdentifier crlIdentifier = value.CrlRefs[0].CrlIdentifier;
            Assert.AreEqual("CN=Test CA", Encoding.UTF8.GetString(crlIdentifier.Issuer));
            Assert.AreEqual(2024, crlIdentifier.IssueTime.Year);
            Assert.IsTrue(crlIdentifier.HasNumber);
            Assert.AreEqual(42L, crlIdentifier.Number);
            Assert.IsFalse(crlIdentifier.IsNumberNegative);
            Assert.IsTrue(crlIdentifier.HasUri);
            Assert.AreEqual("http://example.com/crl1.crl", Encoding.UTF8.GetString(crlIdentifier.Uri));
        }
    }


    /// <summary>
    /// Proves a negative <c>Number</c> lexical value parses per
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer">XML Schema Part 2:
    /// Datatypes</see> section 3.3.13's <c>(\+|-)?[0-9]+</c> pattern — the schema types <c>Number</c>
    /// unrestricted <c>xsd:integer</c>, not <c>xsd:nonNegativeInteger</c>, so a leading <c>'-'</c> is lexically
    /// legal even though CRL numbers are conventionally non-negative.
    /// </summary>
    [TestMethod]
    public void NegativeNumberParses()
    {
        string identifier = CrlIdentifier("CN=Test CA", "2024-01-01T00:00:00Z", number: "-7");
        string document = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], identifier)}</CRLRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            XAdESCrlIdentifier crlIdentifier = value!.CrlRefs[0].CrlIdentifier;
            Assert.IsTrue(crlIdentifier.IsNumberNegative);
            Assert.AreEqual(7L, crlIdentifier.Number);
        }
    }


    /// <summary>
    /// Proves a malformed <c>Number</c> lexical value — embedded whitespace, splitting the digit run — is
    /// refused per
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer">XML Schema Part 2:
    /// Datatypes</see> section 3.3.13's strict <c>xsd:integer</c> grammar, bridged from
    /// <see cref="XAdESGrammar.TryParseXsdInteger"/>.
    /// </summary>
    [TestMethod]
    public void MalformedNumberIsRefused()
    {
        string identifier = CrlIdentifier("CN=Test CA", "2024-01-01T00:00:00Z", number: "4 2");
        string document = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], identifier)}</CRLRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A Number with embedded whitespace must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidIntegerLexicalForm, error.Failure);
    }


    /// <summary>
    /// Proves <see cref="XAdESGrammar.TryParseXsdInteger"/>'s own documented hardening bound: an
    /// eighteen-digit <c>Number</c> — the largest digit run the parser accepts — reads, while a
    /// NINETEEN-digit run one past the bound is refused as <see
    /// cref="XAdESReadFailure.InvalidIntegerLexicalForm"/>, per <see
    /// href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer">XML Schema Part 2: Datatypes</see>
    /// section 3.3.13's own (formally unbounded-precision) <c>xsd:integer</c> lexical space — the refusal is
    /// this reader's own hardening bound, not a spec-mandated narrowing.
    /// </summary>
    [TestMethod]
    public void NumberAtTheDigitBoundParsesButOneDigitBeyondIsRefused()
    {
        string atBound = new string('9', 18);
        string acceptedDocument = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], CrlIdentifier("CN=Test CA", "2024-01-01T00:00:00Z", number: atBound))}</CRLRefs>");
        using XmlNodeTable acceptedTable = Parse(acceptedDocument, BaseMemoryPool.Shared);
        bool isAccepted = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(acceptedTable, acceptedTable.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? acceptedValue, out XAdESReadError acceptedError);
        Assert.IsTrue(isAccepted, $"An eighteen-digit Number must read but was refused with {acceptedError.Failure}.");
        using(acceptedValue)
        {
            Assert.AreEqual(999999999999999999L, acceptedValue!.CrlRefs[0].CrlIdentifier.Number);
        }

        string beyondBound = new string('9', 19);
        string refusedDocument = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], CrlIdentifier("CN=Test CA", "2024-01-01T00:00:00Z", number: beyondBound))}</CRLRefs>");
        using XmlNodeTable refusedTable = Parse(refusedDocument, BaseMemoryPool.Shared);
        bool isRefused = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(refusedTable, refusedTable.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError refusedError);
        Assert.IsFalse(isRefused, "A nineteen-digit Number one past the bound must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidIntegerLexicalForm, refusedError.Failure);
    }


    /// <summary>
    /// Proves a malformed <c>IssueTime</c> lexical value is refused via the strict <c>xsd:dateTime</c> grammar
    /// <see cref="XAdESDateTime.TryParse"/> already enforces, exercised here at Annex A.1.2's own site.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void MalformedIssueTimeIsRefused()
    {
        string identifier = CrlIdentifier("CN=Test CA", "not-a-date");
        string document = Document("CompleteRevocationRefs", $"<CRLRefs>{CrlRef([0x01], identifier)}</CRLRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A malformed IssueTime must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidDateTimeLexicalForm, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's <c>ByName</c>
    /// arm of <c>ResponderID</c>: "If the responder is identified by name, the name shall appear within
    /// <c>ByName</c>."
    /// </summary>
    [TestMethod]
    public void OcspRefWithByNameResponderReads()
    {
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{OcspRefByName("CN=Test Responder", "2024-06-01T12:00:00Z")}</OCSPRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasOcspRefs);
            XAdESOcspIdentifier identifier = value.OcspRefs[0].OcspIdentifier;
            Assert.AreEqual(XAdESResponderIdKind.ByName, identifier.ResponderKind);
            Assert.AreEqual("CN=Test Responder", Encoding.UTF8.GetString(identifier.ByName));
            Assert.AreEqual(2024, identifier.ProducedAt.Year);
            Assert.IsFalse(value.OcspRefs[0].HasDigestAlgAndValue);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's <c>ByKey</c>
    /// arm of <c>ResponderID</c>: "the base-64 DER encoding of the <c>byKey</c> field ... shall appear within
    /// <c>ByKey</c>" — decoded to opaque pooled octets, and the optional <c>DigestAlgAndValue</c> sibling
    /// decodes too, with custody balancing on dispose.
    /// </summary>
    [TestMethod]
    public void OcspRefWithByKeyResponderAndDigestDecodesAndCustodyBalances()
    {
        byte[] keyDigest = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] responseDigest = [0x99];
        string ocspRef = $"""
            <OCSPRef>
              <OCSPIdentifier>
                <ResponderID><ByKey>{Convert.ToBase64String(keyDigest)}</ByKey></ResponderID>
                <ProducedAt>2024-06-01T12:00:00Z</ProducedAt>
              </OCSPIdentifier>
              {DigestAlgAndValue(responseDigest)}
            </OCSPRef>
            """;
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{ocspRef}</OCSPRefs>");

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            XAdESOcspIdentifier identifier = value!.OcspRefs[0].OcspIdentifier;
            Assert.AreEqual(XAdESResponderIdKind.ByKey, identifier.ResponderKind);
            Assert.AreSequenceEqual(keyDigest, identifier.ByKeyOctets!.AsReadOnlySpan().ToArray());
            Assert.IsTrue(value.OcspRefs[0].HasDigestAlgAndValue);
            Assert.AreSequenceEqual(responseDigest, value.OcspRefs[0].DigestAlgAndValue.DigestValueOctets.AsReadOnlySpan().ToArray());

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer (ByKey octets and the digest value) must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves a <c>ResponderID</c> with neither <c>ByName</c> nor <c>ByKey</c> is refused — the schema's
    /// <c>xsd:choice</c> requires exactly one, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void ResponderIdWithNeitherArmIsRefused()
    {
        string ocspRef = """
            <OCSPRef>
              <OCSPIdentifier>
                <ResponderID/>
                <ProducedAt>2024-06-01T12:00:00Z</ProducedAt>
              </OCSPIdentifier>
            </OCSPRef>
            """;
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{ocspRef}</OCSPRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A ResponderID with neither ByName nor ByKey must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves a <c>ResponderID</c> carrying BOTH <c>ByName</c> and <c>ByKey</c> is refused — the schema's
    /// <c>xsd:choice</c> permits exactly one arm, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void ResponderIdWithBothArmsIsRefused()
    {
        string ocspRef = """
            <OCSPRef>
              <OCSPIdentifier>
                <ResponderID><ByName>CN=Test</ByName><ByKey>AQ==</ByKey></ResponderID>
                <ProducedAt>2024-06-01T12:00:00Z</ProducedAt>
              </OCSPIdentifier>
            </OCSPRef>
            """;
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{ocspRef}</OCSPRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A ResponderID with both ByName and ByKey must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's
    /// <c>OtherRefs</c>/<c>OtherRef</c> — "semantics/syntax explicitly out of scope of the present document" —
    /// carries as unmodeled content, reusing <see cref="XAdESRevocationValues.TryReadNonEmptyUnmodeledList"/>.
    /// </summary>
    [TestMethod]
    public void OtherRefsAloneReadsAsUnmodeledContent()
    {
        string document = Document("CompleteRevocationRefs", "<OtherRefs><OtherRef><Foo/></OtherRef></OtherRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasOtherRefs);
            Assert.HasCount(1, value.OtherRefs);
        }
    }


    /// <summary>
    /// Proves Annex A.1.2's "Empty <c>CompleteRevocationRefs</c> qualifying properties shall not be
    /// incorporated" — none of <c>CRLRefs</c>/<c>OCSPRefs</c>/<c>OtherRefs</c> present is a read-time refusal,
    /// per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void EmptyCompleteRevocationRefsIsRefused()
    {
        string document = $"""<CompleteRevocationRefs xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""";

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty CompleteRevocationRefs must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyCompleteRevocationRefs, error.Failure);
    }


    /// <summary>
    /// Proves an <c>Id</c>-only <c>CompleteRevocationRefs</c> — no <c>CRLRefs</c>/<c>OCSPRefs</c>/<c>OtherRefs</c>
    /// child, only the optional <c>Id</c> attribute — is STILL the empty case Annex A.1.2 forbids: the
    /// attribute alone does not satisfy "at least one of CRLRefs/OCSPRefs/OtherRefs." Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void IdOnlyCompleteRevocationRefsIsStillRefusedAsEmpty()
    {
        string document = $"""<CompleteRevocationRefs xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Id="crr1"/>""";

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An Id-only CompleteRevocationRefs must still be refused as empty.");
        Assert.AreEqual(XAdESReadFailure.EmptyCompleteRevocationRefs, error.Failure);
    }


    /// <summary>
    /// Proves a present <c>CRLRefs</c> list with zero <c>CRLRef</c> entries is refused — the schema's
    /// <c>maxOccurs="unbounded"</c> <c>CRLRef</c> sequence defaults to <c>minOccurs="1"</c>, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's "<c>CRLRefs</c> shall
    /// contain a sequence of references to CRLs."
    /// </summary>
    [TestMethod]
    public void EmptyCrlRefsListIsRefused()
    {
        string document = Document("CompleteRevocationRefs", "<CRLRefs/>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A zero-entry CRLRefs must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves a present <c>OCSPRefs</c> list with zero <c>OCSPRef</c> entries is refused — the schema's
    /// <c>maxOccurs="unbounded"</c> <c>OCSPRef</c> sequence defaults to <c>minOccurs="1"</c>, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2's "<c>OCSPRefs</c> shall
    /// contain a sequence of references to OCSP responses."
    /// </summary>
    [TestMethod]
    public void EmptyOcspRefsListIsRefused()
    {
        string document = Document("CompleteRevocationRefs", "<OCSPRefs/>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A zero-entry OCSPRefs must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves Annex A.1.2's "<c>OCSPIdentifier</c> child of <c>OCSPRef</c> shall include the OCSP response's
    /// generation time in <c>ProducedAt</c>" — an <c>OCSPIdentifier</c> missing <c>ProducedAt</c> is refused,
    /// per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void MissingProducedAtIsRefused()
    {
        string ocspRef = """
            <OCSPRef>
              <OCSPIdentifier>
                <ResponderID><ByName>CN=Test</ByName></ResponderID>
              </OCSPIdentifier>
            </OCSPRef>
            """;
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{ocspRef}</OCSPRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An OCSPIdentifier missing ProducedAt must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves the optional <c>URI</c> hint attribute of <c>OCSPIdentifierType</c> (Annex A.1.2) reads exact-character when present — the parity with
    /// <c>CRLIdentifier</c>'s own (unconditionally "shall indicate") <c>URI</c> attribute: both are modeled as optional hint carriage identically, despite the source
    /// text's own non-modal "indicates" for this one. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void OcspIdentifierOptionalUriHintSurfacesWhenPresent()
    {
        string ocspRef = """
            <OCSPRef>
              <OCSPIdentifier URI="http://example.com/ocsp1.der">
                <ResponderID><ByName>CN=Test</ByName></ResponderID>
                <ProducedAt>2024-06-01T12:00:00Z</ProducedAt>
              </OCSPIdentifier>
            </OCSPRef>
            """;
        string document = Document("CompleteRevocationRefs", $"<OCSPRefs>{ocspRef}</OCSPRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            XAdESOcspIdentifier identifier = value!.OcspRefs[0].OcspIdentifier;
            Assert.IsTrue(identifier.HasUri);
            Assert.AreEqual("http://example.com/ocsp1.der", Encoding.UTF8.GetString(identifier.Uri));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.4's syntax rule —
    /// "shall be defined as in XML Schema file ... <c>&lt;xsd:element name="AttributeRevocationRefs"
    /// type="CompleteRevocationRefsType"/&gt;</c>" — the SAME reader accepts <c>AttributeRevocationRefs</c> by
    /// wire content alone.
    /// </summary>
    [TestMethod]
    public void AttributeRevocationRefsReadsThroughTheSameReader()
    {
        string document = Document("AttributeRevocationRefs", $"<CRLRefs>{CrlRef([0x01])}</CRLRefs>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasCrlRefs);
        }
    }


    /// <summary>
    /// Proves a genuine gap in the specification: Annex A.1.4 states no equivalent to A.1.2's "Empty <c>CompleteRevocationRefs</c>
    /// qualifying properties shall not be incorporated" for <c>AttributeRevocationRefs</c> — the schema makes
    /// all three children <c>minOccurs="0"</c> with no cross-child floor of its own (A.1.4 bullets 1)/2) name
    /// only what each child, if present, "shall contain"), so an empty <c>AttributeRevocationRefs</c> reads
    /// through <see cref="XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs"/> rather than refusing as
    /// <see cref="XAdESReadFailure.EmptyCompleteRevocationRefs"/> the way the same wire shape would under
    /// <see cref="XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.4.
    /// </summary>
    [TestMethod]
    public void EmptyAttributeRevocationRefsReads()
    {
        string document = $"""<AttributeRevocationRefs xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""";

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"An empty AttributeRevocationRefs must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(value!.HasCrlRefs);
            Assert.IsFalse(value.HasOcspRefs);
            Assert.IsFalse(value.HasOtherRefs);
        }
    }


    /// <summary>
    /// Proves custody is balanced on a refusal path across all three lists: <c>CRLRefs</c> already decoded a digest before a malformed <c>OCSPRef</c> (an OCSP
    /// <c>ByKey</c> with invalid base64) causes the whole read to refuse, and <see cref="XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs"/>'s own outer
    /// <c>try</c>/<c>finally</c> releases every buffer already rented, per the pooling discipline. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string content = $"""
            <CRLRefs>{CrlRef([0x01])}</CRLRefs>
            <OCSPRefs>
              <OCSPRef>
                <OCSPIdentifier>
                  <ResponderID><ByKey>not-valid-base64!!!</ByKey></ResponderID>
                  <ProducedAt>2024-06-01T12:00:00Z</ProducedAt>
                </OCSPIdentifier>
              </OCSPRef>
            </OCSPRefs>
            """;
        string document = Document("CompleteRevocationRefs", content);

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A malformed OCSPRef must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.InvalidBase64Content, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined (the CRLRef's digest) must already be released.");
            }
        }
    }
}
