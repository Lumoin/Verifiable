using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignaturePolicyStore.TryRead"/> against clause 5.2.10's <c>SignaturePolicyStore</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSignaturePolicyStoreTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string SPDocSpecification(string identifier = "http://example.com/policy-spec")
    {
        return $"""
            <SPDocSpecification xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              <Identifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">{identifier}</Identifier>
            </SPDocSpecification>
            """;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's first choice
    /// arm — <c>"The SignaturePolicyDocument element shall contain the base-64 encoded signature policy"</c>
    /// — decodes through the shared strict base64 decoder into pooled bytes, and that custody balances to
    /// zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyDocumentChoiceDecodesAndCustodyBalancesAfterDispose()
    {
        byte[] policyDocument = [0x01, 0x02, 0x03, 0x04];
        string document = $"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              {SPDocSpecification()}
              <SignaturePolicyDocument>{Convert.ToBase64String(policyDocument)}</SignaturePolicyDocument>
            </SignaturePolicyStore>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignaturePolicyStore? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESSignaturePolicyStoreChoice.SignaturePolicyDocument, value!.Choice);
            Assert.IsNotNull(value.SignaturePolicyDocumentOctets);
            Assert.AreSequenceEqual(policyDocument, value.SignaturePolicyDocumentOctets!.AsReadOnlySpan().ToArray());

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's second choice
    /// arm — <c>"The SigPolDocLocalURI element shall have as value the URI referencing a local store where
    /// the present document can be retrieved"</c> — captures the <c>anyURI</c> content exact-character, with
    /// no pooled content to release.
    /// </summary>
    [TestMethod]
    public void SigPolDocLocalURIChoiceIsCaptured()
    {
        string document = $"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              {SPDocSpecification()}
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyStore? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(XAdESSignaturePolicyStoreChoice.SigPolDocLocalURI, value!.Choice);
            Assert.IsNull(value.SignaturePolicyDocumentOctets);
            Assert.AreEqual("file:///policies/policy1.der", Encoding.UTF8.GetString(value.SigPolDocLocalURI));
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's
    /// <c>SignaturePolicyStoreType</c> schema fragment, the optional <c>Id</c> attribute (<c>xsd:ID</c>) reads
    /// exact-character when present, and is absent by default.
    /// </summary>
    [TestMethod]
    public void OptionalIdAttributeSurfacesWhenPresent()
    {
        string document = $"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" Id="store-1">
              {SPDocSpecification()}
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyStore? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasId);
            Assert.AreEqual("store-1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's
    /// <c>SignaturePolicyStoreType</c> schema fragment, <c>SPDocSpecification</c> is mandatory (schema
    /// <c>minOccurs</c> defaults to 1, no override): its absence is refused.
    /// </summary>
    [TestMethod]
    public void MissingSPDocSpecificationIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "SignaturePolicyStore without SPDocSpecification must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.2's namespace
    /// split matters here too: an element locally named <c>SPDocSpecification</c> but declared in
    /// <see cref="XAdESIdentifiers.XAdESNamespaceV132"/> — not
    /// <see cref="XAdESIdentifiers.XAdESNamespaceV141"/>, the namespace <c>SignaturePolicyStore</c>'s own
    /// schema (clause 5.2.10, Annex C.2) declares its mandatory child in — is not recognized as the required
    /// child at all, and is refused as missing, exactly the pinned, namespace-exact behaviour clause 5.2.10
    /// requires.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationInTheWrongNamespaceIsRefusedAsMissing()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:v132="{XAdESIdentifiers.XAdESNamespaceV132}">
              <v132:SPDocSpecification>
                <v132:Identifier>http://example.com/policy-spec</v132:Identifier>
              </v132:SPDocSpecification>
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An SPDocSpecification in the v132 namespace must not be recognized as SignaturePolicyStore's mandatory child.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's OID-identified
    /// <c>SPDocSpecification</c> narrowing (clause 5.2.9.2's directional Qualifier rule) applies here too,
    /// reusing the same shared reader 5.2.9.2's qualifier does: <c>Qualifier="OIDAsURI"</c> is refused.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationQualifierOIDAsURIIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              <SPDocSpecification xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
                <Identifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Qualifier="OIDAsURI">http://example.com/oid-as-uri</Identifier>
              </SPDocSpecification>
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Qualifier=\"OIDAsURI\" on SignaturePolicyStore's SPDocSpecification must be refused.");
        Assert.AreEqual(XAdESReadFailure.SPDocSpecificationQualifierNotOIDAsURN, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's
    /// <c>SignaturePolicyStoreType</c> choice, the choice is mandatory: neither <c>SignaturePolicyDocument</c>
    /// nor <c>SigPolDocLocalURI</c> present is refused as a missing required child.
    /// </summary>
    [TestMethod]
    public void MissingChoiceIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              {SPDocSpecification()}
            </SignaturePolicyStore>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "SignaturePolicyStore without either choice arm must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, against the <c>SignaturePolicyDocument</c> element of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 5.2.10 (<c>xsd:base64Binary</c>-typed), malformed <c>base64Binary</c>
    /// content is refused through the
    /// shared strict base64 decoder, and that the buffer already rented before the refusal is released —
    /// there is only one pooled field in this whole property, so the outer <c>try</c>/<c>finally</c> custody
    /// pattern degenerates to "zero rented" here rather than "partially rented then released," still worth
    /// pinning since a malformed <c>SignaturePolicyDocument</c> is exactly the shape a hostile local policy
    /// store could carry.
    /// </summary>
    [TestMethod]
    public void MalformedBase64SignaturePolicyDocumentIsRefusedWithBalancedCustody()
    {
        string document = $"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              {SPDocSpecification()}
              <SignaturePolicyDocument>not-valid-base64!!</SignaturePolicyDocument>
            </SignaturePolicyStore>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignaturePolicyStore? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "Malformed base64 content must be refused.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.InvalidBase64Content, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "No buffer must remain outstanding after the refusal.");
            }
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's
    /// <c>SignaturePolicyStoreType</c> schema fragment, an unrecognized attribute on the
    /// <c>SignaturePolicyStore</c> element itself is refused — the type declares only the optional <c>Id</c>
    /// attribute.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnWrappingElementIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" unexpected="value">
              {SPDocSpecification()}
              <SigPolDocLocalURI>file:///policies/policy1.der</SigPolDocLocalURI>
            </SignaturePolicyStore>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.10's
    /// element declaration, an element outside <see cref="XAdESIdentifiers.XAdESNamespaceV141"/>, or a local
    /// name other than <c>SignaturePolicyStore</c>, is refused as unrecognized rather than silently accepted
    /// — the element-identity check every wrapping-element reader in this leaf performs before its own
    /// attribute/content grammar runs.
    /// </summary>
    [TestMethod]
    public void WrongElementIdentityIsRefused()
    {
        using XmlNodeTable table = Parse($"""<NotSignaturePolicyStore xmlns="{XAdESIdentifiers.XAdESNamespaceV141}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyStore.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The wrong element name must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }
}
