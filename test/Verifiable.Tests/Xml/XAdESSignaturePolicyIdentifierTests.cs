using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignaturePolicyIdentifier.TryRead"/> and <see cref="XAdESSignaturePolicyId.TryRead"/>
/// against clause 5.2.9.1's <c>SignaturePolicyIdentifier</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, including the transform-vs-qualifier cross-check and the pinning proof that
/// the <c>SPDocDigestAsInSpecification</c> transform is refused as an ordinary reference-processing transform
/// outside <c>SignaturePolicyId</c>.
/// </summary>
[TestClass]
internal sealed class XAdESSignaturePolicyIdentifierTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string SigPolicyHash(byte[] digest)
    {
        return $"""
            <SigPolicyHash>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
            </SigPolicyHash>
            """;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's explicit-identification arm: a
    /// <c>SignaturePolicyId</c> carrying its mandatory <c>SigPolicyId</c> and <c>SigPolicyHash</c> reads with
    /// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId"/>, and custody balances to zero once
    /// the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void MinimalSignaturePolicyIdReadsAndCustodyBalancesAfterDispose()
    {
        byte[] digest = [0x01, 0x02, 0x03];
        string document = $"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId>
                  <Identifier>urn:oid:1.2.3.4</Identifier>
                </SigPolicyId>
                {SigPolicyHash(digest)}
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.AreEqual(XAdESSignaturePolicyIdentifierChoice.SignaturePolicyId, value!.Choice);
            Assert.IsNotNull(value.SignaturePolicyId);
            Assert.AreSequenceEqual(digest, value.SignaturePolicyId!.SigPolicyHash.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.IsFalse(value.SignaturePolicyId.HasTransforms);
            Assert.IsFalse(value.SignaturePolicyId.HasSigPolicyQualifiers);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's implied-policy arm: <c>"The
    /// SignaturePolicyImplied empty element shall indicate that the data object(s) being signed and other
    /// external data imply the signature policy."</c> — reads with
    /// <see cref="XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied"/> and no
    /// <see cref="XAdESSignaturePolicyIdentifier.SignaturePolicyId"/>.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyImpliedReadsWithNoSignaturePolicyId()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SignaturePolicyImplied/>
            </SignaturePolicyIdentifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied, value!.Choice);
            Assert.IsNull(value.SignaturePolicyId);
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1, the
    /// <c>SignaturePolicyImplied</c> element's own empty-content shape: non-whitespace content inside it is
    /// refused, per the same type-less empty-element pattern <c>AllSignedDataObjects</c> (clause 5.2.3) takes.
    /// </summary>
    [TestMethod]
    public void NonEmptySignaturePolicyImpliedIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SignaturePolicyImplied><Unexpected/></SignaturePolicyImplied>
            </SignaturePolicyIdentifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Non-empty SignaturePolicyImplied must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's
    /// <c>SignaturePolicyIdentifierType</c> choice, the choice is mandatory: neither <c>SignaturePolicyId</c>
    /// nor <c>SignaturePolicyImplied</c> present is refused as a missing required child.
    /// </summary>
    [TestMethod]
    public void EmptySignaturePolicyIdentifierIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty SignaturePolicyIdentifier must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"The SigPolicyId
    /// element shall uniquely identify a specific version of the signature policy"</c> is structurally
    /// mandatory: a <c>SignaturePolicyId</c> without <c>SigPolicyId</c> is refused.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyIdWithoutSigPolicyIdIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                {SigPolicyHash([0x01])}
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "SignaturePolicyId without SigPolicyId must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"The SigPolicyHash
    /// element shall contain the identifier of the hash algorithm and the hash value"</c> is structurally
    /// mandatory: a <c>SignaturePolicyId</c> without <c>SigPolicyHash</c> is refused.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyIdWithoutSigPolicyHashIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "SignaturePolicyId without SigPolicyHash must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"The ds:Transforms
    /// element shall contain the transformations performed on the signature policy document before computing
    /// its hash. The processing model for these transformations shall be as described in XMLDSIG"</c> — a
    /// standalone <c>ds:Transforms</c> element reads through the same shared transform-list model
    /// <c>ds:Reference</c> uses (<see cref="XmlTransform.TryReadList"/>), with its algorithm and count intact.
    /// </summary>
    [TestMethod]
    public void OptionalTransformsReadThroughTheSharedTransformModel()
    {
        string document = $"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                <ds:Transforms>
                  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                {SigPolicyHash([0x01])}
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.SignaturePolicyId!.HasTransforms);
            Assert.HasCount(1, value.SignaturePolicyId.Transforms);
            Assert.AreEqual("http://www.w3.org/2001/10/xml-exc-c14n#", Encoding.UTF8.GetString(value.SignaturePolicyId.Transforms[0].Algorithm));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"The
    /// SigPolicyQualifiers element shall contain one or more qualifiers of the signature policy"</c>: a
    /// present <c>SigPolicyQualifiers</c> with zero <c>SigPolicyQualifier</c> children is refused.
    /// </summary>
    [TestMethod]
    public void EmptySigPolicyQualifiersIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                {SigPolicyHash([0x01])}
                <SigPolicyQualifiers/>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty SigPolicyQualifiers must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"The
    /// SigPolicyQualifiers element may contain one or more qualifiers of the same type"</c>: two
    /// <c>SPURI</c> qualifiers both read, neither treated as an illegal duplicate.
    /// </summary>
    [TestMethod]
    public void SigPolicyQualifiersPermitsRepeatedQualifiersOfTheSameType()
    {
        string document = $"""
            <SignaturePolicyIdentifier xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                {SigPolicyHash([0x01])}
                <SigPolicyQualifiers>
                  <SigPolicyQualifier><SPURI>http://example.com/policy1</SPURI></SigPolicyQualifier>
                  <SigPolicyQualifier><SPURI>http://example.com/policy2</SPURI></SigPolicyQualifier>
                </SigPolicyQualifiers>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.SignaturePolicyId!.SigPolicyQualifiers);
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPURI, value.SignaturePolicyId.SigPolicyQualifiers[0].Kind);
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPURI, value.SignaturePolicyId.SigPolicyQualifiers[1].Kind);
            Assert.AreEqual("http://example.com/policy1", Encoding.UTF8.GetString(value.SignaturePolicyId.SigPolicyQualifiers[0].SPURI));
            Assert.AreEqual("http://example.com/policy2", Encoding.UTF8.GetString(value.SignaturePolicyId.SigPolicyQualifiers[1].SPURI));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's forward
    /// cross-check: <c>"If this transform is used, then the SignaturePolicyIdentifier shall be qualified at
    /// least by the SPDocSpecification qualifier"</c> — a <c>ds:Transforms</c> naming
    /// <c>SPDocDigestAsInSpecification</c> together with an <c>SPDocSpecification</c> qualifier reads
    /// successfully.
    /// </summary>
    [TestMethod]
    public void SPDocDigestTransformWithSPDocSpecificationQualifierReads()
    {
        string document = $$"""
            <SignaturePolicyIdentifier xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                <ds:Transforms>
                  <ds:Transform Algorithm="{{XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri}}"/>
                </ds:Transforms>
                {{SigPolicyHash([0x01])}}
                <SigPolicyQualifiers>
                  <SigPolicyQualifier>
                    <SPDocSpecification xmlns="{{XAdESIdentifiers.XAdESNamespaceV141}}">
                      <Identifier xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}">http://example.com/policy-spec</Identifier>
                    </SPDocSpecification>
                  </SigPolicyQualifier>
                </SigPolicyQualifiers>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(XAdESSigPolicyQualifierKind.SPDocSpecification, value!.SignaturePolicyId!.SigPolicyQualifiers[0].Kind);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's forward
    /// cross-check in its refusing direction: a <c>ds:Transforms</c> naming <c>SPDocDigestAsInSpecification</c>
    /// WITHOUT any <c>SPDocSpecification</c> qualifier is refused.
    /// </summary>
    [TestMethod]
    public void SPDocDigestTransformWithoutSPDocSpecificationQualifierIsRefused()
    {
        string document = $$"""
            <SignaturePolicyIdentifier xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                <ds:Transforms>
                  <ds:Transform Algorithm="{{XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri}}"/>
                </ds:Transforms>
                {{SigPolicyHash([0x01])}}
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "SPDocDigestAsInSpecification without an SPDocSpecification qualifier must be refused.");
        Assert.AreEqual(XAdESReadFailure.SPDocDigestAsInSpecificationRequiresSPDocSpecification, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1, the
    /// cross-check is directional, not bidirectional: an <c>SPDocSpecification</c> qualifier present WITHOUT
    /// the <c>SPDocDigestAsInSpecification</c> transform is never refused by this rule — the clause only
    /// constrains the transform-present case, never the reverse.
    /// </summary>
    [TestMethod]
    public void SPDocSpecificationQualifierWithoutTheTransformIsNotRefused()
    {
        string document = $$"""
            <SignaturePolicyIdentifier xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                {{SigPolicyHash([0x01])}}
                <SigPolicyQualifiers>
                  <SigPolicyQualifier>
                    <SPDocSpecification xmlns="{{XAdESIdentifiers.XAdESNamespaceV141}}">
                      <Identifier xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}">http://example.com/policy-spec</Identifier>
                    </SPDocSpecification>
                  </SigPolicyQualifier>
                </SigPolicyQualifiers>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"An SPDocSpecification qualifier without the transform must not be refused, but was refused with {error.Failure}.");
        value!.Dispose();
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>"This
    /// transform shall not be used in elements different than SignaturePolicyId element"</c> in its enforced
    /// direction: outside <c>SignaturePolicyId</c>, the
    /// <c>SPDocDigestAsInSpecification</c> URI is simply not a supported reference-processing transform, and
    /// the existing XMLDSIG transform-dispatch engine refuses it with
    /// <see cref="XmlSignatureProcessingFailure.UnsupportedTransform"/> — the same disposition every other
    /// algorithm URI this leaf does not recognize at all receives (section 6.6's chapeau).
    /// </summary>
    [TestMethod]
    public void SPDocDigestTransformIsRefusedAsAnOrdinaryReferenceProcessingTransform()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="">
                  <Transforms>
                    <Transform Algorithm="{{XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri}}"/>
                  </Transforms>
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.IsGreaterThan(0, signatureIndices.Length, "The fixture document must carry at least one Signature element.");
        bool isSignatureRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {readError.Failure}.");
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature!, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
            using(digestInput)
            {
                Assert.IsFalse(isComputed, "The SPDocDigestAsInSpecification URI must not be executable as an ordinary reference-processing transform.");
                Assert.IsNull(digestInput);
                Assert.AreEqual(XmlSignatureProcessingFailure.UnsupportedTransform, error.Failure);
            }
        }
    }
}
