using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs, through the full <see cref="XmlReferenceProcessing.TryComputeDigestInput"/> engine rather than
/// the dereferencer alone, that content hidden in a comment follows the section 4.3.3.3 four-form matrix
/// exactly and no other combination: absent from <c>""</c> and <c>#name</c> digest inputs under EVERY conversion (explicit or
/// implicit — section 4.3.3.3 step 4 strips comments from these two forms AT DEREFERENCE, independent of
/// whatever renders the set afterwards), and present under the two <c>#xpointer</c> forms EITHER under an
/// explicit with-comments canonicalization transform OR under the engine's own implicit final conversion
/// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> section 4.3.3.3: "when [XML-C14N] ... is passed a node-set, it processes the
/// node-set as is: with or without comments" — the implicit conversion renders the dereferenced set exactly
/// as the dereferencer left it, and only <c>""</c>/bare-name dereferencing ever marks a set <see
/// cref="XmlNodeSet.WithoutComments"/>).
/// </summary>
[TestClass]
internal sealed class XmlCommentSmugglingEngineTests
{
    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string SmuggledComment = "<!--smuggled-payload-->";


    private static string BuildDocument(string referenceUri, bool withExplicitWithCommentsTransform)
    {
        string transforms = withExplicitWithCommentsTransform
            ? $"""<Transforms><Transform Algorithm="{XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri}"/></Transforms>"""
            : string.Empty;

        return $$"""
            <!--doc-level-comment--><Document>
              <Target Id="target">{{SmuggledComment}}<Payload>data</Payload></Target>
              <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                  <SignatureMethod Algorithm="{{SignatureMethodAlgorithm}}"/>
                  <Reference URI="{{referenceUri}}">
                    {{transforms}}
                    <DigestMethod Algorithm="{{DigestMethodAlgorithm}}"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
    }


    private static string ComputeDigestInputText(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices, "The fixture must carry exactly one Signature element.");

            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"The fixture Signature must read but was refused with {readSignatureError.Failure}.");
            using(signature)
            {
                bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table!, signature!, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
                Assert.IsTrue(isComputed, $"Digest input must compute but was refused with {error.Failure}.");
                using(digestInput)
                {
                    return Encoding.UTF8.GetString(digestInput!.AsReadOnlySpan());
                }
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4 through the full engine, with an explicit
    /// <c>#WithComments</c> canonicalization <c>Transform</c> forcing comment rendering wherever the
    /// node-set itself does not exclude comments: the smuggled comment is absent from the <c>""</c> and
    /// <c>#target</c> (bare-name) digest inputs — "if the URI has no fragment identifier or the fragment
    /// identifier is a shortname XPointer, then delete all comment nodes" — and present under
    /// <c>#xpointer(/)</c> and <c>#xpointer(id('target'))</c>, exactly the four-form matrix and no other
    /// combination.
    /// </summary>
    [TestMethod]
    public void SmuggledCommentFollowsTheFourFormMatrixUnderAnExplicitWithCommentsTransform()
    {
        string emptyText = ComputeDigestInputText(BuildDocument(string.Empty, withExplicitWithCommentsTransform: true));
        string bareNameText = ComputeDigestInputText(BuildDocument("#target", withExplicitWithCommentsTransform: true));
        string xpointerRootText = ComputeDigestInputText(BuildDocument("#xpointer(/)", withExplicitWithCommentsTransform: true));
        string xpointerByIdText = ComputeDigestInputText(BuildDocument("#xpointer(id('target'))", withExplicitWithCommentsTransform: true));

        Assert.DoesNotContain(SmuggledComment, emptyText, "URI=\"\" must strip the smuggled comment even under an explicit with-comments transform.");
        Assert.DoesNotContain(SmuggledComment, bareNameText, "The bare-name XPointer form must strip the smuggled comment even under an explicit with-comments transform.");
        Assert.Contains(SmuggledComment, xpointerRootText, "#xpointer(/) must retain the smuggled comment under an explicit with-comments transform.");
        Assert.Contains(SmuggledComment, xpointerByIdText, "#xpointer(id(...)) must retain the smuggled comment under an explicit with-comments transform.");
    }


    /// <summary>
    /// Proves the "no other combination" half of the matrix
    /// (<see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3): WITHOUT an explicit with-comments canonicalization
    /// <c>Transform</c>, the smuggled comment is STILL absent from <c>""</c> and <c>#target</c> — section
    /// 4.3.3.3 step 4 deletes comments from these two forms at DEREFERENCE time
    /// (<see cref="XmlNodeSet.WithoutComments"/>), before and independent of whatever converts the set to
    /// octets afterwards — but is now PRESENT under both <c>#xpointer(/)</c> and <c>#xpointer(id(...))</c>,
    /// because the engine's own implicit final conversion renders the dereferenced node-set AS IS ("when
    /// [XML-C14N] ... is passed a node-set, it processes the node-set as is: with or without comments"): the
    /// two scheme-based forms are dereferenced WITHOUT the <c>WithoutComments</c> mark specifically so a
    /// with-comments rendering — explicit transform or, as proven here, the implicit default alike — retains
    /// what they carry.
    /// </summary>
    [TestMethod]
    public void SmuggledCommentSurvivesTheImplicitDefaultConversionOnlyForTheTwoSchemeBasedForms()
    {
        string emptyText = ComputeDigestInputText(BuildDocument(string.Empty, withExplicitWithCommentsTransform: false));
        string bareNameText = ComputeDigestInputText(BuildDocument("#target", withExplicitWithCommentsTransform: false));
        string xpointerRootText = ComputeDigestInputText(BuildDocument("#xpointer(/)", withExplicitWithCommentsTransform: false));
        string xpointerByIdText = ComputeDigestInputText(BuildDocument("#xpointer(id('target'))", withExplicitWithCommentsTransform: false));

        Assert.DoesNotContain(SmuggledComment, emptyText, "URI=\"\" must strip the smuggled comment under the implicit default conversion too — step 4 acts at dereference time.");
        Assert.DoesNotContain(SmuggledComment, bareNameText, "The bare-name XPointer form must strip the smuggled comment under the implicit default conversion too.");
        Assert.Contains(SmuggledComment, xpointerRootText, "#xpointer(/) must retain the smuggled comment even with no explicit transform: the implicit conversion renders the node-set as is.");
        Assert.Contains(SmuggledComment, xpointerByIdText, "#xpointer(id(...)) must retain the smuggled comment even with no explicit transform: the implicit conversion renders the node-set as is.");
    }
}
