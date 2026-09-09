using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of reference-loop and deep-<c>Object</c>-nesting shapes: a Manifest-in-Object referencing its own
/// container, and deep Object nesting near the 1024 depth limit.
/// A <c>Manifest</c>'s own references are never auto-followed by this engine — "the digests within such a
/// Manifest are checked at the application's discretion" (<see cref="XmlManifest"/>'s own remarks, section
/// 5.1) — so a self-referencing <c>Manifest</c> cannot recurse inside this leaf; the property worth proving
/// is that dereferencing such a self-reference produces the ordinary node-set it names, and that the
/// structural readers correctly locate a <c>Manifest</c> nested near the documented parse-depth bound (<see
/// cref="XmlSpanReader.MaximumElementDepth"/>, 1024). Every navigation helper this leaf's model readers use
/// is iterative over sibling/child links rather than recursive over document depth, so termination is a
/// property of the code, not something a timed assertion adds proof of: a case that failed to terminate
/// would surface as the test run's own timeout rather than as an assertion failure here.
/// </summary>
[TestClass]
internal sealed class XmlReferenceLoopAndDepthTests
{
    /// <summary>
    /// Proves the "<c>Reference</c> loops via <c>Object</c>-nested manifests" hardening obligation: a
    /// <c>Manifest</c> whose own <c>Reference</c> points back at the <c>Manifest</c> itself — a
    /// <c>ds:Object</c>-nested self-reference — dereferences to the ordinary element-subtree node-set the
    /// <c>Manifest</c>'s own <c>Id</c> identifies (which necessarily includes the very <c>Reference</c>
    /// element pointing back at it, since that <c>Reference</c> is one of the <c>Manifest</c>'s own
    /// descendants): this engine has no automatic manifest-reference-chasing behavior to loop inside in the
    /// first place. This is the DoS posture <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 8.3 names — "even there perverse parameters might cause unacceptable
    /// processing or memory demand" — applied to a self-referencing structure rather than a raw size axis.
    /// </summary>
    [TestMethod]
    public void SelfReferencingManifestDereferencesToItsOwnSubtree()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="#outerRef">
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object Id="outerRef">
                <Manifest Id="selfManifest">
                  <Reference URI="#selfManifest">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </Manifest>
              </Object>
            </Signature>
            """;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"Must read but was refused with {readSignatureError.Failure}.");
            using(signature)
            {
                int manifestElementIndex = signature!.Objects[0].ContentNodeIndices
                    .First(i => table!.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual("Manifest"u8));
                bool isManifestRead = XmlManifest.TryRead(table!, manifestElementIndex, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestReadError);
                Assert.IsTrue(isManifestRead, $"Manifest must read but was refused with {manifestReadError.Failure}.");
                using(manifest)
                {
                    bool isDereferenced = XmlReferenceDereferencer.TryDereference(table!, manifest!.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

                    Assert.IsTrue(isDereferenced, $"The self-reference must dereference but was refused with {error.Failure}.");
                    Assert.IsTrue(result.IsNodeSet);
                    Assert.AreEqual(manifest.ElementIndex, result.NodeSet.ApexElementIndex, "The self-reference must resolve to the Manifest's own element as the subtree apex.");
                }
            }
        }
    }


    /// <summary>
    /// Proves the <see cref="XmlManifest"/> overload stays safe over the same self-referencing <c>Manifest</c> fixture <see
    /// cref="SelfReferencingManifestDereferencesToItsOwnSubtree"/> dereferences directly: computing the digest
    /// input runs the reference through the FULL engine (dereference, transform chain, implicit final conversion) rather than
    /// the dereferencer alone, and computes the correct digest input rather than chasing the self-reference — this engine has
    /// no automatic manifest-reference-chasing behavior to loop inside in the first place, exactly as the sibling test's own
    /// remarks state, now proven through the newly-public entry point rather than only the internal one. Same DoS posture as
    /// <see cref="SelfReferencingManifestDereferencesToItsOwnSubtree"/>: <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second Edition)</see>
    /// section 8.3's "even there perverse parameters might cause unacceptable processing or memory demand," now over the full
    /// engine rather than the dereferencer alone.
    /// </summary>
    [TestMethod]
    public void SelfReferencingManifestReferenceDigestInputComputes()
    {
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="#outerRef">
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object Id="outerRef">
                <Manifest Id="selfManifest">
                  <Reference URI="#selfManifest">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>Ag==</DigestValue>
                  </Reference>
                </Manifest>
              </Object>
            </Signature>
            """;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"Must read but was refused with {readSignatureError.Failure}.");
            using(signature)
            {
                int manifestElementIndex = signature!.Objects[0].ContentNodeIndices
                    .First(i => table!.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual("Manifest"u8));
                bool isManifestRead = XmlManifest.TryRead(table!, manifestElementIndex, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestReadError);
                Assert.IsTrue(isManifestRead, $"Manifest must read but was refused with {manifestReadError.Failure}.");
                using(manifest)
                {
                    bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table!, manifest!, 0, resolver: null, BaseMemoryPool.Shared, out PooledMemory? digestInput, out XmlSignatureProcessingError error);

                    Assert.IsTrue(isComputed, $"The self-reference's digest input must compute but was refused with {error.Failure}.");
                    digestInput!.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Proves the "deep Object nesting near the 1024 depth limit" hardening obligation: deep <c>Object</c>
    /// nesting near the documented parse-depth bound (<see cref="XmlSpanReader.MaximumElementDepth"/>) reads
    /// and locates a <c>Manifest</c> nested at the bottom of the chain — every model-reading helper this
    /// leaf uses (<see cref="XmlSignatureModelGrammar"/>'s child/sibling navigation, <see
    /// cref="XmlManifest.TryRead"/> itself) is iterative over sibling/child links rather than recursive over
    /// document depth, so nothing here can stack-overflow, and <c>Object</c> content is left as opaque node
    /// indices rather than eagerly interpreted. Same DoS posture, now over the parse-depth axis rather than
    /// self-reference: <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 8.3's "even there perverse parameters might
    /// cause unacceptable processing or memory demand."
    /// </summary>
    [TestMethod]
    public void DeepObjectNestingNearTheDocumentedLimitReadsAndLocatesItsNestedManifest()
    {
        const int NestedObjectCount = 900;
        Assert.IsLessThan(XmlSpanReader.MaximumElementDepth, NestedObjectCount + 10, "The fixture's chosen nesting must stay comfortably under the documented parse-depth bound.");

        var builder = new StringBuilder(NestedObjectCount * 16);
        for(int i = 0; i < NestedObjectCount; ++i)
        {
            builder.Append("<Object>");
        }

        builder.Append("""<Manifest xmlns="http://www.w3.org/2000/09/xmldsig#" Id="deep"><Reference><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AQ==</DigestValue></Reference></Manifest>""");
        for(int i = 0; i < NestedObjectCount; ++i)
        {
            builder.Append("</Object>");
        }

        string nestedObjects = builder.ToString();
        string document = $$"""
            <Signature xmlns="{{XmlSignatureIdentifiers.XmlSignatureNamespace}}">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="{{XmlSignatureIdentifiers.CanonicalXml11Uri}}"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="">
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object>{{nestedObjects}}</Object>
            </Signature>
            """;

        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The deeply nested fixture must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
            Assert.IsTrue(isRead, $"Must read but was refused with {readSignatureError.Failure}.");
            using(signature)
            {
                int cursor = signature!.Objects[0].ContentNodeIndices.First(i => table!.KindOf(i) == XmlNodeKind.Element);
                int steps = 0;
                while(table!.LocalNameOf(cursor).SequenceEqual("Object"u8))
                {
                    cursor = FirstElementChildOf(table, cursor);
                    ++steps;
                }

                Assert.AreEqual(NestedObjectCount, steps, "The walk down to the innermost element must cross every nested Object.");
                Assert.IsTrue(table.LocalNameOf(cursor).SequenceEqual("Manifest"u8), "The innermost element must be the nested Manifest.");

                bool isManifestRead = XmlManifest.TryRead(table, cursor, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestReadError);
                Assert.IsTrue(isManifestRead, $"The deeply nested Manifest must read but was refused with {manifestReadError.Failure}.");
                manifest!.Dispose();
            }
        }
    }


    /// <summary>
    /// Finds the first element child of a node — an iterative single-step helper the walking test above uses
    /// so its own depth-descending loop never recurses either.
    /// </summary>
    private static int FirstElementChildOf(XmlNodeTable table, int parentIndex)
    {
        for(int child = table.FirstChildOf(parentIndex); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element)
            {
                return child;
            }
        }

        throw new InvalidOperationException("The fixture guarantees an element child at every nesting level.");
    }
}
