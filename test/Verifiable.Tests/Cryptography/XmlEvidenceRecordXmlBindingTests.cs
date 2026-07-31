using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the staged worked binding of the <c>EvidenceRecord</c> element of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see>: what
/// <see cref="ParseEvidenceRecordXmlDelegate"/> and <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> are
/// contracted to do with a document they did not produce.
/// </summary>
/// <remarks>
/// The refusals matter more than the acceptances here. An Evidence Record is not authenticated by anything until
/// its own time-stamps have been verified, which cannot happen until it has been parsed, so the parse is the one
/// step that runs on octets nothing vouches for — and every shape it must refuse is a shape a verifier would
/// otherwise draw a conclusion from.
/// </remarks>
[TestClass]
internal sealed class XmlEvidenceRecordXmlBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The <c>genTime</c> every token of this class states.</summary>
    private static DateTimeOffset ArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The data object every record of this class archives.</summary>
    private static byte[] DataObject { get; } = [.. "the archived data object"u8];


    /// <summary>
    /// A well-formed record parses into the model with its chain's two algorithm identifiers resolved and its
    /// hash values decoded — the acceptance the refusals below are measured against.
    /// </summary>
    [TestMethod]
    public async Task AWellFormedRecordParsesIntoTheModel()
    {
        byte[] document = Mint();

        using XmlEvidenceRecordParseResult parsed = await ParseAsync(document).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordParseStatus.Valid, parsed.Status, $"The minted record parses ({parsed.FailureReason}).");
        XmlEvidenceRecord record = parsed.EvidenceRecord!;
        Assert.AreEqual(XmlEvidenceRecordWellKnown.Version10, record.Version, "Clause 8's schema fixes the Version attribute.");
        Assert.IsFalse(record.HasEncryptionInformation, "The record carries no EncryptionInformation element.");
        Assert.HasCount(1, record.Chains, "One chain was written.");
        Assert.AreEqual(PkiDigestAlgorithm.Sha256, record.Chains[0].DigestAlgorithm, "Clause 4.1.1's identifier is resolved at the seam rather than carried as text.");
        Assert.AreEqual(XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri, record.Chains[0].CanonicalizationMethodUri, "Clause 4.1.2's identifier is carried as written.");
        Assert.AreEqual(1, record.Chains[0].Order, "Clause 4.1 orders the chains by their Order attributes.");
        Assert.AreEqual(
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            record.Chains[0].ArchiveTimeStamps[0].HashTree!.Sequences[0].DigestValues[0].Length,
            "Clause 3.1.1: the base64 text is decoded to a binary hash value before anything is done with it.");
        Assert.AreEqual(
            XmlEvidenceRecordWellKnown.Rfc3161TimeStampTokenType,
            record.Chains[0].ArchiveTimeStamps[0].TimeStamp.TokenType,
            "Clause 3.1.2's Type attribute is read.");
        Assert.IsNotNull(record.Chains[0].ArchiveTimeStamps[0].TimeStamp.Rfc3161Token, "The RFC 3161 token's base64 is decoded into a carrier.");
    }


    /// <summary>
    /// Clause 4.1.1 binds the digest identifier to the space IETF RFC 3275 and IETF RFC 4051 define, and this
    /// library computes three of the algorithms in it. A chain naming another one is refused for the algorithm
    /// rather than reported as unreadable — a hash tree nothing can recompute proves nothing.
    /// </summary>
    [TestMethod]
    [DataRow("http://www.w3.org/2000/09/xmldsig#sha1", DisplayName = "SHA-1, recognised and refused")]
    [DataRow("http://www.w3.org/2001/04/xmldsig-more#md5", DisplayName = "MD5, recognised and refused")]
    [DataRow("urn:example:not-an-algorithm", DisplayName = "an identifier of no registry at all")]
    public async Task ADigestIdentifierThisLibraryWillNotComputeIsRefusedForTheAlgorithm(string algorithmUri)
    {
        byte[] document = Replace(Mint(), XmlSignatureWellKnown.Sha256DigestUri, algorithmUri);

        using XmlEvidenceRecordParseResult parsed = await ParseAsync(document).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordParseStatus.UnsupportedDigestAlgorithm, parsed.Status,
            "The document is well-formed; what is refused is its producer's choice of algorithm.");
    }


    /// <summary>
    /// Clause 4.1.2 binds the canonicalization identifier to the same space. An identifier outside it is not an
    /// extension a validator may pass over — it is a document naming an algorithm no specification defines.
    /// </summary>
    [TestMethod]
    public async Task ACanonicalizationIdentifierOutsideTheBoundSpaceIsRefused()
    {
        byte[] document = Replace(Mint(), XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri, "urn:example:my-own-canonicalization");

        using XmlEvidenceRecordParseResult parsed = await ParseAsync(document).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordParseStatus.UnsupportedCanonicalizationAlgorithm, parsed.Status,
            "Clause 4.1.2: algorithm identifiers MUST be used as defined in IETF RFC 3275 and IETF RFC 4051.");
    }


    /// <summary>
    /// Clause 2.1 makes <c>Order</c> required wherever same-named siblings occur, and clause 4.1 reads the
    /// element order off those attributes. A set that is not the run 1..n makes "the ATS with the largest Order"
    /// name something no verifier can agree on.
    /// </summary>
    [TestMethod]
    public async Task OrderAttributesThatAreNotTheRunAreRefused()
    {
        byte[] duplicated = Replace(MintWithRenewal(), "<ers:ArchiveTimeStamp Order=\"2\">", "<ers:ArchiveTimeStamp Order=\"1\">");
        using XmlEvidenceRecordParseResult duplicate = await ParseAsync(duplicated).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.OrderMalformed, duplicate.Status, "Two siblings cannot share an Order.");

        byte[] gapped = Replace(MintWithRenewal(), "<ers:ArchiveTimeStamp Order=\"2\">", "<ers:ArchiveTimeStamp Order=\"3\">");
        using XmlEvidenceRecordParseResult gap = await ParseAsync(gapped).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.OrderMalformed, gap.Status, "A gap leaves the position of every later sibling undecided.");

        byte[] missing = Replace(Mint(), " Order=\"1\"><ers:HashTree>", "><ers:HashTree>");
        using XmlEvidenceRecordParseResult absent = await ParseAsync(missing).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.OrderMalformed, absent.Status, "Clause 2.1 makes the attribute required.");
    }


    /// <summary>
    /// A <c>DigestValue</c> that is not base64, or that decodes to a length the chain's algorithm does not
    /// produce, can never take part in the comparison the walk is going to make.
    /// </summary>
    [TestMethod]
    public async Task ADigestValueTheChainsAlgorithmCouldNotHaveProducedIsRefused()
    {
        byte[] document = Mint();
        string text = Encoding.UTF8.GetString(document);
        int at = text.IndexOf("<ers:DigestValue>", StringComparison.Ordinal) + "<ers:DigestValue>".Length;
        int end = text.IndexOf("</ers:DigestValue>", StringComparison.Ordinal);

        byte[] notBase64 = Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, at), "not base64 at all!!", text.AsSpan(end)));
        using XmlEvidenceRecordParseResult malformed = await ParseAsync(notBase64).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.DigestValueMalformed, malformed.Status, "Clause 3.1.1 decodes the text as base64 before using it.");

        byte[] tooShort = Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, at), Convert.ToBase64String(new byte[16]), text.AsSpan(end)));
        using XmlEvidenceRecordParseResult wrongLength = await ParseAsync(tooShort).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.DigestValueMalformed, wrongLength.Status,
            "Clause 4.1.1 makes one algorithm govern every hash value of a chain, so a 16-octet value under SHA-256 is refused.");
    }


    /// <summary>
    /// Clause 3.1.2 registers exactly two <c>TimeStampToken</c> types, and clause 10 makes the set extensible
    /// only by IANA registration. A third value is not an unknown extension.
    /// </summary>
    [TestMethod]
    public async Task ATimeStampTokenTypeOutsideTheRegistryIsRefused()
    {
        byte[] document = Replace(Mint(), "Type=\"RFC3161\"", "Type=\"MYFORMAT\"");

        using XmlEvidenceRecordParseResult parsed = await ParseAsync(document).ConfigureAwait(false);

        Assert.AreEqual(XmlEvidenceRecordParseStatus.TimeStampTokenMalformed, parsed.Status, "Clause 3.1.2 names two formats and this is neither.");
    }


    /// <summary>
    /// Every particle clause 8's schema requires is required in the model too; an implementation that could not
    /// populate one refuses rather than inventing a default.
    /// </summary>
    [TestMethod]
    public async Task AMissingRequiredParticleIsRefusedRatherThanDefaulted()
    {
        byte[] noVersion = Replace(Mint(), " Version=\"1.0\"", string.Empty);
        using XmlEvidenceRecordParseResult version = await ParseAsync(noVersion).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.MissingRequiredElement, version.Status, "Clause 2.1 requires the Version attribute.");

        byte[] noCanonicalization = RemoveElement(Mint(), "<ers:CanonicalizationMethod", "/>");
        using XmlEvidenceRecordParseResult canonicalization = await ParseAsync(noCanonicalization).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.MissingRequiredElement, canonicalization.Status, "Clause 4.1.2 makes CanonicalizationMethod a required element.");
    }


    /// <summary>
    /// The octets are attacker-reachable, so a document type definition is prohibited outright — entity
    /// expansion and external entity resolution both live there — and octets that are not XML at all are a
    /// refusal rather than an exception.
    /// </summary>
    [TestMethod]
    public async Task ADocumentTypeDefinitionAndOctetsThatAreNotXmlAreBothRefused()
    {
        byte[] withDtd = Encoding.UTF8.GetBytes(
            "<!DOCTYPE EvidenceRecord [<!ENTITY x \"y\">]><ers:EvidenceRecord xmlns:ers=\"urn:ietf:params:xml:ns:ers\" Version=\"1.0\"/>");
        using XmlEvidenceRecordParseResult dtd = await ParseAsync(withDtd).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.Malformed, dtd.Status, "A document type definition is prohibited outright.");

        using XmlEvidenceRecordParseResult notXml = await ParseAsync([.. "this is not a document"u8]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.Malformed, notXml.Status, "Octets that are not XML are a status, never an exception.");

        using XmlEvidenceRecordParseResult wrongRoot = await ParseAsync(Encoding.UTF8.GetBytes("<something xmlns=\"urn:example\"/>")).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.Malformed, wrongRoot.Status, "A root element that is not ers:EvidenceRecord is not an Evidence Record.");
    }


    /// <summary>
    /// The bounds travel in the context rather than being captured by the implementation, and a document over
    /// one of them is a refusal rather than a resource exhaustion.
    /// </summary>
    [TestMethod]
    public async Task ADocumentOverOneOfTheStatedBoundsIsRefused()
    {
        byte[] document = Mint();

        using XmlEvidenceRecordParseResult tooLong = await ParseAsync(document, new XmlEvidenceRecordParseLimits { MaximumDocumentByteLength = 16 }).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.LimitExceeded, tooLong.Status, "The document is longer than the bound the caller stated.");

        using XmlEvidenceRecordParseResult tooManyChains = await ParseAsync(document, new XmlEvidenceRecordParseLimits { MaximumChains = 0 }).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.LimitExceeded, tooManyChains.Status, "The bound on chains is the caller's to state per call.");

        using XmlEvidenceRecordParseResult tooDeep = await ParseAsync(document, new XmlEvidenceRecordParseLimits { MaximumElementDepth = 2 }).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordParseStatus.LimitExceeded, tooDeep.Status, "The depth is walked with an explicit stack and bounded by the caller's value.");
    }


    /// <summary>
    /// The canonicalization seam refuses an algorithm outside the bound space, and names a target it cannot find
    /// rather than producing octets for a different element.
    /// </summary>
    [TestMethod]
    public async Task TheCanonicalizationSeamRefusesWhatItCannotDo()
    {
        byte[] document = Mint();

        using XmlEvidenceRecordCanonicalizationResult unsupported = await XmlEvidenceRecordXmlBinding.CanonicalizeAsync(
            new XmlEvidenceRecordCanonicalizationContext
            {
                Document = document,
                AlgorithmUri = "urn:example:my-own-canonicalization",
                Target = XmlEvidenceRecordCanonicalizationTarget.TimeStampElement,
                ChainOrder = 1,
                ArchiveTimeStampOrder = 1
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordCanonicalizationStatus.UnsupportedAlgorithm, unsupported.Status,
            "An algorithm the implementation does not perform is a status, never a silent substitution of another one.");

        using XmlEvidenceRecordCanonicalizationResult absent = await XmlEvidenceRecordXmlBinding.CanonicalizeAsync(
            new XmlEvidenceRecordCanonicalizationContext
            {
                Document = document,
                AlgorithmUri = XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
                Target = XmlEvidenceRecordCanonicalizationTarget.TimeStampElement,
                ChainOrder = 1,
                ArchiveTimeStampOrder = 7
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordCanonicalizationStatus.TargetNotFound, absent.Status, "An Order nothing carries names no element.");

        using XmlEvidenceRecordCanonicalizationResult prefix = await XmlEvidenceRecordXmlBinding.CanonicalizeAsync(
            new XmlEvidenceRecordCanonicalizationContext
            {
                Document = document,
                AlgorithmUri = XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
                Target = XmlEvidenceRecordCanonicalizationTarget.ArchiveTimeStampSequencePrefix,
                ChainCount = 4
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordCanonicalizationStatus.TargetNotFound, prefix.Status, "A prefix longer than the sequence names no element either.");
    }


    /// <summary>
    /// The two forms of one canonicalization algorithm are not interchangeable: a comment inside the element
    /// being canonicalized is in the octets of one and not of the other, which is why the seam's contract makes
    /// the distinction the implementation's obligation.
    /// </summary>
    [TestMethod]
    public async Task TheCommentPreservingFormOfAnAlgorithmIsNotTheOtherOne()
    {
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        byte[] document = XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash(DataObject, PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.CanonicalXml10Uri,
            authority,
            [authority, root],
            ArchiveTime,
            comment: " a comment inside the sequence ");

        byte[] withComments = await CanonicalizeSequenceAsync(document, XmlSignatureWellKnown.CanonicalXml10WithCommentsUri).ConfigureAwait(false);
        byte[] withoutComments = await CanonicalizeSequenceAsync(document, XmlSignatureWellKnown.CanonicalXml10Uri).ConfigureAwait(false);

        Assert.AreNotEqual(Convert.ToBase64String(withComments), Convert.ToBase64String(withoutComments),
            "A comment is in the octets of the comment-preserving form and not of the other, so an implementation that treated them alike would compute a root nothing matches.");
        Assert.Contains("a comment inside the sequence", Encoding.UTF8.GetString(withComments), StringComparison.Ordinal, "The comment-preserving form keeps it.");
        Assert.DoesNotContain("a comment inside the sequence", Encoding.UTF8.GetString(withoutComments), StringComparison.Ordinal, "The other form drops it.");
    }


    /// <summary>
    /// Canonicalizes the whole <c>ArchiveTimeStampSequence</c> of a document under a stated algorithm.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="algorithmUri">The algorithm identifier.</param>
    /// <returns>The canonical octets.</returns>
    private async Task<byte[]> CanonicalizeSequenceAsync(byte[] document, string algorithmUri)
    {
        using XmlEvidenceRecordCanonicalizationResult result = await XmlEvidenceRecordXmlBinding.CanonicalizeAsync(
            new XmlEvidenceRecordCanonicalizationContext
            {
                Document = document,
                AlgorithmUri = algorithmUri,
                Target = XmlEvidenceRecordCanonicalizationTarget.ArchiveTimeStampSequencePrefix,
                ChainCount = 1
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsCanonicalized, $"The seam produces the sequence's binary representation ({result.FailureReason}).");

        return result.BinaryRepresentation!.AsReadOnlySpan().ToArray();
    }


    /// <summary>Parses a document through the staged binding.</summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="limits">The bounds, or <see langword="null"/> for the conformant ones.</param>
    /// <returns>The parse result, which the caller disposes.</returns>
    private ValueTask<XmlEvidenceRecordParseResult> ParseAsync(byte[] document, XmlEvidenceRecordParseLimits? limits = null) =>
        XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext
            {
                Document = document,
                Limits = limits ?? XmlEvidenceRecordParseLimits.Conformant
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);


    /// <summary>Mints a one-chain, one-member record over this class's data object.</summary>
    /// <returns>The document's octets.</returns>
    private static byte[] Mint()
    {
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);

        return XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash(DataObject, PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            authority,
            [authority, root],
            ArchiveTime);
    }


    /// <summary>Mints a record whose chain carries two members, so an <c>Order</c> run of two exists to break.</summary>
    /// <returns>The document's octets.</returns>
    private static byte[] MintWithRenewal()
    {
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        byte[] initial = XmlEvidenceRecordTestFactory.MintInitial(
            [[EvidenceRecordOracle.Hash(DataObject, PkiDigestAlgorithm.Sha256)]],
            PkiDigestAlgorithm.Sha256,
            XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri,
            authority,
            [authority, root],
            ArchiveTime);

        return XmlEvidenceRecordTestFactory.AppendTimestampRenewal(initial, authority, [authority, root], ArchiveTime.AddHours(1));
    }


    /// <summary>Replaces every occurrence of a substring in a document's UTF-8 text.</summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="original">The text to replace.</param>
    /// <param name="replacement">The text to write in its place.</param>
    /// <returns>The changed document's octets.</returns>
    private static byte[] Replace(byte[] document, string original, string replacement)
    {
        string text = Encoding.UTF8.GetString(document);
        Assert.Contains(original, text, StringComparison.Ordinal, $"The document has to carry '{original}' for the case to mean anything.");

        return Encoding.UTF8.GetBytes(text.Replace(original, replacement, StringComparison.Ordinal));
    }


    /// <summary>Removes one element from a document's UTF-8 text, by its opening and closing markers.</summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="opening">The text the element starts with.</param>
    /// <param name="closing">The text the element ends with.</param>
    /// <returns>The changed document's octets.</returns>
    private static byte[] RemoveElement(byte[] document, string opening, string closing)
    {
        string text = Encoding.UTF8.GetString(document);
        int start = text.IndexOf(opening, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, start, $"The document has to carry '{opening}' for the case to mean anything.");
        int end = text.IndexOf(closing, start, StringComparison.Ordinal) + closing.Length;

        return Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, start), text.AsSpan(end)));
    }
}
