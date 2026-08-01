using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="XmlEvidenceRecords.CreateInitialAsync"/> — the initial Evidence Record of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-3.2">IETF RFC 6283 clause 3.2</see> in the XML
/// syntax of clause 8, produced through the parse-side binding's write counterpart and a genuine RFC 3161
/// time-stamp.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every record here is produced by the shipped surface</strong> —
/// <see cref="XmlEvidenceRecords.CreateInitialAsync"/> over the staged
/// <see cref="XmlEvidenceRecordXmlBinding.WriteAsync"/> writer and a <see cref="MintingTimestampResponder"/>
/// that mints genuine tokens in-process — and checked from the produced octets alone: the document crosses to
/// verification as bytes, is parsed back through the staged parser, verified through the shipped
/// <see cref="XmlEvidenceRecords.VerifyAsync"/> (the full Appendix A walk), and its hash tree is recomputed by
/// <see cref="XmlEvidenceRecordOracle"/>, which shares no code with the builder.
/// </para>
/// <para>
/// The oracle's root recomputation matching the time-stamp token's own message imprint is the evidence that
/// the builder produced the clause 3.1.1 tree and not merely one its own verifier walks: the oracle implements
/// the level rule and the first-sequence carve-out independently, from the specification's text.
/// </para>
/// </remarks>
[TestClass]
internal sealed class XmlEvidenceRecordCreationTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The instant the minted time-stamps assert.</summary>
    private static DateTimeOffset ArchiveInstant { get; } = TestClock.CanonicalEpoch.AddHours(3);

    /// <summary>The address the transport delegate is handed; no socket is opened for it.</summary>
    private static string AuthorityAddress { get; } = "https://xml-evidence-record-authority.example.test/tsa";

    /// <summary>The canonicalization method every produced chain states.</summary>
    private static string CanonicalizationMethod { get; } = XmlSignatureWellKnown.CanonicalXml10Uri;

    /// <summary>A binary data object of the archive object under proof.</summary>
    private static ReadOnlyMemory<byte> FirstObject { get; } = new("the first archived object"u8.ToArray());

    /// <summary>A second binary data object of the same archive object.</summary>
    private static ReadOnlyMemory<byte> SecondObject { get; } = new("the second archived object"u8.ToArray());

    /// <summary>A data object of a second, unrelated archive object.</summary>
    private static ReadOnlyMemory<byte> ForeignObject { get; } = new("an object of a different archive object"u8.ToArray());

    /// <summary>An XML data object whose digest clause 4.1.2 takes over the canonical form, not the raw octets.</summary>
    private static ReadOnlyMemory<byte> XmlObject { get; } = new("<archive xmlns=\"urn:example:archive\"   note=\"kept\"><entry>one</entry></archive>"u8.ToArray());

    /// <summary>The same XML infoset as <see cref="XmlObject"/> serialised differently — canonicalization maps both to one binary representation.</summary>
    private static ReadOnlyMemory<byte> XmlObjectReserialized { get; } = new("<archive note=\"kept\" xmlns=\"urn:example:archive\"><entry>one</entry></archive>"u8.ToArray());


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An initial record over one two-object group round-trips from the produced octets alone: the staged
    /// parser accepts the document, the shipped Appendix A walk concludes Verified over the data objects, and
    /// the independent oracle's root recomputation is exactly the message imprint the genuine time-stamp binds.
    /// </summary>
    [TestMethod]
    public async Task AnInitialRecordOverOneGroupVerifiesFromItsOctetsAndTheOracleRecomputesItsRoot()
    {
        using AuthorityRing ring = AuthorityRing.Create();
        using XmlEvidenceRecordCreation creation = await CreateAsync(
            ring, [[Plain(FirstObject, "first"), Plain(SecondObject, "second")]]).ConfigureAwait(false);

        Assert.HasCount(1, creation.Documents, "One group states one Evidence Record document.");
        Assert.AreEqual(ArchiveInstant, creation.ArchiveTime, "The creation reports the instant the acquired token asserts.");

        byte[] document = creation.Documents[0].AsReadOnlySpan().ToArray();
        using XmlEvidenceRecordVerification verification = await VerifyAsync(
            document, [Plain(FirstObject, "first"), Plain(SecondObject, "second")]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, verification.Status,
            "The shipped Appendix A walk accepts the produced record over the archived objects.");

        //The independent oracle: recompute the root from the document's own hash tree and hold it against the
        //token's message imprint, both read out of the produced octets with no builder code involved.
        OracleXmlEvidenceRecord oracleRecord = XmlEvidenceRecordOracle.Parse(document);
        byte[] oracleRoot = XmlEvidenceRecordOracle.RootOf(oracleRecord.Chains[0].ArchiveTimeStamps[0].HashTree, PkiDigestAlgorithm.Sha256);
        using PkiCertificateMemory token = ToTokenCarrier(oracleRecord.Chains[0].ArchiveTimeStamps[0].TimeStampToken);
        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(info.IsRead, "The produced document carries a readable RFC 3161 token.");
        Assert.AreSequenceEqual(oracleRoot, info.MessageImprint!.AsReadOnlySpan().ToArray(),
            "The oracle's independently recomputed root is octet for octet what the genuine time-stamp binds (clause 3.2).");
    }


    /// <summary>
    /// Two archive object groups share one time-stamp over one tree — the centralized shape — and each group's
    /// document proves exactly its own objects: its own group verifies, the other group's objects are refused
    /// as not covered, and both documents carry the identical token.
    /// </summary>
    [TestMethod]
    public async Task TwoGroupsShareOneTimeStampAndEachDocumentProvesExactlyItsOwnGroup()
    {
        using AuthorityRing ring = AuthorityRing.Create();
        using XmlEvidenceRecordCreation creation = await CreateAsync(
            ring,
            [
                [Plain(FirstObject, "first"), Plain(SecondObject, "second")],
                [Plain(ForeignObject, "foreign")]
            ]).ConfigureAwait(false);

        Assert.HasCount(2, creation.Documents, "Two groups state two documents.");

        byte[] firstDocument = creation.Documents[0].AsReadOnlySpan().ToArray();
        byte[] secondDocument = creation.Documents[1].AsReadOnlySpan().ToArray();

        using XmlEvidenceRecordVerification firstVerification = await VerifyAsync(
            firstDocument, [Plain(FirstObject, "first"), Plain(SecondObject, "second")]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, firstVerification.Status, "The first group's document proves the first group.");

        using XmlEvidenceRecordVerification secondVerification = await VerifyAsync(
            secondDocument, [Plain(ForeignObject, "foreign")]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, secondVerification.Status, "The second group's document proves the second group.");

        using XmlEvidenceRecordVerification crossed = await VerifyAsync(
            firstDocument, [Plain(ForeignObject, "foreign")]).ConfigureAwait(false);
        Assert.AreNotEqual(XmlEvidenceRecordVerificationStatus.Verified, crossed.Status,
            "A group's document is no proof about another group's objects (Appendix A step 5.b).");

        OracleXmlEvidenceRecord firstRecord = XmlEvidenceRecordOracle.Parse(firstDocument);
        OracleXmlEvidenceRecord secondRecord = XmlEvidenceRecordOracle.Parse(secondDocument);
        Assert.AreSequenceEqual(
            firstRecord.Chains[0].ArchiveTimeStamps[0].TimeStampToken,
            secondRecord.Chains[0].ArchiveTimeStamps[0].TimeStampToken,
            "Both documents carry the one token acquired over the shared tree's root — RFC 4998 clause 3.2's centralized shape, which clause 3.2 of RFC 6283 keeps.");
    }


    /// <summary>
    /// Clause 4.1.2's canonicalization of XML archive data is load-bearing at creation: a record created over
    /// an XML data object verifies against a DIFFERENTLY SERIALISED document of the same canonical infoset —
    /// which can only hold when the builder digested the canonical form, not the raw octets.
    /// </summary>
    [TestMethod]
    public async Task AnXmlDataObjectIsDigestedOverItsCanonicalFormNotItsRawOctets()
    {
        using AuthorityRing ring = AuthorityRing.Create();
        using XmlEvidenceRecordCreation creation = await CreateAsync(
            ring, [[Xml(XmlObject, "record.xml")]]).ConfigureAwait(false);

        byte[] document = creation.Documents[0].AsReadOnlySpan().ToArray();
        using XmlEvidenceRecordVerification reserializedVerification = await VerifyAsync(
            document, [Xml(XmlObjectReserialized, "record.xml")]).ConfigureAwait(false);
        Assert.AreEqual(XmlEvidenceRecordVerificationStatus.Verified, reserializedVerification.Status,
            "Attribute order and insignificant whitespace differ, the canonical form does not — clause 4.1.2 holds on both sides.");

        using XmlEvidenceRecordVerification rawVerification = await VerifyAsync(
            document, [Plain(XmlObject, "record.xml")]).ConfigureAwait(false);
        Assert.AreNotEqual(XmlEvidenceRecordVerificationStatus.Verified, rawVerification.Status,
            "The same octets presented as non-XML data hash differently, so the record does not cover them — the digest really was over the canonical form.");
    }


    /// <summary>
    /// The creation surface refuses what it cannot make a record from, each with its own classified fault: no
    /// group at all, a group with no data object, XML archive data the canonicalization seam cannot process,
    /// and a write seam that produced no document.
    /// </summary>
    [TestMethod]
    public async Task CreationRefusesEmptyInputsUncanonicalizableDataAndAFailedWriteSeam()
    {
        using AuthorityRing ring = AuthorityRing.Create();

        EvidenceRecordCreationException noGroups = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(async () =>
        {
            using XmlEvidenceRecordCreation _ = await CreateAsync(ring, []).ConfigureAwait(false);
        }, "No group states nothing to prove.");
        Assert.AreEqual(EvidenceRecordCreationFailureKind.NoDataObject, noGroups.FailureKind, "The fault is classified as the missing data object.");

        EvidenceRecordCreationException emptyGroup = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(async () =>
        {
            using XmlEvidenceRecordCreation _ = await CreateAsync(ring, [[]]).ConfigureAwait(false);
        }, "A group holding no data object states nothing either.");
        Assert.AreEqual(EvidenceRecordCreationFailureKind.NoDataObject, emptyGroup.FailureKind, "The same classification covers the empty group.");

        EvidenceRecordCreationException notXml = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(async () =>
        {
            using XmlEvidenceRecordCreation _ = await CreateAsync(
                ring, [[Xml(FirstObject, "not-xml")]]).ConfigureAwait(false);
        }, "Octets that are not well-formed XML have no canonical form to digest.");
        Assert.AreEqual(EvidenceRecordCreationFailureKind.ArchiveDataNotCanonicalizable, notXml.FailureKind,
            "Clause 4.1.2's canonicalization failing is its own classified fault.");

        var refusingWriterResponder = new MintingTimestampResponder(ring.Authority, [ring.Authority, ring.Root], ArchiveInstant);
        var refusingWriterContext = new XmlEvidenceRecordCreationContext
        {
            DataObjectGroups = [[Plain(FirstObject, "first")]],
            DigestAlgorithm = PkiDigestAlgorithm.Sha256,
            CanonicalizationMethodUri = CanonicalizationMethod,
            Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync,
            WriteDocument = static (context, pool, cancellationToken) => ValueTask.FromResult(
                XmlEvidenceRecordWriteResult.Failed(XmlEvidenceRecordWriteStatus.Unwritable, "refused by the test seam")),
            TsaUri = AuthorityAddress,
            FetchTimestampResponse = refusingWriterResponder.FetchAsync
        };
        EvidenceRecordCreationException unwritable = await Assert.ThrowsExactlyAsync<EvidenceRecordCreationException>(
            async () => (await XmlEvidenceRecords.CreateInitialAsync(refusingWriterContext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).Dispose(),
            "A record that was never serialised protects nothing and is a creation fault, not a silent success.");
        Assert.AreEqual(EvidenceRecordCreationFailureKind.DocumentNotWritable, unwritable.FailureKind, "The write seam's refusal is its own classified fault.");
    }


    /// <summary>
    /// The review's exception-path regression: a build failing mid-level — after earlier pairs of the same
    /// level already combined — releases every carrier it rented. The failing pool counts rents against
    /// disposals, so a combined node stranded outside the lists the catch releases would show as an
    /// unreturned rental.
    /// </summary>
    [TestMethod]
    public async Task ABuildFailingMidLevelReleasesEveryCarrierItRented()
    {
        using DigestValue first = await DigestAsync(FirstObject).ConfigureAwait(false);
        using DigestValue second = await DigestAsync(SecondObject).ConfigureAwait(false);
        using DigestValue third = await DigestAsync(ForeignObject).ConfigureAwait(false);
        using DigestValue fourth = await DigestAsync(XmlObject).ConfigureAwait(false);

        //Four single-object groups make a level of two pairs: the first pair combines, and the pool refuses a
        //later rent of that same level, so the first combination is live in no caller-visible list when the
        //walk unwinds.
        for(int failAt = 6; failAt <= 10; ++failAt)
        {
            using var pool = new CountingFailingPool(failAt);
            try
            {
                using XmlEvidenceRecordHashTreeBuild _ = await XmlEvidenceRecordHashTrees.BuildAsync(
                    new XmlEvidenceRecordHashTreeBuildContext
                    {
                        DataObjectDigestGroups = [[first], [second], [third], [fourth]],
                        DigestAlgorithm = PkiDigestAlgorithm.Sha256
                    },
                    pool,
                    TestContext.CancellationToken).ConfigureAwait(false);
            }
            catch(InvalidOperationException)
            {
                //The injected refusal; what matters is the accounting below.
            }

            Assert.AreEqual(pool.RentCount, pool.DisposalCount,
                $"Every carrier rented before the refusal at rent {failAt} is released on the unwind; a difference is the stranded-combination leak.");
        }
    }


    /// <summary>Digests octets under SHA-256 through the registered seam, for leaf inputs the build copies.</summary>
    /// <param name="content">The octets to digest.</param>
    /// <returns>The digest. The caller disposes it.</returns>
    private async ValueTask<DigestValue> DigestAsync(ReadOnlyMemory<byte> content) =>
        await CryptographicKeyEvents.ComputeDigestAsync(
            content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// A pool that counts rents against disposals and refuses the Nth rent — the accounting oracle for the
    /// exception-path regression.
    /// </summary>
    private sealed class CountingFailingPool: MemoryPool<byte>
    {
        /// <summary>The rent ordinal to refuse.</summary>
        private readonly int failAtRent;


        /// <summary>Initialises the pool.</summary>
        /// <param name="failAtRent">The one-based rent ordinal to refuse.</param>
        internal CountingFailingPool(int failAtRent)
        {
            this.failAtRent = failAtRent;
        }


        /// <summary>Gets how many rentals were handed out.</summary>
        internal int RentCount { get; private set; }

        /// <summary>Gets how many handed-out rentals were disposed.</summary>
        internal int DisposalCount { get; private set; }

        /// <inheritdoc/>
        public override int MaxBufferSize => BaseMemoryPool.Shared.MaxBufferSize;


        /// <inheritdoc/>
        public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
        {
            if(RentCount + 1 == failAtRent)
            {
                throw new InvalidOperationException($"The pool refuses rent {failAtRent}, mid-walk by construction.");
            }

            ++RentCount;

            return new CountingOwner(BaseMemoryPool.Shared.Rent(minBufferSize), this);
        }


        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
        }


        /// <summary>One handed-out rental, reporting its disposal back to the pool's count.</summary>
        /// <param name="inner">The wrapped rental.</param>
        /// <param name="pool">The pool whose count the disposal raises.</param>
        private sealed class CountingOwner(IMemoryOwner<byte> inner, CountingFailingPool pool): IMemoryOwner<byte>
        {
            /// <summary>Whether disposal already ran, so a double-dispose does not double-count.</summary>
            private bool disposed;


            /// <inheritdoc/>
            public Memory<byte> Memory => inner.Memory;


            /// <inheritdoc/>
            public void Dispose()
            {
                if(!disposed)
                {
                    disposed = true;
                    ++pool.DisposalCount;
                    inner.Dispose();
                }
            }
        }
    }


    /// <summary>Creates records over <paramref name="groups"/> through the shipped surface and the staged writer, with a genuine minted time-stamp.</summary>
    /// <param name="ring">The authority ring minting the time-stamp.</param>
    /// <param name="groups">The archive object groups.</param>
    /// <returns>The creation. The caller disposes it.</returns>
    private async ValueTask<XmlEvidenceRecordCreation> CreateAsync(
        AuthorityRing ring, IReadOnlyList<IReadOnlyList<XmlEvidenceRecordDataObject>> groups)
    {
        var responder = new MintingTimestampResponder(ring.Authority, [ring.Authority, ring.Root], ArchiveInstant);

        return await XmlEvidenceRecords.CreateInitialAsync(
            new XmlEvidenceRecordCreationContext
            {
                DataObjectGroups = groups,
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                CanonicalizationMethodUri = CanonicalizationMethod,
                Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync,
                WriteDocument = XmlEvidenceRecordXmlBinding.WriteAsync,
                TsaUri = AuthorityAddress,
                FetchTimestampResponse = responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Parses a produced document through the staged binding and verifies it through the shipped Appendix A walk — from the octets alone.</summary>
    /// <param name="document">The produced document's octets.</param>
    /// <param name="objects">The data objects making up the archive object under proof.</param>
    /// <returns>The verification. The caller disposes it.</returns>
    private async ValueTask<XmlEvidenceRecordVerification> VerifyAsync(byte[] document, IReadOnlyList<XmlEvidenceRecordDataObject> objects)
    {
        using XmlEvidenceRecordParseResult parsed = await XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext { Document = document },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The staged parser accepts what the staged writer produced: {parsed.FailureReason}");

        return await XmlEvidenceRecords.VerifyAsync(
            new XmlEvidenceRecordVerificationContext
            {
                EvidenceRecord = parsed.EvidenceRecord!,
                Document = document,
                DataObjects = objects,
                Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Wraps octets as a non-XML data object, hashed exactly as they stand.</summary>
    /// <param name="content">The object's octets.</param>
    /// <param name="name">A reporting name.</param>
    /// <returns>The data object.</returns>
    private static XmlEvidenceRecordDataObject Plain(ReadOnlyMemory<byte> content, string name) =>
        new() { Content = content, Name = name };


    /// <summary>Wraps octets as XML archive data, digested over the canonical form per clause 4.1.2.</summary>
    /// <param name="content">The object's octets.</param>
    /// <param name="name">A reporting name.</param>
    /// <returns>The data object.</returns>
    private static XmlEvidenceRecordDataObject Xml(ReadOnlyMemory<byte> content, string name) =>
        new() { Content = content, IsXmlArchiveData = true, Name = name };


    /// <summary>Copies token DER into a pooled carrier tagged as a time-stamp token.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToTokenCarrier(byte[] token)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(token.Length);
        token.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>The Root CA and Time-Stamping Authority every test here mints its genuine token from.</summary>
    internal sealed class AuthorityRing: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Gets the Root CA the authority is issued by.</summary>
        internal required X509ChainTestRingNode Root { get; init; }

        /// <summary>Gets the Time-Stamping Authority the tokens are signed by.</summary>
        internal required X509ChainTestRingNode Authority { get; init; }


        /// <summary>Builds the ring.</summary>
        /// <returns>The ring. The caller disposes it.</returns>
        internal static AuthorityRing Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

            return new AuthorityRing { Root = root, Authority = authority };
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
