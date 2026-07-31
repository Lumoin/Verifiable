using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the XML Evidence Record Syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see> against Evidence Records produced by
/// other implementations, taken from optional reference material found by layout rather than by a named path.
/// </summary>
/// <remarks>
/// <para>
/// The reference material is not a repository asset: it lives under a gitignored working directory, so every
/// test here reports <c>Inconclusive</c> when it is absent. What it establishes when it is present is what no
/// self-made artifact can — that the readings this wave took of the specification are the readings other
/// producers took, on documents this library never wrote.
/// </para>
/// <para>
/// The corpus is located by content: the directory used is the one holding the most documents whose root element
/// is in the Evidence Record namespace, discovered by walking the cached reference material. Nothing here spells
/// a directory name from that material, and nothing depends on which implementation produced it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ReferenceArtifactXmlEvidenceRecordTests
{
    /// <summary>What a test says when the optional reference material is not present.</summary>
    private const string MissingCorpusMessage =
        "The optional XML Evidence Record reference material is not present under the cached reference directory; this test needs it.";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// At least one record of the corpus proves at least one data object of the corpus, end to end, through the
    /// shipped verification and the staged binding — the interoperability statement this leg exists for.
    /// </summary>
    [TestMethod]
    public async Task ARecordOfTheCorpusProvesADataObjectOfTheCorpus()
    {
        string? directory = TryFindCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCorpusMessage);

            return;
        }

        List<string> evidenceRecords = EvidenceRecordFiles(directory);
        List<string> dataObjects = DataObjectFiles(directory);
        Assert.IsNotEmpty(evidenceRecords, "The corpus holds Evidence Records.");
        Assert.IsNotEmpty(dataObjects, "The corpus holds data objects to prove.");

        var proved = new List<string>();
        foreach(string record in evidenceRecords)
        {
            byte[] document = await File.ReadAllBytesAsync(record, TestContext.CancellationToken).ConfigureAwait(false);
            foreach(string dataObject in dataObjects)
            {
                byte[] content = await File.ReadAllBytesAsync(dataObject, TestContext.CancellationToken).ConfigureAwait(false);
                bool isXml = dataObject.EndsWith(".xml", StringComparison.OrdinalIgnoreCase);
                if(await ProvesAsync(document, content, xmlArchiveData: false).ConfigureAwait(false)
                    || (isXml && await ProvesAsync(document, content, xmlArchiveData: true).ConfigureAwait(false)))
                {
                    proved.Add($"{Path.GetFileName(record)} proves {Path.GetFileName(dataObject)}");
                }
            }
        }

        Assert.IsNotEmpty(proved,
            $"No record of the corpus proved any of its data objects, which would mean this library's reading of Appendix A is not the corpus's. Records tried: {evidenceRecords.Count}, data objects tried: {dataObjects.Count}.");
        Assert.IsTrue(
            proved.Exists(static pair => pair.Contains(".p7m", StringComparison.OrdinalIgnoreCase)),
            $"The corpus's signature object is among the data objects its records prove. Pairs that verified: {string.Join(", ", proved)}");
        TestContext.WriteLine($"Records tried: {evidenceRecords.Count}, data objects tried: {dataObjects.Count}, pairs that verified: {string.Join("; ", proved)}");
    }


    /// <summary>
    /// The root rule of clause 3.1.1 read as a census over the whole corpus: for every initial Archive
    /// Time-Stamp carrying a hash tree, the root this wave's reading reaches is the value the token binds, and
    /// the reading that hashes a single-value first list instead reaches it for none of them.
    /// </summary>
    /// <remarks>
    /// The root of a hash tree does not depend on the data objects at all, so this check runs on every record of
    /// the corpus whether or not the objects it protects are present. It is the XML-syntax counterpart of the
    /// single-value census the ASN.1 side runs, and it settles the same question on a different producer's
    /// artifacts.
    /// </remarks>
    [TestMethod]
    public void TheRootRuleOfClause311HoldsAcrossTheCorpus()
    {
        string? directory = TryFindCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCorpusMessage);

            return;
        }

        var matchesThisWavesReading = new List<string>();
        var matchesTheHashedSingletonReading = new List<string>();
        var matchesNeither = new List<string>();
        foreach(string record in EvidenceRecordFiles(directory))
        {
            byte[] document = File.ReadAllBytes(record);
            OracleXmlEvidenceRecord parsed;
            try
            {
                parsed = XmlEvidenceRecordOracle.Parse(document);
            }
            catch(Exception exception) when(exception is System.Xml.XmlException or FormatException or InvalidOperationException or NullReferenceException)
            {
                //A document the corpus carries to be refused; the parse census below is where those are counted.
                continue;
            }

            if(parsed.Chains.Count == 0 || parsed.Chains[0].ArchiveTimeStamps.Count == 0)
            {
                continue;
            }

            OracleXmlChain chain = parsed.Chains[0];
            OracleXmlArchiveTimeStamp initial = chain.ArchiveTimeStamps[0];
            if(initial.HashTree.Count == 0
                || XmlSignatureWellKnown.DigestAlgorithmFromUri(chain.DigestMethodUri) is not PkiDigestAlgorithm algorithm
                || PkiDigestAlgorithm.FromOid(initial.MessageImprintAlgorithmOid) != algorithm)
            {
                continue;
            }

            string name = Path.GetFileName(record);
            byte[] thisWavesRoot = XmlEvidenceRecordOracle.RootOf(initial.HashTree, algorithm);
            if(thisWavesRoot.AsSpan().SequenceEqual(initial.MessageImprint))
            {
                matchesThisWavesReading.Add(name);
            }
            else if(HashedSingletonRoot(initial.HashTree, algorithm).AsSpan().SequenceEqual(initial.MessageImprint))
            {
                matchesTheHashedSingletonReading.Add(name);
            }
            else
            {
                matchesNeither.Add(name);
            }
        }

        Assert.IsNotEmpty(matchesThisWavesReading,
            "No record of the corpus reaches its own time-stamped value under this wave's reading of clause 3.1.1, which would mean the reading is wrong.");
        Assert.IsEmpty(matchesTheHashedSingletonReading,
            $"A record reaches its time-stamped value only by hashing a single-value first list, which clause 3.1.1 states outright must not happen: {string.Join(", ", matchesTheHashedSingletonReading)}");
        TestContext.WriteLine(
            $"Clause 3.1.1 census: {matchesThisWavesReading.Count} records reach their time-stamped value under this wave's reading, "
            + $"{matchesTheHashedSingletonReading.Count} under the hashed-singleton reading, {matchesNeither.Count} under neither "
            + $"({string.Join(", ", matchesNeither)}).");
    }


    /// <summary>
    /// Every record of the corpus is read to a decision by the staged binding: either it parses into the model,
    /// or it is refused with a status naming why. Nothing throws, and nothing is quietly accepted.
    /// </summary>
    [TestMethod]
    public async Task EveryRecordOfTheCorpusIsReadToADecision()
    {
        string? directory = TryFindCorpusDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCorpusMessage);

            return;
        }

        var parsed = new List<string>();
        var refused = new List<string>();
        foreach(string record in EvidenceRecordFiles(directory))
        {
            byte[] document = await File.ReadAllBytesAsync(record, TestContext.CancellationToken).ConfigureAwait(false);
            using XmlEvidenceRecordParseResult result = await XmlEvidenceRecordXmlBinding.ParseAsync(
                new XmlEvidenceRecordParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsValid)
            {
                parsed.Add(Path.GetFileName(record));
                Assert.IsNotEmpty(result.EvidenceRecord!.Chains, "A record that parsed carries at least one chain.");
                Assert.AreEqual("1.0", result.EvidenceRecord!.Version, "Clause 8's schema fixes the Version attribute to 1.0.");
            }
            else
            {
                refused.Add($"{Path.GetFileName(record)}: {result.Status}");
                Assert.IsNotNull(result.FailureReason, "Every refusal names a reason.");
            }
        }

        Assert.IsNotEmpty(parsed, "The corpus holds records this binding reads.");
        TestContext.WriteLine($"Parse census: {parsed.Count} records read, {refused.Count} refused ({string.Join("; ", refused)}).");
    }


    /// <summary>
    /// Determines whether a record proves one data object, through the shipped verification and the staged
    /// binding.
    /// </summary>
    /// <param name="document">The Evidence Record document's octets.</param>
    /// <param name="dataObject">The data object's octets.</param>
    /// <param name="xmlArchiveData">Whether clause 4.1.2's canonicalization applies to the data object.</param>
    /// <returns><see langword="true"/> when the record verifies over that object alone.</returns>
    private async Task<bool> ProvesAsync(byte[] document, byte[] dataObject, bool xmlArchiveData)
    {
        using XmlEvidenceRecordParseResult parsed = await XmlEvidenceRecordXmlBinding.ParseAsync(
            new XmlEvidenceRecordParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        if(!parsed.IsValid)
        {
            return false;
        }

        using XmlEvidenceRecordVerification verification = await XmlEvidenceRecords.VerifyAsync(
            new XmlEvidenceRecordVerificationContext
            {
                EvidenceRecord = parsed.EvidenceRecord!,
                Document = document,
                DataObjects = [new XmlEvidenceRecordDataObject { Content = dataObject, IsXmlArchiveData = xmlArchiveData }],
                Canonicalize = XmlEvidenceRecordXmlBinding.CanonicalizeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return verification.Status == XmlEvidenceRecordVerificationStatus.Verified;
    }


    /// <summary>
    /// Recomputes a root under the reading clause 3.1.1's exception exists to rule out: a single-value first
    /// list hashed rather than carried forward.
    /// </summary>
    /// <param name="hashTree">The sequences in ascending <c>Order</c>.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <returns>The root that reading reaches.</returns>
    private static byte[] HashedSingletonRoot(List<OracleXmlSequence> hashTree, PkiDigestAlgorithm algorithm)
    {
        byte[]? carried = null;
        for(int i = 0; i < hashTree.Count; ++i)
        {
            var level = new List<byte[]>(hashTree[i].DigestValues);
            if(carried is not null)
            {
                level.Add(carried);
            }

            carried = XmlEvidenceRecordOracle.Combine(level, algorithm);
        }

        return carried!;
    }


    /// <summary>
    /// Lists the Evidence Record documents of a corpus directory: the top-level XML files whose root element is
    /// in the Evidence Record namespace.
    /// </summary>
    /// <param name="directory">The corpus directory.</param>
    /// <returns>The documents' paths, in ordinal order.</returns>
    private static List<string> EvidenceRecordFiles(string directory) =>
        [.. Directory.EnumerateFiles(directory, "*.xml", SearchOption.TopDirectoryOnly)
            .Where(IsEvidenceRecordDocument)
            .OrderBy(static file => file, StringComparer.Ordinal)];


    /// <summary>
    /// Lists the data objects of a corpus directory: every top-level file that is not an Evidence Record.
    /// </summary>
    /// <param name="directory">The corpus directory.</param>
    /// <returns>The data objects' paths, in ordinal order.</returns>
    private static List<string> DataObjectFiles(string directory) =>
        [.. Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
            .Where(static file => !IsEvidenceRecordDocument(file))
            .OrderBy(static file => file, StringComparer.Ordinal)];


    /// <summary>
    /// Determines whether a file is an Evidence Record document, by the namespace its text declares rather than
    /// by its name.
    /// </summary>
    /// <param name="file">The file's path.</param>
    /// <returns><see langword="true"/> when the file names the Evidence Record namespace.</returns>
    private static bool IsEvidenceRecordDocument(string file)
    {
        if(!file.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var buffer = new byte[512];
        using FileStream stream = File.OpenRead(file);
        int read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);

        return Encoding.UTF8.GetString(buffer, 0, read).Contains(XmlEvidenceRecordWellKnown.EvidenceRecordNamespace, StringComparison.Ordinal);
    }


    /// <summary>
    /// Finds the corpus directory by content: the directory under the cached reference material holding the most
    /// Evidence Record documents, with at least one data object beside them.
    /// </summary>
    /// <returns>The directory, or <see langword="null"/> when the reference material is absent.</returns>
    private static string? TryFindCorpusDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");
        if(!Directory.Exists(referenceMaterial))
        {
            return null;
        }

        string? best = null;
        int bestCount = 0;
        foreach(string directory in Directory.EnumerateDirectories(referenceMaterial, "*", SearchOption.AllDirectories))
        {
            int count = EvidenceRecordFiles(directory).Count;
            if(count > bestCount && DataObjectFiles(directory).Count > 0)
            {
                best = directory;
                bestCount = count;
            }
        }

        return best;
    }
}
