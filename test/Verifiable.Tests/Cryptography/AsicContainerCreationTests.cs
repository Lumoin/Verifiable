using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicContainerCreation"/>: the four container profiles this library builds —
/// ASiC-S with CAdES (Part 1 clauses 4.3.3 and 5.3.2.2), ASiC-S with a time assertion
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916202/01.01.01_60/en_31916202v010101p.pdf">
/// ETSI EN 319 162-2 V1.1.1</see> clause 4.2.1), ASiC-E with CAdES (clause 4.3.1) and ASiC-E with a time
/// assertion or an Evidence Record (clause 4.3.2) — against
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Nothing here checks a container by asking the library what it wrote.</strong> Every container is
/// taken apart by <see cref="AsicZipStructureOracle"/> — a raw-octet ZIP reader that walks the end record, the
/// central directory and every local file header itself and shares no code with
/// <see cref="AsicZipAuthoring"/>. Every CAdES object is verified detached by the BouncyCastle CMS reader over
/// the entry octets the oracle extracted, every time-stamp token by the BouncyCastle TSP validator, every
/// Evidence Record by <see cref="EvidenceRecordOracle"/>'s independent Merkle recomputation, and every manifest
/// digest by an independent recomputation through the BouncyCastle digest backend.
/// </para>
/// <para>
/// The signing key under test is minted through <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's
/// test-key convention); the self-signed certificate that carries its public point is minted through a platform
/// <see cref="ECDsa"/> reconstructed from the same key material. Time-stamp tokens come from a
/// <see cref="MintingTimestampResponder"/>, which mints a genuine token over whatever imprint the request
/// octets state, so the acquisition path runs end to end without a network.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicContainerCreationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.asic.example.test/";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every signed container states.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The instant every container entry records.</summary>
    private static DateTimeOffset ContainerInstant { get; } = TestClock.CanonicalEpoch;

    /// <summary>The <c>genTime</c> every minted token states.</summary>
    private static DateTimeOffset TimeAssertionInstant { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The first data object every multi-object container carries.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first archived data object"u8];

    /// <summary>The second data object every multi-object container carries.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second archived data object"u8];


    /// <summary>
    /// An ASiC-S container carrying a CAdES object is the archive Annex A.1 describes: it begins with a local
    /// file header, its first entry is <c>mimetype</c>, that entry is stored with no extra field, and the media
    /// type is therefore readable at offset 38 — all of it read out of the raw octets by the independent oracle.
    /// </summary>
    [TestMethod]
    public async Task SimpleCAdESContainerIsTheArchiveAnnexA1Describes()
    {
        using AsicContainerCreationResult container = await CreateSimpleCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        Assert.AreSequenceEqual(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, octets.AsSpan(0, 4).ToArray(), "Annex A.1 item 4 fixes the first four octets.");

        OracleZipArchive archive = AsicZipStructureOracle.Parse(octets);
        OracleZipEntry mimetype = archive.LocalHeaders[0];

        Assert.AreEqual(AsicWellKnown.MimetypeEntryName, mimetype.Name, "Annex A.1 item 1: 'mimetype' shall be the first file in the ASiC container.");
        Assert.AreEqual(0, mimetype.Method, "Annex A.1 item 3: the mimetype entry shall not be compressed.");
        Assert.AreEqual(0, mimetype.ExtraFieldByteLength, "Annex A.1 item 2: the mimetype entry shall carry no extra field.");
        Assert.AreEqual(AsicWellKnown.AsicSimpleMediaType, AsicZipStructureOracle.MediaTypeAtOffset38(octets),
            "The Annex A.1 NOTE's recognition feature must find the media type at offset 38.");

        Assert.AreSequenceEqual(
            new[] { AsicWellKnown.MimetypeEntryName, "data.txt", AsicManifestNaming.SimpleSignatureEntryName },
            archive.LocalHeaders.Select(entry => entry.Name).ToArray(),
            "Clause 5.3.2.2 Table 3 note b closes the set: the mimetype entry, the data file and META-INF/signature.p7s.");
    }


    /// <summary>
    /// The ASiC-S CAdES object is a DETACHED signature over the data file, which is what clause 4.3.3.2 item 4 b
    /// requires — established by handing the independent CMS reader the signature entry and the data entry the
    /// oracle pulled out of the container, and nothing else.
    /// </summary>
    [TestMethod]
    public async Task SimpleCAdESSignatureIsDetachedOverTheDataFile()
    {
        using AsicContainerCreationResult container = await CreateSimpleCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        byte[] signature = ReadEntry(octets, AsicManifestNaming.SimpleSignatureEntryName);
        byte[] dataFile = ReadEntry(octets, "data.txt");

        Assert.AreSequenceEqual(FirstDataObject, dataFile, "The data file's octets appear in the container unchanged.");
        Assert.IsTrue(VerifiesDetached(signature, dataFile), "The independent CMS reader must verify the signature detached over the data file.");
        Assert.IsFalse(VerifiesDetached(signature, SecondDataObject), "The same signature must not verify over different octets.");

        Assert.AreEqual(AsicContainerProfile.SimpleBaselineCAdES, container.Profile);
        Assert.AreEqual(AsicWellKnown.AsicSimpleExtension, container.FileExtension, "Clause 4.3.3.1 item 2 a names '.asics'.");
        Assert.IsNull(container.ManifestEntryName, "An ASiC-S container carries no manifest.");
    }


    /// <summary>
    /// An ASiC-E container carrying a CAdES object is the shape clause 4.4.4.2 describes: the data files outside
    /// <c>META-INF</c>, one <c>ASiCManifest</c> file, and one <c>*signature*.p7s</c> file the manifest's
    /// <c>SigReference</c> names.
    /// </summary>
    [TestMethod]
    public async Task ExtendedCAdESContainerIsTheShapeClause4442Describes()
    {
        using AsicContainerCreationResult container = await CreateExtendedCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        OracleZipArchive archive = AsicZipStructureOracle.Parse(octets);

        Assert.AreSequenceEqual(
            new[] { AsicWellKnown.MimetypeEntryName, "first.txt", "folder/second.bin", "META-INF/ASiCManifest1.xml", "META-INF/signature1.p7s" },
            archive.LocalHeaders.Select(entry => entry.Name).ToArray());

        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicZipStructureOracle.MediaTypeAtOffset38(octets),
            "Clause 4.4.4.1 item 2 fixes the ASiC-E CAdES media type with no alternative branch.");
        Assert.AreEqual(AsicContainerProfile.ExtendedCAdES, container.Profile);
        Assert.AreEqual(AsicWellKnown.AsicExtendedExtension, container.FileExtension, "Clause 4.4.4.1 item 1 a names '.asice'.");
        Assert.AreEqual(AsicManifestRole.Signature, AsicManifestNaming.RoleFromEntryName(container.ManifestEntryName),
            "The manifest is stored under a name clause 4.4.4.2 item 2 dispatches as an ASiCManifest file.");
        Assert.IsTrue(AsicManifestNaming.IsSignatureEntryName(container.SignatureEntryName),
            "The CAdES object is stored under a name clause 4.4.4.2 item 3 a dispatches as a signature file.");
    }


    /// <summary>
    /// The ASiC-E CAdES object is detached over the manifest's octets AS THEY ARE STORED — the conformance claim
    /// of Annex A.4.1 ("the signature(s) or the time-stamp token shall apply to the file containing the
    /// <c>ASiCManifest</c> element") and of Part 2 clause 4.3.1. The octets handed to the independent reader are
    /// the ones the raw-ZIP oracle extracted from the finished container, so nothing the library holds in memory
    /// takes part in the check.
    /// </summary>
    [TestMethod]
    public async Task ExtendedCAdESSignatureIsDetachedOverTheManifestOctetsAsStored()
    {
        using AsicContainerCreationResult container = await CreateExtendedCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);
        byte[] signature = ReadEntry(octets, container.SignatureEntryName!);

        Assert.IsTrue(VerifiesDetached(signature, manifest), "The CAdES object must verify detached over the stored manifest octets.");
        Assert.IsFalse(VerifiesDetached(signature, ReadEntry(octets, "first.txt")),
            "It must not verify over a data file: an ASiC-E signature covers the manifest, and the manifest covers the data.");
    }


    /// <summary>
    /// Every <c>ds:DigestValue</c> the produced manifest states is the digest of the entry beside it, recomputed
    /// independently from the container's own octets — the comparison clause 4.4.4.2 item d makes an
    /// unconditional error to fail.
    /// </summary>
    [TestMethod]
    public async Task EveryManifestDigestIsTheDigestOfTheEntryItNames()
    {
        using AsicContainerCreationResult container = await CreateExtendedCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace asic = AsicManifestXmlBinding.AsicNamespace;
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;

        List<XElement> references = [.. document.Root!.Elements(asic + "DataObjectReference")];
        Assert.HasCount(2, references, "Annex A.4.2: there shall be one DataObjectReference element for each referenced file object.");

        foreach(XElement reference in references)
        {
            AsicContainerUriResolution resolved = AsicContainerUri.Resolve(reference.Attribute("URI")!.Value);
            Assert.AreEqual(AsicContainerUriStatus.Resolved, resolved.Status, "Annex A.6 item 2 resolves a manifest reference against the container root.");

            string algorithmUri = reference.Element(ds + XmlSignatureWellKnown.DigestMethodElementName)!.Attribute(XmlSignatureWellKnown.AlgorithmAttributeName)!.Value;
            PkiDigestAlgorithm algorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(algorithmUri)
                ?? throw new InvalidOperationException($"'{algorithmUri}' does not name a digest algorithm this library computes.");

            byte[] stated = Convert.FromBase64String(reference.Element(ds + XmlSignatureWellKnown.DigestValueElementName)!.Value);
            byte[] recomputed = EvidenceRecordOracle.Hash(ReadEntry(octets, resolved.EntryName!), algorithm);

            Assert.AreSequenceEqual(recomputed, stated, $"The digest stated for '{resolved.EntryName}' must be the digest of that entry.");
        }

        Assert.AreEqual(
            AsicContainerUri.ToReference(container.SignatureEntryName!),
            document.Root.Element(asic + "SigReference")!.Attribute("URI")!.Value,
            "Annex A.4.1: the SigReference names the file the manifest is protected by.");
    }


    /// <summary>
    /// The manifest the container layer builds validates against the authentic schema the Annex A.3 attachment
    /// carries — so the references, media types and root-file markers this layer writes are checked against the
    /// specification's own grammar rather than against this library's reading of it.
    /// </summary>
    [TestMethod]
    public async Task TheProducedManifestValidatesAgainstTheAuthenticSchema()
    {
        string? schemaPath = await AsicManifestSchemaOracle.TryFindAuthenticSchemaAsync().ConfigureAwait(false);
        if(schemaPath is null)
        {
            Assert.Inconclusive(AsicManifestSchemaOracle.MissingSchemaMessage);

            return;
        }

        using AsicContainerCreationResult container = await CreateExtendedCAdESAsync().ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);

        List<string> problems = AsicManifestSchemaOracle.Validate(manifest, schemaPath);

        Assert.IsEmpty(problems, string.Join(Environment.NewLine, problems));
    }


    /// <summary>
    /// The three-phase split reaches the container layer intact: phase one states the octets a signer signs and
    /// the manifest they cover, a signer that never saw the container produces the signature value, and phase
    /// three assembles a container whose CAdES object verifies detached over the manifest phase one wrote.
    /// </summary>
    [TestMethod]
    public async Task TheThreePhaseSplitProducesAContainerARemoteSignerNeverSaw()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
                BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()),
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(preparation.ManifestDocument, "An ASiC-E preparation states the manifest the signature will cover.");
            Assert.IsGreaterThan(0, preparation.SignaturePreparation.SigningInput.Length, "Phase one states the octets a signer signs.");

            byte[] manifestFromPhaseOne = preparation.ManifestDocument!.AsReadOnlySpan().ToArray();

            //Phase two, as a signing service that holds the key and sees nothing else would run it: the octets
            //phase one produced go in, a signature value comes back.
            CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = privateKey.Tag.Get<Purpose>();
            SigningDelegate signing = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);
            (Signature signatureValue, _) = await signing(
                privateKey.AsReadOnlyMemory(), preparation.SignaturePreparation.SigningInput.AsReadOnlyMemory(), BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            using(signatureValue)
            {
                using IMemoryOwner<byte> der = EcdsaSignatureEncoding.ConvertP1363ToDer(signatureValue.AsReadOnlySpan(), BaseMemoryPool.Shared, out int derLength);
                using AsicContainerCreationResult container = AsicContainerCreation.CompleteSignature(
                    preparation, certificate, algorithm, der.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);

                byte[] octets = container.Container.AsReadOnlySpan().ToArray();
                byte[] storedManifest = ReadEntry(octets, container.ManifestEntryName!);

                Assert.AreSequenceEqual(manifestFromPhaseOne, storedManifest, "The container stores the very octets phase one committed the signer to.");
                Assert.IsTrue(VerifiesDetached(ReadEntry(octets, container.SignatureEntryName!), storedManifest),
                    "The completed signature must verify detached over those octets.");
            }
        }
    }


    /// <summary>
    /// An ASiC-S time assertion container carries <c>META-INF/timestamp.tst</c> and nothing else in
    /// <c>META-INF</c> (clause 4.3.3.2 item 4 a), and that token binds the data file: the independent TSP
    /// validator accepts it and its message imprint is the digest of the entry the oracle extracted.
    /// </summary>
    [TestMethod]
    public async Task SimpleTimeAssertionContainerCarriesATokenOverTheDataFile()
    {
        using AsicContainerCreationResult container = await CreateTimeAssertionAsync(AsicContainerShape.Simple).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        OracleZipArchive archive = AsicZipStructureOracle.Parse(octets);

        Assert.AreSequenceEqual(
            new[] { AsicWellKnown.MimetypeEntryName, "data.txt", AsicManifestNaming.SimpleTimestampEntryName },
            archive.LocalHeaders.Select(entry => entry.Name).ToArray());

        Assert.AreEqual(AsicContainerProfile.SimpleTimeAssertion, container.Profile);
        Assert.AreEqual(TimeAssertionInstant, container.TimestampTime);
        Assert.IsNull(container.EvidenceRecordArchiveTime, "No Evidence Record is in this container.");

        byte[] token = ReadEntry(octets, AsicManifestNaming.SimpleTimestampEntryName);
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(token), "The independent TSP validator must accept the token.");
        Assert.AreSequenceEqual(
            EvidenceRecordOracle.Hash(ReadEntry(octets, "data.txt"), PkiDigestAlgorithm.Sha256),
            ImprintOf(token),
            "Clause 4.3.3.2 item 4 a: the token applies to the data file.");
    }


    /// <summary>
    /// An ASiC-E time assertion container's token binds the manifest file rather than the data files (clause
    /// 4.4.4.2 item 3 b with Annex A.4.1), and the manifest's <c>SigReference</c> names that token.
    /// </summary>
    [TestMethod]
    public async Task ExtendedTimeAssertionContainerCarriesATokenOverTheManifest()
    {
        using AsicContainerCreationResult container = await CreateTimeAssertionAsync(AsicContainerShape.Extended).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(AsicContainerProfile.ExtendedTimeAssertion, container.Profile);
        Assert.IsTrue(AsicManifestNaming.IsTimestampEntryName(container.TimestampEntryName));
        Assert.AreEqual(AsicManifestRole.Signature, AsicManifestNaming.RoleFromEntryName(container.ManifestEntryName));

        byte[] token = ReadEntry(octets, container.TimestampEntryName!);
        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);

        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(token), "The independent TSP validator must accept the token.");
        Assert.AreSequenceEqual(EvidenceRecordOracle.Hash(manifest, PkiDigestAlgorithm.Sha256), ImprintOf(token),
            "Annex A.4.1: the token applies to the file containing the ASiCManifest element.");

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        Assert.AreEqual(
            AsicContainerUri.ToReference(container.TimestampEntryName!),
            document.Root!.Element(AsicManifestXmlBinding.AsicNamespace + "SigReference")!.Attribute("URI")!.Value);
    }


    /// <summary>
    /// An ASiC-S Evidence Record container carries <c>META-INF/evidencerecord.ers</c> (clause 4.3.3.2 item 4 d),
    /// and that record proves the data file: the independent Merkle recomputation walks the record's own reduced
    /// hash tree from the data file's hash to the root its embedded token binds, and the shipped verification
    /// agrees.
    /// </summary>
    [TestMethod]
    public async Task SimpleEvidenceRecordContainerCarriesARecordProvingTheDataFile()
    {
        using AsicContainerCreationResult container = await CreateEvidenceRecordAsync(AsicContainerShape.Simple).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        OracleZipArchive archive = AsicZipStructureOracle.Parse(octets);

        Assert.AreSequenceEqual(
            new[] { AsicWellKnown.MimetypeEntryName, "data.txt", AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName },
            archive.LocalHeaders.Select(entry => entry.Name).ToArray());

        Assert.AreEqual(AsicContainerProfile.SimpleTimeAssertion, container.Profile,
            "Part 2 clause 4.2.1 a admits the Evidence Record branch of Part 1 clause 4.3.3.2 item 4, so the profile is the time assertion one.");
        Assert.AreEqual(TimeAssertionInstant, container.EvidenceRecordArchiveTime);
        Assert.IsNull(container.TimestampTime, "The container carries no bare time-stamp token entry.");

        byte[] record = ReadEntry(octets, AsicManifestNaming.SimpleBinaryEvidenceRecordEntryName);
        byte[] dataFile = ReadEntry(octets, "data.txt");

        AssertRecordProves(record, dataFile);
        await AssertShippedVerificationAcceptsAsync(record, dataFile).ConfigureAwait(false);
    }


    /// <summary>
    /// An ASiC-E Evidence Record container carries the record beside an <c>ASiCEvidenceRecordManifest</c> file,
    /// the record proves every data object that manifest names, and — the clause 4.4.4.2 NOTE 2 statement — it
    /// does NOT prove the manifest file itself.
    /// </summary>
    [TestMethod]
    public async Task ExtendedEvidenceRecordProvesTheManifestsTargetsAndNotTheManifest()
    {
        using AsicContainerCreationResult container = await CreateEvidenceRecordAsync(AsicContainerShape.Extended).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(AsicContainerProfile.ExtendedTimeAssertion, container.Profile);
        Assert.AreEqual(AsicManifestRole.EvidenceRecord, AsicManifestNaming.RoleFromEntryName(container.ManifestEntryName),
            "Clause 4.4.3.2 item 4 dispatches the manifest by its ASiCEvidenceRecordManifest name.");
        Assert.IsTrue(AsicManifestNaming.IsBinaryEvidenceRecordEntryName(container.EvidenceRecordEntryName),
            "Clause 4.4.4.2 item 4 a names the RFC 4998 form '*evidencerecord*.ers'.");

        byte[] record = ReadEntry(octets, container.EvidenceRecordEntryName!);
        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);

        AssertRecordProves(record, ReadEntry(octets, "first.txt"));
        AssertRecordProves(record, ReadEntry(octets, "folder/second.bin"));
        await AssertShippedVerificationAcceptsAsync(record, ReadEntry(octets, "first.txt")).ConfigureAwait(false);
        await AssertShippedVerificationAcceptsAsync(record, ReadEntry(octets, "folder/second.bin")).ConfigureAwait(false);

        Assert.IsNull(
            EvidenceRecordOracle.RecomputeRoot(
                EvidenceRecordOracle.Hash(manifest, PkiDigestAlgorithm.Sha256),
                EvidenceRecordOracle.ParseEvidenceRecord(record).Chains[0][0].ReducedHashtree,
                PkiDigestAlgorithm.Sha256),
            "Clause 4.4.4.2 NOTE 2: the ASiCManifest file itself is not covered by the Evidence Record it names.");

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        Assert.AreEqual(
            AsicContainerUri.ToReference(container.EvidenceRecordEntryName!),
            document.Root!.Element(AsicManifestXmlBinding.AsicNamespace + "SigReference")!.Attribute("URI")!.Value);
    }


    /// <summary>
    /// Clause 4.4.3.2 item 4 binds the two algorithms together: the manifest's <c>ds:DigestMethod</c> "shall
    /// match the digest algorithm used to create the initial Archive Time-stamp protecting the first
    /// <c>ReducedHashTree</c>". One property states both, so the produced container cannot state two.
    /// </summary>
    [TestMethod]
    [DataRow("SHA-384", DisplayName = "SHA-384")]
    [DataRow("SHA-512", DisplayName = "SHA-512")]
    public async Task TheEvidenceRecordManifestStatesTheAlgorithmTheRecordWasBuiltUnder(string algorithmName)
    {
        PkiDigestAlgorithm algorithm = string.Equals(algorithmName, "SHA-384", StringComparison.Ordinal)
            ? PkiDigestAlgorithm.Sha384
            : PkiDigestAlgorithm.Sha512;

        using AsicContainerCreationResult container = await CreateEvidenceRecordAsync(AsicContainerShape.Extended, algorithm).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();
        byte[] record = ReadEntry(octets, container.EvidenceRecordEntryName!);
        byte[] manifest = ReadEntry(octets, container.ManifestEntryName!);

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(record);
        Assert.AreEqual(algorithm.Identifier.Oid, parsed.Chains[0][0].MessageImprintAlgorithmOid);

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(manifest));
        XNamespace ds = XmlSignatureWellKnown.XmlSignatureNamespace;
        foreach(XElement reference in document.Root!.Elements(AsicManifestXmlBinding.AsicNamespace + "DataObjectReference"))
        {
            string stated = reference.Element(ds + XmlSignatureWellKnown.DigestMethodElementName)!.Attribute(XmlSignatureWellKnown.AlgorithmAttributeName)!.Value;
            Assert.AreEqual(XmlSignatureWellKnown.DigestUriFromAlgorithm(algorithm), stated);
        }

        AssertRecordProves(record, ReadEntry(octets, "first.txt"));
    }


    /// <summary>
    /// Clause 4.3.3.1 item 1 gives an ASiC-S container two branches for its <c>mimetype</c> content: the media
    /// type of the signed file object when it has one, and the fixed ASiC-S media type when it has none. Both
    /// are read back out of the container at offset 38 by the independent oracle.
    /// </summary>
    [TestMethod]
    [DataRow(null, "application/vnd.etsi.asic-s+zip", DisplayName = "no media type for the signed object (item 1 a)")]
    [DataRow("application/pdf", "application/pdf", DisplayName = "the signed object's own media type (item 1 b)")]
    public async Task SimpleContainerStatesTheMediaTypeClause4331Item1Selects(string? dataObjectMediaType, string expected)
    {
        using AsicContainerCreationResult container = await CreateSimpleCAdESAsync(dataObjectMediaType).ConfigureAwait(false);
        byte[] octets = container.Container.AsReadOnlySpan().ToArray();

        Assert.AreEqual(expected, container.MediaType);
        Assert.AreEqual(expected, AsicZipStructureOracle.MediaTypeAtOffset38(octets));
    }


    /// <summary>
    /// The ZIP archive comment clauses 4.3.3.1 item 3 and 4.4.4.1 item 3 admit is written only when the caller
    /// asks for it — the conformant reading of a permission — and carries the container's own media type.
    /// </summary>
    [TestMethod]
    public async Task TheMediaTypeArchiveCommentIsWrittenOnlyWhenAskedFor()
    {
        using AsicContainerCreationResult without = await CreateSimpleCAdESAsync().ConfigureAwait(false);
        Assert.IsNull(AsicZipStructureOracle.Parse(without.Container.AsReadOnlySpan().ToArray()).Comment);

        using AsicContainerCreationResult with = await CreateSimpleCAdESAsync(stateComment: true).ConfigureAwait(false);
        string? comment = AsicZipStructureOracle.Parse(with.Container.AsReadOnlySpan().ToArray()).Comment;

        Assert.AreEqual(AsicWellKnown.MediaTypeComment(AsicWellKnown.AsicSimpleMediaType), comment);
        Assert.AreEqual(AsicWellKnown.AsicSimpleMediaType, AsicWellKnown.MediaTypeFromComment(comment));
    }


    /// <summary>A container with no data object is refused: clause 4.3.3.2 item 2 and clause 4.4.2 item 2 both require at least one data file.</summary>
    [TestMethod]
    public async Task AContainerWithNoDataObjectIsRefused() =>
        await AssertRefusedAsync(AsicContainerCreationFailureKind.NoDataObject, AsicContainerShape.Extended, []).ConfigureAwait(false);


    /// <summary>An ASiC-S container with two data objects is refused: clause 4.3.3.2 item 2 admits exactly one.</summary>
    [TestMethod]
    public async Task ASimpleContainerWithTwoDataObjectsIsRefused() =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.SimpleContainerNotSingleDataObject,
            AsicContainerShape.Simple,
            [DataObject("first.txt", FirstDataObject), DataObject("second.txt", SecondDataObject)]).ConfigureAwait(false);


    /// <summary>A data object inside <c>META-INF</c> is refused: clause 4.4.2 item 2 places every data file outside that folder.</summary>
    [TestMethod]
    public async Task ADataObjectInsideMetaInfIsRefused() =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.DataObjectInMetaInf,
            AsicContainerShape.Extended,
            [DataObject("META-INF/signature1.p7s", FirstDataObject)]).ConfigureAwait(false);


    /// <summary>Two data objects under one name are refused: a container names each file object once.</summary>
    [TestMethod]
    public async Task TwoDataObjectsUnderOneNameAreRefused() =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.DuplicateDataObjectName,
            AsicContainerShape.Extended,
            [DataObject("same.txt", FirstDataObject), DataObject("same.txt", SecondDataObject)]).ConfigureAwait(false);


    /// <summary>An ASiC-S data object in a folder is refused: clause 4.3.3.2 item 2 puts the one data file at the container root level.</summary>
    [TestMethod]
    public async Task ASimpleDataObjectBelowTheContainerRootIsRefused() =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.DataObjectNotAtContainerRoot,
            AsicContainerShape.Simple,
            [DataObject("folder/data.txt", FirstDataObject)]).ConfigureAwait(false);


    /// <summary>A data object named <c>mimetype</c> is refused: Annex A.1 reserves that root-level name.</summary>
    [TestMethod]
    public async Task ADataObjectNamedMimetypeIsRefused() =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.DataObjectNotAtContainerRoot,
            AsicContainerShape.Simple,
            [DataObject(AsicWellKnown.MimetypeEntryName, FirstDataObject)]).ConfigureAwait(false);


    /// <summary>A data object name a container may not carry is refused before any octet is written.</summary>
    [TestMethod]
    [DataRow("../outside.txt", DisplayName = "a traversal name")]
    [DataRow("/absolute.txt", DisplayName = "an absolute name")]
    [DataRow("folder\\file.txt", DisplayName = "a backslash-separated name")]
    public async Task ADataObjectNameAContainerMayNotCarryIsRefused(string name) =>
        await AssertRefusedAsync(
            AsicContainerCreationFailureKind.DataObjectNameRejected,
            AsicContainerShape.Extended,
            [DataObject(name, FirstDataObject)]).ConfigureAwait(false);


    /// <summary>
    /// An ASiC-E container asked for without a manifest serialisation seam is refused with the typed failure the
    /// fail-closed rule requires: this library ships no XML implementation, and clause 4.4.4.2 item 2 makes the
    /// manifest file mandatory for the shape.
    /// </summary>
    [TestMethod]
    public async Task AnExtendedContainerWithoutAManifestSeamIsRefused()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerSignatureContext context = BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()) with
            {
                EncodeManifest = null
            };

            AsicContainerCreationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerCreationException>(async () =>
            {
                using AsicContainerCreationResult _ = await AsicContainerCreation.SignAsync(
                    context, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerCreationFailureKind.ManifestEncoderMissing, refusal.FailureKind);
        }
    }


    /// <summary>
    /// A manifest seam that answers with a failure status rather than a document stops the creation with the
    /// status it stated; nothing is written from a manifest that was never produced.
    /// </summary>
    [TestMethod]
    public async Task AManifestSeamThatProducesNoDocumentStopsTheCreation()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerSignatureContext context = BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()) with
            {
                EncodeManifest = RefusingEncoder
            };

            AsicContainerCreationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerCreationException>(async () =>
            {
                using AsicContainerCreationResult _ = await AsicContainerCreation.SignAsync(
                    context, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerCreationFailureKind.ManifestEncodingFailed, refusal.FailureKind);
            Assert.Contains(nameof(AsicManifestEncodeStatus.ExtensionMalformed), refusal.Message, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// A digest algorithm clause 5.2.1 refuses outright, or one this library will not create under, stops the
    /// creation before any octet is written — the creation-side algorithm gate.
    /// </summary>
    [TestMethod]
    [DataRow("1.2.840.113549.2.5", 16, DisplayName = "MD5, which clause 5.2.1 forbids as a digest algorithm")]
    [DataRow("1.3.14.3.2.26", 20, DisplayName = "SHA-1, refused as a creation-side digest")]
    [DataRow("2.16.840.1.101.3.4.2.4", 28, DisplayName = "SHA-224, which this library does not compute")]
    public async Task ADigestAlgorithmCreationRefusesStopsTheContainer(string oid, int outputByteLength)
    {
        var refused = new PkiDigestAlgorithm(new AlgorithmIdentifier(oid), PkiDigestAlgorithm.Sha256.DigestTag, outputByteLength);

        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerSignatureContext context = BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()) with
            {
                ManifestDigestAlgorithm = refused
            };

            AsicContainerCreationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerCreationException>(async () =>
            {
                using AsicContainerCreationResult _ = await AsicContainerCreation.SignAsync(
                    context, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerCreationFailureKind.DigestAlgorithmRefused, refusal.FailureKind);
        }
    }


    /// <summary>
    /// A caller-supplied dated constraints table that does not assert the manifest's digest algorithm reliable at
    /// the signing instant stops the creation, and the same table with the assertion in force lets it proceed.
    /// </summary>
    [TestMethod]
    public async Task TheSuppliedConstraintsTableDecidesWhetherTheManifestDigestIsAllowed()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerSignatureContext expired = BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()) with
            {
                AlgorithmConstraints = new CryptographicConstraints
                {
                    Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, null, TrustedUntil: SigningTime.AddDays(-1))]
                }
            };

            AsicContainerCreationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerCreationException>(async () =>
            {
                using AsicContainerCreationResult _ = await AsicContainerCreation.SignAsync(
                    expired, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerCreationFailureKind.DigestAlgorithmRefused, refusal.FailureKind);

            AsicContainerSignatureContext inForce = expired with
            {
                AlgorithmConstraints = new CryptographicConstraints
                {
                    Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, null, TrustedUntil: SigningTime.AddDays(1))]
                }
            };

            using AsicContainerCreationResult container = await AsicContainerCreation.SignAsync(
                inForce, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AsicContainerProfile.ExtendedCAdES, container.Profile);
        }
    }


    /// <summary>
    /// Everything the composition itself decides is a function of the context and of nothing else: two
    /// containers built from the same data objects carry the same entry names in the same order and the
    /// byte-identical manifest, whoever signed them. The container's own octets are NOT compared, because the
    /// protective object inside them is not the composition's: an ECDSA signature is randomised, and a
    /// Time-Stamping Authority states its own instants and serial numbers.
    /// </summary>
    [TestMethod]
    public async Task WhatTheCompositionDecidesIsAFunctionOfTheContextAlone()
    {
        using AsicContainerCreationResult first = await CreateExtendedCAdESAsync().ConfigureAwait(false);
        using AsicContainerCreationResult second = await CreateExtendedCAdESAsync().ConfigureAwait(false);

        Assert.AreSequenceEqual(first.EntryNames.ToArray(), second.EntryNames.ToArray(), "The naming scheme decides the same names for the same container.");
        Assert.AreEqual(first.MediaType, second.MediaType);
        Assert.AreEqual(first.Profile, second.Profile);

        byte[] firstManifest = ReadEntry(first.Container.AsReadOnlySpan().ToArray(), first.ManifestEntryName!);
        byte[] secondManifest = ReadEntry(second.Container.AsReadOnlySpan().ToArray(), second.ManifestEntryName!);

        Assert.AreSequenceEqual(firstManifest, secondManifest,
            "The manifest is a function of the data objects and the chosen names; a producer that let it drift would sign different octets for the same container.");
    }


    /// <summary>
    /// Builds an ASiC-S container carrying a CAdES object over one data file.
    /// </summary>
    /// <param name="dataObjectMediaType">The media type the data file states, or <see langword="null"/> to state none.</param>
    /// <param name="stateComment">Whether the ZIP archive comment states the container's media type.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateSimpleCAdESAsync(string? dataObjectMediaType = null, bool stateComment = false)
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerSignatureContext context = BuildSignatureContext(
                AsicContainerShape.Simple,
                certificate,
                [DataObject("data.txt", FirstDataObject, dataObjectMediaType)]) with
            {
                StateMediaTypeArchiveComment = stateComment
            };

            return await AsicContainerCreation.SignAsync(context, privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Builds an ASiC-E container carrying a CAdES object over an <c>ASiCManifest</c> file naming two data files.
    /// </summary>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateExtendedCAdESAsync()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            return await AsicContainerCreation.SignAsync(
                BuildSignatureContext(AsicContainerShape.Extended, certificate, ExtendedDataObjects()),
                privateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Builds a time-assertion container of the requested shape against a Time-Stamping Authority that mints a
    /// genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="shape">Which container shape to build.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateTimeAssertionAsync(AsicContainerShape shape)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], TimeAssertionInstant);

        return await AsicContainerCreation.CreateTimeAssertionAsync(
            new AsicContainerTimeAssertionContext
            {
                Shape = shape,
                DataObjects = shape == AsicContainerShape.Simple ? [DataObject("data.txt", FirstDataObject)] : ExtendedDataObjects(),
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds an Evidence Record container of the requested shape.
    /// </summary>
    /// <param name="shape">Which container shape to build.</param>
    /// <param name="algorithm">The algorithm the record's hash tree and the manifest's digests are stated under.</param>
    /// <returns>The container. The caller owns and disposes it.</returns>
    private async Task<AsicContainerCreationResult> CreateEvidenceRecordAsync(AsicContainerShape shape, PkiDigestAlgorithm? algorithm = null)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], TimeAssertionInstant);

        return await AsicContainerCreation.CreateEvidenceRecordAsync(
            new AsicContainerEvidenceRecordContext
            {
                Shape = shape,
                DataObjects = shape == AsicContainerShape.Simple ? [DataObject("data.txt", FirstDataObject)] : ExtendedDataObjects(),
                LastModified = ContainerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync,
                DigestAlgorithm = algorithm ?? PkiDigestAlgorithm.Sha256,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the signature context every CAdES test shares.
    /// </summary>
    /// <param name="shape">Which container shape to build.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="dataObjects">The data objects the container carries.</param>
    /// <returns>The context.</returns>
    private static AsicContainerSignatureContext BuildSignatureContext(
        AsicContainerShape shape, PkiCertificateMemory certificate, IReadOnlyList<AsicDataObject> dataObjects) =>
        new()
        {
            Shape = shape,
            DataObjects = dataObjects,
            SignerCertificate = certificate,
            SigningTime = SigningTime,
            LastModified = ContainerInstant,
            EncodeManifest = AsicManifestXmlBinding.EncodeAsync
        };


    /// <summary>The two data objects every ASiC-E container in this class carries, one of them in a folder.</summary>
    /// <returns>The data objects.</returns>
    private static IReadOnlyList<AsicDataObject> ExtendedDataObjects() =>
    [
        DataObject("first.txt", FirstDataObject, "text/plain"),
        DataObject("folder/second.bin", SecondDataObject)
    ];


    /// <summary>
    /// States one data object.
    /// </summary>
    /// <param name="name">The container entry name.</param>
    /// <param name="content">The object's octets.</param>
    /// <param name="mediaType">The media type the object states, or <see langword="null"/> to state none.</param>
    /// <returns>The data object.</returns>
    private static AsicDataObject DataObject(string name, byte[] content, string? mediaType = null) =>
        new() { Name = name, Content = content, MediaType = mediaType };


    /// <summary>
    /// Asserts that a creation refuses the supplied data objects with the expected failure kind.
    /// </summary>
    /// <param name="expected">The failure kind the refusal must carry.</param>
    /// <param name="shape">Which container shape was asked for.</param>
    /// <param name="dataObjects">The data objects the caller supplied.</param>
    /// <returns>A task that completes when the assertion has been made.</returns>
    private async Task AssertRefusedAsync(
        AsicContainerCreationFailureKind expected, AsicContainerShape shape, IReadOnlyList<AsicDataObject> dataObjects)
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            AsicContainerCreationException refusal = await Assert.ThrowsExactlyAsync<AsicContainerCreationException>(async () =>
            {
                using AsicContainerCreationResult _ = await AsicContainerCreation.SignAsync(
                    BuildSignatureContext(shape, certificate, dataObjects), privateKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(expected, refusal.FailureKind, refusal.Message);
        }
    }


    /// <summary>
    /// Walks an Evidence Record's own reduced hash tree from a data object's hash to the root its embedded token
    /// binds, entirely through the independent oracle.
    /// </summary>
    /// <param name="record">The record's octets, as the container stores them.</param>
    /// <param name="dataObject">The data object the record is claimed to prove.</param>
    private static void AssertRecordProves(byte[] record, byte[] dataObject)
    {
        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(record);
        Assert.HasCount(1, parsed.Chains, "A container this library creates carries one Archive Timestamp chain.");

        OracleArchiveTimeStamp archiveTimeStamp = parsed.Chains[0][0];
        PkiDigestAlgorithm algorithm = PkiDigestAlgorithm.FromOid(archiveTimeStamp.MessageImprintAlgorithmOid)
            ?? throw new InvalidOperationException($"'{archiveTimeStamp.MessageImprintAlgorithmOid}' does not name a digest algorithm this library computes.");

        byte[]? recomputed = EvidenceRecordOracle.RecomputeRoot(
            EvidenceRecordOracle.Hash(dataObject, algorithm), archiveTimeStamp.ReducedHashtree, algorithm);

        Assert.IsNotNull(recomputed, "The independent walk must reach a root from the record's own reduced hash tree.");
        Assert.AreSequenceEqual(archiveTimeStamp.MessageImprint, recomputed, "The root the independent walk reaches must be what the record's token binds.");
    }


    /// <summary>
    /// Asserts that the shipped Evidence Record verification accepts a record read back out of a container.
    /// </summary>
    /// <param name="record">The record's octets, as the container stores them.</param>
    /// <param name="dataObject">The data object the record is claimed to prove.</param>
    /// <returns>A task that completes when the assertion has been made.</returns>
    private async Task AssertShippedVerificationAcceptsAsync(byte[] record, byte[] dataObject)
    {
        using EvidenceRecord read = EvidenceRecord.Read(record, BaseMemoryPool.Shared);
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = read, DataObject = dataObject },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
        Assert.AreEqual(TimeAssertionInstant, verification.InitialArchiveTime);
    }


    /// <summary>
    /// Reads one entry's octets out of a container through the independent raw-ZIP oracle.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="name">The entry name to read.</param>
    /// <returns>The entry's octets.</returns>
    /// <exception cref="InvalidOperationException">When the container carries no entry of that name.</exception>
    private static byte[] ReadEntry(byte[] container, string name)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            if(string.Equals(header.Name, name, StringComparison.Ordinal))
            {
                return AsicZipStructureOracle.ReadEntryContent(container, header);
            }
        }

        throw new InvalidOperationException($"The container carries no entry named '{name}'.");
    }


    /// <summary>
    /// Verifies a detached CMS signature over the supplied content with the independent BouncyCastle reader,
    /// which never sees the creation surface's objects.
    /// </summary>
    /// <param name="signature">The DER-encoded CMS <c>SignedData</c>.</param>
    /// <param name="content">The detached content the signature is claimed to cover.</param>
    /// <returns><see langword="true"/> when a signer of the object verifies over that content under a certificate the object itself embeds.</returns>
    private static bool VerifiesDetached(byte[] signature, byte[] content)
    {
        var signedData = new BcCmsSignedData(new CmsProcessableByteArray(content), signature);
        foreach(SignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            foreach(BcX509Certificate candidate in signedData.GetCertificates().EnumerateMatches(signer.SignerID))
            {
                try
                {
                    if(signer.Verify(candidate))
                    {
                        return true;
                    }
                }
                catch(CmsException)
                {
                    //This embedded certificate is not the signer's; try the next one the object carries.
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Checks a time-stamp token against the independent BouncyCastle TSP validator, trying each certificate the
    /// token itself embeds.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token.</returns>
    private static bool VerifiesUnderAnyEmbeddedCertificate(byte[] token)
    {
        var parsed = new TimeStampToken(new BcCmsSignedData(token));
        foreach(BcX509Certificate candidate in parsed.GetCertificates().EnumerateMatches(null))
        {
            try
            {
                parsed.Validate(candidate);

                return true;
            }
            catch(TspException)
            {
                //This embedded certificate is not the authority's own; try the next.
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the <c>messageImprint</c> a time-stamp token binds, through the independent BouncyCastle TSP reader.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns>The imprint octets.</returns>
    private static byte[] ImprintOf(byte[] token) =>
        new TimeStampToken(new BcCmsSignedData(token)).TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();


    /// <summary>
    /// A manifest serialisation seam that always answers with a failure status, for the fail-closed test.
    /// </summary>
    /// <param name="context">The manifest to write, which this seam never writes.</param>
    /// <param name="pool">The memory pool, unused.</param>
    /// <param name="cancellationToken">A cancellation token, unused.</param>
    /// <returns>A failed encode result.</returns>
    private static ValueTask<AsicManifestEncodeResult> RefusingEncoder(
        AsicManifestEncodeContext context, MemoryPool<byte> pool, System.Threading.CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(AsicManifestEncodeResult.Failed(AsicManifestEncodeStatus.ExtensionMalformed, "this seam writes nothing"));


    /// <summary>
    /// Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's
    /// test-key convention), and a self-signed certificate over the exact same public point minted through a
    /// platform <see cref="ECDsa"/> reconstructed from the BouncyCastle-produced coordinates.
    /// </summary>
    /// <returns>The certificate and the private key; the caller disposes both.</returns>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP256Signer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            using ECDsa platformKey = ECDsa.Create(ecParameters);
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(platformCertificate.RawData.Length);
            platformCertificate.RawData.CopyTo(owner.Memory.Span);

            return (new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate), keys.PrivateKey);
        }
    }
}
