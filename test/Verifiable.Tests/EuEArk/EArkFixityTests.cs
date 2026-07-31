using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for <see cref="EArkFixity"/> and the two cases it closes over: every algorithm name the base
/// METS <c>CHECKSUMTYPE</c> enumeration admits is classified, a value this library cannot recompute is carried as
/// the text the document stated rather than dropped, and nothing but the SHA-2 family ever reaches a digest
/// carrier.
/// </summary>
/// <remarks>
/// <para>
/// The asymmetry under test is the one <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP
/// v2.2.0</see> forces: its <c>@CHECKSUMTYPE</c> attribute is an enumeration of eleven values, three of which are
/// error-detection codes and two of which are broken hash functions, and the specification imposes no minimum
/// strength anywhere. Reading has to admit all eleven — a package this library did not produce is what a reader
/// exists for — while writing admits three. Both halves are checked here.
/// </para>
/// <para>
/// Every carrier is rented from the house pool and disposed.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkFixityTests
{
    /// <summary>A SHA-256 digest of the empty octet string, as the lower-case hexadecimal a document states it in.</summary>
    private const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// <summary>A SHA-384 digest, 48 octets of hexadecimal, whose value is immaterial to what is being checked.</summary>
    private const string Sha384Value = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

    /// <summary>A SHA-512 digest, 64 octets of hexadecimal, whose value is immaterial to what is being checked.</summary>
    private const string Sha512Value =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";


    /// <summary>
    /// Every value the enumeration admits is classified, and each of the four reasons a fixity cannot be
    /// recomputed is reachable — so no algorithm the specification calls schema-valid ends up unclassified.
    /// </summary>
    /// <param name="algorithmName">The <c>@CHECKSUMTYPE</c> value, or <see langword="null"/>.</param>
    /// <param name="expected">The classification the value is given.</param>
    [TestMethod]
    [DataRow("SHA-256", EArkFixityStatus.Recomputable, DisplayName = "SHA-256, which this library computes")]
    [DataRow("SHA-384", EArkFixityStatus.Recomputable, DisplayName = "SHA-384, which this library computes")]
    [DataRow("SHA-512", EArkFixityStatus.Recomputable, DisplayName = "SHA-512, which this library computes")]
    [DataRow("Adler-32", EArkFixityStatus.NonCryptographicAlgorithm, DisplayName = "Adler-32, an error-detection code")]
    [DataRow("CRC32", EArkFixityStatus.NonCryptographicAlgorithm, DisplayName = "CRC32, an error-detection code")]
    [DataRow("MNP", EArkFixityStatus.NonCryptographicAlgorithm, DisplayName = "MNP, an error-detection code")]
    [DataRow("MD5", EArkFixityStatus.WeakCryptographicAlgorithm, DisplayName = "MD5, which the reference packages themselves use")]
    [DataRow("SHA-1", EArkFixityStatus.WeakCryptographicAlgorithm, DisplayName = "SHA-1, whose collision resistance is broken")]
    [DataRow("HAVAL", EArkFixityStatus.UnsupportedCryptographicAlgorithm, DisplayName = "HAVAL, which nothing here computes")]
    [DataRow("TIGER", EArkFixityStatus.UnsupportedCryptographicAlgorithm, DisplayName = "TIGER, which nothing here computes")]
    [DataRow("WHIRLPOOL", EArkFixityStatus.UnsupportedCryptographicAlgorithm, DisplayName = "WHIRLPOOL, which nothing here computes")]
    [DataRow("sha-256", EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "the right name in the wrong case, which is not an enumeration facet")]
    [DataRow("SHA256", EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "the name without its hyphen")]
    [DataRow("", EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "an empty name")]
    [DataRow(null, EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "no name at all")]
    public void EveryAlgorithmTheEnumerationAdmitsIsClassified(string? algorithmName, EArkFixityStatus expected) =>
        Assert.AreEqual(expected, EArkFixity.ClassifyAlgorithm(algorithmName));


    /// <summary>
    /// Every member of the enumeration is recognised as schema-valid by
    /// <see cref="MetsWellKnown.IsChecksumType"/> even when this library will not compute it — membership and
    /// recomputability are two different questions and the vocabulary answers only the first.
    /// </summary>
    [TestMethod]
    public void EveryMemberOfTheEnumerationIsSchemaValidWhetherOrNotItIsRecomputable()
    {
        string[] enumeration =
        [
            MetsWellKnown.Adler32ChecksumType,
            MetsWellKnown.Crc32ChecksumType,
            MetsWellKnown.HavalChecksumType,
            MetsWellKnown.Md5ChecksumType,
            MetsWellKnown.MnpChecksumType,
            MetsWellKnown.Sha1ChecksumType,
            MetsWellKnown.Sha256ChecksumType,
            MetsWellKnown.Sha384ChecksumType,
            MetsWellKnown.Sha512ChecksumType,
            MetsWellKnown.TigerChecksumType,
            MetsWellKnown.WhirlpoolChecksumType
        ];

        Assert.HasCount(11, enumeration, "The base METS schema states eleven checksum types.");

        int recomputable = 0;
        foreach(string checksumType in enumeration)
        {
            Assert.IsTrue(MetsWellKnown.IsChecksumType(checksumType), checksumType);
            if(MetsWellKnown.DigestAlgorithmFromChecksumType(checksumType) is not null)
            {
                ++recomputable;
            }
        }

        Assert.AreEqual(3, recomputable, "Only the SHA-2 family resolves onto the registry the digest seam dispatches on.");
        Assert.IsFalse(MetsWellKnown.IsChecksumType("SHA-224"), "A hash function the enumeration does not name is not schema-valid.");
        Assert.IsFalse(MetsWellKnown.IsChecksumType(null));
    }


    /// <summary>
    /// A fixity stated under an algorithm this library computes reaches the recomputable case with its value in a
    /// digest carrier of the algorithm's own length, which is what makes a later comparison against a
    /// recomputation possible at all.
    /// </summary>
    /// <param name="checksumType">The <c>@CHECKSUMTYPE</c> value.</param>
    /// <param name="checksum">The <c>@CHECKSUM</c> value.</param>
    /// <param name="expectedLength">How many octets the algorithm produces.</param>
    [TestMethod]
    [DataRow("SHA-256", EmptySha256, 32, DisplayName = "SHA-256")]
    [DataRow("SHA-384", Sha384Value, 48, DisplayName = "SHA-384")]
    [DataRow("SHA-512", Sha512Value, 64, DisplayName = "SHA-512")]
    public void AFixityStatedUnderASupportedAlgorithmReachesTheRecomputableCase(string checksumType, string checksum, int expectedLength)
    {
        using EArkFixity fixity = EArkFixity.Read(checksumType, checksum, BaseMemoryPool.Shared);

        Assert.AreEqual(EArkFixityStatus.Recomputable, fixity.Status);
        Assert.IsTrue(fixity.IsRecomputable);

        var recomputable = Assert.IsInstanceOfType<EArkRecomputableFixity>(fixity);
        Assert.AreEqual(checksumType, recomputable.ChecksumType);
        Assert.AreEqual(expectedLength, recomputable.Digest.Length);
        Assert.AreEqual(checksum, Convert.ToHexStringLower(recomputable.Digest.AsReadOnlySpan()));
    }


    /// <summary>
    /// Hexadecimal is read in either case, because neither specification says which one a document writes and the
    /// reference packages use both.
    /// </summary>
    [TestMethod]
    public void HexadecimalIsReadInEitherCase()
    {
        using EArkFixity lower = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, EmptySha256, BaseMemoryPool.Shared);
        using EArkFixity upper = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, EmptySha256.ToUpperInvariant(), BaseMemoryPool.Shared);

        var lowerCase = Assert.IsInstanceOfType<EArkRecomputableFixity>(lower);
        var upperCase = Assert.IsInstanceOfType<EArkRecomputableFixity>(upper);

        Assert.AreSequenceEqual(lowerCase.Digest.AsReadOnlySpan().ToArray(), upperCase.Digest.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// A fixity this library cannot recompute is carried with the algorithm name and the value exactly as the
    /// document stated them, never dropped and never silently treated as absent — the half of the fixity ruling a
    /// validation rule needs in order to say what a package actually met.
    /// </summary>
    /// <param name="checksumType">The <c>@CHECKSUMTYPE</c> value, or <see langword="null"/>.</param>
    /// <param name="checksum">The <c>@CHECKSUM</c> value, or <see langword="null"/>.</param>
    /// <param name="expected">The reason the value cannot be recomputed.</param>
    [TestMethod]
    [DataRow("MD5", "d41d8cd98f00b204e9800998ecf8427e", EArkFixityStatus.WeakCryptographicAlgorithm, DisplayName = "an MD5 value, which most of the reference corpus states")]
    [DataRow("CRC32", "00000000", EArkFixityStatus.NonCryptographicAlgorithm, DisplayName = "a CRC32 value")]
    [DataRow("WHIRLPOOL", "19fa61d75522a466", EArkFixityStatus.UnsupportedCryptographicAlgorithm, DisplayName = "a WHIRLPOOL value")]
    [DataRow("BLAKE3", "0000", EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "an algorithm outside the enumeration")]
    [DataRow(null, "0000", EArkFixityStatus.UnrecognizedAlgorithm, DisplayName = "a value with no algorithm beside it")]
    public void AFixityThisLibraryCannotRecomputeIsCarriedAsTheTextItWasStatedIn(string? checksumType, string? checksum, EArkFixityStatus expected)
    {
        using EArkFixity fixity = EArkFixity.Read(checksumType, checksum, BaseMemoryPool.Shared);

        Assert.AreEqual(expected, fixity.Status);
        Assert.IsFalse(fixity.IsRecomputable);

        var stated = Assert.IsInstanceOfType<EArkStatedFixity>(fixity);
        Assert.AreEqual(checksumType ?? string.Empty, stated.ChecksumType);
        Assert.AreEqual(checksum ?? string.Empty, stated.Checksum);
    }


    /// <summary>
    /// A value that is not the digest of the algorithm it is stated under never reaches a digest carrier: a value
    /// of the wrong length can never equal a recomputation, and one that is not hexadecimal is not a digest at
    /// all.
    /// </summary>
    /// <param name="checksum">The <c>@CHECKSUM</c> value.</param>
    [TestMethod]
    [DataRow("", DisplayName = "an empty value")]
    [DataRow("e3b0c44298fc1c149afbf4c8996fb924", DisplayName = "half a SHA-256 digest")]
    [DataRow("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500", DisplayName = "a SHA-256 digest with an octet too many")]
    [DataRow("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g5", DisplayName = "a value carrying a character that is not a hexadecimal digit")]
    [DataRow("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85 5", DisplayName = "a value carrying an interior space")]
    public void AValueThatIsNotTheDigestOfItsAlgorithmNeverReachesADigestCarrier(string checksum)
    {
        using EArkFixity fixity = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, checksum, BaseMemoryPool.Shared);

        Assert.AreEqual(EArkFixityStatus.MalformedChecksum, fixity.Status);

        var stated = Assert.IsInstanceOfType<EArkStatedFixity>(fixity);
        Assert.AreEqual(MetsWellKnown.Sha256ChecksumType, stated.ChecksumType);
        Assert.AreEqual(checksum, stated.Checksum);
    }


    /// <summary>
    /// Surrounding whitespace is not a defect: an attribute value the producer indented is the same value, and
    /// refusing it would refuse conformant documents for a reason no specification states.
    /// </summary>
    [TestMethod]
    public void SurroundingWhitespaceIsNotADefect()
    {
        using EArkFixity fixity = EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, $"  {EmptySha256}\n", BaseMemoryPool.Shared);

        Assert.AreEqual(EArkFixityStatus.Recomputable, fixity.Status);
    }


    /// <summary>
    /// Reading never refuses and never throws, whatever the document stated — a fixity this library cannot
    /// recompute has still been stated, and what to do about it is a validation rule's decision rather than the
    /// reader's.
    /// </summary>
    [TestMethod]
    public void ReadingNeverRefusesAndNeverThrows()
    {
        foreach(string? algorithmName in new[] { null, string.Empty, "MD5", "\0", new string('x', 4096) })
        {
            using EArkFixity fixity = EArkFixity.Read(algorithmName, null, BaseMemoryPool.Shared);

            Assert.AreNotEqual(EArkFixityStatus.NotEvaluated, fixity.Status, "A read that happened is never unevaluated.");
        }

        _ = Assert.Throws<ArgumentNullException>(() => EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, EmptySha256, null!));
    }


    /// <summary>
    /// The creation-side floor is enforced where the model is built rather than where it is written: an algorithm
    /// with no conformant checksum-type name and a digest of the wrong length are both refused by the recomputable
    /// case's own constructor, so no serialisation seam can ever be handed one.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each construction under test throws, so no instance is created to dispose; the digest each attempt is handed is disposed by its own using.")]
    public void TheCreationSideFloorIsEnforcedWhereTheModelIsBuilt()
    {
        //SHA-1 is a first-class member of the METS enumeration and has no name in this library's writer table,
        //which is the whole point: the floor is this library's, not the specification's.
        var sha1 = new PkiDigestAlgorithm(AlgorithmIdentifier.Sha1, PkiDigestAlgorithm.Sha256.DigestTag, 20);
        Assert.IsNull(MetsWellKnown.ChecksumTypeFromDigestAlgorithm(sha1));

        using DigestValue twentyOctets = Rent(20);
        _ = Assert.Throws<ArgumentException>(() => new EArkRecomputableFixity(sha1, twentyOctets));

        using DigestValue tooShort = Rent(16);
        _ = Assert.Throws<ArgumentException>(() => new EArkRecomputableFixity(PkiDigestAlgorithm.Sha256, tooShort));

        _ = Assert.Throws<ArgumentNullException>(() => new EArkRecomputableFixity(PkiDigestAlgorithm.Sha256, null!));

        //Rents a digest carrier of an exact length from the house pool, whose content is immaterial: every
        //refusal above is decided by the algorithm and the length alone.
        static DigestValue Rent(int length) =>
            new(BaseMemoryPool.Shared.Rent(length), PkiDigestAlgorithm.Sha256.DigestTag);
    }


    /// <summary>
    /// The stated case refuses to carry a status that is not a reason: the recomputable status belongs to the
    /// other case, and the unevaluated one states nothing at all.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each construction under test throws, so no instance is created to dispose.")]
    public void TheStatedCaseRefusesAStatusThatIsNotAReason()
    {
        _ = Assert.Throws<ArgumentException>(() => new EArkStatedFixity("MD5", "00", EArkFixityStatus.Recomputable));
        _ = Assert.Throws<ArgumentException>(() => new EArkStatedFixity("MD5", "00", EArkFixityStatus.NotEvaluated));
        _ = Assert.Throws<ArgumentNullException>(() => new EArkStatedFixity(null!, "00", EArkFixityStatus.WeakCryptographicAlgorithm));
        _ = Assert.Throws<ArgumentNullException>(() => new EArkStatedFixity("MD5", null!, EArkFixityStatus.WeakCryptographicAlgorithm));
    }


    /// <summary>
    /// Every status this stage declares reserves zero for the outcome that has not been computed, so a
    /// default-initialised field never reads as a fixity that can be recomputed, a parse that succeeded or a
    /// document that was written — the fail-closed convention, checked over the whole set rather than one member
    /// of it.
    /// </summary>
    /// <remarks>
    /// The names are resolved at run time rather than compared as constants, so this is a statement about what the
    /// enumerations declare rather than one the compiler can fold away before the test runs.
    /// </remarks>
    [TestMethod]
    public void EveryStatusThisStageDeclaresReservesZeroForTheUncomputedOutcome()
    {
        Assert.AreEqual(nameof(EArkFixityStatus.NotEvaluated), Enum.GetName(default(EArkFixityStatus)));
        Assert.AreEqual(nameof(MetsParseStatus.NotEvaluated), Enum.GetName(default(MetsParseStatus)));
        Assert.AreEqual(nameof(MetsEncodeStatus.NotEvaluated), Enum.GetName(default(MetsEncodeStatus)));
        Assert.AreEqual(nameof(PremisParseStatus.NotEvaluated), Enum.GetName(default(PremisParseStatus)));
        Assert.AreEqual(nameof(PremisEncodeStatus.NotEvaluated), Enum.GetName(default(PremisEncodeStatus)));
        Assert.AreEqual(nameof(EArkObjectKind.None), Enum.GetName(default(EArkObjectKind)));

        Assert.AreNotEqual(nameof(EArkFixityStatus.Recomputable), Enum.GetName(default(EArkFixityStatus)));
        Assert.AreNotEqual(nameof(MetsParseStatus.Valid), Enum.GetName(default(MetsParseStatus)));
        Assert.AreNotEqual(nameof(MetsEncodeStatus.Encoded), Enum.GetName(default(MetsEncodeStatus)));
        Assert.AreNotEqual(nameof(PremisParseStatus.Valid), Enum.GetName(default(PremisParseStatus)));
        Assert.AreNotEqual(nameof(PremisEncodeStatus.Encoded), Enum.GetName(default(PremisEncodeStatus)));
    }


    /// <summary>
    /// Naming an algorithm as a checksum type reaches exactly the algorithms naming it as an object identifier
    /// does, so a caller cannot widen what this library computes by choosing which form to state it in.
    /// </summary>
    [TestMethod]
    public void NamingAnAlgorithmAsAChecksumTypeReachesTheSameSetAsNamingItAsAnObjectIdentifier()
    {
        foreach(PkiDigestAlgorithm algorithm in new[] { PkiDigestAlgorithm.Sha256, PkiDigestAlgorithm.Sha384, PkiDigestAlgorithm.Sha512 })
        {
            string? checksumType = MetsWellKnown.ChecksumTypeFromDigestAlgorithm(algorithm);

            Assert.IsNotNull(checksumType);
            Assert.AreEqual(algorithm, MetsWellKnown.DigestAlgorithmFromChecksumType(checksumType));
            Assert.AreEqual(algorithm, PkiDigestAlgorithm.FromOid(algorithm.Identifier.Oid));
        }

        Assert.IsNull(MetsWellKnown.DigestAlgorithmFromChecksumType(MetsWellKnown.Md5ChecksumType));
        Assert.IsNull(MetsWellKnown.DigestAlgorithmFromChecksumType(null));
    }
}
