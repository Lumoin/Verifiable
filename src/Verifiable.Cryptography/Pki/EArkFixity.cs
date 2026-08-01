using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Whether a fixity value an Information Package states can be recomputed, and when it cannot, what kind of
/// algorithm it names.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a recomputable fixity.
/// </para>
/// <para>
/// The distinctions below exist because neither the METS <c>@CHECKSUMTYPE</c> enumeration nor the preservation
/// metadata's own hash-function vocabulary imposes a minimum strength: MD5, CRC32 and Adler-32 are first-class,
/// equally schema-valid values there. This library computes the SHA-2 family and nothing else, so a document
/// naming anything outside it is carried with its value as text and this status beside it — never dropped, never
/// silently treated as absent, and never recomputed against a different algorithm.
/// </para>
/// </remarks>
public enum EArkFixityStatus
{
    /// <summary>No classification has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// The algorithm is one this library computes — SHA-256, SHA-384 or SHA-512 — and the stated value is the
    /// right number of octets for it, so the fixity can be recomputed through the registered digest seam and
    /// compared.
    /// </summary>
    Recomputable = 1,

    /// <summary>
    /// The algorithm is an error-detection code rather than a hash function: <c>Adler-32</c>, <c>CRC32</c> or
    /// <c>MNP</c>. Such a value detects accidental corruption and nothing else — two different contents can be
    /// produced with the same value at will — so it is evidence of transfer integrity, never of authenticity.
    /// </summary>
    NonCryptographicAlgorithm = 2,

    /// <summary>
    /// The algorithm is a hash function whose collision resistance is broken: <c>MD5</c> or <c>SHA-1</c>. The
    /// reference material's own worked packages use MD5, so meeting it says nothing about a producer's diligence
    /// — it is what the ecosystem writes — but a colliding pair can be constructed, so the value cannot carry a
    /// fixity claim.
    /// </summary>
    WeakCryptographicAlgorithm = 3,

    /// <summary>
    /// The algorithm is a hash function the vocabulary names and this library does not implement: <c>HAVAL</c>,
    /// <c>TIGER</c> or <c>WHIRLPOOL</c>. Nothing is being said about its strength — only that no registered digest
    /// function computes it here, so the value cannot be recomputed.
    /// </summary>
    UnsupportedCryptographicAlgorithm = 4,

    /// <summary>
    /// The algorithm name is not one either vocabulary states. For a METS <c>@CHECKSUMTYPE</c> that also makes the
    /// document schema-invalid, because the attribute's type is an enumeration; for a preservation-metadata
    /// <c>messageDigestAlgorithm</c>, whose vocabulary is externally hosted and open, it means only that the name
    /// is unrecognised here.
    /// </summary>
    UnrecognizedAlgorithm = 5,

    /// <summary>
    /// The algorithm resolved but the stated value is not its digest: not hexadecimal, or not the number of octets
    /// the algorithm produces. A value of the wrong length can never equal a recomputation, so it is carried and
    /// flagged rather than parsed into a carrier that would claim to be a digest.
    /// </summary>
    MalformedChecksum = 6
}


/// <summary>
/// One fixity value an Information Package states about a file — the <c>@CHECKSUM</c>/<c>@CHECKSUMTYPE</c>
/// attribute pair of a METS element, or the <c>messageDigest</c>/<c>messageDigestAlgorithm</c> pair of a
/// preservation-metadata <c>fixity</c> block.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One type for both vocabularies, because the problem is one problem.</strong> The attribute pair appears
/// at four independent places in the METS profile of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> — <c>CSIP29</c>/<c>30</c>
/// on a descriptive-metadata reference, <c>CSIP43</c>/<c>44</c> on a digital-provenance reference,
/// <c>CSIP56</c>/<c>57</c> on a rights reference and <c>CSIP71</c>/<c>72</c> on a file entry — and a fifth time as
/// <c>PM34</c>/<c>PM35</c> in <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>. All
/// five state an algorithm by name and a value as hexadecimal, and all five are answered the same way.
/// </para>
/// <para>
/// <strong>A closed sum with two cases, so that no field lies.</strong> A fixity is either recomputable — the
/// algorithm resolved onto the registry the digest seam dispatches on and the value is a digest of the right
/// length, carried in a <see cref="DigestValue"/> — or merely stated, in which case the algorithm name and the
/// value are carried as the text the document had and <see cref="Status"/> says why. Modelling it as one record
/// with nullable fields would let a caller read a digest carrier that was never populated; modelling it as two
/// cases makes an exhaustive switch the only way to ask.
/// </para>
/// <para>
/// <strong>Reading and writing are asymmetric on purpose.</strong> <see cref="Read"/> accepts every value the
/// vocabularies admit, because a package this library did not produce is exactly what it exists to read. Nothing
/// in this library writes anything but a <see cref="EArkRecomputableFixity"/>, whose constructor admits only an
/// algorithm <see cref="MetsWellKnown.ChecksumTypeFromDigestAlgorithm"/> names — the specification states no
/// minimum strength, so the floor is this library's own.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns whatever carrier it holds; whoever holds the fixity disposes it.
/// </para>
/// </remarks>
public abstract record EArkFixity: IDisposable
{
    /// <summary>
    /// Restricts the cases to those declared in this assembly, making this a closed hierarchy: no external type
    /// can derive from it.
    /// </summary>
    /// <param name="status">The classification of the stated algorithm and value.</param>
    private protected EArkFixity(EArkFixityStatus status)
    {
        Status = status;
    }


    /// <summary>The classification of the stated algorithm and value.</summary>
    public EArkFixityStatus Status { get; }

    /// <summary>Gets whether the fixity can be recomputed and compared, which is true only of <see cref="EArkRecomputableFixity"/>.</summary>
    public bool IsRecomputable => Status == EArkFixityStatus.Recomputable;


    /// <summary>Disposes whatever carrier the case holds.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Disposes whatever carrier the case holds when <paramref name="disposing"/> is <see langword="true"/>.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    /// <remarks>
    /// The hierarchy is closed by the constructor above and no case holds an unmanaged resource, so this exists
    /// to give each case one place to release its carrier rather than to support a finalizer — the shape
    /// <c>CtapUserPresenceContinuation</c> already established elsewhere in this repository for a closed sum
    /// whose cases own pooled memory.
    /// </remarks>
    protected abstract void Dispose(bool disposing);


    /// <summary>
    /// Classifies an algorithm name without reading a value beside it.
    /// </summary>
    /// <param name="algorithmName">The <c>@CHECKSUMTYPE</c> or <c>messageDigestAlgorithm</c> value, or <see langword="null"/>.</param>
    /// <returns>
    /// The classification. <see cref="EArkFixityStatus.Recomputable"/> means only that the algorithm is one this
    /// library computes — whether the value beside it is a digest of that algorithm is
    /// <see cref="Read"/>'s question.
    /// </returns>
    public static EArkFixityStatus ClassifyAlgorithm(string? algorithmName) => algorithmName switch
    {
        null => EArkFixityStatus.UnrecognizedAlgorithm,
        _ when MetsWellKnown.DigestAlgorithmFromChecksumType(algorithmName) is not null => EArkFixityStatus.Recomputable,
        _ when IsOneOf(algorithmName, MetsWellKnown.Adler32ChecksumType, MetsWellKnown.Crc32ChecksumType, MetsWellKnown.MnpChecksumType) => EArkFixityStatus.NonCryptographicAlgorithm,
        _ when IsOneOf(algorithmName, MetsWellKnown.Md5ChecksumType, MetsWellKnown.Sha1ChecksumType) => EArkFixityStatus.WeakCryptographicAlgorithm,
        _ when IsOneOf(algorithmName, MetsWellKnown.HavalChecksumType, MetsWellKnown.TigerChecksumType, MetsWellKnown.WhirlpoolChecksumType) => EArkFixityStatus.UnsupportedCryptographicAlgorithm,
        _ => EArkFixityStatus.UnrecognizedAlgorithm
    };


    /// <summary>
    /// Reads a stated algorithm name and value into whichever case they are.
    /// </summary>
    /// <param name="algorithmName">The <c>@CHECKSUMTYPE</c> or <c>messageDigestAlgorithm</c> value, or <see langword="null"/>.</param>
    /// <param name="checksum">The <c>@CHECKSUM</c> or <c>messageDigest</c> value, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool a digest carrier is rented from.</param>
    /// <returns>
    /// A <see cref="EArkRecomputableFixity"/> when the algorithm resolves and the value is its digest, and a
    /// <see cref="EArkStatedFixity"/> carrying the text and the reason otherwise. Never <see langword="null"/>,
    /// and never a refusal: a document that states a fixity this library cannot recompute has still stated one,
    /// and the caller — a validation rule, ultimately — is what decides what to do about it.
    /// </returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static EArkFixity Read(string? algorithmName, string? checksum, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        EArkFixityStatus status = ClassifyAlgorithm(algorithmName);
        if(status != EArkFixityStatus.Recomputable)
        {
            return new EArkStatedFixity(algorithmName ?? string.Empty, checksum ?? string.Empty, status);
        }

        PkiDigestAlgorithm algorithm = MetsWellKnown.DigestAlgorithmFromChecksumType(algorithmName)!.Value;
        ReadOnlySpan<char> value = (checksum ?? string.Empty).AsSpan().Trim();
        if(value.Length != algorithm.OutputByteLength * 2)
        {
            return new EArkStatedFixity(algorithmName!, checksum ?? string.Empty, EArkFixityStatus.MalformedChecksum);
        }

        IMemoryOwner<byte> owner = pool.Rent(algorithm.OutputByteLength);
        try
        {
            if(!TryDecodeHex(value, owner.Memory.Span[..algorithm.OutputByteLength]))
            {
                owner.Dispose();

                return new EArkStatedFixity(algorithmName!, checksum ?? string.Empty, EArkFixityStatus.MalformedChecksum);
            }

            return new EArkRecomputableFixity(algorithm, new DigestValue(owner, algorithm.DigestTag));
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        //Hexadecimal is what both vocabularies write a fixity value as, in either case. Decoding is done here
        //rather than through a framework helper so that an odd digit, a stray separator and a value of the wrong
        //length are all one answer — false — instead of three different exceptions.
        static bool TryDecodeHex(ReadOnlySpan<char> text, Span<byte> destination)
        {
            for(int i = 0; i < destination.Length; ++i)
            {
                int high = DecodeDigit(text[i * 2]);
                int low = DecodeDigit(text[(i * 2) + 1]);
                if(high < 0 || low < 0)
                {
                    return false;
                }

                destination[i] = (byte)((high << 4) | low);
            }

            return true;
        }

        //One hexadecimal digit, in either case, or a negative number when the character is not one.
        static int DecodeDigit(char character) => character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };
    }


    /// <summary>
    /// Determines whether a value is one of three candidates, compared ordinally.
    /// </summary>
    /// <param name="value">The value to test.</param>
    /// <param name="first">The first candidate.</param>
    /// <param name="second">The second candidate.</param>
    /// <param name="third">The third candidate, or <see langword="null"/> when there are only two.</param>
    /// <returns><see langword="true"/> when the value equals one of the candidates.</returns>
    private static bool IsOneOf(string value, string first, string second, string? third = null) =>
        string.Equals(value, first, StringComparison.Ordinal)
        || string.Equals(value, second, StringComparison.Ordinal)
        || (third is not null && string.Equals(value, third, StringComparison.Ordinal));
}


/// <summary>
/// The fixity case whose algorithm this library computes: the value is carried as a digest and can be recomputed
/// through the registered digest seam and compared.
/// </summary>
/// <remarks>
/// The constructor is where the creation-side floor is enforced. An algorithm
/// <see cref="MetsWellKnown.ChecksumTypeFromDigestAlgorithm"/> cannot name has no conformant
/// <c>@CHECKSUMTYPE</c> spelling, and a digest of the wrong length can never equal a recomputation, so neither
/// can become a document — both are refused where the model is built rather than where it is written.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkRecomputableFixity: EArkFixity
{
    /// <summary>
    /// Initialises a recomputable fixity from an algorithm and the digest computed under it.
    /// </summary>
    /// <param name="algorithm">The algorithm, which must be one <see cref="MetsWellKnown.ChecksumTypeFromDigestAlgorithm"/> names.</param>
    /// <param name="digest">The digest. Ownership transfers to this instance.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="digest"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="algorithm"/> has no conformant checksum-type name, or when
    /// <paramref name="digest"/> does not hold as many octets as <paramref name="algorithm"/> produces.
    /// </exception>
    public EArkRecomputableFixity(PkiDigestAlgorithm algorithm, DigestValue digest): base(EArkFixityStatus.Recomputable)
    {
        ArgumentNullException.ThrowIfNull(digest);

        string? checksumType = MetsWellKnown.ChecksumTypeFromDigestAlgorithm(algorithm);
        if(checksumType is null)
        {
            throw new ArgumentException(
                $"The algorithm '{algorithm.Identifier.Oid}' has no conformant checksum-type name, so no package this library writes can state it.",
                nameof(algorithm));
        }

        if(digest.Length != algorithm.OutputByteLength)
        {
            throw new ArgumentException(
                $"A digest stated under '{checksumType}' is {algorithm.OutputByteLength} octets long, not {digest.Length}.",
                nameof(digest));
        }

        Algorithm = algorithm;
        Digest = digest;
        ChecksumType = checksumType;
    }


    /// <summary>The algorithm, resolved onto the registry the digest seam dispatches on.</summary>
    public PkiDigestAlgorithm Algorithm { get; }

    /// <summary>The digest. The instance owns it.</summary>
    public DigestValue Digest { get; }

    /// <summary>The conformant name the algorithm is stated by — one of <c>SHA-256</c>, <c>SHA-384</c> and <c>SHA-512</c>.</summary>
    public string ChecksumType { get; }


    /// <summary>Disposes <see cref="Digest"/>.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            Digest.Dispose();
        }
    }


    /// <summary>A short debugger string showing the algorithm the fixity is stated under.</summary>
    private string DebuggerDisplay => $"EArkRecomputableFixity({ChecksumType}, {Digest.Length} octets)";
}


/// <summary>
/// The fixity case this library cannot recompute: the algorithm name and the value are carried exactly as the
/// document stated them, and <see cref="EArkFixity.Status"/> says why.
/// </summary>
/// <remarks>
/// Nothing here is a refusal. A package whose fixity is stated under MD5 is a package the reference material's own
/// examples produce, and dropping the value would leave a validation rule unable to say what it met. What the
/// case does refuse is to pretend: the value never reaches a digest carrier, so nothing downstream can compare it
/// against a recomputation by accident.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkStatedFixity: EArkFixity
{
    /// <summary>
    /// Initialises a stated fixity from the text a document carried.
    /// </summary>
    /// <param name="checksumType">The algorithm name as stated, or the empty string when the document stated none.</param>
    /// <param name="checksum">The value as stated, or the empty string when the document stated none.</param>
    /// <param name="status">Why the value cannot be recomputed.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="checksumType"/> or <paramref name="checksum"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="status"/> is <see cref="EArkFixityStatus.Recomputable"/>, which is
    /// <see cref="EArkRecomputableFixity"/>'s case, or <see cref="EArkFixityStatus.NotEvaluated"/>, which states
    /// nothing at all.
    /// </exception>
    public EArkStatedFixity(string checksumType, string checksum, EArkFixityStatus status): base(status)
    {
        ArgumentNullException.ThrowIfNull(checksumType);
        ArgumentNullException.ThrowIfNull(checksum);

        if(status is EArkFixityStatus.Recomputable or EArkFixityStatus.NotEvaluated)
        {
            throw new ArgumentException($"A stated fixity carries a reason it cannot be recomputed, not '{status}'.", nameof(status));
        }

        ChecksumType = checksumType;
        Checksum = checksum;
    }


    /// <summary>The algorithm name exactly as the document stated it, which may be outside either vocabulary.</summary>
    public string ChecksumType { get; }

    /// <summary>The value exactly as the document stated it, which may be neither hexadecimal nor of any digest's length.</summary>
    public string Checksum { get; }


    /// <summary>Does nothing: the case owns no carrier.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
    }


    /// <summary>A short debugger string showing what was stated and why it cannot be recomputed.</summary>
    private string DebuggerDisplay => $"EArkStatedFixity({ChecksumType}, {Status})";
}
