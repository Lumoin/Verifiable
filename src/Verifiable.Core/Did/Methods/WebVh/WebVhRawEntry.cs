using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// A single did:webvh <c>did.jsonl</c> log entry as parsed from one JSON Lines record.
/// </summary>
/// <remarks>
/// This carries only the structural values the resolver reasons about. The JCS-canonical byte forms the
/// verification steps hash and sign over are produced on demand by <see cref="WebVhCanonicalizer"/> in the
/// <c>Verifiable.Json</c> leaf and disposed back to the pool after use, so a parsed entry never holds an
/// unpooled byte buffer.
/// </remarks>
public sealed record WebVhRawEntry
{
    /// <summary>The <c>versionId</c> string: the version number, a literal dash, and the entryHash.</summary>
    public required string VersionId { get; init; }

    /// <summary>The <c>versionTime</c> string (UTC ISO8601), or <see langword="null"/> when absent.</summary>
    public required string? VersionTime { get; init; }

    /// <summary>The parameters declared by this entry.</summary>
    public required WebVhDeclaredParameters DeclaredParameters { get; init; }

    /// <summary>The Data Integrity proofs attached to this entry.</summary>
    public required ImmutableArray<WebVhProof> Proofs { get; init; }
}


/// <summary>
/// A Data Integrity proof attached to a did:webvh log entry.
/// </summary>
/// <remarks>
/// did:webvh v1.0 fixes the cryptosuite to <c>eddsa-jcs-2022</c> and the <c>proofPurpose</c> to
/// <c>assertionMethod</c>; the proof is signed by a key in the active <c>updateKeys</c> list. The
/// JCS-canonical proof options the signature was created over are produced on demand through
/// <see cref="WebVhProofOptionsInput"/>.
/// </remarks>
public sealed record WebVhProof
{
    /// <summary>The proof <c>type</c> (<c>DataIntegrityProof</c> for did:webvh v1.0), or <see langword="null"/> when absent.</summary>
    public required string? Type { get; init; }

    /// <summary>The proof <c>cryptosuite</c> (<c>eddsa-jcs-2022</c> for did:webvh v1.0), or <see langword="null"/> when absent.</summary>
    public required string? Cryptosuite { get; init; }

    /// <summary>The proof <c>created</c> timestamp, or <see langword="null"/> when absent.</summary>
    public required string? Created { get; init; }

    /// <summary>The proof <c>expires</c> timestamp, or <see langword="null"/> when absent.</summary>
    public string? Expires { get; init; }

    /// <summary>The <c>verificationMethod</c> the proof references (a <c>did:key</c> built from an updateKey), or <see langword="null"/> when absent.</summary>
    public required string? VerificationMethod { get; init; }

    /// <summary>The proof <c>proofPurpose</c>, or <see langword="null"/> when absent.</summary>
    public required string? ProofPurpose { get; init; }

    /// <summary>The multibase-encoded <c>proofValue</c> (the signature), or <see langword="null"/> when absent.</summary>
    public required string? ProofValue { get; init; }
}


/// <summary>
/// One record of the <c>did-witness.json</c> file: the <c>versionId</c> the witness proofs apply to and the
/// Data Integrity proofs attesting it (did:webvh v1.0, The Witness Proofs File).
/// </summary>
/// <remarks>
/// Each proof signs over the JCS canonicalization of the single-property object
/// <c>{"versionId": "&lt;n-hash&gt;"}</c>; the proofs reuse <see cref="WebVhProof"/>, the same Data Integrity
/// proof shape the log entries carry.
/// </remarks>
public sealed record WebVhWitnessProofEntry
{
    /// <summary>The <c>versionId</c> of the DID Log entry these witness proofs apply to.</summary>
    public required string VersionId { get; init; }

    /// <summary>The witness Data Integrity proofs attesting <see cref="VersionId"/>.</summary>
    public required ImmutableArray<WebVhProof> Proofs { get; init; }
}


/// <summary>
/// The fetched <c>did-witness.json</c> file as a verifiable, pooled artifact: its parsed witness proof
/// records together with the content bytes the proof-options canonicalizer re-derives from
/// (did:webvh v1.0, The Witness Proofs File).
/// </summary>
/// <remarks>
/// <para>
/// The parsed <see cref="Entries"/> drive which proofs are checked; <see cref="Content"/> — the original
/// fetched bytes, not a re-serialization — is what the proof-options canonicalizer re-parses, so a verified
/// signature is computed over the exact published proof object. The two are kept together because verifying
/// the records requires the bytes they were parsed from.
/// </para>
/// <para>
/// The content is rented from the resolver's <see cref="System.Buffers.MemoryPool{T}"/> and <strong>owned</strong>
/// by this instance: <see cref="Dispose"/> returns it to the pool, so the witness JSON is tracked and reclaimed
/// like every other did:webvh working buffer rather than left to the garbage collector. Pooling it (rather than
/// wrapping the transport's GC body) keeps it uniform with the crypto working buffers and ready for the
/// pinned/zeroizing pool the resolver will adopt. <see cref="Content"/> is a read view into the owned buffer and
/// MUST NOT be used after <see cref="Dispose"/>.
/// </para>
/// </remarks>
public sealed class WebVhWitnessFile: IDisposable
{
    private readonly IMemoryOwner<byte> contentOwner;
    private readonly int contentLength;

    /// <summary>Creates a witness file, taking ownership of <paramref name="contentOwner"/>.</summary>
    /// <param name="entries">The parsed witness proof records, in file order.</param>
    /// <param name="contentOwner">The pooled buffer holding the fetched <c>did-witness.json</c> bytes; ownership transfers to this instance.</param>
    /// <param name="contentLength">The number of valid bytes at the start of <paramref name="contentOwner"/>.</param>
    public WebVhWitnessFile(ImmutableArray<WebVhWitnessProofEntry> entries, IMemoryOwner<byte> contentOwner, int contentLength)
    {
        ArgumentNullException.ThrowIfNull(contentOwner);

        Entries = entries;
        this.contentOwner = contentOwner;
        this.contentLength = contentLength;
    }

    /// <summary>The parsed witness proof records, in file order.</summary>
    public ImmutableArray<WebVhWitnessProofEntry> Entries { get; }

    /// <summary>The fetched <c>did-witness.json</c> bytes the proof options are re-derived from.</summary>
    public ReadOnlyMemory<byte> Content => contentOwner.Memory[..contentLength];

    /// <summary>Returns the pooled content buffer to the pool.</summary>
    public void Dispose()
    {
        contentOwner.Dispose();
    }
}


/// <summary>
/// Parses the fetched <c>did-witness.json</c> content (a JSON array of <see cref="WebVhWitnessProofEntry"/>)
/// into its records.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf, which owns JSON parsing. The records are bundled with their
/// pooled source bytes into a <see cref="WebVhWitnessFile"/> by the resolver. The JCS-canonical proof-options
/// the signature verification hashes over are produced separately and on demand through
/// <see cref="WebVhWitnessProofOptionsInput"/>, re-parsing those bytes.
/// </remarks>
/// <param name="content">The fetched <c>did-witness.json</c> bytes to parse.</param>
/// <returns>The parsed witness proof records, in file order.</returns>
public delegate ImmutableArray<WebVhWitnessProofEntry> WebVhWitnessFileParser(ReadOnlySpan<byte> content);


/// <summary>
/// Parses one raw <c>did.jsonl</c> log entry line into a <see cref="WebVhRawEntry"/>.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf, which owns JSON parsing. The canonical byte forms are
/// produced separately and on demand through <see cref="WebVhCanonicalizer"/>.
/// </remarks>
/// <param name="rawEntryLine">The UTF-8 bytes of a single <c>did.jsonl</c> line (without the trailing newline).</param>
/// <returns>The parsed entry.</returns>
public delegate WebVhRawEntry WebVhLineParser(ReadOnlyMemory<byte> rawEntryLine);


/// <summary>
/// Deserializes the <c>state</c> DIDDoc from a <c>did.jsonl</c> log entry line into a
/// <see cref="DidDocument"/>.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf so <see cref="Verifiable.Core"/> takes no serializer
/// dependency; returns <see langword="null"/> on malformed input rather than throwing.
/// </remarks>
/// <param name="rawEntryLine">The UTF-8 bytes of the resolved entry's <c>did.jsonl</c> line.</param>
/// <returns>The DID document from the entry's <c>state</c>, or <see langword="null"/> when it is not a valid document.</returns>
public delegate DidDocument? WebVhStateDeserializer(ReadOnlySpan<byte> rawEntryLine);


/// <summary>
/// The identity fields of a single entry's <c>state</c> DIDDoc the portability check reasons about: the
/// top-level <c>id</c> and the <c>alsoKnownAs</c> list (did:webvh v1.0, DID Portability).
/// </summary>
/// <param name="Id">The DIDDoc top-level <c>id</c>, or <see langword="null"/> when absent.</param>
/// <param name="AlsoKnownAs">The DIDDoc <c>alsoKnownAs</c> entries, or an empty array when absent.</param>
public sealed record WebVhDocumentIdentity(string? Id, ImmutableArray<string> AlsoKnownAs);


/// <summary>
/// Reads the <see cref="WebVhDocumentIdentity"/> (the <c>state</c> DIDDoc <c>id</c> and <c>alsoKnownAs</c>)
/// from a <c>did.jsonl</c> entry line.
/// </summary>
/// <remarks>
/// Implemented by the <c>Verifiable.Json</c> leaf. This reads only the two fixed identity fields the
/// portability check needs from each entry, rather than deserializing every entry's full DID document.
/// </remarks>
/// <param name="rawEntryLine">The UTF-8 bytes of a <c>did.jsonl</c> line.</param>
/// <returns>The entry's DIDDoc identity fields.</returns>
public delegate WebVhDocumentIdentity WebVhDocumentIdentityReader(ReadOnlySpan<byte> rawEntryLine);
