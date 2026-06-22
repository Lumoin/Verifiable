using System;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Produces the entry-hash verification input: <c>JCS(entry with the <c>proof</c> property removed and
/// <c>versionId</c> set to <paramref name="predecessorVersionId"/>)</c>.
/// </summary>
/// <remarks>
/// The predecessor <c>versionId</c> is the SCID for the first entry and the previous entry's full
/// <c>versionId</c> otherwise (did:webvh v1.0, Entry Hash Generation and Verification). The returned
/// <see cref="TaggedMemory{T}"/> wraps the JCS serializer output tagged as JSON, the same way the JOSE layer
/// wraps its serialized JWT parts; the verification code reads the span and the buffer is GC-managed.
/// </remarks>
/// <param name="rawEntryLine">The UTF-8 bytes of the entry's <c>did.jsonl</c> line.</param>
/// <param name="predecessorVersionId">The predecessor <c>versionId</c>.</param>
/// <returns>The JCS-canonical bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhEntryHashInput(
    ReadOnlyMemory<byte> rawEntryLine,
    string predecessorVersionId);


/// <summary>
/// Produces the Data Integrity document input: <c>JCS(entry with the <c>proof</c> property removed)</c>, the
/// unsecured document the controller proof is computed over.
/// </summary>
/// <param name="rawEntryLine">The UTF-8 bytes of the entry's <c>did.jsonl</c> line.</param>
/// <returns>The JCS-canonical bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhDocumentInput(ReadOnlyMemory<byte> rawEntryLine);


/// <summary>
/// Produces the SCID verification input: <c>JCS(entry with <c>proof</c> removed and <c>versionId</c> set to
/// the literal "{SCID}")</c> with the scid value text-replaced by "{SCID}" on the canonical string
/// (did:webvh v1.0, SCID Generation and Verification).
/// </summary>
/// <param name="rawEntryLine">The UTF-8 bytes of the first entry's <c>did.jsonl</c> line.</param>
/// <param name="scid">The declared scid value to replace with the placeholder.</param>
/// <returns>The SCID verification input bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhScidInput(
    ReadOnlyMemory<byte> rawEntryLine,
    string scid);


/// <summary>
/// Produces the proof-options input: <c>JCS(the proof at <paramref name="proofIndex"/> with its
/// <c>proofValue</c> removed)</c>.
/// </summary>
/// <param name="rawEntryLine">The UTF-8 bytes of the entry's <c>did.jsonl</c> line.</param>
/// <param name="proofIndex">The zero-based index of the proof in the entry's <c>proof</c> array.</param>
/// <returns>The JCS-canonical proof-options bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhProofOptionsInput(
    ReadOnlyMemory<byte> rawEntryLine,
    int proofIndex);


/// <summary>
/// Produces the witness-proof document input: <c>JCS({"versionId": "&lt;versionId&gt;"})</c>, the single-property
/// object a witness proof in <c>did-witness.json</c> is computed over (did:webvh v1.0, The Witness Proofs File).
/// </summary>
/// <param name="versionId">The <c>versionId</c> the witness proof attests.</param>
/// <returns>The JCS-canonical versionId-object bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhWitnessDocumentInput(string versionId);


/// <summary>
/// Produces the witness proof-options input: <c>JCS(the proof at <paramref name="proofIndex"/> of the witness
/// record at <paramref name="entryIndex"/> with its <c>proofValue</c> removed)</c>.
/// </summary>
/// <remarks>
/// Re-parses <see cref="WebVhWitnessFile.Content"/> so the canonical proof options are derived from the exact
/// published proof object — including any fields the structural parse does not surface — the same way the log
/// entry proof options are re-derived from the raw entry line.
/// </remarks>
/// <param name="witnessFile">The parsed witness file, whose retained content is re-parsed.</param>
/// <param name="entryIndex">The zero-based index of the witness record in the file's top-level array.</param>
/// <param name="proofIndex">The zero-based index of the proof within that record's <c>proof</c> array.</param>
/// <returns>The JCS-canonical witness proof-options bytes tagged as JSON.</returns>
public delegate TaggedMemory<byte> WebVhWitnessProofOptionsInput(
    WebVhWitnessFile witnessFile,
    int entryIndex,
    int proofIndex);


/// <summary>
/// The bundle of on-demand did:webvh canonicalizers, implemented by the <c>Verifiable.Json</c> leaf, that
/// produce the JCS-canonical byte forms the verification steps hash and sign over.
/// </summary>
/// <remarks>
/// Each canonicalizer returns a <see cref="TaggedMemory{T}"/> wrapping the JCS serializer output, mirroring
/// the JOSE layer's tagged JWT-part buffers: there is no copy into a pool, and the verification code reads
/// the span without owning a disposable buffer.
/// </remarks>
public sealed record WebVhCanonicalizer
{
    /// <summary>The entry-hash input canonicalizer.</summary>
    public required WebVhEntryHashInput EntryHashInput { get; init; }

    /// <summary>The Data Integrity document canonicalizer.</summary>
    public required WebVhDocumentInput DocumentInput { get; init; }

    /// <summary>The SCID verification-input canonicalizer.</summary>
    public required WebVhScidInput ScidInput { get; init; }

    /// <summary>The proof-options canonicalizer.</summary>
    public required WebVhProofOptionsInput ProofOptionsInput { get; init; }

    /// <summary>The witness-proof document canonicalizer (<c>JCS({"versionId": ...})</c>).</summary>
    public required WebVhWitnessDocumentInput WitnessDocumentInput { get; init; }

    /// <summary>The witness proof-options canonicalizer.</summary>
    public required WebVhWitnessProofOptionsInput WitnessProofOptionsInput { get; init; }
}
