using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The typed <c>MetadataBLOBPayload</c> a Metadata BLOB's JWS payload segment decodes to, structurally
/// parsed but with the enclosing JWS signature NOT yet verified.
/// </summary>
/// <param name="LegalHeader">
/// The <c>legalHeader</c> member, or <see langword="null"/> when absent, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary</see>: "MUST be in each
/// BLOB, is an indication of the acceptance of the relevant legal agreement". This library exposes
/// the member's presence as data rather than enforcing that MUST itself — accepting or acting on a
/// legal agreement is not a verification-procedure concern.
/// </param>
/// <param name="No">
/// The <c>no</c> member — the BLOB's serial number, per the same section: "This serial number MUST
/// be incremented whenever the contents of the BLOB changes. Serial numbers MUST be consecutive and
/// strictly monotonic." <see cref="MetadataBlobVerification"/> reads this value from the unverified
/// payload to enforce monotonicity as part of its processing-rules procedure, before this payload is
/// projected to a verified <see cref="MetadataBlobPayload"/>.
/// </param>
/// <param name="NextUpdate">
/// The <c>nextUpdate</c> member — the ISO-8601 date by which a fresh BLOB SHOULD be downloaded, per
/// the same section. <see cref="MetadataBlobVerification"/> reads this value from the unverified
/// payload to enforce staleness as part of its processing-rules procedure, before this payload is
/// projected to a verified <see cref="MetadataBlobPayload"/>.
/// </param>
/// <param name="Entries">
/// The <c>entries</c> member, in wire order.
/// </param>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-payload-blob">FIDO
/// Metadata Service v3.1, section 3.1.6: Metadata BLOB Payload dictionary.</see>
/// <para>
/// The trust position is <em>unverified payload</em>: these entries have been parsed off the wire,
/// but the enclosing <see cref="UnverifiedMetadataBlob"/>'s JWS signature has not been checked, so
/// every entry in <see cref="Entries"/> is untrustworthy until
/// <see cref="MetadataBlobVerification"/>'s full processing-rules procedure passes and calls
/// <see cref="ToVerified"/>. A function expecting the verified <see cref="MetadataBlobPayload"/>
/// rejects this type at compile time, preventing an unverified payload from reaching a query that
/// requires a verified one — mirrors <see cref="Verifiable.JCose.UnverifiedJwtPayload"/>'s
/// trust-state rationale.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This payload owns <see cref="Entries"/> and disposes each one — a
/// single-owner tree: each entry separately owns its own
/// <see cref="MetadataBlobPayloadEntry.AttestationRootCertificates"/> list.
/// <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/> is an independent, GC-managed copy
/// (mirroring <c>PackedAttestationStatement.Signature</c>'s plain-array shape), so it needs no
/// pooled-buffer disposal of its own.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedMetadataBlobPayload(No={No}, NextUpdate={NextUpdate}, Entries={Entries.Count})")]
public sealed record UnverifiedMetadataBlobPayload(
    string? LegalHeader,
    long No,
    DateOnly NextUpdate,
    IReadOnlyList<MetadataBlobPayloadEntry> Entries): IDisposable
{
    /// <summary>
    /// Determines whether this payload and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Entries"/> by reference; this
    /// override compares it element-wise instead.
    /// </summary>
    /// <param name="other">The other payload to compare against.</param>
    /// <returns><see langword="true"/> when every member matches, including an element-wise comparison of <see cref="Entries"/>.</returns>
    public bool Equals(UnverifiedMetadataBlobPayload? other) =>
        other is not null
        && LegalHeader == other.LegalHeader
        && No == other.No
        && NextUpdate == other.NextUpdate
        && Entries.SequenceEqual(other.Entries);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(UnverifiedMetadataBlobPayload?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(LegalHeader, StringComparer.Ordinal);
        hash.Add(No);
        hash.Add(NextUpdate);
        foreach(MetadataBlobPayloadEntry entry in Entries)
        {
            hash.Add(entry);
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Projects this unverified payload to a verified <see cref="MetadataBlobPayload"/>, moving
    /// ownership of <see cref="Entries"/> to the returned instance without copying — the entries and
    /// the certificate carriers they own are the SAME objects, now reachable only through the
    /// returned payload.
    /// </summary>
    /// <returns>The verified payload.</returns>
    /// <remarks>
    /// This instance must not be used after calling this method, and in particular must not be
    /// disposed: <see cref="Entries"/> is now owned by the returned <see cref="MetadataBlobPayload"/>,
    /// and disposing both would dispose each entry twice.
    /// </remarks>
    public MetadataBlobPayload ToVerified() =>
        new(LegalHeader, No, NextUpdate, Entries);


    /// <summary>
    /// Releases every entry in <see cref="Entries"/>.
    /// </summary>
    public void Dispose()
    {
        foreach(MetadataBlobPayloadEntry entry in Entries)
        {
            entry.Dispose();
        }
    }
}


/// <summary>
/// A Metadata BLOB parsed from untrusted input: the compact-JWS envelope plus its typed payload,
/// structurally parsed but with the enclosing JWS signature NOT yet verified.
/// </summary>
/// <param name="Algorithm">
/// The JWT Header <c>alg</c> value, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see>. Checked against
/// <see cref="MetadataBlobVerification"/>'s supported-algorithm allowlist before anything else about
/// this instance is trusted.
/// </param>
/// <param name="X5c">
/// The JWT Header <c>x5c</c> certificate chain, leaf first, per RFC 7515 §4.1.6 — the BLOB signing
/// certificate chain, per the same section. Owned by this instance. Untrusted until
/// <see cref="MetadataBlobVerification"/> validates the chain against the caller's trust anchors.
/// </param>
/// <param name="SigningInput">
/// The exact bytes the JWS signature covers: <c>EncodedJWTHeader || "." || EncodedMetadataBLOBPayload</c>,
/// per the same section's <c>tbsPayload</c> definition. Aliases the buffer supplied to the
/// <see cref="ParseMetadataBlobDelegate"/> that produced this instance (wrap, don't copy) — it
/// remains valid only as long as that buffer does.
/// </param>
/// <param name="Signature">
/// The decoded JWS signature bytes (the third compact-serialization segment, base64url-decoded), not
/// yet checked against <see cref="SigningInput"/> and the leaf certificate's public key. ES256
/// signatures are already the fixed-width IEEE P1363 encoding per RFC 7518 §3.4 — no DER unwrap is
/// applied, unlike the WebAuthn attestation/assertion signature wire format.
/// </param>
/// <param name="Payload">
/// The typed, unverified <c>MetadataBLOBPayload</c>. Owned by this instance.
/// </param>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB.</see>
/// <para>
/// The trust position is <em>unverified BLOB</em>: <see cref="ParseMetadataBlobDelegate"/> has
/// checked only that the input is a structurally well-formed compact JWS conforming to the Metadata
/// BLOB syntax — the JWS signature over <see cref="SigningInput"/> has not been checked and the
/// <see cref="X5c"/> chain has not been validated against any trust anchor, so every member of this
/// instance, including <see cref="Payload"/>, is untrustworthy. A function expecting the verified
/// <see cref="MetadataBlob"/> rejects this type at compile time, preventing an unverified BLOB from
/// reaching a code path that requires a fully verified one — mirrors
/// <see cref="Verifiable.JCose.UnverifiedJwtPayload"/>'s trust-state rationale.
/// </para>
/// <para>
/// <see cref="MetadataBlobVerification"/> runs its full processing-rules procedure — algorithm
/// allowlist, chain validation, signature verification, serial-number monotonicity, and
/// <c>nextUpdate</c> staleness — against this type, and constructs the verified
/// <see cref="MetadataBlob"/> via <see cref="ToVerified"/> only once every check that procedure
/// performs has passed.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="X5c"/> and <see cref="Payload"/> and
/// disposes both; it does not own the buffer <see cref="SigningInput"/> aliases. A rejected
/// verification disposes this instance before returning; an accepted verification projects it to a
/// <see cref="MetadataBlob"/> via <see cref="ToVerified"/> instead of disposing it — see that
/// method's remarks on the ownership transfer this instance must not be used after.
/// </para>
/// </remarks>
[DebuggerDisplay("UnverifiedMetadataBlob(Algorithm={Algorithm,nq}, X5c={X5c.Count}, No={Payload.No})")]
public sealed record UnverifiedMetadataBlob(
    string Algorithm,
    IReadOnlyList<PkiCertificateMemory> X5c,
    ReadOnlyMemory<byte> SigningInput,
    ReadOnlyMemory<byte> Signature,
    UnverifiedMetadataBlobPayload Payload): IDisposable
{
    /// <summary>
    /// Determines whether this BLOB and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="X5c"/> and the
    /// <see cref="ReadOnlyMemory{T}"/> members by reference/identity; this override compares each
    /// by value instead.
    /// </summary>
    /// <param name="other">The other BLOB to compare against.</param>
    /// <returns><see langword="true"/> when every member matches by value.</returns>
    public bool Equals(UnverifiedMetadataBlob? other) =>
        other is not null
        && Algorithm == other.Algorithm
        && X5c.SequenceEqual(other.X5c)
        && SigningInput.Span.SequenceEqual(other.SigningInput.Span)
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && Payload.Equals(other.Payload);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(UnverifiedMetadataBlob?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Algorithm, StringComparer.Ordinal);
        foreach(PkiCertificateMemory certificate in X5c)
        {
            hash.Add(certificate);
        }

        hash.AddBytes(SigningInput.Span);
        hash.AddBytes(Signature.Span);
        hash.Add(Payload);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Projects this unverified BLOB to a verified <see cref="MetadataBlob"/>, moving ownership of
    /// <see cref="X5c"/> and <see cref="Payload"/> to the returned instance without copying — the
    /// underlying certificate carriers and payload entries are the SAME objects, now reachable only
    /// through the returned BLOB.
    /// </summary>
    /// <returns>The verified BLOB.</returns>
    /// <remarks>
    /// This instance must not be used after calling this method, and in particular must not be
    /// disposed: <see cref="X5c"/> and <see cref="Payload"/> are now owned by the returned
    /// <see cref="MetadataBlob"/>, and disposing both would dispose each member twice.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfer: the intermediate verified payload is captured by the returned MetadataBlob, whose caller owns disposal; disposing it here would dispose the live entries the returned instance carries.")]
    public MetadataBlob ToVerified() =>
        new(Algorithm, X5c, SigningInput, Signature, Payload.ToVerified());


    /// <summary>
    /// Releases <see cref="X5c"/> and <see cref="Payload"/>. Does not release the buffer
    /// <see cref="SigningInput"/> aliases — see the type-level ownership remarks.
    /// </summary>
    public void Dispose()
    {
        foreach(PkiCertificateMemory certificate in X5c)
        {
            certificate.Dispose();
        }

        Payload.Dispose();
    }
}


/// <summary>
/// Decodes a Metadata BLOB's raw compact-JWS bytes into an <see cref="UnverifiedMetadataBlob"/>.
/// </summary>
/// <param name="blobBytes">The raw compact-JWS bytes, exactly as the caller obtained them.</param>
/// <param name="pool">
/// The memory pool the decoded certificate carriers and the payload's shared raw-statement buffer
/// rent from.
/// </param>
/// <returns>The decoded, unverified BLOB.</returns>
/// <remarks>
/// The concrete JSON codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ParseAttestationObjectDelegate"/>. This delegate
/// checks only structural well-formedness; <see cref="MetadataBlobVerification"/> is what
/// establishes trust in the returned instance and projects it to a verified <see cref="MetadataBlob"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="blobBytes"/> is not a well-formed compact JWS conforming to the
/// Metadata BLOB syntax defined in
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7</see>, including an unsupported <c>x5u</c> header (out of
/// this library's fetcher-free scope).
/// </exception>
public delegate UnverifiedMetadataBlob ParseMetadataBlobDelegate(ReadOnlyMemory<byte> blobBytes, MemoryPool<byte> pool);
