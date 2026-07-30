using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Whether the octets an <c>archive-time-stamp-v3</c> attribute's message imprint was computed over could be
/// stated for one signature, and if not, why not — the outcome vocabulary of the coverage computation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clauses 5.5.2 and 5.5.3</see>.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as a stated coverage.
/// Every value other than <see cref="Stated"/> means the same thing to a validation process: nothing has been
/// shown about what the token protects, which is the fail-closed reading of step 1) of clause 5.6.2.3.4 of
/// ETSI EN 319 102-1. The values exist to tell a diagnostician which of the conditions held.
/// </remarks>
public enum ArchiveTimestampCoverageStatus
{
    /// <summary>No computation has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The index was valid and the message imprint input of clause 5.5.3 was assembled.</summary>
    Stated = 1,

    /// <summary>The Signed Data Object could not be walked as a CMS SignedData whose signer this computation could reach.</summary>
    SignedDataMalformed = 2,

    /// <summary>The time-stamp token could not be walked as a CMS SignedData, or its content is not a readable <c>TSTInfo</c>.</summary>
    TokenMalformed = 3,

    /// <summary>
    /// The token carries no <c>ats-hash-index-v3</c> unsigned attribute. This is what an <c>archive-time-stamp</c>
    /// of the deprecated v2 form (Annex A.2.4) looks like from here: a genuine archive time-stamp whose covered
    /// octets this computation does not state.
    /// </summary>
    HashIndexAbsent = 4,

    /// <summary>The <c>ats-hash-index-v3</c> attribute is present but is not a single well-formed DER <c>ATSHashIndexV3</c>.</summary>
    HashIndexMalformed = 5,

    /// <summary>The index's <c>hashIndAlgorithm</c> is not the algorithm of the token's own message imprint, which clause 5.5.2 requires it to be.</summary>
    HashIndexAlgorithmMismatch = 6,

    /// <summary>The index names a hash algorithm this library cannot compute, so no hash value of it can be recomputed.</summary>
    HashIndexAlgorithmUnsupported = 7,

    /// <summary>
    /// The index is invalid per clause 5.5.2: it holds an entry for which no current certificate, revocation
    /// information object or unsigned attribute value produces a matching hash value.
    /// </summary>
    HashIndexInvalid = 8,

    /// <summary>
    /// The signature encapsulates no content and the caller supplied neither the detached content nor its
    /// digest, so step 2) of the imprint input of clause 5.5.3 has no value (clause 5.5.3 NOTE 1).
    /// </summary>
    SignedContentUnavailable = 9
}


/// <summary>
/// One object of a signature and whether the <c>ats-hash-index-v3</c> of an archive time-stamp covers it.
/// </summary>
/// <param name="Index">The zero-based position of the object within the field it was read from.</param>
/// <param name="IsCovered">Whether a hash-index entry matched this object's recomputed hash value.</param>
[DebuggerDisplay("Object {Index}: covered {IsCovered}")]
public readonly record struct CoveredObject(int Index, bool IsCovered);


/// <summary>
/// One <c>AttributeValue</c> of one unsigned attribute of a signature and whether the
/// <c>ats-hash-index-v3</c> of an archive time-stamp covers it. Clause 5.5.2 indexes unsigned attributes per
/// value rather than per attribute, so this is the unit of coverage the specification defines.
/// </summary>
/// <param name="AttributeIndex">The zero-based position of the <c>Attribute</c> within <c>unsignedAttrs</c>.</param>
/// <param name="ValueIndex">The zero-based position of the value within that attribute's <c>attrValues</c>.</param>
/// <param name="AttributeType">The attribute's <c>attrType</c> object identifier in dotted form.</param>
/// <param name="IsCovered">Whether a hash-index entry matched the recomputed hash of this attribute type and value.</param>
[DebuggerDisplay("Attribute {AttributeIndex} ({AttributeType}) value {ValueIndex}: covered {IsCovered}")]
public readonly record struct CoveredAttributeValue(int AttributeIndex, int ValueIndex, string AttributeType, bool IsCovered);


/// <summary>
/// Which objects of one signature an <c>ats-hash-index-v3</c> covers, per object, together with whether every
/// entry of the index found material to match — the two questions clause 5.5.2's semantics separates.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The check is asymmetric, and deliberately so.</strong> Clause 5.5.2 states one failure mode: the
/// index "is invalid if it contains a reference for which the original value is not found". It states no
/// requirement in the other direction. Material added to a signature after an archive time-stamp was applied
/// therefore has no entry, is reported here as not covered, and is not an error — NOTE 5 of that clause names
/// this as the point of the design: further certificates, revocation information and unsigned attributes can be
/// added later "without invalidating such an archive time-stamp". A reading that required every current object
/// to be indexed would make every augmentation break every earlier archive time-stamp.
/// </para>
/// </remarks>
public sealed record AtsHashIndexCoverage
{
    /// <summary>Gets the coverage of every instance of <c>CertificateChoices</c> in <c>SignedData.certificates</c>, in the order they appear.</summary>
    public required IReadOnlyList<CoveredObject> Certificates { get; init; }

    /// <summary>Gets the coverage of every instance of <c>RevocationInfoChoice</c> in <c>SignedData.crls</c>, in the order they appear.</summary>
    public required IReadOnlyList<CoveredObject> RevocationInformation { get; init; }

    /// <summary>Gets the coverage of every <c>AttributeValue</c> of every <c>Attribute</c> in the signer's <c>unsignedAttrs</c>.</summary>
    public required IReadOnlyList<CoveredAttributeValue> UnsignedAttributeValues { get; init; }

    /// <summary>
    /// Gets whether every entry of every hash-index list matched some current object. This is the validity
    /// condition of clause 5.5.2; <see langword="false"/> makes the <c>ats-hash-index-v3</c> invalid and the
    /// archive time-stamp unusable, whatever the per-object coverage says.
    /// </summary>
    public required bool EveryIndexEntryMatched { get; init; }
}


/// <summary>
/// The result of stating what one <c>archive-time-stamp-v3</c> protects: the octets its message imprint was
/// computed over, per clause 5.5.3, and which objects of the signature its <c>ats-hash-index-v3</c> covers, per
/// clause 5.5.2.
/// </summary>
/// <remarks>
/// The instance owns <see cref="MessageImprintInput"/>; disposing it returns that buffer. A caller handing the
/// octets onward — the format binding of the validation engine does exactly this — copies them into a carrier of
/// its own, so ownership never forks.
/// </remarks>
[DebuggerDisplay("ArchiveTimestampCoverage: {Status}")]
public sealed class ArchiveTimestampCoverage: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new result. Internal: an instance only ever comes from
    /// <see cref="ArchiveTimestampV3.StateCoverageAsync"/>, so a status and the members that status implies
    /// cannot disagree.
    /// </summary>
    /// <param name="status">Whether the coverage could be stated, and if not why.</param>
    /// <param name="messageImprintInput">The assembled imprint input, or <see langword="null"/> when nothing was stated.</param>
    /// <param name="protectedObjects">The per-object coverage, or <see langword="null"/> when the index was never evaluated against the material.</param>
    internal ArchiveTimestampCoverage(
        ArchiveTimestampCoverageStatus status,
        SignedContentMemory? messageImprintInput,
        AtsHashIndexCoverage? protectedObjects)
    {
        Status = status;
        MessageImprintInput = messageImprintInput;
        ProtectedObjects = protectedObjects;
    }


    /// <summary>Gets whether the coverage could be stated, and if not why.</summary>
    public ArchiveTimestampCoverageStatus Status { get; }

    /// <summary>Gets whether the coverage was stated, which is the only outcome a proof of existence may be derived from.</summary>
    public bool IsStated => Status == ArchiveTimestampCoverageStatus.Stated;

    /// <summary>
    /// Gets the octets the token's <c>messageImprint</c> is asserted to have been computed over — the four-part
    /// concatenation of clause 5.5.3 — or <see langword="null"/> when nothing was stated. Owned by this instance.
    /// </summary>
    public SignedContentMemory? MessageImprintInput { get; }

    /// <summary>
    /// Gets which objects of the signature the index covers, or <see langword="null"/> when the index could not
    /// be evaluated against the material at all. It is present, and worth reading, even when the index turned
    /// out to be invalid.
    /// </summary>
    public AtsHashIndexCoverage? ProtectedObjects { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            MessageImprintInput?.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// The inputs of the message imprint computation of clause 5.5.3 — what a generator hands the computation when
/// it is about to request an archive time-stamp token.
/// </summary>
public sealed record ArchiveTimestampImprintContext
{
    /// <summary>Gets the Signed Data Object the archive time-stamp is being applied to, as its wire octets.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>Gets the index that goes into the token's <c>ats-hash-index-v3</c> attribute and into step 4) of the imprint input.</summary>
    public required AtsHashIndexV3 HashIndex { get; init; }

    /// <summary>
    /// Gets the algorithm the archive time-stamp's message imprint is computed under, which step 2) of clause
    /// 5.5.3 also requires the signed data to be hashed under and clause 5.5.2 requires
    /// <see cref="AtsHashIndexV3.HashIndexAlgorithm"/> to equal.
    /// </summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the zero-based index of the <c>SignerInfo</c> the archive time-stamp corresponds to (clause 5.5.1: one attribute per <c>SignerInfo</c>).</summary>
    public int SignerIndex { get; init; }

    /// <summary>
    /// Gets the signed content of a detached signature, used for step 2) when the <c>SignedData</c> encapsulates
    /// no content. Clause 5.5.3 NOTE 1: for detached signatures the hash of the signed data has to come from
    /// outside the signature.
    /// </summary>
    public SignedContentMemory? DetachedSignedContent { get; init; }

    /// <summary>
    /// Gets the digest of the signed content of a detached signature, the other form clause 5.5.3 NOTE 1 admits
    /// ("the hash can be provided from an external trusted source"). It is used only when
    /// <see cref="DetachedSignedContent"/> is absent, and only when its length is the one
    /// <see cref="MessageImprintAlgorithm"/> produces — a digest under any other algorithm would silently
    /// compute an imprint over something the specification does not define.
    /// </summary>
    public DigestValue? DetachedSignedContentDigest { get; init; }
}


/// <summary>
/// The inputs of the coverage computation — what a verifier hands the computation for one archive time-stamp it
/// found on a signature.
/// </summary>
public sealed record ArchiveTimestampCoverageContext
{
    /// <summary>Gets the Signed Data Object the archive time-stamp was found on, as its wire octets.</summary>
    public required CmsSignedData SignedData { get; init; }

    /// <summary>Gets the time-stamp token the <c>archive-time-stamp-v3</c> attribute envelopes, as its wire octets.</summary>
    public required PkiCertificateMemory ArchiveTimestampToken { get; init; }

    /// <summary>Gets the zero-based index of the <c>SignerInfo</c> the archive time-stamp corresponds to.</summary>
    public int SignerIndex { get; init; }

    /// <summary>Gets the signed content of a detached signature, used for step 2) of clause 5.5.3 when the <c>SignedData</c> encapsulates none.</summary>
    public SignedContentMemory? DetachedSignedContent { get; init; }

    /// <summary>Gets the digest of the signed content of a detached signature, used only when the content itself is absent and only when its length matches the token's message-imprint algorithm.</summary>
    public DigestValue? DetachedSignedContentDigest { get; init; }
}


/// <summary>
/// The <c>archive-time-stamp-v3</c> and <c>ats-hash-index-v3</c> computations of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clauses 5.5.2 and 5.5.3</see>: building the hash index over what a signature
/// carries, assembling the four-part input the archive time-stamp's message imprint is computed over, and
/// deciding what an archive time-stamp already on a signature protects.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One implementation serves both directions.</strong> Creating an archive time-stamp and validating one
/// are the same computation read forwards and backwards: clause 5.5.2's verifier "recalculates" the hash values
/// and clause 5.5.3's verifier recomputes the message imprint "in the same way as in the creation of the
/// attribute". Both directions here walk the same structure through <c>ReadMaterial</c>, take the same digests
/// through <c>ComputeMaterialDigestsAsync</c>, and assemble the same concatenation through
/// <c>AssembleMessageImprintInput</c>. A generator and a verifier that disagreed about any of the three would
/// produce archive time-stamps nobody could validate, so there is deliberately no second implementation to
/// disagree with.
/// </para>
/// <para>
/// <strong>The imprint concatenates whole encodings; other time-stamps do not.</strong> Clause 5.5.3 builds its
/// input from fields "in their binary encoded form without any modification and including the tag, length and
/// value octets", and clause 5.5.2 hashes whole certificates, whole revocation entries, and whole attribute type
/// and value encodings. The <c>content-time-stamp</c> of clause 5.2.8 and the <c>signature-time-stamp</c> of
/// clause 5.3 do the opposite — they hash raw values "without the ASN.1 tag and length" — and the time-stamps on
/// references of Annex A.1.5 use a third convention again. Nothing here is shared with those computations, and
/// nothing here should be generalised into a helper they could reach: a helper that conflated the conventions
/// would produce imprints that verify against the wrong specification.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> Both the Signed Data Object and the token arrive from a network
/// location or a document. Every structure is read through <see cref="AsnReader"/>'s bounds-checked cursors, the
/// walks are straight-line with no recursion, octets trailing a structure are rejected rather than ignored, and
/// the number of certificates, revocation objects, attributes and attribute values walked is bounded. The
/// verifier-facing <see cref="StateCoverageAsync"/> never lets a parse failure escape: it maps every one of them
/// to a status that states no coverage, which is what the proof-of-existence extraction building block of
/// ETSI EN 319 102-1 clause 5.6.2.3 treats as a time-stamp that protects nothing it can name. The
/// generator-facing entry points fail with typed exceptions instead, because a generator handing in material it
/// cannot encode is a composition fault rather than an adversarial input.
/// </para>
/// </remarks>
public static class ArchiveTimestampV3
{
    /// <summary>The id-signedData content type (RFC 5652 §5.1).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The largest number of <c>SignerInfo</c> structures traversed while looking for the chosen signer.</summary>
    private const int MaximumSignerInfos = 64;

    /// <summary>The largest number of instances of <c>CertificateChoices</c> walked, matching the bound the CAdES facts binding reads certificates within.</summary>
    private const int MaximumCertificates = 256;

    /// <summary>The largest number of instances of <c>RevocationInfoChoice</c> walked, matching the bound the CAdES facts binding reads revocation objects within.</summary>
    private const int MaximumRevocationInformation = 256;

    /// <summary>The largest number of unsigned attributes walked, matching the bound the CAdES facts binding surfaces attributes within.</summary>
    private const int MaximumUnsignedAttributes = 64;

    /// <summary>The largest number of unsigned attribute values walked across all attributes, each of which costs one digest.</summary>
    private const int MaximumUnsignedAttributeValues = 256;

    /// <summary>The <c>[0]</c> constructed context tag: <c>ContentInfo.content</c>, <c>SignedData.certificates</c>, <c>SignerInfo.signedAttrs</c>.</summary>
    private static Asn1Tag ContextConstructed0 { get; } = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The <c>[1]</c> constructed context tag: <c>SignedData.crls</c> and <c>SignerInfo.unsignedAttrs</c>.</summary>
    private static Asn1Tag ContextConstructed1 { get; } = new(TagClass.ContextSpecific, 1, isConstructed: true);


    /// <summary>
    /// Computes the <c>ats-hash-index-v3</c> of clause 5.5.2 over what a signature carries right now: a hash
    /// value for every instance of <c>CertificateChoices</c> in <c>SignedData.certificates</c>, one for every
    /// instance of <c>RevocationInfoChoice</c> in <c>SignedData.crls</c>, and one for every <c>AttributeValue</c>
    /// of every <c>Attribute</c> in the signer's <c>unsignedAttrs</c> — "a hash value for every instance ... as
    /// present at the time when the corresponding archive time-stamp is requested", and no other hash value.
    /// </summary>
    /// <param name="signedData">The Signed Data Object the archive time-stamp is being applied to.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> the archive time-stamp corresponds to.</param>
    /// <param name="hashIndexAlgorithm">The algorithm every hash value is computed under, which clause 5.5.2 requires to be the algorithm of the token's own message imprint.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoded index. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this computation walks within.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host.</exception>
    public static async ValueTask<AtsHashIndexV3> ComputeHashIndexAsync(
        CmsSignedData signedData,
        int signerIndex,
        PkiDigestAlgorithm hashIndexAlgorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        CmsArchiveMaterial material = ReadMaterial(signedData.AsReadOnlyMemory(), signerIndex);
        using MaterialDigests digests = await ComputeMaterialDigestsAsync(material, hashIndexAlgorithm, pool, cancellationToken).ConfigureAwait(false);

        return AtsHashIndexV3.Create(
            hashIndexAlgorithm, digests.Certificates, digests.RevocationInformation, digests.UnsignedAttributeValues, pool);
    }


    /// <summary>
    /// Assembles the octets an <c>archive-time-stamp-v3</c>'s message imprint is computed over, per clause
    /// 5.5.3: the concatenation, in this order, of the <c>SignedData.encapContentInfo.eContentType</c> field,
    /// the hash of the signed data under the archive time-stamp's own algorithm, the <c>version</c>, <c>sid</c>,
    /// <c>digestAlgorithm</c>, <c>signedAttrs</c>, <c>signatureAlgorithm</c> and <c>signature</c> fields of the
    /// corresponding <c>SignerInfo</c> in their order of appearance, and a single instance of
    /// <c>ATSHashIndexV3</c>.
    /// </summary>
    /// <param name="context">The Signed Data Object, the index, the algorithm, and any detached signed content.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The imprint input. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the context's signer index is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index, or the signed data is neither encapsulated nor supplied.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries trailing octets.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    /// <remarks>
    /// <para>
    /// Step 2)'s hash is recomputed over the signed content under the archive time-stamp's own algorithm; it is
    /// never taken from the <c>message-digest</c> signed attribute, whose value was computed under the signer's
    /// digest algorithm and equals it only when the two algorithms happen to coincide. Clause 5.5.3 states the
    /// rule directly: "The hash algorithm applied shall be the same as the hash algorithm used for computing the
    /// archive time-stamp's message imprint."
    /// </para>
    /// <para>
    /// The <c>unsignedAttrs</c> field is excluded from step 3), which is what makes the scheme extensible: the
    /// unsigned attributes are bound instead through the hash index of step 4), one entry per attribute value,
    /// so later additions leave the earlier imprint intact.
    /// </para>
    /// </remarks>
    public static async ValueTask<SignedContentMemory> BuildMessageImprintInputAsync(
        ArchiveTimestampImprintContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(context.SignerIndex);

        CmsArchiveMaterial material = ReadMaterial(context.SignedData.AsReadOnlyMemory(), context.SignerIndex);
        using DigestValue? signedContentDigest = await ResolveSignedContentDigestAsync(
            material, context.DetachedSignedContent, context.DetachedSignedContentDigest, context.MessageImprintAlgorithm, pool, cancellationToken).ConfigureAwait(false);
        if(signedContentDigest is null)
        {
            throw new CryptographicException(
                "The signature encapsulates no content and neither the detached signed content nor its digest was supplied, so step 2) of the archive time-stamp's message imprint input has no value (ETSI EN 319 122-1 clause 5.5.3 NOTE 1).");
        }

        return AssembleMessageImprintInput(material, signedContentDigest.AsReadOnlySpan(), context.HashIndex.AsReadOnlySpan(), pool);
    }


    /// <summary>
    /// States what one <c>archive-time-stamp-v3</c> already on a signature protects: it reads the
    /// <c>ats-hash-index-v3</c> out of the token, checks the index against the material the signature carries
    /// now per clause 5.5.2, and — only when the index is valid — assembles the octets the token's
    /// <c>messageImprint</c> should be the digest of, per clause 5.5.3.
    /// </summary>
    /// <param name="context">The Signed Data Object, the token, and any detached signed content.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The result, which the caller disposes in every case.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the context's signer index is negative.</exception>
    /// <exception cref="InvalidOperationException">When no <see cref="ComputeDigestDelegate"/> has been registered — a composition fault of the host, never an outcome of the input.</exception>
    /// <remarks>
    /// <para>
    /// The caller of this computation does not have to trust it: the octets it returns are a claim about what
    /// the token's message imprint was computed over, and the validation process checks that claim by hashing
    /// them under the token's own algorithm and comparing the result to the token's <c>messageImprint</c> field.
    /// A claim that does not hold makes the time-stamp protect nothing, exactly as a stated status of anything
    /// other than <see cref="ArchiveTimestampCoverageStatus.Stated"/> does.
    /// </para>
    /// <para>
    /// Clause 5.5.2 has the index validated first and the imprint recomputed only afterwards, and that order is
    /// kept here: an invalid index yields no imprint input at all, so a signature whose archive time-stamp
    /// references material that is no longer there can derive no proof of existence from that token.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the assembled imprint input transfers to the returned result, which the caller disposes; every failure path returns a result that owns nothing.")]
    public static async ValueTask<ArchiveTimestampCoverage> StateCoverageAsync(
        ArchiveTimestampCoverageContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(context.SignerIndex);

        CmsArchiveMaterial material;
        try
        {
            material = ReadMaterial(context.SignedData.AsReadOnlyMemory(), context.SignerIndex);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return NotStated(ArchiveTimestampCoverageStatus.SignedDataMalformed);
        }

        CmsArchiveMaterial tokenMaterial;
        try
        {
            //A time-stamp token is itself a CMS SignedData, so the same walk reaches both its encapsulated
            //TSTInfo and the unsigned attributes of its own signer, which is where clause 5.5.3 places the
            //ats-hash-index-v3 the token has to include.
            tokenMaterial = ReadMaterial(context.ArchiveTimestampToken.AsReadOnlyMemory(), signerIndex: 0);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return NotStated(ArchiveTimestampCoverageStatus.TokenMalformed);
        }

        AtsHashIndexV3? hashIndex = null;
        try
        {
            ArchiveTimestampCoverageStatus readStatus = TryReadHashIndex(tokenMaterial, pool, out hashIndex);
            if(readStatus != ArchiveTimestampCoverageStatus.Stated)
            {
                return NotStated(readStatus);
            }

            if(!tokenMaterial.HasEncapsulatedContent)
            {
                return NotStated(ArchiveTimestampCoverageStatus.TokenMalformed);
            }

            using TimestampTokenInfo tokenInfo = TimestampTokenInfo.Read(tokenMaterial.EncapsulatedContent, pool);
            if(!tokenInfo.IsRead)
            {
                return NotStated(ArchiveTimestampCoverageStatus.TokenMalformed);
            }

            //Clause 5.5.2: hashIndAlgorithm "shall be the same as the hash algorithm used for computing the
            //message imprint included in the time-stamp token enveloped in the archive time-stamp unsigned
            //attribute". An index under another algorithm names hash values of objects nothing binds.
            if(!string.Equals(hashIndex!.HashIndexAlgorithm.Oid, tokenInfo.MessageImprintAlgorithm.Oid, StringComparison.Ordinal))
            {
                return NotStated(ArchiveTimestampCoverageStatus.HashIndexAlgorithmMismatch);
            }

            if(PkiDigestAlgorithm.FromOid(hashIndex.HashIndexAlgorithm.Oid) is not PkiDigestAlgorithm algorithm)
            {
                return NotStated(ArchiveTimestampCoverageStatus.HashIndexAlgorithmUnsupported);
            }

            using MaterialDigests digests = await ComputeMaterialDigestsAsync(material, algorithm, pool, cancellationToken).ConfigureAwait(false);
            AtsHashIndexCoverage coverage = EvaluateCoverage(hashIndex, digests, material);
            if(!coverage.EveryIndexEntryMatched)
            {
                return new ArchiveTimestampCoverage(ArchiveTimestampCoverageStatus.HashIndexInvalid, messageImprintInput: null, coverage);
            }

            using DigestValue? signedContentDigest = await ResolveSignedContentDigestAsync(
                material, context.DetachedSignedContent, context.DetachedSignedContentDigest, algorithm, pool, cancellationToken).ConfigureAwait(false);
            if(signedContentDigest is null)
            {
                return new ArchiveTimestampCoverage(ArchiveTimestampCoverageStatus.SignedContentUnavailable, messageImprintInput: null, coverage);
            }

            SignedContentMemory imprintInput = AssembleMessageImprintInput(
                material, signedContentDigest.AsReadOnlySpan(), hashIndex.AsReadOnlySpan(), pool);

            return new ArchiveTimestampCoverage(ArchiveTimestampCoverageStatus.Stated, imprintInput, coverage);
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return NotStated(ArchiveTimestampCoverageStatus.SignedDataMalformed);
        }
        finally
        {
            hashIndex?.Dispose();
        }

        //Builds the result of every outcome that states nothing, so no branch has to repeat the null members.
        static ArchiveTimestampCoverage NotStated(ArchiveTimestampCoverageStatus status) =>
            new(status, messageImprintInput: null, protectedObjects: null);
    }


    /// <summary>
    /// Reads the single <c>ats-hash-index-v3</c> attribute clause 5.5.3 requires an <c>archive-time-stamp-v3</c>
    /// token to include among the unsigned attributes of its own <c>SignerInfo</c>.
    /// </summary>
    /// <param name="archiveTimestampToken">The time-stamp token the <c>archive-time-stamp-v3</c> attribute envelopes.</param>
    /// <param name="pool">The memory pool the returned index is rented from.</param>
    /// <returns>The index, or <see langword="null"/> when the token carries no single well-formed one. The caller owns and disposes what is returned.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// A token of the deprecated v2 archive time-stamp form (Annex A.2.4) carries no such attribute and yields
    /// <see langword="null"/> here, as does a token whose attribute is malformed:
    /// <see cref="StateCoverageAsync"/> distinguishes the two in its status, while a caller that only wants the
    /// index has the same thing to do in either case.
    /// </remarks>
    public static AtsHashIndexV3? ReadHashIndexFromToken(PkiCertificateMemory archiveTimestampToken, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(archiveTimestampToken);
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            CmsArchiveMaterial tokenMaterial = ReadMaterial(archiveTimestampToken.AsReadOnlyMemory(), signerIndex: 0);

            return TryReadHashIndex(tokenMaterial, pool, out AtsHashIndexV3? hashIndex) == ArchiveTimestampCoverageStatus.Stated ? hashIndex : null;
        }
        catch(Exception exception) when(exception is AsnContentException or CryptographicException)
        {
            return null;
        }
    }


    /// <summary>
    /// Finds the <c>ats-hash-index-v3</c> attribute among a token's own unsigned attributes and decodes its
    /// single value.
    /// </summary>
    /// <param name="tokenMaterial">The walked structure of the time-stamp token.</param>
    /// <param name="pool">The memory pool the decoded index is rented from.</param>
    /// <param name="hashIndex">Receives the decoded index, or <see langword="null"/> when there is none to decode.</param>
    /// <returns><see cref="ArchiveTimestampCoverageStatus.Stated"/> when an index was decoded, otherwise the status naming why not.</returns>
    private static ArchiveTimestampCoverageStatus TryReadHashIndex(CmsArchiveMaterial tokenMaterial, MemoryPool<byte> pool, out AtsHashIndexV3? hashIndex)
    {
        hashIndex = null;
        ReadOnlyMemory<byte> encodedValue = default;
        int found = 0;
        for(int i = 0; i < tokenMaterial.UnsignedAttributeValues.Count; ++i)
        {
            UnsignedAttributeValueMaterial value = tokenMaterial.UnsignedAttributeValues[i];
            if(string.Equals(value.AttributeType, CAdESSignatureFacts.AtsHashIndexV3AttributeOid, StringComparison.Ordinal))
            {
                encodedValue = value.Value;
                ++found;
            }
        }

        if(found == 0)
        {
            return ArchiveTimestampCoverageStatus.HashIndexAbsent;
        }

        //Clause 5.5.2 gives the attribute exactly one AttributeValue, and clause 5.5.3 has the token include a
        //single ats-hash-index-v3 attribute. Two values, or two attributes, leave which instance step 4) of the
        //imprint input concatenates undecided, so nothing is stated rather than one of them guessed at.
        if(found > 1 || encodedValue.IsEmpty)
        {
            return ArchiveTimestampCoverageStatus.HashIndexMalformed;
        }

        try
        {
            hashIndex = AtsHashIndexV3.Read(encodedValue.Span, pool);

            return ArchiveTimestampCoverageStatus.Stated;
        }
        catch(AsnContentException)
        {
            return ArchiveTimestampCoverageStatus.HashIndexMalformed;
        }
    }


    /// <summary>
    /// Recomputes the hash value of every object the three lists of clause 5.5.2 index, under one algorithm and
    /// through the registered digest seam.
    /// </summary>
    /// <param name="material">The walked structure of the signature.</param>
    /// <param name="algorithm">The algorithm every hash value is computed under.</param>
    /// <param name="pool">The memory pool every digest and every concatenation buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digests, which the caller disposes as one.</returns>
    private static async ValueTask<MaterialDigests> ComputeMaterialDigestsAsync(
        CmsArchiveMaterial material,
        PkiDigestAlgorithm algorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        var digests = new MaterialDigests();
        try
        {
            for(int i = 0; i < material.Certificates.Count; ++i)
            {
                digests.Certificates.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                    material.Certificates[i], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            for(int i = 0; i < material.RevocationInformation.Count; ++i)
            {
                digests.RevocationInformation.Add(await CryptographicKeyEvents.ComputeDigestAsync(
                    material.RevocationInformation[i], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false));
            }

            for(int i = 0; i < material.UnsignedAttributeValues.Count; ++i)
            {
                //Clause 5.5.2: "the hash value of the octets resulting from concatenating the corresponding
                //Attribute.attrType field and one of the instances of AttributeValue within the
                //Attribute.attrValues field", both whole encodings, tag and length octets included.
                UnsignedAttributeValueMaterial value = material.UnsignedAttributeValues[i];
                digests.UnsignedAttributeValues.Add(await ComputeConcatenatedDigestAsync(
                    value.AttributeTypeEncoding, value.Value, algorithm, pool, cancellationToken).ConfigureAwait(false));
            }

            return digests;
        }
        catch
        {
            digests.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Computes the digest of two encodings laid end to end, without either of them being copied into a longer
    /// lived buffer than the computation itself.
    /// </summary>
    /// <param name="first">The octets that come first.</param>
    /// <param name="second">The octets that follow them.</param>
    /// <param name="algorithm">The algorithm the digest is computed under.</param>
    /// <param name="pool">The memory pool the concatenation buffer and the digest are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest. The caller disposes it.</returns>
    private static async ValueTask<DigestValue> ComputeConcatenatedDigestAsync(
        ReadOnlyMemory<byte> first,
        ReadOnlyMemory<byte> second,
        PkiDigestAlgorithm algorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        int total = first.Length + second.Length;
        using IMemoryOwner<byte> concatenation = pool.Rent(total);
        first.CopyTo(concatenation.Memory);
        second.CopyTo(concatenation.Memory[first.Length..]);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            concatenation.Memory[..total], algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Resolves the hash of the signed data that step 2) of clause 5.5.3 concatenates: the encapsulated content
    /// when the signature carries it, otherwise what the caller supplied for a detached signature.
    /// </summary>
    /// <param name="material">The walked structure of the signature.</param>
    /// <param name="detachedContent">The detached signed content, when the caller has it.</param>
    /// <param name="detachedDigest">The digest of the detached signed content, when the caller has only that.</param>
    /// <param name="algorithm">The archive time-stamp's own algorithm, which the hash has to be computed under.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest, which the caller disposes, or <see langword="null"/> when there is no signed data to hash.</returns>
    private static async ValueTask<DigestValue?> ResolveSignedContentDigestAsync(
        CmsArchiveMaterial material,
        SignedContentMemory? detachedContent,
        DigestValue? detachedDigest,
        PkiDigestAlgorithm algorithm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(material.HasEncapsulatedContent)
        {
            return await CryptographicKeyEvents.ComputeDigestAsync(
                material.EncapsulatedContent, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        if(detachedContent is SignedContentMemory content)
        {
            return await CryptographicKeyEvents.ComputeDigestAsync(
                content.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        //A digest of another length was computed under another algorithm than the one the archive time-stamp
        //names, and clause 5.5.3 requires step 2)'s hash to be under that algorithm. Using it would compute an
        //imprint over a concatenation the specification does not define, so it is refused rather than adapted.
        if(detachedDigest is DigestValue supplied && supplied.AsReadOnlySpan().Length == algorithm.OutputByteLength)
        {
            return CopySuppliedDigest(supplied.AsReadOnlySpan(), algorithm.DigestTag, pool);
        }

        return null;

        //Copies a digest the caller owns into one this computation owns, so every path out of here returns a
        //carrier with the same, single owner.
        static DigestValue CopySuppliedDigest(ReadOnlySpan<byte> digest, Tag tag, MemoryPool<byte> pool)
        {
            IMemoryOwner<byte> owner = pool.Rent(digest.Length);
            try
            {
                digest.CopyTo(owner.Memory.Span);

                return new DigestValue(owner, tag);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }
    }


    /// <summary>
    /// Lays out the four parts of the message imprint input of clause 5.5.3 end to end, in the order the clause
    /// lists them.
    /// </summary>
    /// <param name="material">The walked structure of the signature.</param>
    /// <param name="signedContentDigest">The octets representing the hash of the signed data, part 2).</param>
    /// <param name="hashIndex">The DER-encoded <c>ATSHashIndexV3</c>, part 4).</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The imprint input. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static SignedContentMemory AssembleMessageImprintInput(
        CmsArchiveMaterial material,
        ReadOnlySpan<byte> signedContentDigest,
        ReadOnlySpan<byte> hashIndex,
        MemoryPool<byte> pool)
    {
        int total = material.EncapsulatedContentTypeEncoding.Length + signedContentDigest.Length + hashIndex.Length;
        for(int i = 0; i < material.SignerInfoFields.Count; ++i)
        {
            total += material.SignerInfoFields[i].Length;
        }

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> destination = owner.Memory.Span[..total];
            int written = 0;

            //1) SignedData.encapContentInfo.eContentType, tag and length octets included.
            material.EncapsulatedContentTypeEncoding.Span.CopyTo(destination[written..]);
            written += material.EncapsulatedContentTypeEncoding.Length;

            //2) The octets representing the hash of the signed data.
            signedContentDigest.CopyTo(destination[written..]);
            written += signedContentDigest.Length;

            //3) version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm and signature of the SignerInfo,
            //in their order of appearance and without unsignedAttrs.
            for(int i = 0; i < material.SignerInfoFields.Count; ++i)
            {
                material.SignerInfoFields[i].Span.CopyTo(destination[written..]);
                written += material.SignerInfoFields[i].Length;
            }

            //4) A single instance of ATSHashIndexV3.
            hashIndex.CopyTo(destination[written..]);
            written += hashIndex.Length;

            Debug.Assert(written == total, "The imprint input fills exactly the length its four parts add up to.");

            return new SignedContentMemory(owner);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Decides which objects an index covers and whether every one of its entries found material to match — the
    /// membership test of clause 5.5.2's semantics, run from the index towards the material and then read back
    /// the other way for reporting.
    /// </summary>
    /// <param name="hashIndex">The index read out of the token.</param>
    /// <param name="digests">The recomputed hash values of everything the signature carries now.</param>
    /// <param name="material">The walked structure of the signature, which names the attribute values.</param>
    /// <returns>The per-object coverage.</returns>
    private static AtsHashIndexCoverage EvaluateCoverage(AtsHashIndexV3 hashIndex, MaterialDigests digests, CmsArchiveMaterial material)
    {
        bool[] certificatesCovered = new bool[digests.Certificates.Count];
        bool[] revocationCovered = new bool[digests.RevocationInformation.Count];
        bool[] attributeValuesCovered = new bool[digests.UnsignedAttributeValues.Count];

        bool everyEntryMatched = MatchEntries(hashIndex.CertificatesHashIndex, digests.Certificates, certificatesCovered);
        everyEntryMatched &= MatchEntries(hashIndex.CrlsHashIndex, digests.RevocationInformation, revocationCovered);
        everyEntryMatched &= MatchEntries(hashIndex.UnsignedAttributeValuesHashIndex, digests.UnsignedAttributeValues, attributeValuesCovered);

        var certificates = new List<CoveredObject>(certificatesCovered.Length);
        for(int i = 0; i < certificatesCovered.Length; ++i)
        {
            certificates.Add(new CoveredObject(i, certificatesCovered[i]));
        }

        var revocationInformation = new List<CoveredObject>(revocationCovered.Length);
        for(int i = 0; i < revocationCovered.Length; ++i)
        {
            revocationInformation.Add(new CoveredObject(i, revocationCovered[i]));
        }

        var attributeValues = new List<CoveredAttributeValue>(attributeValuesCovered.Length);
        for(int i = 0; i < attributeValuesCovered.Length; ++i)
        {
            UnsignedAttributeValueMaterial value = material.UnsignedAttributeValues[i];
            attributeValues.Add(new CoveredAttributeValue(value.AttributeIndex, value.ValueIndex, value.AttributeType, attributeValuesCovered[i]));
        }

        return new AtsHashIndexCoverage
        {
            Certificates = certificates,
            RevocationInformation = revocationInformation,
            UnsignedAttributeValues = attributeValues,
            EveryIndexEntryMatched = everyEntryMatched
        };
    }


    /// <summary>
    /// Tests one hash-index list against the recomputed hash values of the material of its kind, marking every
    /// object an entry matched.
    /// </summary>
    /// <param name="entries">The index list's entries.</param>
    /// <param name="digests">The recomputed hash values, in the order the objects appear.</param>
    /// <param name="covered">Receives, per object, whether some entry matched it.</param>
    /// <returns><see langword="true"/> when every entry matched at least one object, which is what clause 5.5.2 requires of a valid index.</returns>
    private static bool MatchEntries(IReadOnlyList<ReadOnlyMemory<byte>> entries, List<DigestValue> digests, Span<bool> covered)
    {
        bool everyEntryMatched = true;
        for(int entry = 0; entry < entries.Count; ++entry)
        {
            bool matched = false;
            for(int i = 0; i < digests.Count; ++i)
            {
                //The scan does not stop at the first match: two identical objects — which clause 6.3's
                //requirement e) discourages but does not forbid — share a hash value, and one entry covers both.
                if(digests[i].AsReadOnlySpan().SequenceEqual(entries[entry].Span))
                {
                    covered[i] = true;
                    matched = true;
                }
            }

            everyEntryMatched &= matched;
        }

        return everyEntryMatched;
    }


    /// <summary>
    /// Walks a CMS SignedData down to one signer, collecting exactly what clauses 5.5.2 and 5.5.3 name: the
    /// encapsulated content type and content, every instance of <c>CertificateChoices</c> and
    /// <c>RevocationInfoChoice</c>, the signer's fields other than <c>unsignedAttrs</c>, and every value of
    /// every unsigned attribute.
    /// </summary>
    /// <param name="encoded">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> to read.</param>
    /// <returns>The walked structure, whose members are views into <paramref name="encoded"/>.</returns>
    /// <exception cref="CryptographicException">When the structure is not a CMS SignedData with a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    /// <remarks>
    /// Read under <see cref="AsnEncodingRules.DER"/>, not <see cref="AsnEncodingRules.BER"/>, and this is a
    /// knowing narrowing rather than an oversight: <see cref="CmsSignedDataAugmentation"/> preserves BER
    /// indefinite-length framing on the octets it splices (clause 4.7.2 permits BER generally), because a
    /// third-party verifier may still need to check such a signature byte-for-byte, but this computation — the
    /// <c>ats-hash-index-v3</c> index and the archive time-stamp's message imprint input, clauses 5.5.2/5.5.3 —
    /// has no re-encoding step that could turn an indefinite-length BER structure into the DER this walk needs
    /// without risking the very re-encoding NOTE 7 forbids, so an indefinite-length Signed Data Object is
    /// rejected here (surfacing as <see cref="AsnContentException"/>, mapped by every caller to
    /// <see cref="ArchiveTimestampCoverageStatus.SignedDataMalformed"/> or the augmentation-side equivalent)
    /// rather than accepted and mishandled. This is the documented gap: a signature this library's own
    /// augmentation surface has left in legal indefinite-length BER form is not self-validatable by this
    /// computation.
    /// </remarks>
    private static CmsArchiveMaterial ReadMaterial(ReadOnlyMemory<byte> encoded, int signerIndex)
    {
        var outer = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        if(contentInfo.PeekTag() != Asn1Tag.ObjectIdentifier)
        {
            //Classified the same way the augmentation primitive classifies it: a structure that parses as DER but
            //is not shaped like a ContentInfo is a cryptographic-structure failure, not a malformed encoding.
            throw new CryptographicException("A CMS ContentInfo begins with its contentType object identifier (RFC 5652 §3).");
        }

        string contentType = contentInfo.ReadObjectIdentifier();
        if(!string.Equals(contentType, SignedDataOid, StringComparison.Ordinal))
        {
            throw new CryptographicException($"The CMS content type '{contentType}' is not id-signedData (RFC 5652 §5.1).");
        }

        AsnReader explicitContent = contentInfo.ReadSequence(ContextConstructed0);
        contentInfo.ThrowIfNotEmpty();
        AsnReader signedData = explicitContent.ReadSequence();
        explicitContent.ThrowIfNotEmpty();

        _ = signedData.ReadEncodedValue();
        _ = signedData.ReadEncodedValue();

        AsnReader encapContentInfo = signedData.ReadSequence();
        ReadOnlyMemory<byte> contentTypeEncoding = encapContentInfo.ReadEncodedValue();
        ReadOnlyMemory<byte> content = default;
        bool hasContent = false;
        if(encapContentInfo.HasData)
        {
            AsnReader eContent = encapContentInfo.ReadSequence(ContextConstructed0);

            //A DER OCTET STRING is primitive, so its content octets are a view into the structure rather than
            //something to reassemble. A constructed one is not DER, and rather than concatenate its segments and
            //hash something whose provenance is no longer a slice of the input, the content is treated as absent
            //so the caller's own copy of the signed data, or nothing at all, decides step 2) of clause 5.5.3.
            hasContent = eContent.TryReadPrimitiveOctetString(out content);
        }

        List<ReadOnlyMemory<byte>> certificates = ReadChoiceSet(signedData, ContextConstructed0, MaximumCertificates, "certificates");
        List<ReadOnlyMemory<byte>> revocationInformation = ReadChoiceSet(signedData, ContextConstructed1, MaximumRevocationInformation, "crls");

        AsnReader signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
        signedData.ThrowIfNotEmpty();

        AsnReader signerInfo = LocateSignerInfo(signerInfos, signerIndex);
        List<ReadOnlyMemory<byte>> fields = [];
        ReadSignerInfoFields(signerInfo, fields, out ReadOnlyMemory<byte> unsignedAttributes, out bool hasUnsignedAttributes);
        List<UnsignedAttributeValueMaterial> unsignedAttributeValues = hasUnsignedAttributes
            ? ReadUnsignedAttributeValues(unsignedAttributes)
            : [];

        return new CmsArchiveMaterial(
            contentTypeEncoding, content, hasContent, certificates, revocationInformation, fields, unsignedAttributeValues);
    }


    /// <summary>
    /// Reads one optional implicitly tagged <c>SET OF</c> of a <c>SignedData</c> — <c>certificates</c> or
    /// <c>crls</c> — returning every member's whole encoding.
    /// </summary>
    /// <param name="signedData">The reader positioned inside the <c>SignedData</c> SEQUENCE.</param>
    /// <param name="setTag">The implicit tag the field carries.</param>
    /// <param name="maximumMembers">The largest number of members read.</param>
    /// <param name="fieldName">The field's name, for the message of a bound failure.</param>
    /// <returns>The members' encodings, in the order they appear, or an empty list when the field is absent.</returns>
    /// <exception cref="AsnContentException">When the set is malformed or holds more members than the bound admits.</exception>
    /// <remarks>
    /// Every member is taken, not only the ones a certificate or revocation-list parser would understand:
    /// clause 5.5.2 indexes "every instance of <c>CertificateChoices</c>" and every instance of
    /// <c>RevocationInfoChoice</c>, which includes the attribute-certificate and other-format alternatives, and
    /// "no other hash value shall be included". Skipping an alternative would build an index a conformant
    /// verifier finds entries missing from.
    /// </remarks>
    private static List<ReadOnlyMemory<byte>> ReadChoiceSet(AsnReader signedData, Asn1Tag setTag, int maximumMembers, string fieldName)
    {
        List<ReadOnlyMemory<byte>> members = [];
        if(!signedData.HasData || signedData.PeekTag() != setTag)
        {
            //Clause 5.5.2 NOTE 3: an absent field leaves its hash-index list empty rather than unstated.
            return members;
        }

        AsnReader set = signedData.ReadSetOf(skipSortOrderValidation: true, setTag);
        while(set.HasData)
        {
            if(members.Count == maximumMembers)
            {
                throw new AsnContentException($"A SignedData '{fieldName}' field is walked with at most {maximumMembers} members.");
            }

            members.Add(set.ReadEncodedValue());
        }

        return members;
    }


    /// <summary>
    /// Returns a reader positioned inside the <c>SignerInfo</c> at one index of a <c>signerInfos</c> set.
    /// </summary>
    /// <param name="signerInfos">The reader positioned inside the <c>signerInfos</c> set.</param>
    /// <param name="signerIndex">The zero-based index of the signer to read.</param>
    /// <returns>The reader positioned inside the chosen <c>SignerInfo</c>.</returns>
    /// <exception cref="CryptographicException">When the set holds no <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When an entry is malformed.</exception>
    private static AsnReader LocateSignerInfo(AsnReader signerInfos, int signerIndex)
    {
        for(int index = 0; index <= Math.Min(signerIndex, MaximumSignerInfos); ++index)
        {
            if(!signerInfos.HasData)
            {
                break;
            }

            AsnReader candidate = signerInfos.ReadSequence();
            if(index == signerIndex)
            {
                return candidate;
            }
        }

        throw new CryptographicException($"The CMS SignedData holds no SignerInfo at index {signerIndex} (RFC 5652 §5.1), or the index exceeds the {MaximumSignerInfos} structures this computation walks.");
    }


    /// <summary>
    /// Reads the fields of a <c>SignerInfo</c> in their order of appearance (RFC 5652 §5.3), collecting the six
    /// clause 5.5.3 step 3) concatenates and separating the <c>unsignedAttrs</c> field it excludes.
    /// </summary>
    /// <param name="signerInfo">The reader positioned inside the <c>SignerInfo</c> SEQUENCE.</param>
    /// <param name="fields">The list the six fields' whole encodings are appended to.</param>
    /// <param name="unsignedAttributes">Receives the whole encoding of the <c>unsignedAttrs</c> field, when there is one.</param>
    /// <param name="hasUnsignedAttributes">Receives whether the signer carries an <c>unsignedAttrs</c> field.</param>
    /// <exception cref="CryptographicException">When a field is absent or not of the type the syntax states.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed or truncated.</exception>
    private static void ReadSignerInfoFields(
        AsnReader signerInfo,
        List<ReadOnlyMemory<byte>> fields,
        out ReadOnlyMemory<byte> unsignedAttributes,
        out bool hasUnsignedAttributes)
    {
        if(signerInfo.PeekTag() != Asn1Tag.Integer)
        {
            throw new CryptographicException("A CMS SignerInfo begins with its version INTEGER (RFC 5652 §5.3).");
        }

        fields.Add(signerInfo.ReadEncodedValue());

        //SignerIdentifier is either an issuerAndSerialNumber SEQUENCE or a [0] IMPLICIT primitive OCTET STRING
        //holding a subject key identifier; the [0] constructed tag at this position would be signedAttrs, which
        //cannot precede the identifier.
        Asn1Tag identifierTag = signerInfo.PeekTag();
        if(identifierTag != Asn1Tag.Sequence && identifierTag != new Asn1Tag(TagClass.ContextSpecific, 0))
        {
            throw new CryptographicException("A CMS SignerInfo carries a SignerIdentifier CHOICE (RFC 5652 §5.3).");
        }

        fields.Add(signerInfo.ReadEncodedValue());

        if(signerInfo.PeekTag() != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS SignerInfo carries its digestAlgorithm as a SEQUENCE (RFC 5652 §5.3).");
        }

        fields.Add(signerInfo.ReadEncodedValue());

        if(signerInfo.PeekTag() == ContextConstructed0)
        {
            fields.Add(signerInfo.ReadEncodedValue());
        }

        if(signerInfo.PeekTag() != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS SignerInfo carries its signatureAlgorithm as a SEQUENCE (RFC 5652 §5.3).");
        }

        fields.Add(signerInfo.ReadEncodedValue());

        if(signerInfo.PeekTag() != new Asn1Tag(UniversalTagNumber.OctetString))
        {
            throw new CryptographicException("A CMS SignerInfo carries its signature as an OCTET STRING (RFC 5652 §5.3).");
        }

        fields.Add(signerInfo.ReadEncodedValue());

        if(!signerInfo.HasData)
        {
            unsignedAttributes = default;
            hasUnsignedAttributes = false;

            return;
        }

        if(signerInfo.PeekTag() != ContextConstructed1)
        {
            throw new CryptographicException("A CMS SignerInfo ends with its optional unsignedAttrs [1] IMPLICIT field (RFC 5652 §5.3).");
        }

        unsignedAttributes = signerInfo.ReadEncodedValue();
        hasUnsignedAttributes = true;
        signerInfo.ThrowIfNotEmpty();
    }


    /// <summary>
    /// Itemises an <c>unsignedAttrs</c> set into one entry per <c>AttributeValue</c>, each carrying the whole
    /// encoding of its attribute's <c>attrType</c> field and the whole encoding of the one value — the pair
    /// clause 5.5.2 concatenates before hashing.
    /// </summary>
    /// <param name="unsignedAttributes">The whole encoding of the <c>[1] IMPLICIT SET OF Attribute</c> field.</param>
    /// <returns>One entry per value, in the order the values appear.</returns>
    /// <exception cref="AsnContentException">When the set is malformed or exceeds the bounds this walk stays within.</exception>
    private static List<UnsignedAttributeValueMaterial> ReadUnsignedAttributeValues(ReadOnlyMemory<byte> unsignedAttributes)
    {
        var reader = new AsnReader(unsignedAttributes, AsnEncodingRules.DER);
        AsnReader set = reader.ReadSetOf(skipSortOrderValidation: true, ContextConstructed1);
        reader.ThrowIfNotEmpty();

        List<UnsignedAttributeValueMaterial> values = [];
        int attributeIndex = 0;
        while(set.HasData)
        {
            if(attributeIndex == MaximumUnsignedAttributes)
            {
                throw new AsnContentException($"An unsignedAttrs set is walked with at most {MaximumUnsignedAttributes} attributes.");
            }

            AsnReader attribute = set.ReadSequence();
            ReadOnlyMemory<byte> attributeTypeEncoding = attribute.ReadEncodedValue();
            string attributeType = AsnDecoder.ReadObjectIdentifier(attributeTypeEncoding.Span, AsnEncodingRules.DER, out _);
            AsnReader attributeValues = attribute.ReadSetOf(skipSortOrderValidation: true);
            attribute.ThrowIfNotEmpty();

            int valueIndex = 0;
            while(attributeValues.HasData)
            {
                if(values.Count == MaximumUnsignedAttributeValues)
                {
                    throw new AsnContentException($"An unsignedAttrs set is walked with at most {MaximumUnsignedAttributeValues} attribute values in total.");
                }

                values.Add(new UnsignedAttributeValueMaterial(
                    attributeIndex, valueIndex, attributeType, attributeTypeEncoding, attributeValues.ReadEncodedValue()));
                ++valueIndex;
            }

            ++attributeIndex;
        }

        return values;
    }


    /// <summary>
    /// One <c>AttributeValue</c> of one unsigned attribute, with everything clause 5.5.2 needs to hash it and
    /// everything the coverage report needs to name it.
    /// </summary>
    /// <param name="AttributeIndex">The zero-based position of the <c>Attribute</c> within <c>unsignedAttrs</c>.</param>
    /// <param name="ValueIndex">The zero-based position of the value within that attribute's <c>attrValues</c>.</param>
    /// <param name="AttributeType">The attribute's <c>attrType</c> object identifier in dotted form.</param>
    /// <param name="AttributeTypeEncoding">The whole encoding of the <c>attrType</c> field, tag and length octets included.</param>
    /// <param name="Value">The whole encoding of the one <c>AttributeValue</c>, tag and length octets included.</param>
    private readonly record struct UnsignedAttributeValueMaterial(
        int AttributeIndex,
        int ValueIndex,
        string AttributeType,
        ReadOnlyMemory<byte> AttributeTypeEncoding,
        ReadOnlyMemory<byte> Value);


    /// <summary>
    /// The parts of a CMS SignedData the archive time-stamp computations reach, as views into the octets they
    /// were read from.
    /// </summary>
    /// <param name="EncapsulatedContentTypeEncoding">The whole encoding of <c>encapContentInfo.eContentType</c>, part 1) of the imprint input.</param>
    /// <param name="EncapsulatedContent">The content octets of <c>encapContentInfo.eContent</c>, whose hash is part 2).</param>
    /// <param name="HasEncapsulatedContent">Whether the structure encapsulates its content as a primitive OCTET STRING.</param>
    /// <param name="Certificates">The whole encoding of every instance of <c>CertificateChoices</c> in <c>certificates</c>.</param>
    /// <param name="RevocationInformation">The whole encoding of every instance of <c>RevocationInfoChoice</c> in <c>crls</c>.</param>
    /// <param name="SignerInfoFields">The whole encodings of the signer's fields other than <c>unsignedAttrs</c>, in their order of appearance — part 3).</param>
    /// <param name="UnsignedAttributeValues">One entry per value of every unsigned attribute of the signer.</param>
    private sealed record CmsArchiveMaterial(
        ReadOnlyMemory<byte> EncapsulatedContentTypeEncoding,
        ReadOnlyMemory<byte> EncapsulatedContent,
        bool HasEncapsulatedContent,
        IReadOnlyList<ReadOnlyMemory<byte>> Certificates,
        IReadOnlyList<ReadOnlyMemory<byte>> RevocationInformation,
        IReadOnlyList<ReadOnlyMemory<byte>> SignerInfoFields,
        IReadOnlyList<UnsignedAttributeValueMaterial> UnsignedAttributeValues);


    /// <summary>
    /// The recomputed hash values of everything the three hash-index lists of clause 5.5.2 index, held together
    /// so that one <c>using</c> releases every digest whether the computation completed or failed part way.
    /// </summary>
    private sealed class MaterialDigests: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Gets the hash value of every instance of <c>CertificateChoices</c>, in the order they appear.</summary>
        public List<DigestValue> Certificates { get; } = [];

        /// <summary>Gets the hash value of every instance of <c>RevocationInfoChoice</c>, in the order they appear.</summary>
        public List<DigestValue> RevocationInformation { get; } = [];

        /// <summary>Gets the hash value of every unsigned attribute value, in the order the values appear.</summary>
        public List<DigestValue> UnsignedAttributeValues { get; } = [];


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            DisposeAll(Certificates);
            DisposeAll(RevocationInformation);
            DisposeAll(UnsignedAttributeValues);
            disposed = true;

            //Releases one list's digests, so the three lists are released the same way.
            static void DisposeAll(List<DigestValue> digests)
            {
                for(int i = 0; i < digests.Count; ++i)
                {
                    digests[i].Dispose();
                }
            }
        }
    }
}
