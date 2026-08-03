using System;
using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A digest algorithm named on the wire by its object identifier, paired with the <see cref="Tag"/> and output
/// length the registered digest seam needs to compute it — the resolution every DER structure this library reads
/// requires before it can check a digest it was handed (an RFC 3161 <c>messageImprint</c>, an ESS
/// <c>ESSCertIDv2</c> certificate hash, a CMS <c>message-digest</c> attribute).
/// </summary>
/// <remarks>
/// <para>
/// Only SHA-256, SHA-384 and SHA-512 resolve. Those are exactly the digest algorithms
/// <see cref="CryptoTags"/> names as get-only tag statics, and therefore the only ones the registered
/// <see cref="ComputeDigestDelegate"/> is asked to dispatch on through this type. An unresolved algorithm is
/// never treated as "assume it matched": every caller of <see cref="FromOid"/> fails closed on
/// <see langword="null"/>.
/// </para>
/// <para>
/// SHA-1 is deliberately absent. Resolving it would silently widen what the CAdES signing-certificate binding
/// and the RFC 3161 message-imprint check accept, and the cryptographic constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.3</see> would in any case have to assert it reliable before a
/// signature relying on it could validate.
/// </para>
/// </remarks>
/// <param name="Identifier">The algorithm's identity, keyed by object identifier.</param>
/// <param name="DigestTag">The tag the registered digest seam dispatches the algorithm on.</param>
/// <param name="OutputByteLength">The digest length in bytes.</param>
[DebuggerDisplay("PkiDigestAlgorithm: {Identifier.Oid}, {OutputByteLength} bytes")]
public readonly record struct PkiDigestAlgorithm(AlgorithmIdentifier Identifier, Tag DigestTag, int OutputByteLength)
{
    /// <summary>SHA-256 (OID 2.16.840.1.101.3.4.2.1), 32 bytes.</summary>
    public static PkiDigestAlgorithm Sha256 { get; } = new(AlgorithmIdentifier.Sha256, CryptoTags.Sha256Digest, 32);

    /// <summary>SHA-384 (OID 2.16.840.1.101.3.4.2.2), 48 bytes.</summary>
    public static PkiDigestAlgorithm Sha384 { get; } = new(AlgorithmIdentifier.Sha384, CryptoTags.Sha384Digest, 48);

    /// <summary>SHA-512 (OID 2.16.840.1.101.3.4.2.3), 64 bytes.</summary>
    public static PkiDigestAlgorithm Sha512 { get; } = new(AlgorithmIdentifier.Sha512, CryptoTags.Sha512Digest, 64);


    /// <summary>
    /// Resolves a digest algorithm from the object identifier a DER structure named it by.
    /// </summary>
    /// <param name="oid">The dotted-decimal object identifier.</param>
    /// <returns>The resolved algorithm, or <see langword="null"/> when this library cannot compute it.</returns>
    public static PkiDigestAlgorithm? FromOid(string oid) => oid switch
    {
        WellKnownOids.Sha256 => Sha256,
        WellKnownOids.Sha384 => Sha384,
        WellKnownOids.Sha512 => Sha512,
        _ => null
    };


    /// <summary>
    /// Resolves the digest algorithm a computed digest carrier names in its own tag, so a caller holding a
    /// <see cref="DigestValue"/> does not restate the algorithm beside it — two statements of one fact is the
    /// shape a mismatch takes.
    /// </summary>
    /// <param name="digest">The digest carrier, tagged by the registered digest seam.</param>
    /// <returns>The resolved algorithm, or <see langword="null"/> when the tag names no digest algorithm this library states in PKI structures.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="digest"/> is <see langword="null"/>.</exception>
    public static PkiDigestAlgorithm? FromDigest(DigestValue digest)
    {
        ArgumentNullException.ThrowIfNull(digest);

        return !digest.Tag.TryGet(out HashAlgorithmName name) ? null : name switch
        {
            var n when n == HashAlgorithmName.SHA256 => Sha256,
            var n when n == HashAlgorithmName.SHA384 => Sha384,
            var n when n == HashAlgorithmName.SHA512 => Sha512,
            _ => (PkiDigestAlgorithm?)null
        };
    }
}


/// <summary>
/// Whether the <c>TSTInfo</c> of a time-stamp token could be read, and if not, why.
/// </summary>
/// <remarks>
/// <see cref="NotRead"/> occupies zero so a default-initialised status never reads as a successful parse.
/// </remarks>
public enum TimestampTokenInfoStatus
{
    /// <summary>No read has been attempted. The value of an unset field, by design.</summary>
    NotRead = 0,

    /// <summary>The <c>TSTInfo</c> was well-formed DER and its message-imprint algorithm resolved.</summary>
    Read = 1,

    /// <summary>The bytes were not a well-formed DER <c>TSTInfo</c>, or carried data beyond it.</summary>
    Malformed = 2,

    /// <summary>The <c>TSTInfo</c> parsed, but its <c>messageImprint.hashAlgorithm</c> is one this library cannot compute (see <see cref="PkiDigestAlgorithm.FromOid"/>).</summary>
    UnsupportedMessageImprintAlgorithm = 3,

    /// <summary>
    /// The token's own CMS signature did not verify, so its content was never read. Reported only by
    /// <see cref="TimestampTokenInfo.ReadFromTokenAsync"/>, which has to open the token to reach its content;
    /// the full validation of a token is the time-stamp validation building block of EN 319 102-1 clause 5.4.
    /// </summary>
    TokenNotVerified = 4
}


/// <summary>
/// The facts the <c>TSTInfo</c> content of a time-stamp token carries, per
/// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">IETF RFC 3161 §2.4.2</see> as profiled by
/// <see href="https://www.rfc-editor.org/rfc/rfc5816">IETF RFC 5816</see>: the message imprint that binds the
/// time-stamped data, the generation time the Time-Stamping Authority asserts, and the token's own identity
/// fields. This is the data extraction step 3) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.4.4</see> mandates the time-stamp validation building block return ("the
/// generation time and the message imprint present in the <c>TSTInfo</c> field").
/// </summary>
/// <remarks>
/// <para>
/// <strong>Attacker-reachable input.</strong> A time-stamp token arrives inside a signature, so the DER is
/// treated as hostile exactly as <see cref="ManagedCertificate"/> treats a certificate: every structure is read
/// through <see cref="AsnReader"/>'s bounds-checked cursors under <see cref="AsnEncodingRules.DER"/>, the walk
/// is straight-line with no recursion, data trailing the <c>TSTInfo</c> SEQUENCE is rejected, every optional
/// field is consumed and closed, and the message imprint has to be exactly as long as the algorithm it names
/// produces. A malformed token yields <see cref="TimestampTokenInfoStatus.Malformed"/> rather than an exception
/// escaping to the caller.
/// </para>
/// <para>
/// <strong>This type does not validate the token.</strong> It reads the content of a token whose own signature
/// is verified elsewhere — the CMS seam verifies the signature, clause 5.4 of EN 319 102-1 validates the token
/// as a Basic Signature, and <see cref="VerifyMessageImprintAsync"/> checks that the imprint binds the data the
/// caller claims it does. Reading a <c>TSTInfo</c> establishes nothing on its own.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A successfully read instance owns the pooled <see cref="MessageImprint"/> buffer;
/// the caller disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("TimestampTokenInfo: {Status}, generated {GenerationTime}")]
public sealed class TimestampTokenInfo: IDisposable
{
    /// <summary>The pooled message-imprint carrier this instance owns, or <see langword="null"/> when the read failed.</summary>
    private DigestValue? Imprint { get; }

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;

    /// <summary>
    /// The <c>id-ct-TSTInfo</c> content type (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see>,
    /// registered under RFC 5652's content-type arc), the <c>eContentType</c> a time-stamp token's CMS
    /// <c>SignedData</c> MUST carry.
    /// </summary>
    private const string TstInfoContentTypeOid = "1.2.840.113549.1.9.16.1.4";


    /// <summary>
    /// Initialises a new instance. Private: an instance only ever comes from <see cref="Read"/>, so a status and
    /// the fields that status implies cannot disagree.
    /// </summary>
    /// <param name="status">Whether the read succeeded, and if not why.</param>
    /// <param name="version">The <c>version</c> field.</param>
    /// <param name="policyOid">The <c>policy</c> field.</param>
    /// <param name="messageImprintAlgorithm">The <c>messageImprint.hashAlgorithm</c> identity.</param>
    /// <param name="imprint">The owned <c>messageImprint.hashedMessage</c> carrier.</param>
    /// <param name="generationTime">The <c>genTime</c> field.</param>
    /// <param name="accuracy">The <c>accuracy</c> field, when present.</param>
    /// <param name="isOrdered">The <c>ordering</c> field.</param>
    /// <param name="serialNumber">The <c>serialNumber</c> field, hex-encoded.</param>
    /// <param name="nonce">The <c>nonce</c> field, hex-encoded, when present.</param>
    /// <param name="timestampAuthorityName">The name read from the <c>tsa</c> field, when present.</param>
    /// <param name="hasEmbeddedCertificates">See <see cref="HasEmbeddedCertificates"/>.</param>
    private TimestampTokenInfo(
        TimestampTokenInfoStatus status,
        int version,
        string policyOid,
        AlgorithmIdentifier messageImprintAlgorithm,
        DigestValue? imprint,
        DateTimeOffset generationTime,
        TimeSpan? accuracy,
        bool isOrdered,
        string serialNumber,
        string? nonce,
        string? timestampAuthorityName,
        bool hasEmbeddedCertificates)
    {
        Status = status;
        Version = version;
        PolicyOid = policyOid;
        MessageImprintAlgorithm = messageImprintAlgorithm;
        Imprint = imprint;
        GenerationTime = generationTime;
        Accuracy = accuracy;
        IsOrdered = isOrdered;
        SerialNumber = serialNumber;
        Nonce = nonce;
        TimestampAuthorityName = timestampAuthorityName;
        HasEmbeddedCertificates = hasEmbeddedCertificates;
    }


    /// <summary>Gets whether the <c>TSTInfo</c> could be read, and if not, why.</summary>
    public TimestampTokenInfoStatus Status { get; }

    /// <summary>Gets whether the <c>TSTInfo</c> was read; every other member is meaningful only when this is <see langword="true"/>.</summary>
    public bool IsRead => Status == TimestampTokenInfoStatus.Read;

    /// <summary>Gets the <c>version</c> field; RFC 3161 §2.4.2 defines version 1.</summary>
    public int Version { get; }

    /// <summary>Gets the dotted-decimal <c>policy</c> object identifier the TSA asserts the token was issued under.</summary>
    public string PolicyOid { get; }

    /// <summary>Gets the identity of the <c>messageImprint.hashAlgorithm</c>.</summary>
    public AlgorithmIdentifier MessageImprintAlgorithm { get; }

    /// <summary>Gets the <c>messageImprint.hashedMessage</c> value, owned by this instance; <see langword="null"/> when <see cref="IsRead"/> is <see langword="false"/>.</summary>
    public DigestValue? MessageImprint => Imprint;

    /// <summary>Gets the <c>genTime</c> the TSA asserts the token was created at.</summary>
    public DateTimeOffset GenerationTime { get; }

    /// <summary>Gets the <c>accuracy</c> the token declares for <see cref="GenerationTime"/>, or <see langword="null"/> when it declares none.</summary>
    public TimeSpan? Accuracy { get; }

    /// <summary>Gets the <c>ordering</c> flag: whether tokens from this TSA can be ordered by <see cref="GenerationTime"/> alone.</summary>
    public bool IsOrdered { get; }

    /// <summary>
    /// Gets the <c>serialNumber</c> as the upper-case hexadecimal of its DER INTEGER content octets. A serial
    /// number is public routing metadata copied verbatim off the wire rather than a domain value needing a
    /// carrier, the same choice <see cref="RevocationSourceFacts"/> makes for a responder URI.
    /// </summary>
    public string SerialNumber { get; }

    /// <summary>Gets the <c>nonce</c> as upper-case hexadecimal, or <see langword="null"/> when the token carries none.</summary>
    public string? Nonce { get; }

    /// <summary>
    /// Gets the name read from the optional <c>tsa</c> field: a rendered <c>directoryName</c>, or the string
    /// value of a <c>uniformResourceIdentifier</c>, <c>rfc822Name</c> or <c>dNSName</c>. <see langword="null"/>
    /// when the field is absent or carries a form this type does not decode. RFC 3161 §2.4.2 makes this field
    /// "a hint in identifying the name of the TSA"; identification is based on the token's certificate, never on
    /// this value.
    /// </summary>
    public string? TimestampAuthorityName { get; }

    /// <summary>
    /// Gets whether the token's own CMS <c>SignedData</c> carried at least one embedded certificate in its
    /// optional <c>certificates</c> set (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">
    /// IETF RFC 5652 §5.1</see>) — wavecb S4's probe for CB-6.3-28 (the "certificate and revocation values
    /// embedded in the electronic time-stamp itself" service-provision option). Only
    /// <see cref="ReadFromTokenAsync"/> ever sees the wrapping CMS layer, so this is always
    /// <see langword="false"/> on an instance <see cref="Read"/> produced directly from already-unwrapped
    /// <c>TSTInfo</c> content — not a genuine "no embedded certificates" fact there, just the absence of the
    /// visibility needed to establish one.
    /// </summary>
    /// <remarks>
    /// This is a certificates-only probe. RFC 5652 SignedData's optional <c>crls</c> field is not modelled
    /// anywhere in this library's CMS verification surface — <see cref="CmsVerifiedContent"/> exposes
    /// <see cref="CmsVerifiedContent.Certificates"/> only, with no accessor for embedded revocation values — so
    /// a token that embeds ONLY revocation material with no certificate at all is not detected by this
    /// property. Widening <see cref="CmsVerifiedContent"/> to also surface embedded CRLs is a larger CMS-surface
    /// change than this minimal accessor need justifies on its own; flagged loudly for review adjudication
    /// rather than silently narrowing CB-6.3-28's own "certificate AND revocation values" wording to
    /// certificates alone without a record of the gap.
    /// </remarks>
    public bool HasEmbeddedCertificates { get; }


    /// <summary>
    /// Reads the <c>TSTInfo</c> of a time-stamp token — the encapsulated content of the token's CMS SignedData,
    /// whose content type is <c>id-ct-TSTInfo</c>.
    /// </summary>
    /// <param name="tstInfo">The DER-encoded <c>TSTInfo</c>.</param>
    /// <param name="pool">The memory pool the message-imprint carrier is rented from.</param>
    /// <returns>
    /// The read facts. Check <see cref="Status"/>: only <see cref="TimestampTokenInfoStatus.Read"/> means the
    /// other members carry data. <see cref="HasEmbeddedCertificates"/> is always <see langword="false"/> on the
    /// instance this overload returns — see that member's remarks. The caller disposes the returned instance
    /// in every case.
    /// </returns>
    public static TimestampTokenInfo Read(ReadOnlyMemory<byte> tstInfo, BaseMemoryPool pool) =>
        Read(tstInfo, pool, hasEmbeddedCertificates: false);


    /// <summary>
    /// The core of <see cref="Read(ReadOnlyMemory{byte}, BaseMemoryPool)"/>, additionally threading through the
    /// <see cref="HasEmbeddedCertificates"/> fact <see cref="ReadFromTokenAsync"/> alone can observe (it opens
    /// the wrapping CMS layer this overload never sees) — the single choke point both entry points share, so
    /// the fact is set exactly once, at the point of construction, never patched onto an already-minted
    /// instance.
    /// </summary>
    /// <param name="tstInfo">The DER-encoded <c>TSTInfo</c>.</param>
    /// <param name="pool">The memory pool the message-imprint carrier is rented from.</param>
    /// <param name="hasEmbeddedCertificates">See <see cref="HasEmbeddedCertificates"/>.</param>
    /// <returns>The read facts; see <see cref="Read(ReadOnlyMemory{byte}, BaseMemoryPool)"/>.</returns>
    private static TimestampTokenInfo Read(ReadOnlyMemory<byte> tstInfo, BaseMemoryPool pool, bool hasEmbeddedCertificates)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int version;
        string policyOid;
        string hashOid;
        byte[] imprintBytes;
        ReadOnlyMemory<byte> serialNumber;
        DateTimeOffset generationTime;
        TimeSpan? accuracy;
        bool isOrdered;
        string? nonce;
        string? timestampAuthorityName;

        try
        {
            var outer = new AsnReader(tstInfo, AsnEncodingRules.DER);
            AsnReader info = outer.ReadSequence();

            //Anything beyond the TSTInfo SEQUENCE is not part of the structure: accepting it would let an
            //attacker append content that a differently-written parser might read instead.
            outer.ThrowIfNotEmpty();

            if(!info.TryReadInt32(out version))
            {
                return Failed(TimestampTokenInfoStatus.Malformed, hasEmbeddedCertificates);
            }

            policyOid = info.ReadObjectIdentifier();

            AsnReader messageImprint = info.ReadSequence();
            AsnReader hashAlgorithm = messageImprint.ReadSequence();
            hashOid = hashAlgorithm.ReadObjectIdentifier();
            if(hashAlgorithm.HasData)
            {
                //AlgorithmIdentifier.parameters is ANY DEFINED BY algorithm OPTIONAL; a NULL is the common
                //encoding for the SHA-2 family and is consumed without interpretation.
                _ = hashAlgorithm.ReadEncodedValue();
            }

            hashAlgorithm.ThrowIfNotEmpty();
            imprintBytes = messageImprint.ReadOctetString();
            messageImprint.ThrowIfNotEmpty();

            serialNumber = info.ReadIntegerBytes();
            generationTime = info.ReadGeneralizedTime();
            accuracy = info.HasData && info.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true)
                ? ReadAccuracy(info.ReadSequence())
                : null;

            isOrdered = info.HasData && info.PeekTag() == new Asn1Tag(UniversalTagNumber.Boolean) && info.ReadBoolean();
            nonce = info.HasData && info.PeekTag() == new Asn1Tag(UniversalTagNumber.Integer)
                ? Convert.ToHexString(info.ReadIntegerBytes().Span)
                : null;

            timestampAuthorityName = info.HasData && info.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)
                ? ReadTimestampAuthorityName(info.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                : null;

            if(info.HasData && info.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
            {
                //extensions [1] IMPLICIT Extensions OPTIONAL: consumed so the closing emptiness check is exact,
                //but not interpreted — no extension defined for TSTInfo affects the facts read here.
                _ = info.ReadEncodedValue();
            }

            info.ThrowIfNotEmpty();
        }
        catch(AsnContentException)
        {
            return Failed(TimestampTokenInfoStatus.Malformed, hasEmbeddedCertificates);
        }

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(hashOid);
        if(algorithm is null)
        {
            return Failed(TimestampTokenInfoStatus.UnsupportedMessageImprintAlgorithm, hasEmbeddedCertificates);
        }

        if(imprintBytes.Length != algorithm.Value.OutputByteLength)
        {
            //A hashedMessage whose length contradicts the algorithm it was hashed under is not a message
            //imprint at all; rejecting it here keeps the comparison in VerifyMessageImprintAsync total.
            return Failed(TimestampTokenInfoStatus.Malformed, hasEmbeddedCertificates);
        }

        IMemoryOwner<byte> imprintOwner = pool.Rent(imprintBytes.Length);
        try
        {
            imprintBytes.CopyTo(imprintOwner.Memory.Span);

            return new TimestampTokenInfo(
                TimestampTokenInfoStatus.Read,
                version,
                policyOid,
                algorithm.Value.Identifier,
                new DigestValue(imprintOwner, algorithm.Value.DigestTag),
                generationTime,
                accuracy,
                isOrdered,
                Convert.ToHexString(serialNumber.Span),
                nonce,
                timestampAuthorityName,
                hasEmbeddedCertificates);
        }
        catch
        {
            imprintOwner.Dispose();

            throw;
        }

        //Builds the instance every unsuccessful read returns: the status, and nothing else. Takes
        //hasEmbeddedCertificates explicitly (no closure capture) even though every call site in THIS overload
        //passes through the same enclosing parameter, since a static local function cannot close over it.
        static TimestampTokenInfo Failed(TimestampTokenInfoStatus status, bool hasEmbeddedCertificates) =>
            new(status, version: 0, policyOid: string.Empty, messageImprintAlgorithm: default,
                imprint: null, generationTime: default, accuracy: null, isOrdered: false,
                serialNumber: string.Empty, nonce: null, timestampAuthorityName: null, hasEmbeddedCertificates);
    }


    /// <summary>
    /// Opens a DER-encoded time-stamp token through the registered CMS verification seam and reads the
    /// <c>TSTInfo</c> it encapsulates — the data extraction of step 3) of clause 5.4.4 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
    /// ETSI EN 319 102-1 V1.4.1</see>.
    /// </summary>
    /// <param name="token">The DER-encoded time-stamp token, a CMS SignedData whose encapsulated content type is <c>id-ct-TSTInfo</c>.</param>
    /// <param name="pool">The memory pool the token's decoded content and the message-imprint carrier are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The read facts, or <see cref="TimestampTokenInfoStatus.TokenNotVerified"/> when the token's own CMS
    /// signature does not verify. Unlike <see cref="Read(ReadOnlyMemory{byte}, BaseMemoryPool)"/>, the returned
    /// instance's <see cref="HasEmbeddedCertificates"/> reflects a genuine observation of the token's own CMS
    /// <c>certificates</c> set. The caller disposes the returned instance in every case.
    /// </returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="VerifyCmsSignedDataDelegate"/> has been registered.</exception>
    /// <remarks>
    /// <para>
    /// Opening a token verifies its CMS signature because that is what reaching its content requires; it does
    /// not validate the token. Establishing that the token is trustworthy — a chain to a trust anchor for the
    /// Time-Stamping Authority, a policy, a validity window — is the time-stamp validation building block of
    /// clause 5.4, composed by a caller through <see cref="ValidateTimestampTokenAsyncDelegate"/>.
    /// </para>
    /// <para>
    /// A time-stamp token reaches this method as the value of a signature attribute, which for the unsigned
    /// attributes is arbitrary attacker-supplied DER. The CMS seam is arbitrary caller-supplied code over those
    /// octets and each shipped backend raises its own exception type from a structure it cannot open, so both the
    /// carrier construction and the seam call are wrapped in the same
    /// <c>catch(Exception) when(not OperationCanceledException)</c> the building blocks use: a token that cannot
    /// be opened is <see cref="TimestampTokenInfoStatus.TokenNotVerified"/>, never an exception escaping into a
    /// validation process.
    /// </para>
    /// </remarks>
    public static async ValueTask<TimestampTokenInfo> ReadFromTokenAsync(
        PkiCertificateMemory token,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyCmsSignedDataDelegate verifyCms = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No VerifyCmsSignedDataDelegate has been registered.");

        CmsSignedData? carrier = null;
        try
        {
            carrier = CmsSignedData.FromBytes(token.AsReadOnlySpan(), pool);
            CmsVerifiedContent content = await verifyCms(carrier, pool, cancellationToken).ConfigureAwait(false);
            using(content)
            {
                //RFC 3161 §2.4.2: a TimeStampToken's SignedData eContentType SHALL be id-ct-TSTInfo and its
                //eContent SHALL be the DER TSTInfo. A verified SignedData whose encapsulated content is anything
                //else is not a time-stamp token; refuse to read its content as a TSTInfo rather than trusting the
                //bytes to be one because the signature verified.
                if(!string.Equals(content.ContentType, TstInfoContentTypeOid, StringComparison.Ordinal))
                {
                    return NotVerified();
                }

                //The single choke point where HasEmbeddedCertificates is actually observable: content.Certificates
                //is read (and, via the enclosing using, disposed) here, before the CMS layer this call opened
                //goes out of scope — see the private Read(bytes, pool, bool) overload's remarks.
                return Read(content.Content, pool, hasEmbeddedCertificates: content.Certificates.Count > 0);
            }
        }
        catch(Exception exception) when(exception is not OperationCanceledException)
        {
            return NotVerified();
        }
        finally
        {
            carrier?.Dispose();
        }

        //Builds the instance a token whose CMS layer could not be opened or read returns.
        static TimestampTokenInfo NotVerified() =>
            new(TimestampTokenInfoStatus.TokenNotVerified, version: 0, policyOid: string.Empty,
                messageImprintAlgorithm: default, imprint: null, generationTime: default, accuracy: null,
                isOrdered: false, serialNumber: string.Empty, nonce: null, timestampAuthorityName: null,
                hasEmbeddedCertificates: false);
    }


    /// <summary>
    /// Checks that this token's message imprint is the digest of <paramref name="data"/> under the algorithm the
    /// token names — step 2) of clause 5.2.8.4.2.5 of EN 319 102-1 for a time-stamp on a Signed Data Object, and
    /// the same binding check a signature time-stamp needs against the signature value.
    /// </summary>
    /// <param name="data">The data the token is claimed to time-stamp.</param>
    /// <param name="pool">The memory pool the computed digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> only when the imprint equals the digest of <paramref name="data"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    /// <remarks>
    /// The digest is computed through <see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>,
    /// never a framework hash, so the check carries the same provenance and instrumentation as every other digest
    /// the library takes.
    /// </remarks>
    public async ValueTask<bool> VerifyMessageImprintAsync(ReadOnlyMemory<byte> data, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(!IsRead || Imprint is null)
        {
            return false;
        }

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(MessageImprintAlgorithm.Oid);
        if(algorithm is null)
        {
            return false;
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            data, algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return computed.AsReadOnlySpan().SequenceEqual(Imprint.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Imprint?.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// Reads an RFC 3161 <c>Accuracy</c> — <c>seconds</c>, <c>millis</c> <c>[0]</c> and <c>micros</c>
    /// <c>[1]</c>, each optional — as the single interval they add up to.
    /// </summary>
    /// <param name="accuracy">The reader positioned inside the <c>Accuracy</c> SEQUENCE.</param>
    /// <returns>The accuracy interval; <see cref="TimeSpan.Zero"/> when every component is absent.</returns>
    private static TimeSpan ReadAccuracy(AsnReader accuracy)
    {
        long ticks = 0;
        if(accuracy.HasData && accuracy.PeekTag() == new Asn1Tag(UniversalTagNumber.Integer))
        {
            ticks += ReadComponent(accuracy, new Asn1Tag(UniversalTagNumber.Integer)) * TimeSpan.TicksPerSecond;
        }

        if(accuracy.HasData && accuracy.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0))
        {
            ticks += ReadComponent(accuracy, new Asn1Tag(TagClass.ContextSpecific, 0)) * TimeSpan.TicksPerMillisecond;
        }

        if(accuracy.HasData && accuracy.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1))
        {
            ticks += ReadComponent(accuracy, new Asn1Tag(TagClass.ContextSpecific, 1)) * TimeSpan.TicksPerMicrosecond;
        }

        accuracy.ThrowIfNotEmpty();

        return TimeSpan.FromTicks(ticks);
    }


    /// <summary>
    /// Reads one <c>Accuracy</c> component as a bounded non-negative integer.
    /// </summary>
    /// <param name="accuracy">The reader positioned at the component.</param>
    /// <param name="tag">The component's tag.</param>
    /// <returns>The component's value.</returns>
    /// <exception cref="AsnContentException">Thrown when the component does not fit a 32-bit integer or is negative, which no legal <c>Accuracy</c> component is.</exception>
    private static long ReadComponent(AsnReader accuracy, Asn1Tag tag)
    {
        if(!accuracy.TryReadInt32(out int value, tag) || value < 0)
        {
            throw new AsnContentException("An RFC 3161 Accuracy component must be a non-negative integer (RFC 3161 §2.4.2).");
        }

        return value;
    }


    /// <summary>
    /// Reads the optional <c>tsa</c> field's <c>GeneralName</c> as the identification hint this type surfaces.
    /// </summary>
    /// <param name="tsa">The reader positioned inside the explicit <c>[0]</c> wrapper.</param>
    /// <returns>The name, or <see langword="null"/> for a <c>GeneralName</c> form this type does not decode.</returns>
    private static string? ReadTimestampAuthorityName(AsnReader tsa)
    {
        if(!tsa.HasData)
        {
            return null;
        }

        string? name;
        Asn1Tag tag = tsa.PeekTag();
        if(tag == new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true))
        {
            name = PkiDistinguishedNameText.Read(tsa.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4)));
        }
        else if(tag == new Asn1Tag(TagClass.ContextSpecific, 1)
            || tag == new Asn1Tag(TagClass.ContextSpecific, 2)
            || tag == new Asn1Tag(TagClass.ContextSpecific, 6))
        {
            name = tsa.ReadCharacterString(UniversalTagNumber.IA5String, tag);
        }
        else
        {
            //otherName, x400Address, ediPartyName, iPAddress and registeredID carry no name text this type
            //surfaces; the value is consumed so the closing emptiness check stays exact.
            _ = tsa.ReadEncodedValue();
            name = null;
        }

        tsa.ThrowIfNotEmpty();

        return name;
    }
}
