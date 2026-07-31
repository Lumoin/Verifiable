using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identity of the base format a signature is encoded in — the "applicable base format" the format checking
/// building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.2.1</see> checks conformance against.
/// </summary>
/// <remarks>
/// An open wire-value wrapper rather than an enumeration: clause 5.1.1 keeps the validation algorithm format
/// neutral and each AdES base standard is a separate deliverable, so a format binding added later mints its own
/// identity without this type changing.
/// </remarks>
/// <param name="Value">The format's identity.</param>
[DebuggerDisplay("SignatureFormatIdentifier: {Value}")]
public readonly record struct SignatureFormatIdentifier(string Value)
{
    /// <summary>CMS Advanced Electronic Signatures (ETSI EN 319 122).</summary>
    public static SignatureFormatIdentifier CAdES { get; } = new("CAdES");

    /// <summary>XML Advanced Electronic Signatures (ETSI EN 319 132).</summary>
    public static SignatureFormatIdentifier XAdES { get; } = new("XAdES");

    /// <summary>PDF Advanced Electronic Signatures (ETSI EN 319 142).</summary>
    public static SignatureFormatIdentifier PAdES { get; } = new("PAdES");

    /// <summary>JSON Advanced Electronic Signatures (ETSI TS 119 182).</summary>
    public static SignatureFormatIdentifier JAdES { get; } = new("JAdES");
}


/// <summary>
/// The octets a signature covers — the Signer's Document, the Signer's Document Representation, or the content
/// a signature encapsulates (clauses 4.2.3, 4.2.4 and 4.2.10 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>) — held in pooled memory rather than as a naked buffer.
/// </summary>
/// <remarks>
/// A format-neutral carrier: the cryptographic verification building block of clause 5.2.7 hashes these octets
/// and a time-stamp on a Signed Data Object binds them, whatever base format the signature is in. Owns its
/// underlying pool-rented memory; disposing the carrier returns the buffer.
/// </remarks>
/// <param name="content">The owned content bytes.</param>
[DebuggerDisplay("SignedContentMemory({Length} bytes)")]
public sealed class SignedContentMemory(IMemoryOwner<byte> content): SensitiveMemory(content, ContentTag)
{
    /// <summary>
    /// The tag every instance carries for CBOM and OpenTelemetry provenance: octets under a signature, in the
    /// format's own encoding.
    /// </summary>
    public static Tag ContentTag { get; } = Tag.Create(Purpose.Signature).With(EncodingScheme.Raw);


    /// <summary>Gets the length of the content in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and wraps the buffer.
    /// </summary>
    /// <param name="bytes">The content octets.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The carrier; the caller takes ownership.</returns>
    public static SignedContentMemory FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        try
        {
            bytes.CopyTo(owner.Memory.Span);

            return new SignedContentMemory(owner);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}


/// <summary>
/// Whether a signature attribute the format binding surfaced is covered by the signature.
/// </summary>
/// <remarks>
/// The distinction clause 5.2.9 of EN 319 102-1 asks the presentation building block to make clear ("which
/// attributes were signed and which were unsigned"), and the distinction clause 5.2.8.4 draws when it applies
/// the signature elements constraints to signed properties only.
/// </remarks>
public enum SignatureAttributeScope
{
    /// <summary>The binding did not state the scope. The value of an unset field, by design.</summary>
    Unknown = 0,

    /// <summary>The attribute is covered by the signature.</summary>
    Signed = 1,

    /// <summary>The attribute is not covered by the signature.</summary>
    Unsigned = 2
}


/// <summary>
/// One signature attribute (in XML-format vocabulary, one signature property) a format binding found, reported
/// by identity and scope so that clause 5.2.8.4.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> can check the signature elements constraints against it without the engine
/// knowing the format's encoding.
/// </summary>
/// <param name="Identifier">The attribute's identity in its format's own vocabulary — a dotted-decimal object identifier for CAdES, an element or member name for the XML and JSON formats.</param>
/// <param name="Scope">Whether the signature covers the attribute.</param>
/// <param name="IsWellFormed">Whether the binding could decode the attribute. Clause 5.2.8.4.1's first bullet requires the SVA to "proceed as if the attribute was not present" when it is present but malformed, so an attribute reported with <see langword="false"/> here satisfies no presence constraint.</param>
[DebuggerDisplay("SignatureAttributeFacts: {Identifier}, {Scope}, well-formed {IsWellFormed}")]
public sealed record SignatureAttributeFacts(string Identifier, SignatureAttributeScope Scope, bool IsWellFormed);


/// <summary>
/// One reference to the signing certificate carried by a signing certificate identifier attribute, per clause
/// 4.2.5.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> — the material the identification of the signing certificate building block
/// (clause 5.2.3.4) matches the candidate certificate against, and the signing certificate reference constraint
/// (clause 5.2.8.4.2.1) checks the certification path against.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="CertificateDigest"/> is owned by the <see cref="SignatureFacts"/> that
/// surfaced this reference and must not be disposed separately.
/// </remarks>
[DebuggerDisplay("SigningCertificateReference: {DigestAlgorithm.Oid}, signer reference {IsSignerReference}")]
public sealed record SigningCertificateReference
{
    /// <summary>The digest algorithm the reference declares its certificate hash was taken under.</summary>
    public required AlgorithmIdentifier DigestAlgorithm { get; init; }

    /// <summary>
    /// The certificate hash the reference carries, or <see langword="null"/> when
    /// <see cref="DigestAlgorithm"/> is one this library cannot compute (see <see cref="PkiDigestAlgorithm.FromOid"/>).
    /// A reference with no digest matches no certificate: the identification building block cannot ascertain the
    /// binding, so it fails closed rather than accepting the reference unchecked.
    /// </summary>
    public DigestValue? CertificateDigest { get; init; }

    /// <summary>The issuer name the reference's optional <c>IssuerSerial</c> carries, or <see langword="null"/> when it carries none. Clause 5.2.3.4 step 3) compares it with the signing certificate and reports a warning on a mismatch.</summary>
    public string? IssuerName { get; init; }

    /// <summary>The serial number the reference's optional <c>IssuerSerial</c> carries, upper-case hexadecimal; <see langword="null"/> when it carries none.</summary>
    public string? SerialNumber { get; init; }

    /// <summary>
    /// Whether the format identifies this reference as the reference to the signer's certificate directly, which
    /// step 1) of clause 5.2.3.4 lets the identification building block use without walking the other references.
    /// </summary>
    public required bool IsSignerReference { get; init; }
}


/// <summary>
/// What a time-stamp token embedded in a signature time-stamps — the classification the validation algorithm
/// branches on, since clause 5.2.8.4.2.5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> treats time-stamps on Signed Data Objects, clause 5.5.4 treats signature
/// time-stamps, and clause 5.6.2.3 treats archive time-stamps, each differently.
/// </summary>
public enum SignatureTimestampClass
{
    /// <summary>The binding could not classify the token. The value of an unset field, by design; a token of unknown class drives no check.</summary>
    Unknown = 0,

    /// <summary>A time-stamp over the Signed Data Object, applied before signing (clause 5.2.8.4.2.5).</summary>
    ContentTimestamp = 1,

    /// <summary>A time-stamp over the signature value, which clause 5.5.4 uses to determine best-signature-time.</summary>
    SignatureTimestamp = 2,

    /// <summary>A time-stamp over the signature together with its validation data references.</summary>
    ValidationDataTimestamp = 3,

    /// <summary>An archive time-stamp over the signature and its validation material, which clause 5.6.2.3 extracts proofs of existence from.</summary>
    ArchiveTimestamp = 4
}


/// <summary>
/// One time-stamp token a signature embeds, classified by what it time-stamps.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Token"/> is owned by the <see cref="SignatureFacts"/> that surfaced it
/// and must not be disposed separately.
/// </remarks>
[DebuggerDisplay("EmbeddedTimestamp: {Class} #{Ordinal} from {Identifier}")]
public sealed record EmbeddedTimestamp
{
    /// <summary>What the token time-stamps.</summary>
    public required SignatureTimestampClass Class { get; init; }

    /// <summary>The identity of the attribute the token was carried in, in the format's own vocabulary.</summary>
    public required string Identifier { get; init; }

    /// <summary>The DER-encoded time-stamp token, tagged <see cref="PkiCertificateTags.TimestampToken"/>.</summary>
    public required PkiCertificateMemory Token { get; init; }

    /// <summary>The token's position among the tokens of the same class, in the order the signature carries them, starting at zero.</summary>
    public required int Ordinal { get; init; }
}


/// <summary>
/// One Signed Data Object the Driving Application supplies to the validation, for the detached case clause
/// 5.2.7.4 step 1) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> covers ("the building block shall obtain the signed data items ... if not
/// provided in the inputs").
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Content"/> is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run.
/// </remarks>
[DebuggerDisplay("SignerDocumentReference: {Identifier}")]
public sealed record SignerDocumentReference
{
    /// <summary>The identifier (for example a URI) the signature refers to the document by — the value Table 15 of clause 5.2.7.3 asks a <c>HASH_FAILURE</c> or <c>SIGNED_DATA_NOT_FOUND</c> report to name.</summary>
    public required string Identifier { get; init; }

    /// <summary>The document's bytes, or <see langword="null"/> when the caller could name the document but not obtain it.</summary>
    public SignedContentMemory? Content { get; init; }
}


/// <summary>
/// The names a format binding gives the material an <see cref="AlgorithmUse"/> is about, so that the validation
/// processes can decide the questions
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> asks about a cryptographic constraints failure — clause 5.3.4 step 6) asks
/// whether "the material concerned by this failure is the signature value", and clause 5.5.4 step 4)c) whether it
/// "is the signature value or a signed attribute".
/// </summary>
/// <remarks>
/// A binding names other material freely; only the two names below carry meaning to the algorithm, and a use
/// named neither is material the processes treat as being outside the signature itself (a certificate, a
/// revocation data instance, a time-stamp token).
/// </remarks>
public static class SignatureMaterialIdentifiers
{
    /// <summary>The signature value itself — the material clause 5.3.4 step 6) and clause 5.5.4 step 4)c) ask about.</summary>
    public static string SignatureValue { get; } = "signature value";

    /// <summary>The digest over the signed attributes, which clause 5.5.4 step 4)c) covers as "a signed attribute".</summary>
    public static string SignedAttributesDigest { get; } = "signed attributes digest";


    /// <summary>
    /// Reports whether a name is one of the two the algorithm reasons about — the signature value or the digest
    /// over the signed attributes.
    /// </summary>
    /// <param name="materialIdentifier">The name a binding gave the material.</param>
    /// <returns><see langword="true"/> when the material is part of the signature itself.</returns>
    public static bool IsSignatureOwnMaterial(string materialIdentifier) =>
        string.Equals(materialIdentifier, SignatureValue, StringComparison.Ordinal)
        || string.Equals(materialIdentifier, SignedAttributesDigest, StringComparison.Ordinal);
}


/// <summary>
/// Whether a format binding could extract the facts of a signature, and if not, why.
/// </summary>
/// <remarks>
/// <see cref="NotExtracted"/> occupies zero so a default-initialised status never reads as a successful
/// extraction.
/// </remarks>
public enum SignatureFactsStatus
{
    /// <summary>No extraction has been attempted. The value of an unset field, by design.</summary>
    NotExtracted = 0,

    /// <summary>The signature conformed to its base format to the extent the cryptographic verification building block can process it, and its facts were extracted.</summary>
    Extracted = 1,

    /// <summary>The signature is not conformant to its base format — the <c>FAILED</c> outcome of clause 5.2.2.3.</summary>
    FormatFailure = 2
}


/// <summary>
/// Where the signed content a <see cref="SignatureFacts"/> carries came from — inside the Signed Data Object, or
/// beside it from the Driving Application. This is the distinction the containment rule of clause 5.6.2.3 step 5)
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> turns on: a proof of existence for an object is a proof for "each object
/// contained in" it, and a detached Signer's Document is not contained in the Signed Data Object at all — the
/// signature binds it by the digest of RFC 5652 clause 5.4's <c>message-digest</c> attribute alone, which is the
/// digest-reference territory of step 4) rather than the containment territory of step 5).
/// </summary>
/// <remarks>
/// <see cref="NotPresent"/> occupies zero, so a binding that states no placement never has its content read as
/// contained in the Signed Data Object. That is the fail-closed direction: a containment rule that cannot tell
/// the two apart states the stronger claim for both.
/// </remarks>
public enum SignedContentPlacement
{
    /// <summary>The facts carry no signed content. The value of an unset field, by design.</summary>
    NotPresent = 0,

    /// <summary>
    /// The content is encapsulated in the Signed Data Object — the <c>eContent</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.2">IETF RFC 5652 clause 5.2</see> — so every
    /// octet of it is contained in the object a proof of existence is about.
    /// </summary>
    Encapsulated = 1,

    /// <summary>
    /// The content travelled beside the Signed Data Object as the Signer's Document of Table 8 of clause 5.2.2.2,
    /// which is what an Associated Signature Container carries for the CAdES objects of ETSI EN 319 162-1 clause
    /// 4.4.4.2 item 3 a) and clause 4.3.3.2 item 4 b). RFC 5652 clause 5.2 states the case outright: "the content
    /// is not present ... supplied by other means".
    /// </summary>
    Detached = 2
}


/// <summary>
/// Everything the format-neutral validation algorithm of clause 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> needs to know about one signature, extracted by the binding for its base
/// format. The building blocks read this; none of them reads a format's own encoding.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam that keeps the engine format neutral. A binding for a base format implements
/// <see cref="ExtractSignatureFactsAsyncDelegate"/> and <see cref="VerifySignatureCryptographyAsyncDelegate"/>,
/// bundles them in a <see cref="SignatureFormatSeam"/>, and everything from format checking (clause 5.2.2) to
/// signature acceptance validation (clause 5.2.8) then runs unchanged over the facts. The library ships the CMS
/// binding (<see cref="CAdESSignatureFacts"/>); a binding for another base format adds no engine code.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every carrier it extracted from the signature —
/// <see cref="SignedContent"/>, <see cref="SignatureValue"/>, <see cref="EmbeddedCertificates"/>,
/// <see cref="EmbeddedCertificateRevocationLists"/>, <see cref="EmbeddedOcspResponses"/>, the tokens of
/// <see cref="Timestamps"/> and the digests of <see cref="SigningCertificateReferences"/> — and disposes them
/// all. <see cref="SigningCertificate"/> is one of <see cref="EmbeddedCertificates"/> and is not disposed twice.
/// <see cref="SignedDataObject"/> is a non-owning reference to the caller's carrier.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureFacts: {Status}, {Format.Value}, {Attributes.Count} attributes")]
public sealed class SignatureFacts: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets whether the facts could be extracted, and if not, why.</summary>
    public required SignatureFactsStatus Status { get; init; }

    /// <summary>Gets the base format the binding that produced these facts speaks.</summary>
    public required SignatureFormatIdentifier Format { get; init; }

    /// <summary>Gets whether the facts were extracted; every other member carries data only when this is <see langword="true"/>.</summary>
    public bool IsExtracted => Status == SignatureFactsStatus.Extracted;

    /// <summary>Gets what the binding could state about a format failure — the "any information available why parsing of the signature failed" a <see cref="FormatFailureReportData"/> carries; <see langword="null"/> when the extraction succeeded.</summary>
    public string? FormatFailureReason { get; init; }

    /// <summary>Gets a non-owning reference to the Signed Data Object the facts were extracted from, so a later block can hand the same bytes back to the binding's own verification.</summary>
    public SensitiveMemory? SignedDataObject { get; init; }

    /// <summary>Gets the identity of the signed content — for CMS the encapsulated content type object identifier; empty when the format names none.</summary>
    public string SignedContentIdentifier { get; init; } = string.Empty;

    /// <summary>
    /// Gets the signed content, owned by this instance: the octets the signature encapsulates, or — for a
    /// detached signature — the Signer's Document the caller supplied beside it as a
    /// <see cref="SignerDocumentReference"/>. <see cref="SignedContentPlacement"/> states which of the two this
    /// is. <see langword="null"/> when the signature encapsulates nothing and the caller supplied nothing.
    /// </summary>
    public SignedContentMemory? SignedContent { get; init; }

    /// <summary>
    /// Gets where <see cref="SignedContent"/> came from — the fact the containment rule of clause 5.6.2.3 step 5)
    /// turns on, since a detached Signer's Document is not contained in the Signed Data Object;
    /// <see cref="SignedContentPlacement.NotPresent"/> when there is no signed content.
    /// </summary>
    public SignedContentPlacement SignedContentPlacement { get; init; }

    /// <summary>
    /// Gets the signature value octets — clause 4.2.9's "signature", the object a signature time-stamp binds and
    /// the object clause 5.6.2.4 asks a proof of existence about when it determines best-signature-time. Owned by
    /// this instance; <see langword="null"/> when the binding could not isolate it.
    /// </summary>
    public SignedContentMemory? SignatureValue { get; init; }

    /// <summary>Gets every signature attribute the binding found, signed and unsigned, in the order the signature carries them.</summary>
    public IReadOnlyList<SignatureAttributeFacts> Attributes { get; init; } = [];

    /// <summary>Gets the references to the signing certificate the signing certificate identifier attributes carry, in the order the signature carries them.</summary>
    public IReadOnlyList<SigningCertificateReference> SigningCertificateReferences { get; init; } = [];

    /// <summary>Gets the certificate the signature identifies as the signer's, or <see langword="null"/> when the signature carries no copy of it. One of <see cref="EmbeddedCertificates"/>.</summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>Gets the certificates the signature carries, owned by this instance — the "Other Certificates" of Table 12 of clause 5.2.6.2 and part of the certificate validation data of clause 5.2.4.3.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedCertificates { get; init; } = [];

    /// <summary>Gets the certificate revocation lists the signature carries, owned by this instance.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedCertificateRevocationLists { get; init; } = [];

    /// <summary>Gets the OCSP responses the signature carries, owned by this instance.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedOcspResponses { get; init; } = [];

    /// <summary>Gets the time-stamp tokens the signature embeds, owned by this instance, classified by what each time-stamps.</summary>
    public IReadOnlyList<EmbeddedTimestamp> Timestamps { get; init; } = [];

    /// <summary>Gets the claimed signing time of clause 4.2.5.8 — the value clause 5.2.8.4.2.2 makes available to the Driving Application; <see langword="null"/> when the attribute is absent or malformed.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>Gets the signature policy identifier the signature declares (clause 4.2.5.3), which the validation context initialization building block maps to a validation policy; <see langword="null"/> when the signature declares none.</summary>
    public string? SignaturePolicyIdentifier { get; init; }

    /// <summary>
    /// Gets the algorithms the signature itself used, each named with the material that used it — the input the
    /// cryptographic constraints check of clause 5.2.8.4.1 assesses, whose NOTE 2 extends the concern to "any of
    /// the certificate, CRLs, time-stamps or other material used in the validation process" that the blocks add
    /// from their own inputs.
    /// </summary>
    public IReadOnlyList<AlgorithmUse> AlgorithmUses { get; init; } = [];


    /// <summary>
    /// Creates the facts of a signature that is not conformant to its base format — the <c>FAILED</c> outcome of
    /// clause 5.2.2.3.
    /// </summary>
    /// <param name="format">The base format the binding checked against.</param>
    /// <param name="reason">What the binding could state about the failure.</param>
    /// <returns>The facts, owning nothing.</returns>
    public static SignatureFacts FormatFailure(SignatureFormatIdentifier format, string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);

        return new SignatureFacts
        {
            Status = SignatureFactsStatus.FormatFailure,
            Format = format,
            FormatFailureReason = reason
        };
    }


    /// <summary>
    /// Finds the first attribute with a given identity.
    /// </summary>
    /// <param name="identifier">The attribute's identity in the format's own vocabulary.</param>
    /// <param name="attribute">The matching attribute when present; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when an attribute with that identity is present, whether or not it is well-formed.</returns>
    public bool TryGetAttribute(string identifier, [NotNullWhen(true)] out SignatureAttributeFacts? attribute)
    {
        ArgumentNullException.ThrowIfNull(identifier);

        for(int i = 0; i < Attributes.Count; ++i)
        {
            if(string.Equals(Attributes[i].Identifier, identifier, StringComparison.Ordinal))
            {
                attribute = Attributes[i];

                return true;
            }
        }

        attribute = null;

        return false;
    }


    /// <summary>
    /// Selects the embedded time-stamp tokens of one class.
    /// </summary>
    /// <param name="timestampClass">The class to select.</param>
    /// <returns>The tokens of that class, in signature order; empty when the signature embeds none.</returns>
    public IReadOnlyList<EmbeddedTimestamp> TimestampsOfClass(SignatureTimestampClass timestampClass)
    {
        List<EmbeddedTimestamp> selected = [];
        for(int i = 0; i < Timestamps.Count; ++i)
        {
            if(Timestamps[i].Class == timestampClass)
            {
                selected.Add(Timestamps[i]);
            }
        }

        return selected;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        SignedContent?.Dispose();
        SignatureValue?.Dispose();
        DisposeAll(EmbeddedCertificates);
        DisposeAll(EmbeddedCertificateRevocationLists);
        DisposeAll(EmbeddedOcspResponses);
        for(int i = 0; i < Timestamps.Count; ++i)
        {
            Timestamps[i].Token.Dispose();
        }

        for(int i = 0; i < SigningCertificateReferences.Count; ++i)
        {
            SigningCertificateReferences[i].CertificateDigest?.Dispose();
        }

        disposed = true;

        //Releases one list of owned carriers; the signing certificate is an element of EmbeddedCertificates and
        //is therefore released exactly once, by that list.
        static void DisposeAll(IReadOnlyList<PkiCertificateMemory> carriers)
        {
            for(int i = 0; i < carriers.Count; ++i)
            {
                carriers[i].Dispose();
            }
        }
    }
}


/// <summary>
/// The per-call context an <see cref="ExtractSignatureFactsAsyncDelegate"/> implementation receives, so the
/// delegate carries no caller data through a lambda closure.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run; the delegate must not dispose any of it.
/// </remarks>
[DebuggerDisplay("SignatureFactsExtractionContext: {SignerDocuments.Count} signer documents")]
public sealed record SignatureFactsExtractionContext
{
    /// <summary>The Signed Data Object to extract facts from — the mandatory input of Table 8 of clause 5.2.2.2.</summary>
    public required SensitiveMemory SignedDataObject { get; init; }

    /// <summary>The Signer's Documents the Driving Application supplied, for a detached signature; empty when the signature encapsulates its content.</summary>
    public IReadOnlyList<SignerDocumentReference> SignerDocuments { get; init; } = [];
}


/// <summary>
/// Extracts the facts of a signature in one base format, so the format-neutral building blocks can validate it.
/// This is the seam a binding for CAdES, XAdES, PAdES or JAdES fills; the library ships the CMS one.
/// </summary>
/// <param name="context">The Signed Data Object and any caller-supplied Signer's Documents.</param>
/// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The extracted facts. The delegate reports a signature it cannot parse as
/// <see cref="SignatureFactsStatus.FormatFailure"/> rather than throwing: the Signed Data Object is
/// attacker-reachable input and clause 5.2.2.3 of EN 319 102-1 defines an indication, not an exception, for it.
/// The caller owns and disposes the returned facts.
/// </returns>
public delegate ValueTask<SignatureFacts> ExtractSignatureFactsAsyncDelegate(
    SignatureFactsExtractionContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


/// <summary>
/// The outcome of the cryptographic checks clause 5.2.7.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> prescribes, in the vocabulary of its Table 15.
/// </summary>
/// <remarks>
/// <see cref="NotVerified"/> occupies zero so a default-initialised outcome never reads as a successful
/// verification.
/// </remarks>
public enum SignatureCryptographicOutcome
{
    /// <summary>No verification has been performed. The value of an unset field, by design.</summary>
    NotVerified = 0,

    /// <summary>Every check of clause 5.2.7.4 succeeded — the <c>PASSED</c> row of Table 15.</summary>
    Verified = 1,

    /// <summary>The hash of at least one signed data item does not match the corresponding hash value in the signature — the <c>FAILED</c>/<c>HASH_FAILURE</c> row of Table 15 (step 2)).</summary>
    HashFailure = 2,

    /// <summary>The cryptographic verification of the signature value failed — the <c>FAILED</c>/<c>SIG_CRYPTO_FAILURE</c> row of Table 15 (step 4)).</summary>
    SignatureValueFailure = 3,

    /// <summary>The signed data could not be obtained — the <c>INDETERMINATE</c>/<c>SIGNED_DATA_NOT_FOUND</c> row of Table 15 (step 1)).</summary>
    SignedDataNotFound = 4
}


/// <summary>
/// What a format binding's cryptographic verification concluded, in the vocabulary of Table 15 of clause 5.2.7.3
/// of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
[DebuggerDisplay("SignatureCryptographicVerification: {Outcome}")]
public sealed record SignatureCryptographicVerification
{
    /// <summary>The outcome of the checks of clause 5.2.7.4.</summary>
    public required SignatureCryptographicOutcome Outcome { get; init; }

    /// <summary>The identifiers of the signed data items that caused a <see cref="SignatureCryptographicOutcome.HashFailure"/> or a <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/>, which Table 15 says the process should output; empty when the binding had none to name.</summary>
    public IReadOnlyList<string> FailingObjectIdentifiers { get; init; } = [];

    /// <summary>What the binding could state about the outcome beyond the indication, for a Driving Application to present; <see langword="null"/> when it had nothing to add.</summary>
    public string? Reason { get; init; }
}


/// <summary>
/// The per-call context a <see cref="VerifySignatureCryptographyAsyncDelegate"/> implementation receives — the
/// inputs of Table 14 of clause 5.2.7.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> — so the delegate carries no caller data through a lambda closure.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns;
/// the delegate must not dispose any of it.
/// </remarks>
[DebuggerDisplay("SignatureCryptographicVerificationContext: chain of {ValidatedCertificateChain.Count}")]
public sealed record SignatureCryptographicVerificationContext
{
    /// <summary>The signature's facts — Table 14's mandatory "Signature" input, in the form the engine holds it.</summary>
    public required SignatureFacts Signature { get; init; }

    /// <summary>Table 14's mandatory "Signing Certificate" input.</summary>
    public required PkiCertificateMemory SigningCertificate { get; init; }

    /// <summary>Table 14's optional "Validated certificate chain" input, which its NOTE 1 says some algorithms need in full; empty when no chain was validated.</summary>
    public IReadOnlyList<PkiCertificateMemory> ValidatedCertificateChain { get; init; } = [];

    /// <summary>Table 14's optional "Signer's Document or Signer's Document Representation" input; empty when the signature encapsulates its content.</summary>
    public IReadOnlyList<SignerDocumentReference> SignerDocuments { get; init; } = [];
}


/// <summary>
/// Performs the cryptographic checks of clause 5.2.7.4 of EN 319 102-1 for one base format: obtaining the signed
/// data items, checking their integrity, and verifying the signature value under the signing certificate's
/// public key.
/// </summary>
/// <param name="context">The signature, the signing certificate and the optional chain and documents.</param>
/// <param name="pool">The memory pool any scratch buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The outcome in Table 15's vocabulary. The delegate reports a failure rather than throwing: the signature is
/// attacker-reachable input and clause 5.2.7.3 defines indications, not exceptions, for every way the checks can
/// fail.
/// </returns>
public delegate ValueTask<SignatureCryptographicVerification> VerifySignatureCryptographyAsyncDelegate(
    SignatureCryptographicVerificationContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


/// <summary>
/// The per-call context a <see cref="StateTimestampCoverageAsyncDelegate"/> implementation receives, so the
/// delegate carries no caller data through a lambda closure.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns;
/// the delegate must not dispose any of it.
/// </remarks>
[DebuggerDisplay("TimestampCoverageContext: {Timestamp.Class} from {Timestamp.Identifier}")]
public sealed record TimestampCoverageContext
{
    /// <summary>The signature the time-stamp is embedded in.</summary>
    public required SignatureFacts Signature { get; init; }

    /// <summary>The embedded time-stamp whose coverage is asked about.</summary>
    public required EmbeddedTimestamp Timestamp { get; init; }
}


/// <summary>
/// States the octets one embedded time-stamp's <c>messageImprint</c> is computed over according to the format
/// specification the binding speaks — what step 1) of clause 5.6.2.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> means by objects "protected by the time-stamp", and what step 3)a) of clause
/// 5.5.4 means by a message imprint "generated according to the corresponding signature format specification".
/// </summary>
/// <param name="context">The signature and the time-stamp.</param>
/// <param name="pool">The memory pool the returned carrier is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The octets, which the caller owns and disposes, or <see langword="null"/> when the binding cannot state them
/// for that time-stamp class. A binding reports a token it cannot parse the same way; the POE extraction building
/// block admits nothing into its set for a time-stamp whose coverage is not stated and verified.
/// </returns>
public delegate ValueTask<SignedContentMemory?> StateTimestampCoverageAsyncDelegate(
    TimestampCoverageContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


/// <summary>
/// The per-call context a <see cref="StateTimestampProtectsObjectAsyncDelegate"/> implementation receives — one
/// candidate object of the signature, asked about one time-stamp — so the delegate carries no caller data through
/// a lambda closure.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns;
/// the delegate must not dispose any of it.
/// </remarks>
[DebuggerDisplay("TimestampProtectedObjectContext: {Kind} against {Timestamp.Class} from {Timestamp.Identifier}")]
public sealed record TimestampProtectedObjectContext
{
    /// <summary>The signature both the time-stamp and the candidate object are carried in.</summary>
    public required SignatureFacts Signature { get; init; }

    /// <summary>The embedded time-stamp whose protection of the candidate object is asked about.</summary>
    public required EmbeddedTimestamp Timestamp { get; init; }

    /// <summary>The candidate object's own encoded octets, as the extracted facts carry them.</summary>
    public required PkiCertificateMemory Object { get; init; }

    /// <summary>What the candidate object is, which decides where in the format's own coverage statement the answer is looked up.</summary>
    public required ValidationObjectKind Kind { get; init; }
}


/// <summary>
/// Decides whether one embedded time-stamp is shown to protect one individual object of the signature — the
/// object-level reading of "objects ... that are protected by the time-stamp" of step 1) of clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>, which a format specification may state more finely than the per-class
/// classification of clause 5.6.3.1 does.
/// </summary>
/// <param name="context">The signature, the time-stamp, and the one candidate object.</param>
/// <param name="pool">The memory pool any scratch buffer and any computed digest is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// <see langword="true"/> when the object may be admitted into the set the POE extraction building block derives
/// proofs for, <see langword="false"/> when the binding shows it is not protected. The delegate reports rather
/// than throws: the signature is attacker-reachable input, and a binding that cannot decide answers the
/// fail-closed way for the object in question.
/// </returns>
/// <remarks>
/// This is a narrowing filter, never a widening one: the class-based admission of clause 5.6.3.1 decides which
/// objects are candidates at all, and a binding that supplies this delegate can only remove candidates the format
/// specification shows the time-stamp does not in fact protect. A binding that supplies nothing keeps the
/// per-class admission exactly as it stands.
/// </remarks>
public delegate ValueTask<bool> StateTimestampProtectsObjectAsyncDelegate(
    TimestampProtectedObjectContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);


/// <summary>
/// One base format's binding to the format-neutral validation algorithm: the delegates the building blocks call
/// instead of knowing the format. A seam bundle of delegates and context records, not an interface.
/// </summary>
/// <remarks>
/// The engine holds a bundle, never a format-specific type. Adding a base format is adding a bundle;
/// <see cref="CAdESSignatureFacts.Seam"/> is the one this library ships.
/// </remarks>
[DebuggerDisplay("SignatureFormatSeam: {Format.Value}")]
public sealed record SignatureFormatSeam
{
    /// <summary>The base format this bundle speaks.</summary>
    public required SignatureFormatIdentifier Format { get; init; }

    /// <summary>Extracts the signature's facts, and thereby performs the parse the format checking building block of clause 5.2.2 checks.</summary>
    public required ExtractSignatureFactsAsyncDelegate ExtractFacts { get; init; }

    /// <summary>Performs the cryptographic checks of clause 5.2.7.4 over the format's own encoding.</summary>
    public required VerifySignatureCryptographyAsyncDelegate VerifyCryptography { get; init; }

    /// <summary>
    /// States what a time-stamp embedded in the signature covers, so that the POE extraction building block of
    /// clause 5.6.2.3 can verify the binding rather than infer it from the attribute the token was found in.
    /// <see langword="null"/> when the binding states nothing about any class, which the block treats as a
    /// time-stamp that protects nothing it can name.
    /// </summary>
    public StateTimestampCoverageAsyncDelegate? StateTimestampCoverage { get; init; }

    /// <summary>
    /// States, per object, whether a time-stamp embedded in the signature protects it, so that the POE extraction
    /// building block of clause 5.6.2.3 admits into its set only the objects the format specification shows the
    /// time-stamp actually covers rather than everything the per-class rule of clause 5.6.3.1 names.
    /// <see langword="null"/> when the binding states nothing at object granularity, which leaves the per-class
    /// admission in force exactly as it stands.
    /// </summary>
    /// <remarks>
    /// A format whose archive time-stamps name their protected objects one by one — the <c>ats-hash-index-v3</c>
    /// of ETSI EN 319 122-1 clause 5.5.2 is one — supplies this so that material appended to a signature
    /// <em>after</em> an archive time-stamp was applied gains no proof of existence from it. Without it, the
    /// coarser class rule would grant one, which is a proof of existence nothing in the signature establishes.
    /// </remarks>
    public StateTimestampProtectsObjectAsyncDelegate? StateTimestampProtectsObject { get; init; }
}


/// <summary>
/// The per-call context a <see cref="ValidateTimestampTokenAsyncDelegate"/> implementation receives — the inputs
/// of Table 19 of clause 5.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> that a caller of the time-stamp validation building block supplies per call.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> <see cref="Token"/> is a non-owning reference to memory the validation run owns.
/// </remarks>
[DebuggerDisplay("TimestampTokenValidationContext: at {ValidationTime}")]
public sealed record TimestampTokenValidationContext
{
    /// <summary>The DER-encoded time-stamp token to validate — Table 19's mandatory input.</summary>
    public required PkiCertificateMemory Token { get; init; }

    /// <summary>The instant to validate the token at.</summary>
    public required DateTimeOffset ValidationTime { get; init; }
}


/// <summary>
/// Validates a time-stamp token per clause 5.4 of EN 319 102-1 — step 1) of clause 5.2.8.4.2.5, which the
/// signature acceptance validation building block runs for each time-stamp on a Signed Data Object before it
/// checks the token's message imprint itself.
/// </summary>
/// <param name="context">The token and the instant to validate it at.</param>
/// <param name="pool">The memory pool any scratch buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>What the time-stamp validation concluded, in the building-block vocabulary of clause 5.1.3.</returns>
/// <remarks>
/// A seam rather than a direct call because clause 5.4.4 step 1) has time-stamp validation run the whole
/// validation process for Basic Signatures on the token, with its own trust anchors and its own policy — inputs
/// only the composing process holds.
/// </remarks>
public delegate ValueTask<BuildingBlockConclusion> ValidateTimestampTokenAsyncDelegate(
    TimestampTokenValidationContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
