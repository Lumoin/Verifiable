using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates the raw bytes handed to the Trusted List seams. A single member: the seams are
/// format-agnostic (a caller may back them with XML per TLv6, or any future encoding the specification
/// adopts), so the tag exists only to give the carrier CBOM/OTel provenance, the same reason
/// <see cref="PkiObjectKind"/> exists for <see cref="PkiCertificateMemory"/>.
/// </summary>
public enum TrustedListDocumentKind
{
    /// <summary>The raw, not-yet-parsed bytes of a Trusted List (or List Of the Trusted Lists) document.</summary>
    Document = 0
}


/// <summary>
/// Pre-built <see cref="Tag"/> instances for the raw document bytes the Trusted List seams exchange.
/// </summary>
public static class TrustedListTags
{
    /// <summary>Tag for the raw, not-yet-parsed bytes of a Trusted List document.</summary>
    public static Tag Document { get; } = Tag.Create(TrustedListDocumentKind.Document);
}


/// <summary>
/// Why <see cref="ParseTrustedListDelegate"/> did, or did not, produce a <see cref="TrustedList"/>.
/// </summary>
public enum TrustedListParseStatus
{
    /// <summary>The document parsed into a well-formed <see cref="TrustedList"/>.</summary>
    Valid,

    /// <summary>The document is not well-formed at all (malformed markup, truncated, wrong root element).</summary>
    Malformed,

    /// <summary>A required element (per ETSI TS 119 612 V2.4.1 clause 5) was absent.</summary>
    MissingRequiredElement,

    /// <summary>
    /// A qualifier <c>CriteriaList</c> nested deeper than the parser's supported bound. Distinct from
    /// <see cref="MissingRequiredElement"/>: nothing is absent, but bounding untrusted-input recursion depth
    /// (the document is attacker-reachable) means a document that nests beyond the bound is rejected rather
    /// than walked arbitrarily deep.
    /// </summary>
    ExcessiveNesting
}


/// <summary>
/// The outcome of <see cref="ParseTrustedListDelegate"/>. On success it owns a <see cref="TrustedList"/> (and
/// every certificate that list's tree carries); the caller disposes it. On failure it owns nothing.
/// </summary>
public sealed record TrustedListParseResult : IDisposable
{
    /// <summary>The parse outcome; <see cref="TrustedListParseStatus.Valid"/> is the only success.</summary>
    public required TrustedListParseStatus Status { get; init; }

    /// <summary>The parsed document; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="TrustedListParseStatus.Valid"/>.</summary>
    public TrustedList? Document { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="TrustedListParseStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="TrustedListParseStatus.Valid"/>.</summary>
    public bool IsValid => Status == TrustedListParseStatus.Valid;


    /// <summary>Creates a successful result owning <paramref name="document"/>.</summary>
    /// <param name="document">The parsed document; ownership transfers to the result.</param>
    /// <returns>A <see cref="TrustedListParseStatus.Valid"/> result.</returns>
    public static TrustedListParseResult Valid(TrustedList document) =>
        new() { Status = TrustedListParseStatus.Valid, Document = document };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="status">The failure status; must not be <see cref="TrustedListParseStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static TrustedListParseResult Failed(TrustedListParseStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };


    /// <summary>Disposes <see cref="Document"/>, when present.</summary>
    public void Dispose() => Document?.Dispose();
}


/// <summary>
/// Parses raw Trusted List document bytes into the pure <see cref="TrustedList"/> model — no signature
/// verification is performed; use <see cref="VerifyTrustedListSignatureDelegate"/> separately to establish
/// trust in <paramref name="document"/> before or after parsing it, exactly as the CMS/CAdES pair in this
/// namespace separates content parsing from signature verification.
/// </summary>
/// <remarks>
/// <para>
/// This library ships no implementation: parsing is XML per the TLv6 profile (or any encoding a future
/// specification revision adopts), and this project stays serialization-agnostic (it references neither
/// <c>Verifiable.Json</c> nor an XML package), mirroring <see cref="Verifiable.Core.Model.DataIntegrity.CanonicalizationDelegate"/>'s
/// "no shipped implementation" shape. A worked XML/<c>System.Security.Cryptography.Xml</c>-based
/// implementation is staged as a promotable example under the test project.
/// </para>
/// <para>
/// <strong>Fail-closed on structure.</strong> Every required element ETSI TS 119 612 V2.4.1 clause 5 defines
/// is required in the returned model too (non-nullable, non-<see langword="init"/>-optional); an
/// implementation that cannot populate a required field MUST return
/// <see cref="TrustedListParseResult.Failed(TrustedListParseStatus, string)"/> rather than inventing a
/// default. Untrusted document depth (a maliciously deep <c>CriteriaList</c> nesting, for example) MUST be
/// bounded by the implementation; this codebase's own worked example walks the document with an explicit
/// <see cref="Stack{T}"/> rather than recursively, so a depth bound is a natural counter check on that stack.
/// </para>
/// <para>
/// <strong>Example implementation shape (using <c>System.Xml.Linq</c>):</strong>
/// </para>
/// <code>
/// ParseTrustedListDelegate parseTrustedList = (document, pool, cancellationToken) =>
/// {
///     XDocument xml = XDocument.Load(new MemoryStream(document.AsReadOnlySpan().ToArray()));
///     //... walk xml.Root iteratively (a Stack&lt;XElement&gt;, never recursion) into a TrustedList.
///     return ValueTask.FromResult(TrustedListParseResult.Valid(trustedList));
/// };
/// </code>
/// </remarks>
/// <param name="document">The raw document bytes. The caller retains ownership and disposes it.</param>
/// <param name="pool">The memory pool the implementation rents any certificate byte carriers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<TrustedListParseResult> ParseTrustedListDelegate(
    PooledMemory document,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Why <see cref="VerifyTrustedListSignatureDelegate"/> did, or did not, confirm the document's signature.
/// </summary>
public enum TrustedListSignatureStatus
{
    /// <summary>The document's signature verified against a supplied trust anchor.</summary>
    Valid,

    /// <summary>The document carries no signature at all.</summary>
    MissingSignature,

    /// <summary>The document's cryptographic signature value did not verify.</summary>
    InvalidSignature,

    /// <summary>The document's signature is missing the mandatory signing-certificate binding.</summary>
    MissingSigningCertificateBinding,

    /// <summary>The signing-certificate binding's digest does not match the certificate the signature carries.</summary>
    SigningCertificateBindingMismatch,

    /// <summary>The signing-certificate binding declares a hash algorithm this implementation does not support.</summary>
    UnsupportedHashAlgorithm,

    /// <summary>The signature is otherwise valid, but the signer is not among the supplied trust anchors.</summary>
    UntrustedSigner,

    /// <summary>The document is not well-formed enough to locate or parse its signature.</summary>
    Malformed
}


/// <summary>
/// The outcome of <see cref="VerifyTrustedListSignatureDelegate"/>.
/// </summary>
public sealed record TrustedListSignatureVerificationResult
{
    /// <summary>The verification outcome; <see cref="TrustedListSignatureStatus.Valid"/> is the only success.</summary>
    public required TrustedListSignatureStatus Status { get; init; }

    /// <summary>Returns <see langword="true"/> when <see cref="Status"/> is <see cref="TrustedListSignatureStatus.Valid"/>.</summary>
    public bool IsValid => Status == TrustedListSignatureStatus.Valid;

    /// <summary>The signing time the signature's signed properties asserted, when present and the signature verified.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>A short, human-readable reason, present on every non-<see cref="TrustedListSignatureStatus.Valid"/> outcome.</summary>
    public string? FailureReason { get; init; }


    /// <summary>Creates a successful result.</summary>
    /// <param name="signingTime">The signature's asserted signing time, when present.</param>
    /// <returns>A <see cref="TrustedListSignatureStatus.Valid"/> result.</returns>
    public static TrustedListSignatureVerificationResult Valid(DateTimeOffset? signingTime) =>
        new() { Status = TrustedListSignatureStatus.Valid, SigningTime = signingTime };

    /// <summary>Creates a failed result.</summary>
    /// <param name="status">The failure status; must not be <see cref="TrustedListSignatureStatus.Valid"/>.</param>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A failed result.</returns>
    public static TrustedListSignatureVerificationResult Failed(TrustedListSignatureStatus status, string reason) =>
        new() { Status = status, FailureReason = reason };
}


/// <summary>
/// Verifies a Trusted List document's own signature against a caller-supplied set of trust anchors —
/// answers exactly "did this document verify," independent of <see cref="ParseTrustedListDelegate"/>
/// parsing its content.
/// </summary>
/// <remarks>
/// <para>
/// This library ships no implementation, for the same reason <see cref="ParseTrustedListDelegate"/> ships
/// none: verifying the TLv6 profile's XAdES-BASELINE-B enveloped signature is an XML operation, and this
/// project stays serialization-agnostic. A worked implementation using
/// <see cref="System.Security.Cryptography.Xml"/>'s <c>SignedXml</c> for the XMLDSIG core plus a small,
/// targeted read of the <c>xades:SigningCertificate</c> binding — structurally the XML analogue of the ESS
/// <c>signing-certificate-v2</c> check <see cref="CAdESVerification"/> already performs for CMS — is staged
/// under the test project.
/// </para>
/// <para>
/// <strong><paramref name="trustAnchors"/> is bootstrap trust, not PKIX discovery.</strong> A Trusted List
/// signer is not chain-built to a public root; it is trusted only because it appears in the caller's
/// already-established trust set (for the EU LOTL, hard-configured; for a member state list, the
/// <see cref="OtherTrustedListPointer.ServiceDigitalIdentities"/> the LOTL published for it). An
/// implementation MUST reject (<see cref="TrustedListSignatureStatus.UntrustedSigner"/>) a cryptographically
/// valid signature whose signer is absent from <paramref name="trustAnchors"/> — fail-closed, the same
/// discipline <see cref="ValidateCertificateChainAsyncDelegate"/> applies to its own trust anchors.
/// </para>
/// </remarks>
/// <param name="document">The raw, signed document bytes. The caller retains ownership and disposes it.</param>
/// <param name="trustAnchors">The certificates the signer must be one of.</param>
/// <param name="pool">The memory pool the implementation rents any scratch buffers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The verification result.</returns>
public delegate ValueTask<TrustedListSignatureVerificationResult> VerifyTrustedListSignatureDelegate(
    PooledMemory document,
    IReadOnlyList<PkiCertificateMemory> trustAnchors,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken = default);
