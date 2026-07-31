using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The carriers one signature validation run created, held so that the run — and nothing inside it — owns them.
/// </summary>
/// <remarks>
/// <para>
/// Every result record the validation processes of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5</see> produce is non-owning: a conclusion references the certificates,
/// digests and time-stamp facts the run consulted rather than owning them, because the same certificate is
/// reported by several blocks and referenced by several report data records. Something has to own them, and that
/// something is this ledger, which the composition root creates and disposes.
/// </para>
/// <para>
/// Carriers are released in the reverse of the order they were tracked, so a carrier built from another is always
/// released first. Tracking the same instance twice would release it twice; every call site tracks exactly once,
/// at the point the instance is created.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureValidationResources: {Count} carriers")]
public sealed class SignatureValidationResources: IDisposable
{
    /// <summary>The carriers tracked so far, in tracking order.</summary>
    private readonly List<IDisposable> resources = [];

    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>Gets the number of carriers tracked so far.</summary>
    public int Count => resources.Count;


    /// <summary>
    /// Tracks one carrier and hands it back, so a creation and its tracking are one expression.
    /// </summary>
    /// <typeparam name="T">The carrier's type.</typeparam>
    /// <param name="resource">The carrier the run has just created and now owns.</param>
    /// <returns>The same carrier.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="resource"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the run has already been disposed.</exception>
    public T Track<T>(T resource) where T: IDisposable
    {
        ArgumentNullException.ThrowIfNull(resource);
        ObjectDisposedException.ThrowIf(disposed, this);

        resources.Add(resource);

        return resource;
    }


    /// <summary>
    /// Tracks every carrier of a list — the shape the chain completion seam hands back newly acquired
    /// certificates in.
    /// </summary>
    /// <param name="carriers">The carriers the run has just taken ownership of.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="carriers"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the run has already been disposed.</exception>
    public void TrackRange(IReadOnlyList<PkiCertificateMemory> carriers)
    {
        ArgumentNullException.ThrowIfNull(carriers);
        ObjectDisposedException.ThrowIf(disposed, this);

        for(int i = 0; i < carriers.Count; ++i)
        {
            resources.Add(carriers[i]);
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        for(int i = resources.Count - 1; i >= 0; --i)
        {
            resources[i].Dispose();
        }

        resources.Clear();
    }
}


/// <summary>
/// The delegates one signature validation run reaches the outside world through — the format binding, the
/// certificate chain seams, the revocation seam and the signature policy seam. A seam bundle of delegates and
/// context records, not an interface.
/// </summary>
/// <remarks>
/// Clause 5.1.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> puts obtaining validation material outside the validation algorithm; every
/// member here is the boundary at which the algorithm asks the composition for something it does not compute
/// itself. Nothing here holds state between calls and nothing reads a clock.
/// </remarks>
[DebuggerDisplay("SignatureValidationSeams: {Format.Format.Value}")]
public sealed record SignatureValidationSeams
{
    /// <summary>The base format binding: the fact extraction the format checking building block of clause 5.2.2 runs, and the cryptographic verification of clause 5.2.7.</summary>
    public required SignatureFormatSeam Format { get; init; }

    /// <summary>The chain building seam step 2) of clause 5.2.6.4 and step 1) of clause 5.6.2.1.4 compose.</summary>
    public required CompleteCertificateChainAsyncDelegate CompleteCertificateChain { get; init; }

    /// <summary>The certification path validation seam of <see href="https://www.rfc-editor.org/rfc/rfc5280">RFC 5280</see> §6.1 that step 4) of clause 5.2.6.4 and step 2) of clause 5.6.2.1.4 compose.</summary>
    public required ValidateCertificateChainAsyncDelegate ValidateCertificateChain { get; init; }

    /// <summary>The revocation seam consulted for a certificate the caller supplied no <see cref="RevocationStatusInformation"/> about, or <see langword="null"/> when the run is offline.</summary>
    public CheckCertificateRevocationStatusAsyncDelegate? CheckRevocation { get; init; }

    /// <summary>The signature policy document seam of clause 5.2.4.4, or <see langword="null"/> when the caller's own constraints drive the run.</summary>
    public ResolveSignatureValidationPolicyAsyncDelegate? ResolveSignaturePolicy { get; init; }

    /// <summary>
    /// Whether the signature algorithm the format binding surfaces needs the full certificate chain to determine
    /// the public key, which step 4) of clause 5.3.4 conditions its <c>NO_CERTIFICATE_CHAIN_FOUND</c> early return
    /// on. Defaults to <see langword="false"/>: the RSA and elliptic-curve algorithms the shipped bindings speak
    /// take the public key from the signing certificate alone, so the cryptographic verification can still run and
    /// the general branch of step 4) reports the same sub-indication through step 5)f).
    /// </summary>
    public bool SignatureAlgorithmRequiresFullCertificateChain { get; init; }
}


/// <summary>
/// Everything the Driving Application hands one signature validation run — the union of the inputs of Table 18
/// (clause 5.3.2), Table 20 (clause 5.5.2) and Table 27 (clause 5.6.3.2) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// One record for all three processes, because clause 5.1.2 lets the SVA choose among them for the same
/// signature and because clause 5.5.4 step 2) and clause 5.6.3.4 step 3) each run the next process down "with all
/// the inputs". A process ignores the inputs its own table does not name.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run.
/// </para>
/// </remarks>
[DebuggerDisplay("SignatureValidationInputs: {CertificateValidationData.Count} validation data objects")]
public sealed record SignatureValidationInputs
{
    /// <summary>The Signed Data Object — the one mandatory input of Tables 18, 20 and 27.</summary>
    public required SensitiveMemory SignedDataObject { get; init; }

    /// <summary>The validation constraints the run applies unless a signature policy mapping replaces them — clause 5.1.4's set of constraints, carrying the trust anchor list of Tables 18, 20 and 27.</summary>
    public required SignatureValidationConstraints Constraints { get; init; }

    /// <summary>The Signer's Documents or Signer's Document Representations, for a detached signature; empty when the signature encapsulates its content.</summary>
    public IReadOnlyList<SignerDocumentReference> SignerDocuments { get; init; } = [];

    /// <summary>The signing certificate the Driving Application supplies, or <see langword="null"/> when the signature's own copy is to be used.</summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>The "Signature Validation Policies" input: the mapping from signature creation policies to validation constraints that clause 5.2.4.4 selects through.</summary>
    public IReadOnlyList<SignaturePolicyConstraintsMapping> SignaturePolicies { get; init; } = [];

    /// <summary>The local configuration decision of clause 5.2.4.4 for a creation policy the mapping does not cover.</summary>
    public UnmappedSignaturePolicyHandling UnmappedSignaturePolicyHandling { get; init; }

    /// <summary>The "Certificate Validation Data" input the Driving Application supplies in addition to what the signature carries: certificates, certificate revocation lists and OCSP responses, each carrying its own <see cref="PkiObjectKind"/> discriminator.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; init; } = [];

    /// <summary>The revocation status information the Driving Application's own checkers established about the certificates of the chain — the facts NOTE 7 of clause 5.2.6.4 assumes are supplied.</summary>
    public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformation { get; init; } = [];

    /// <summary>
    /// Table 20's "time indication for signature existence": a time the Driving Application knows, or assumes,
    /// the signature has existed, which step 1) of clause 5.5.4 initializes best-signature-time to.
    /// <see langword="null"/> when the Driving Application states none, in which case that step uses the current
    /// time.
    /// </summary>
    public DateTimeOffset? TimeIndicationForSignatureExistence { get; init; }

    /// <summary>Table 27's optional "A set of POEs": proofs of existence the Driving Application obtained elsewhere, which NOTE 3 of clause 5.6.3.4 says "are used without additional processing".</summary>
    public ProofOfExistenceSet ProofsOfExistence { get; init; } = ProofOfExistenceSet.Empty;

    /// <summary>
    /// The Evidence Records accompanying the signature, which step 1) of clause 5.6.3.4 validates "according to
    /// IETF RFC 4998 or IETF RFC 6283" before anything else the process does. Empty — the default — is the state
    /// the step's own NOTE describes as having nothing to validate, and every process below behaves exactly as it
    /// did before this input existed.
    /// </summary>
    /// <remarks>
    /// The input is the Driving Application's, like every other member here: an Evidence Record travels beside a
    /// signature (in an Associated Signature Container, in an archival package, in a CMS unsigned attribute the
    /// caller has already located), and which objects it is claimed to protect is knowledge the container or the
    /// package carries rather than the record.
    /// </remarks>
    public IReadOnlyList<EvidenceRecordValidationInput> EvidenceRecords { get; init; } = [];

    /// <summary>
    /// The constraints applicable for validating time-stamps, which step 1) of clause 5.4.4 has the time-stamp
    /// validation building block use in place of the signature's own — "a trust anchor list applicable for
    /// validating time-stamps according to the validation policy" and "a validation policy applicable for
    /// validating time-stamps if defined by the validation policy". <see langword="null"/> when the validation
    /// policy defines none, in which case <see cref="Constraints"/> apply to time-stamps too.
    /// </summary>
    public SignatureValidationConstraints? TimestampConstraints { get; init; }

    /// <summary>The time-stamp certificate of Table 19, when the Driving Application supplies one for the time-stamps the signature embeds.</summary>
    public PkiCertificateMemory? TimestampCertificate { get; init; }


    /// <summary>
    /// Gets the constraints a time-stamp token is validated under: <see cref="TimestampConstraints"/> when the
    /// validation policy defines them, and <see cref="Constraints"/> otherwise.
    /// </summary>
    public SignatureValidationConstraints ConstraintsForTimestamps => TimestampConstraints ?? Constraints;
}
