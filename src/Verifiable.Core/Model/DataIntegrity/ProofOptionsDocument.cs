using System;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the proof options document that gets canonicalized and hashed during
/// Data Integrity proof creation and verification.
/// </summary>
/// <remarks>
/// <para>
/// This is the intermediate artifact described in
/// <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">W3C Data Integrity §4.2 Add Proof</see>.
/// It contains the proof metadata fields without <c>proofValue</c>, plus an optional
/// <c>@context</c> inherited from the secured document. The signing algorithm serializes
/// this document, canonicalizes it, and hashes the result alongside the credential hash.
/// The verifier reconstructs the same document from the proof to verify the signature.
/// </para>
/// <para>
/// This type is distinct from <see cref="DataIntegrityProof"/> because:
/// </para>
/// <list type="bullet">
/// <item><description>It never carries <c>proofValue</c> (which is the output of signing).</description></item>
/// <item><description>It carries <c>@context</c> inherited from the secured document for RDFC canonicalization.</description></item>
/// <item><description>It uses a string representation for <c>verificationMethod</c> matching the JSON wire format,
/// while <c>cryptosuite</c> carries the full <see cref="CryptosuiteInfo"/> for type safety.</description></item>
/// </list>
/// <para>
/// <strong>Context handling:</strong> The <see cref="Context"/> property carries the secured
/// document's <c>@context</c> for cryptosuites that require JSON-LD processing (e.g., RDFC-based
/// suites). For JCS-based suites, this is <see langword="null"/>. Implementations SHOULD
/// permanently cache context files and MUST validate them per
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">§2.4.1 Validating Contexts</see>
/// and <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context Validation</see>.
/// See also <see href="https://github.com/w3c/vc-data-integrity/issues/323">Issue #323</see>
/// regarding external context availability and longevity.
/// </para>
/// </remarks>
public sealed class ProofOptionsDocument
{
    /// <summary>
    /// The proof type identifier. For Data Integrity proofs this is <c>"DataIntegrityProof"</c>.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The cryptosuite identifying the algorithms used (e.g., <c>eddsa-rdfc-2022</c>,
    /// <c>ecdsa-sd-2023</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This carries the full <see cref="CryptosuiteInfo"/> rather than just the name string,
    /// providing type safety, debugger display, and access to suite metadata. The serializer
    /// reads <see cref="CryptosuiteInfo.CryptosuiteName"/> when producing the JSON wire format.
    /// </para>
    /// </remarks>
    public required CryptosuiteInfo Cryptosuite { get; init; }

    /// <summary>
    /// The proof creation timestamp as an XML Schema 1.1 <c>dateTimeStamp</c> string.
    /// </summary>
    public required string Created { get; init; }

    /// <summary>
    /// The verification method identifier (typically a DID URL) as a string reference.
    /// </summary>
    public required string VerificationMethod { get; init; }

    /// <summary>
    /// The intended purpose of the proof (e.g., <c>"assertionMethod"</c>).
    /// </summary>
    public required string ProofPurpose { get; init; }

    /// <summary>
    /// The <c>@context</c> inherited from the secured document for RDFC canonicalization.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <see langword="null"/> for JCS-based cryptosuites which do not require
    /// JSON-LD processing. For RDFC-based cryptosuites, this carries the credential's
    /// context so that the proof options document can be expanded and canonicalized.
    /// </para>
    /// </remarks>
    public object? Context { get; init; }


    /// <summary>
    /// Creates a <see cref="ProofOptionsDocument"/> from an existing <see cref="DataIntegrityProof"/>
    /// and the secured document's context. Used during verification to reconstruct the proof
    /// options document that was canonicalized during signing.
    /// </summary>
    /// <param name="proof">The proof from the secured document.</param>
    /// <param name="context">The secured document's <c>@context</c>, or <see langword="null"/> for JCS-based suites.</param>
    /// <returns>The reconstructed proof options document.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="proof"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the proof does not contain a <see cref="DataIntegrityProof.Cryptosuite"/>.
    /// </exception>
    public static ProofOptionsDocument FromProof(DataIntegrityProof proof, object? context)
    {
        ArgumentNullException.ThrowIfNull(proof);

        if(proof.Cryptosuite is null)
        {
            throw new InvalidOperationException("Cannot construct proof options document from a proof without a cryptosuite.");
        }

        return new ProofOptionsDocument
        {
            Type = proof.Type ?? DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = proof.Cryptosuite,
            Created = proof.Created ?? string.Empty,
            VerificationMethod = proof.VerificationMethod?.Id ?? string.Empty,
            ProofPurpose = proof.ProofPurpose ?? string.Empty,
            Context = context
        };
    }


    /// <summary>
    /// Creates a <see cref="ProofOptionsDocument"/> for signing with the specified parameters.
    /// </summary>
    /// <param name="cryptosuite">The cryptosuite information.</param>
    /// <param name="created">The formatted creation timestamp.</param>
    /// <param name="verificationMethodId">The verification method DID URL.</param>
    /// <param name="proofPurpose">The proof purpose string.</param>
    /// <param name="context">The secured document's <c>@context</c>, or <see langword="null"/> for JCS-based suites.</param>
    /// <returns>A new proof options document ready for serialization and canonicalization.</returns>
    public static ProofOptionsDocument ForSigning(
        CryptosuiteInfo cryptosuite,
        string created,
        string verificationMethodId,
        string proofPurpose,
        object? context)
    {
        ArgumentNullException.ThrowIfNull(cryptosuite);
        ArgumentException.ThrowIfNullOrWhiteSpace(created);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
        ArgumentException.ThrowIfNullOrWhiteSpace(proofPurpose);

        return new ProofOptionsDocument
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = cryptosuite,
            Created = created,
            VerificationMethod = verificationMethodId,
            ProofPurpose = proofPurpose,
            Context = context
        };
    }
}