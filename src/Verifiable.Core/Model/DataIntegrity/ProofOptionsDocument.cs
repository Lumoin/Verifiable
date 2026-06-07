using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the proof options document that gets canonicalized and hashed during
/// Data Integrity proof creation and verification.
/// </summary>
/// <remarks>
/// <para>
/// This is the intermediate artifact described in
/// <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">W3C Data Integrity §4.2 Add Proof</see>
/// and reconstructed during
/// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">§4.2 Verify Proof</see>:
/// the proof with <c>proofValue</c> removed, plus an optional <c>@context</c> inherited
/// from the secured document for RDFC canonicalization. The signing algorithm serializes
/// this document, canonicalizes it, and hashes the result alongside the document hash;
/// the verifier reconstructs the same bytes to verify the signature.
/// </para>
/// <para>
/// There is ONE construction path — <see cref="FromProof"/> over a
/// <see cref="DataIntegrityProof"/> — for signing and verification alike: the signer
/// builds the complete proof skeleton (everything except <c>proofValue</c>) FIRST and
/// derives the options from it, so every member the wire proof will carry — including
/// <see cref="Id"/> and <see cref="PreviousProof"/> for chains — is covered by the
/// signature, exactly as §4.2's proof-minus-proofValue reconstruction expects.
/// </para>
/// <para>
/// <strong>Shape preservation:</strong> when the proof was parsed from a wire document,
/// <see cref="ReceivedProofJson"/> carries the signer's own bytes and the serializer
/// reconstructs the options from THEM (removing <c>proofValue</c>) rather than from the
/// typed members — scalar-versus-array shapes (e.g. a multi-domain set), member presence,
/// and timestamp formats survive exactly as signed.
/// </para>
/// <para>
/// <strong>Challenge and domain:</strong> when present, <see cref="Challenge"/> and
/// <see cref="Domain"/> are part of the canonicalized options and therefore covered by
/// the signature — that coverage is what makes them anti-replay bindings rather than
/// advisory fields. Both are required for presentation proofs using
/// <c>proofPurpose: authentication</c>.
/// </para>
/// <para>
/// <strong>Context handling:</strong> the <see cref="Context"/> property carries the
/// secured document's <c>@context</c> for cryptosuites that require JSON-LD processing
/// (RDFC-based suites); for JCS-based suites it is <see langword="null"/>. See
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context Validation</see>.
/// </para>
/// </remarks>
public sealed class ProofOptionsDocument
{
    /// <summary>
    /// The proof identifier, when the proof carries one (e.g. as a chain target).
    /// Covered by the signature.
    /// </summary>
    public string? Id { get; init; }

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
    /// The proof expiry timestamp as an XML Schema 1.1 <c>dateTimeStamp</c> string,
    /// when present. Covered by the signature.
    /// </summary>
    public string? Expires { get; init; }

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
    /// The security domain binding for this proof, or <see langword="null"/> if not
    /// domain-bound. Per Data Integrity 1.0 §2.1 the value is a string or an unordered
    /// set of strings; this carries the set form.
    /// </summary>
    /// <remarks>
    /// When present, this value is included in the canonicalized proof options and is therefore
    /// covered by the signature. Verifiers must check that the domain matches their own identifier
    /// to prevent cross-domain replay attacks.
    /// </remarks>
    public IReadOnlyList<string>? Domain { get; init; }

    /// <summary>
    /// The challenge value binding this proof to a specific verifier interaction,
    /// or <see langword="null"/> if not challenge-bound.
    /// </summary>
    /// <remarks>
    /// When present, this value is included in the canonicalized proof options and is therefore
    /// covered by the signature. Verifiers must check that the challenge matches the value they
    /// issued to prevent replay attacks. Required for presentation proofs where
    /// <see cref="ProofPurpose"/> is <c>"authentication"</c>.
    /// </remarks>
    public string? Challenge { get; init; }

    /// <summary>
    /// The proof's <c>nonce</c>, when present. Covered by the signature.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The chained proof reference (<c>previousProof</c>), when present. Coverage by the
    /// signature is what makes a proof chain cryptographically chained
    /// (Data Integrity 1.0 §2.1.2).
    /// </summary>
    public string? PreviousProof { get; init; }

    /// <summary>
    /// The proof's received wire JSON, when the proof was parsed from a wire document.
    /// The serializer prefers this — removing <c>proofValue</c> and injecting
    /// <see cref="Context"/> — over re-serializing the typed members, so verification
    /// canonicalizes the signer's own bytes. See
    /// <see cref="DataIntegrityProof.ReceivedProofJson"/>.
    /// </summary>
    public string? ReceivedProofJson { get; init; }


    /// <summary>
    /// Creates a <see cref="ProofOptionsDocument"/> from a <see cref="DataIntegrityProof"/>
    /// and the secured document's context. The single construction path: the signer passes
    /// the complete proof skeleton (no <c>proofValue</c> yet) and the verifier passes the
    /// parsed proof — both yield the same options, which is the §4.2 contract.
    /// </summary>
    /// <param name="proof">The proof skeleton (signing) or the parsed proof (verification).</param>
    /// <param name="context">The secured document's <c>@context</c>, or <see langword="null"/> for JCS-based suites.</param>
    /// <returns>The proof options document.</returns>
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
            Id = proof.Id,
            Type = proof.Type ?? DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = proof.Cryptosuite,
            Created = proof.Created ?? string.Empty,
            Expires = proof.Expires,
            VerificationMethod = proof.VerificationMethod?.Id ?? string.Empty,
            ProofPurpose = proof.ProofPurpose ?? string.Empty,
            Context = context,
            Domain = proof.Domain,
            Challenge = proof.Challenge,
            Nonce = proof.Nonce,
            PreviousProof = proof.PreviousProof,
            ReceivedProofJson = proof.ReceivedProofJson
        };
    }
}
