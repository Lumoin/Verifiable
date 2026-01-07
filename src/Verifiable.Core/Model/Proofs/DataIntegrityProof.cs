using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Model.Proofs;

/// <summary>
/// Represents a Data Integrity proof as defined in the W3C Verifiable Credential
/// Data Integrity 1.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// A Data Integrity proof provides information about the proof mechanism, parameters
/// required to verify the proof, and the proof value itself. It is the structure that
/// gets serialized into the <c>proof</c> property of a Verifiable Credential or
/// Verifiable Presentation.
/// </para>
/// <para>
/// The proof is created by canonicalizing the document (transformation), hashing the
/// result, and signing the hash. Verification reverses this process to confirm
/// authenticity and integrity.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("DataIntegrityProof(Cryptosuite = {Cryptosuite?.CryptosuiteName}, Purpose = {ProofPurpose})")]
public sealed class DataIntegrityProof: IEquatable<DataIntegrityProof>
{
    /// <summary>
    /// The proof type identifier value for Data Integrity proofs.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"DataIntegrityProof"</c> and is case-sensitive.
    /// Use this constant in converters and comparisons to avoid magic strings.
    /// </remarks>
    public const string DataIntegrityProofType = "DataIntegrityProof";

    /// <summary>
    /// An optional identifier for this proof, used for referencing in proof chains.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When present, this should be a URL (typically a URN UUID such as
    /// <c>urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5</c>). Other proofs in the same
    /// document can reference this proof via their <see cref="PreviousProof"/> property
    /// to establish a proof chain.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proof-chains">
    /// Data Integrity 1.0 §2.1.2 Proof Chains</see>.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// The proof type identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The value must be a string that maps to a URL. For Data Integrity proofs,
    /// this is <c>"DataIntegrityProof"</c>. The type determines what other fields
    /// are required to secure and verify the proof.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof">
    /// Data Integrity 1.0 §3.1 DataIntegrityProof</see>.
    /// </para>
    /// </remarks>
    public string Type { get; set; } = DataIntegrityProofType;

    /// <summary>
    /// The cryptosuite specifying the algorithms used to create this proof.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the specific combination of canonicalization, hashing, and signing
    /// algorithms. If the proof <see cref="Type"/> is <c>DataIntegrityProof</c>, this
    /// property is required.
    /// </para>
    /// <para>
    /// The concrete type provides full metadata about the cryptosuite including the
    /// canonicalization algorithm, hash algorithm, and signature algorithm. For unknown
    /// cryptosuites encountered during deserialization, this will be an instance of
    /// <see cref="UnknownCryptosuiteInfo"/>.
    /// </para>
    /// <para>
    /// Standard cryptosuites include:
    /// </para>
    /// <list type="bullet">
    /// <item><description><see cref="EddsaRdfc2022CryptosuiteInfo"/>: EdDSA signatures with RDF canonicalization.</description></item>
    /// <item><description><see cref="EddsaJcs2022CryptosuiteInfo"/>: EdDSA signatures with JSON Canonicalization Scheme.</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites">
    /// Data Integrity 1.0 §3 Cryptographic Suites</see>.
    /// </para>
    /// </remarks>
    public CryptosuiteInfo? Cryptosuite { get; set; }

    /// <summary>
    /// A reference to the verification method (public key) used to verify the proof.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The concrete type is determined by the <see cref="ProofPurpose"/> value during
    /// deserialization. For example, when <c>proofPurpose</c> is <c>"assertionMethod"</c>,
    /// this will be an <see cref="AssertionMethod"/> instance.
    /// </para>
    /// <para>
    /// In JSON, this is serialized as either a string URI reference or an embedded
    /// verification method object:
    /// </para>
    /// <code>
    /// "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    /// </code>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public VerificationMethodReference? VerificationMethod { get; set; }

    /// <summary>
    /// The intended purpose of the proof.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acts as a safeguard to prevent the proof from being misused for a purpose other
    /// than intended. The verifier must ensure the proof purpose matches their expectations.
    /// </para>
    /// <para>
    /// Standard values include:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>assertionMethod</c>: For making claims or assertions (used in credentials).</description></item>
    /// <item><description><c>authentication</c>: For proving control of an identifier (used in presentations).</description></item>
    /// <item><description><c>capabilityInvocation</c>: For invoking capabilities.</description></item>
    /// <item><description><c>capabilityDelegation</c>: For delegating capabilities.</description></item>
    /// <item><description><c>keyAgreement</c>: For key agreement operations.</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proof-purposes">
    /// Data Integrity 1.0 §2.2 Proof Purposes</see>.
    /// </para>
    /// </remarks>
    public string? ProofPurpose { get; set; }

    /// <summary>
    /// The date and time when the proof was created.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If included, must be an XML Schema 1.1 <c>dateTimeStamp</c> string in UTC (denoted
    /// by Z at the end) or with a time zone offset. The value is stored as a string to
    /// preserve the exact format from the source document.
    /// </para>
    /// <para>
    /// Use <see cref="DateTimeStampFormat.TryParse"/> to convert to <see cref="DateTimeOffset"/>
    /// and <see cref="DateTimeStampFormat.Format(DateTimeOffset, string)"/> to create valid values.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? Created { get; set; }

    /// <summary>
    /// The date and time when the proof expires.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If present, the proof should be considered invalid at or after this time.
    /// Must be an XML Schema 1.1 <c>dateTimeStamp</c> string. The value is stored as a
    /// string to preserve the exact format from the source document.
    /// </para>
    /// <para>
    /// Use <see cref="DateTimeStampFormat.TryParse"/> to convert to <see cref="DateTimeOffset"/>
    /// and <see cref="DateTimeStampFormat.Format(DateTimeOffset, string)"/> to create valid values.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? Expires { get; set; }

    /// <summary>
    /// One or more security domains in which the proof is meant to be used.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A verifier should use this value to ensure the proof was intended for use
    /// in their security domain. Useful in challenge-response protocols.
    /// </para>
    /// <para>
    /// Example values include: <c>domain.example</c> (DNS domain),
    /// <c>https://domain.example:8443</c> (Web origin), or custom strings.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? Domain { get; set; }

    /// <summary>
    /// A challenge value for mitigating replay attacks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Should be included if a <see cref="Domain"/> is specified. The value is used
    /// once for a particular domain and window of time. Verifiers issue challenges
    /// that provers must include in their proofs.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? Challenge { get; set; }

    /// <summary>
    /// The multibase-encoded signature value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The actual cryptographic proof that the document has not been tampered with.
    /// The value must use a multibase header and encoding as described in the
    /// Controlled Identifiers specification.
    /// </para>
    /// <para>
    /// Most cryptosuites use base58-btc encoding (prefix <c>z</c>).
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? ProofValue { get; set; }

    /// <summary>
    /// A reference to a previous proof that this proof depends on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used when creating chained proofs where one proof depends on another,
    /// such as in notarization scenarios. The value identifies another proof
    /// by its <see cref="Id"/>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proof-chains">
    /// Data Integrity 1.0 §2.1.2 Proof Chains</see>.
    /// </para>
    /// </remarks>
    public string? PreviousProof { get; set; }

    /// <summary>
    /// An optional nonce value for additional randomness.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Can be used to increase privacy by decreasing linkability that results from
    /// deterministically generated signatures.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>.
    /// </para>
    /// </remarks>
    public string? Nonce { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(DataIntegrityProof? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Type, other.Type, StringComparison.Ordinal)
            && string.Equals(Cryptosuite?.CryptosuiteName, other.Cryptosuite?.CryptosuiteName, StringComparison.Ordinal)
            && Equals(VerificationMethod, other.VerificationMethod)
            && string.Equals(ProofPurpose, other.ProofPurpose, StringComparison.Ordinal)
            && string.Equals(Created, other.Created, StringComparison.Ordinal)
            && string.Equals(Expires, other.Expires, StringComparison.Ordinal)
            && string.Equals(Domain, other.Domain, StringComparison.Ordinal)
            && string.Equals(Challenge, other.Challenge, StringComparison.Ordinal)
            && string.Equals(ProofValue, other.ProofValue, StringComparison.Ordinal)
            && string.Equals(PreviousProof, other.PreviousProof, StringComparison.Ordinal)
            && string.Equals(Nonce, other.Nonce, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is DataIntegrityProof proof && Equals(proof);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(DataIntegrityProof? left, DataIntegrityProof? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(DataIntegrityProof? left, DataIntegrityProof? right) =>
        !(left == right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id);
        hash.Add(Type);
        hash.Add(Cryptosuite?.CryptosuiteName);
        hash.Add(VerificationMethod);
        hash.Add(ProofPurpose);
        hash.Add(Created);
        hash.Add(Expires);
        hash.Add(Domain);
        hash.Add(Challenge);
        hash.Add(ProofValue);
        hash.Add(PreviousProof);
        hash.Add(Nonce);

        return hash.ToHashCode();
    }
}