using System.Buffers;
using System.Diagnostics;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Configuration for Data Integrity proof signing on a <see cref="CredentialBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// Captures the signing parameters that are fixed across multiple builds —
/// the private key, verification method, cryptosuite, canonicalization, and
/// codec wiring. Per-build parameters (issuer, subject, validity period) are
/// supplied at <see cref="CredentialBuilder.BuildAndSignAsync(Issuer, CredentialSubjectInput, DateTime, IEnumerable{string}?, DateTime?, string?, CancellationToken)"/>
/// time.
/// </para>
/// <para>
/// The config is set on the builder via
/// <see cref="CredentialBuilderExtensions.WithDataIntegritySigning(CredentialBuilder, DataIntegritySigningConfig)"/>.
/// <see cref="CredentialBuilder.BuildAndSignAsync(Issuer, CredentialSubjectInput, DateTime, IEnumerable{string}?, DateTime?, string?, CancellationToken)"/>
/// reads the config and applies the proof after the credential is built.
/// </para>
/// <para>
/// All fields are <see langword="required"/>; <see cref="ContextResolver"/> is
/// nullable because RDF-canonicalization-free cryptosuites (e.g.,
/// <c>eddsa-jcs-2022</c>) do not need a JSON-LD context resolver.
/// </para>
/// <para>
/// <strong>Time handling.</strong>
#pragma warning disable RS0030 // Banned API referenced in documentation only.
/// <see cref="ProofCreated"/> is the timestamp written into the proof's
/// <c>created</c> field. The library does not consult
/// <see cref="System.DateTime.UtcNow"/> or <see cref="System.TimeProvider"/>;
/// the caller supplies the timestamp explicitly so signing remains
/// deterministic and testable.
#pragma warning restore RS0030
/// </para>
/// </remarks>
[DebuggerDisplay("DataIntegritySigningConfig VerificationMethodId={VerificationMethodId,nq} Cryptosuite={Cryptosuite}")]
public sealed record DataIntegritySigningConfig
{
    /// <summary>
    /// The private key material used to produce the proof signature.
    /// </summary>
    public required PrivateKeyMemory PrivateKey { get; init; }

    /// <summary>
    /// The DID URL identifying the verification method that resolves to the
    /// public counterpart of <see cref="PrivateKey"/>, e.g.,
    /// <c>"did:web:example.com#key-1"</c>.
    /// </summary>
    public required string VerificationMethodId { get; init; }

    /// <summary>
    /// The cryptosuite to apply, e.g.,
    /// <c>EddsaJcs2022CryptosuiteInfo.Instance</c> or
    /// <c>EddsaRdfc2022CryptosuiteInfo.Instance</c>. The cryptosuite determines
    /// the signature algorithm, hash algorithm, and canonicalization expectations.
    /// </summary>
    public required CryptosuiteInfo Cryptosuite { get; init; }

    /// <summary>
    /// The timestamp written into the proof's <c>created</c> field. Supplied
    /// explicitly by the caller; the library never consults a system clock.
    /// </summary>
    public required DateTime ProofCreated { get; init; }

    /// <summary>
    /// The canonicalization function for the cryptosuite's algorithm
    /// (RDFC for <c>eddsa-rdfc-2022</c>, JCS for <c>eddsa-jcs-2022</c>, etc.).
    /// </summary>
    public required CanonicalizationDelegate Canonicalize { get; init; }

    /// <summary>
    /// Resolves JSON-LD contexts during canonicalization. Required for
    /// RDFC-based cryptosuites; pass <see langword="null"/> for JCS-based
    /// cryptosuites that do not consult contexts.
    /// </summary>
    public ContextResolverDelegate? ContextResolver { get; init; }

    /// <summary>
    /// Encodes the signature bytes into the proof-value string form expected
    /// by the cryptosuite (typically multibase base58btc or base64url-no-pad).
    /// </summary>
    public required ProofValueEncoderDelegate EncodeProofValue { get; init; }

    /// <summary>
    /// Serializes a <see cref="VerifiableCredential"/> for canonicalization input.
    /// </summary>
    public required CredentialSerializeDelegate Serialize { get; init; }

    /// <summary>
    /// Deserializes a credential JSON string back into a
    /// <see cref="VerifiableCredential"/>.
    /// </summary>
    public required CredentialDeserializeDelegate Deserialize { get; init; }

    /// <summary>
    /// Serializes the proof-options object for canonicalization input.
    /// </summary>
    public required ProofOptionsSerializeDelegate SerializeProofOptions { get; init; }

    /// <summary>
    /// Encoding delegate (e.g., Base58 encoder) passed through to the proof
    /// value encoder when the cryptosuite needs raw byte encoding.
    /// </summary>
    public required EncodeDelegate Encoder { get; init; }

    /// <summary>
    /// Computes a digest. Wired to a provider-side implementation registered
    /// on <see cref="CryptographicKeyFactory"/> such as
    /// <c>MicrosoftEntropyFunctions.ComputeDigestAsync</c>. The hash algorithm
    /// comes from the cryptosuite at signing time; the delegate dispatches on
    /// the algorithm via the <see cref="Tag"/> built per-call inside
    /// <see cref="CredentialDataIntegrityExtensions.SignAsync"/>.
    /// </summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }

    /// <summary>
    /// Memory pool for signature and digest allocations. Production
    /// deployments typically pass <c>SensitiveMemoryPool&lt;byte&gt;.Shared</c>;
    /// tests may inject a different pool for instrumentation.
    /// </summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
