namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The application's per-request answer to "what must this Credential Request's <c>jwt</c> key
/// proof(s) satisfy?", resolved at the
/// <see cref="Server.ResolveCredentialProofExpectationDelegate"/> seam. It carries the values the
/// library-side <see cref="CredentialProofValidator"/> needs but cannot know: the
/// server-provided <c>c_nonce</c> the proof must echo (and whether the Issuer's Nonce Endpoint
/// makes one mandatory), the algorithms acceptable for the proof signature
/// (<c>proof_signing_alg_values_supported</c> / local policy), and the <c>iat</c> acceptance
/// window (§13.8).
/// </summary>
/// <remarks>
/// Returning this expectation OPTS IN to library-side proof validation at the Credential
/// Endpoint. When the seam is unwired the endpoint does not validate proofs itself and leaves the
/// whole §F.4 check to the <see cref="Server.IssueCredentialDelegate"/> seam (the default). The
/// Credential Issuer's <c>c_nonce</c> store and its single-use retirement remain the
/// application's responsibility either way — this expectation only supplies the value to compare
/// against.
/// </remarks>
public sealed record CredentialProofExpectation
{
    /// <summary>
    /// The server-provided <c>c_nonce</c> the proof's <c>nonce</c> claim MUST echo, or
    /// <see langword="null"/> when the Issuer has no Nonce Endpoint and requires none.
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// Whether a matching <c>nonce</c> is REQUIRED in every proof (§F.4: "if the server has a
    /// Nonce Endpoint, the nonce in the key proof matches the server-provided c_nonce value").
    /// </summary>
    public required bool IsNonceRequired { get; init; }

    /// <summary>
    /// The proof signature algorithms acceptable per the issuer's
    /// <c>proof_signing_alg_values_supported</c> metadata and local policy (§F.4). A proof whose
    /// <c>alg</c> is not in this set is rejected. <see langword="null"/> or empty accepts any
    /// registered asymmetric signature algorithm the validator otherwise admits.
    /// </summary>
    public IReadOnlyCollection<string>? AcceptableProofSigningAlgorithms { get; init; }

    /// <summary>
    /// The half-width of the <c>iat</c> acceptance window (§13.8). The proof's <c>iat</c> must lie
    /// within <c>now ± IatSkew</c>.
    /// </summary>
    public TimeSpan IatSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether a request that carries NO <c>jwt</c> proof should be refused by the endpoint as
    /// <c>invalid_proof</c>. When <see langword="false"/> (the default), a proof-less request is
    /// passed through to <see cref="Server.IssueCredentialDelegate"/> — some Credential
    /// Configurations declare no <c>proof_types_supported</c> and bind no holder key.
    /// </summary>
    public bool IsProofRequired { get; init; }

    /// <summary>
    /// The seams that OPT IN to library-side verification of Appendix F.2 <c>di_vp</c> presentation
    /// proofs (deserialization, the holder <see cref="DiVpProofVerification.Resolver"/>, the W3C Data
    /// Integrity verify delegates). When
    /// <see langword="null"/> (the default) the endpoint validates no <c>di_vp</c> presentations
    /// itself and leaves each in <see cref="CredentialRequest.DiVpProofs"/> for
    /// <see cref="Server.IssueCredentialDelegate"/> to verify — the established parse-and-surface
    /// behaviour, unchanged. When set, the library verifies each <c>di_vp</c> presentation with
    /// <see cref="CredentialProofValidator.ValidateDiVpAsync"/> BEFORE issuance, mapping
    /// <see cref="ExpectedNonce"/> to the presentation proof's <c>challenge</c> and the Credential
    /// Issuer Identifier to its <c>domain</c>.
    /// </summary>
    public DiVpProofVerification? DiVpVerification { get; init; }

    /// <summary>
    /// The seam that OPTS IN to library-side resolution of the Appendix F.1 <c>x5c</c> key-reference
    /// mode of a <c>jwt</c> key proof. When <see langword="null"/> (the default) a proof that
    /// references its key by <c>x5c</c> cannot be resolved and is rejected as <c>invalid_proof</c>;
    /// the embedded-<c>jwk</c> and <c>kid</c> modes are unaffected. When set, the library resolves
    /// the holder key from the <c>x5c</c> chain by composing the existing X.509 parse + chain-validate
    /// surface, validating to the trust anchors the application places on the threaded
    /// <see cref="Verifiable.Core.ExchangeContext"/>.
    /// </summary>
    public Oid4VciProofX509Verification? X509Verification { get; init; }

    /// <summary>
    /// The seam that OPTS IN to library-side resolution of the Appendix F.1 <c>kid</c> key-reference
    /// mode of a <c>jwt</c> key proof (§F.1: "kid ... If the Credential is to be bound to a DID, the
    /// kid refers to a DID URL which identifies a particular key in the DID Document"). When
    /// <see langword="null"/> (the default) a proof that references its key by <c>kid</c> cannot be
    /// resolved and is rejected as <c>invalid_proof</c>; the embedded-<c>jwk</c> and <c>x5c</c> modes
    /// are unaffected. The application typically wraps its <see cref="Verifiable.Core.Resolvers.DidResolver"/>
    /// or key store here; the endpoint threads the request <see cref="Verifiable.Core.ExchangeContext"/>
    /// so a network-resolving <c>kid</c> is fetched under the context's SSRF policy.
    /// </summary>
    public CredentialProofValidator.ResolveProofKeyDelegate? KidResolver { get; init; }
}
