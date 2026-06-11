using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The neutral information model of an OID4VCI 1.0 §8.2 Credential Request, parsed from the
/// JSON request body by the application-wired
/// <see cref="Server.ParseCredentialRequestDelegate"/> (default in <c>Verifiable.Json</c>) and
/// handed to the <see cref="Server.IssueCredentialDelegate"/> issuance seam.
/// </summary>
/// <remarks>
/// <para>
/// The library reads only the wire shape; the application owns proof verification and
/// minting. Exactly one of <see cref="CredentialConfigurationId"/> /
/// <see cref="CredentialIdentifier"/> identifies what is requested (§8.2 — they are mutually
/// exclusive); the Credential Endpoint enforces that shape before the seam is consulted.
/// </para>
/// <para>
/// <see cref="Proofs"/> mirrors the §8.2 <c>proofs</c> object: a map from proof type name
/// (<see cref="Oid4VciCredentialParameterNames.JwtProofType"/> et al.) to the non-empty array
/// of key proofs of that type. The application verifies each proof against its <c>c_nonce</c>
/// store and binds each issued Credential to the proven holder key.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialRequest ConfigurationId={CredentialConfigurationId} Identifier={CredentialIdentifier} ProofTypes={Proofs.Count}")]
public sealed record CredentialRequest
{
    /// <summary>
    /// The §8.2 <c>credential_configuration_id</c>, or <see langword="null"/> when issuance is
    /// requested through <see cref="CredentialIdentifier"/>.
    /// </summary>
    public string? CredentialConfigurationId { get; init; }

    /// <summary>
    /// The §8.2 <c>credential_identifier</c>, or <see langword="null"/> when issuance is
    /// requested through <see cref="CredentialConfigurationId"/>.
    /// </summary>
    public string? CredentialIdentifier { get; init; }

    /// <summary>
    /// The §8.2 <c>proofs</c> map — proof type name to the array of key proofs of that type.
    /// Empty when the Credential Request carries no proofs (valid only for Credential
    /// Configurations that declare no <c>proof_types_supported</c>; the issuance seam decides).
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Proofs { get; init; } =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

    /// <summary>
    /// The §8.2 <c>di_vp</c> key proofs (Appendix F.2) — a non-empty array of W3C Verifiable
    /// Presentation JSON objects, each carried verbatim as its serialized JSON. Unlike
    /// <see cref="Proofs"/> (whose values are string proofs such as <c>jwt</c> / <c>attestation</c>),
    /// a <c>di_vp</c> proof is an object, so it is surfaced here rather than dropped. Empty when the
    /// request carries no <c>di_vp</c> proof type; the issuance seam owns the Data Integrity
    /// verification of each presentation.
    /// </summary>
    public IReadOnlyList<string> DiVpProofs { get; init; } = [];

    /// <summary>
    /// The §8.2 <c>credential_response_encryption</c> object, or <see langword="null"/> when
    /// the Wallet did not ask for an encrypted response. When present, §8.3 requires the
    /// response to be encrypted per §10 regardless of its content.
    /// </summary>
    public CredentialResponseEncryption? ResponseEncryption { get; init; }
}
