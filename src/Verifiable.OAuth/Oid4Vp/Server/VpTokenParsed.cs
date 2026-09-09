using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Raw results from parsing and cryptographically verifying a VP token.
/// Produced by <see cref="SdJwtVpTokenVerification"/>, consumed by the executor
/// to construct a <see cref="Validation.ValidationContext"/> for library-side
/// validation.
/// </summary>
[DebuggerDisplay("VpTokenParsed CredentialQueryId={CredentialQueryId} KbJwtSignatureValid={KbJwtSignatureValid} CredentialSignatureValid={CredentialSignatureValid}")]
public sealed record VpTokenParsed
{
    /// <summary>The DCQL credential query identifier the presented credential answered.</summary>
    public required CredentialQueryId CredentialQueryId { get; init; }

    /// <summary>The verified credential's claims, disclosures, type, issuer, trust evidence, and status claim.</summary>
    public required VpCredentialClaims Credential { get; init; }

    /// <summary>
    /// The public key the credential's own issuer signature verified under, borrowed for this flow step.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A borrowed reference, never this record's to dispose: it belongs to whatever the seat's own
    /// issuer-key seam answered from — <see cref="ResolveIssuerKeyDelegate"/> for SD-JWT,
    /// <see cref="SdCwtVpVerificationSeams.ResolveIssuerKey"/> for SD-CWT, and for mdoc the
    /// <see cref="Verifiable.Core.Model.Mdoc.MdocIacaTrustResolution"/> riding the
    /// <see cref="MdocVpVerificationResult"/> the caller of
    /// <see cref="MdocVpTokenVerification.VerifyAsync"/> disposes when the step ends. <see langword="null"/> when no key resolved or the issuer signature did not verify under
    /// the one that did.
    /// </para>
    /// <para>
    /// On the credential-status path it is populated for every format — SD-JWT, SD-CWT and mdoc alike —
    /// because
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List §8.3</see> orders the steps: "Upon receiving a Referenced Token, a Relying Party MUST
    /// first perform the validation of the Referenced Token" and only "If the validation was successful"
    /// evaluate its status. A status check therefore runs only downstream of a verified issuer signature,
    /// which is exactly the point at which this key is known. It is what
    /// <see cref="Verifiable.Core.StatusList.StatusListResolutionContext.ReferencedTokenIssuerKey"/> is
    /// filled from, making Section 11.3's same-key recommendation reachable behind the status resolver.
    /// </para>
    /// </remarks>
    public PublicKeyMemory? CredentialIssuerKey { get; init; }

    /// <summary>The <c>nonce</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtNonce { get; init; }

    /// <summary>The <c>aud</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtAud { get; init; }

    /// <summary>The <c>iat</c> claim extracted from the KB-JWT.</summary>
    public DateTimeOffset? KbJwtIat { get; init; }

    /// <summary>Whether the KB-JWT signature was cryptographically valid.</summary>
    public bool KbJwtSignatureValid { get; init; }

    /// <summary>Whether the credential issuer signature was cryptographically valid.</summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>Whether the <c>sd_hash</c> matched the presented disclosures (SD-JWT).</summary>
    public bool SdHashValid { get; init; }

    /// <summary>Whether the session transcript was correctly computed (mdoc).</summary>
    public bool SessionTranscriptValid { get; init; }

    /// <summary>
    /// The <c>transaction_data_hashes</c> array extracted from the KB-JWT
    /// payload per OID4VP 1.0 §8.4, or <see langword="null"/> when the KB-JWT
    /// did not carry the claim. Each entry is a base64url-encoded digest the
    /// Wallet computed over the corresponding transaction_data string the
    /// Verifier sent in the Authorization Request.
    /// </summary>
    public IReadOnlyList<string>? KbJwtTransactionDataHashes { get; init; }

    /// <summary>
    /// The <c>transaction_data_hashes_alg</c> claim extracted from the KB-JWT,
    /// or <see langword="null"/> when absent. When absent and
    /// <see cref="KbJwtTransactionDataHashes"/> is present, the Wallet implicitly
    /// chose SHA-256 per OID4VP 1.0 §8.4.
    /// </summary>
    public string? KbJwtTransactionDataHashesAlg { get; init; }

    /// <summary>
    /// The shortest disclosure salt length, in bytes, across the presentation's disclosures, or
    /// <see langword="null"/> when the format carries no disclosure salts (mdoc) or there were none.
    /// Captured here because the parse step holds the <c>SdToken</c> disclosures; the executor copies it
    /// onto <see cref="Validation.ValidationContext.MinimumDisclosureSaltLengthBytes"/> for the
    /// salt-length signal. RFC 9901 §9.3 RECOMMENDS at least 16 bytes (128 bits).
    /// </summary>
    public int? MinimumDisclosureSaltLengthBytes { get; init; }

    /// <summary>
    /// Whether any disclosure salt in this presentation was already seen by the application's
    /// salt-reuse store — a correlation/replay signal (RFC 9901 §9.4 requires unique salts). Only ever
    /// <see langword="true"/> when a salt-reuse seam was wired and a reuse was found, so it is the
    /// verifier's opt-in equivalent of DPoP-JTI replay. <see langword="false"/> when no seam was wired
    /// or no reuse occurred.
    /// </summary>
    public bool SaltReused { get; init; }
}
