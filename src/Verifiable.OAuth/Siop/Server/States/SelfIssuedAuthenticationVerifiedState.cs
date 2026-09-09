using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// Terminal success of the SIOPv2 RP flow: the Wallet's Self-Issued ID Token validated per
/// §11.1 — signature, subject-syntax classification, <c>sub</c>↔key binding, audience, nonce,
/// and expiry — and the End-User's self-issued subject is established.
/// </summary>
[DebuggerDisplay("SelfIssuedAuthenticationVerifiedState Subject={Subject} SyntaxType={SubjectSyntaxType}")]
public sealed record SelfIssuedAuthenticationVerifiedState: FlowState
{
    /// <summary>The verified <c>sub</c> — a JWK Thumbprint URI or a DID, per the Subject Syntax Type.</summary>
    public required string Subject { get; init; }

    /// <summary>The classified §11.1 Subject Syntax Type of <see cref="Subject"/>.</summary>
    public required SiopSubjectSyntaxType SubjectSyntaxType { get; init; }

    /// <summary>The transaction nonce the verified ID Token carried.</summary>
    public required string Nonce { get; init; }

    /// <summary>When verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }

    /// <summary>
    /// The IETF Token Status List outcomes for the §12 combined response's <c>vp_token</c>, keyed by the
    /// DCQL credential query identifier, carried through from
    /// <see cref="SelfIssuedAuthenticationVerified.CredentialStatuses"/>. <see langword="null"/> for an
    /// id_token-only response, an unreferenced status, or an executor registered without a status
    /// resolver. A relying party hosting the SIOP flow reads this from the terminal state to act on
    /// revocation/suspension.
    /// </summary>
    public IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome>? CredentialStatuses { get; init; }

    /// <summary>
    /// The §12 combined response's verified <c>vp_token</c> credential, keyed by the
    /// <see cref="CredentialQueryId"/> it was presented under, carried through from
    /// <see cref="SelfIssuedAuthenticationVerified.Credentials"/>. <see langword="null"/> for an
    /// id_token-only response.
    /// </summary>
    public IReadOnlyDictionary<CredentialQueryId, VpCredentialClaims>? Credentials { get; init; }
}
