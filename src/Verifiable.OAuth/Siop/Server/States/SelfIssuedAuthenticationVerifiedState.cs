using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// Terminal success of the SIOPv2 RP flow: the Wallet's Self-Issued ID Token validated per
/// §11.1 — signature, subject-syntax classification, <c>sub</c>↔key binding, audience, nonce,
/// and expiry — and the End-User's self-issued subject is established.
/// </summary>
[DebuggerDisplay("SelfIssuedAuthenticationVerifiedState Subject={Subject} SyntaxType={SubjectSyntaxType}")]
public sealed record SelfIssuedAuthenticationVerifiedState: OAuthFlowState
{
    /// <summary>The verified <c>sub</c> — a JWK Thumbprint URI or a DID, per the Subject Syntax Type.</summary>
    public required string Subject { get; init; }

    /// <summary>The classified §11.1 Subject Syntax Type of <see cref="Subject"/>.</summary>
    public required SiopSubjectSyntaxType SubjectSyntaxType { get; init; }

    /// <summary>The transaction nonce the verified ID Token carried.</summary>
    public required string Nonce { get; init; }

    /// <summary>When verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}
