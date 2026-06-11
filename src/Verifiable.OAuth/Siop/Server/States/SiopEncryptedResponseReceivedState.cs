using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// The Wallet's ENCRYPTED Self-Issued ID Token response has been received and recorded against the
/// transaction, but not yet decrypted or verified: the <c>id_token</c> arrived as a compact JWE
/// encrypted to the Relying Party's public encryption key. Overrides
/// <see cref="OAuthFlowState.NextAction"/> to declare a <see cref="DecryptSiopResponse"/> action:
/// the effectful JWE decryption (validating <c>enc</c> against <see cref="AllowedEncAlgorithms"/>
/// first) and the §11.1 validation of the recovered inner id_token run through the
/// <see cref="OAuthActionExecutor"/> (not in the pure transition), producing the
/// <see cref="SelfIssuedAuthenticationVerified"/> / <see cref="SiopFlowFailed"/> input that advances
/// the flow. The encrypted-response sibling of <see cref="SiopResponseReceivedState"/>, which carries
/// the bare-JWS id_token; the SIOP parallel of the OID4VP verifier's
/// <see cref="Verifiable.OAuth.Oid4Vp.Server.States.VerifierResponseReceivedState"/>.
/// </summary>
[DebuggerDisplay("SiopEncryptedResponseReceivedState FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record SiopEncryptedResponseReceivedState: OAuthFlowState
{
    /// <summary>The compact JWE (five dot-separated segments) the Wallet POSTed. Preserved for audit and replay detection.</summary>
    public required string EncryptedIdToken { get; init; }

    /// <summary>The RP's <c>client_id</c> — the required <c>aud</c> of the recovered inner token.</summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>The transaction nonce the recovered inner token MUST echo.</summary>
    public required string ExpectedNonce { get; init; }

    /// <summary>The signing algorithms the RP accepts for the recovered inner token.</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>
    /// The identifier of the decryption private key whose public half the RP advertised as its
    /// encryption key. The <see cref="DecryptSiopResponse"/> handler resolves it to live key material
    /// via the server's <c>DecryptionKeyResolver</c>.
    /// </summary>
    public required KeyId DecryptionKeyId { get; init; }

    /// <summary>
    /// The content encryption algorithms the RP advertised for an encrypted response. The JWE
    /// <c>enc</c> header is validated against this set before any cryptographic operation.
    /// </summary>
    public required IReadOnlyList<string> AllowedEncAlgorithms { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }


    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new DecryptSiopResponse(
            EncryptedIdToken,
            DecryptionKeyId,
            AllowedEncAlgorithms,
            ExpectedAudience,
            ExpectedNonce,
            AllowedAlgorithms);
}
