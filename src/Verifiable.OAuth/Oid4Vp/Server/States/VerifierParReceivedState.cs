using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The Verifier has received and validated a PAR request. Initial server-side state.
/// </summary>
/// <remarks>
/// Per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §5.2</see>
/// and
/// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>,
/// the PAR response is sent immediately. JAR signing is deferred to the JAR request
/// endpoint. <see cref="OAuthFlowState.NextAction"/> returns
/// <see cref="Verifiable.Core.Automata.NullAction.Instance"/>.
/// </remarks>
[DebuggerDisplay("VerifierParReceived FlowId={FlowId} RequestUri={Par.RequestUri}")]
public sealed record VerifierParReceivedState: OAuthFlowState
{
    /// <summary>
    /// The PAR response carrying the generated <c>request_uri</c> and
    /// <c>expires_in</c>.
    /// </summary>
    public required ParResponse Par { get; init; }

    /// <summary>The transaction nonce to embed in the JAR.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>The prepared DCQL query to embed in the JAR.</summary>
    public required PreparedDcqlQuery Query { get; init; }

    /// <summary>
    /// The identifier of the ephemeral private key for JWE decryption.
    /// </summary>
    public required KeyId DecryptionKeyId { get; init; }

    /// <summary>
    /// The identifier of the signing key used to sign the JAR at the JAR request
    /// endpoint.
    /// </summary>
    public required KeyId SigningKeyId { get; init; }

    /// <summary>
    /// The content encryption algorithms the Verifier advertised in
    /// <c>encrypted_response_enc_values_supported</c>. Carried through all states so
    /// the <see cref="DecryptResponseAction"/> handler can validate the JWE
    /// <c>enc</c> header against this set per
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0 §5.1</see>.
    /// </summary>
    public required IReadOnlyList<string> AllowedEncAlgorithms { get; init; }
}
