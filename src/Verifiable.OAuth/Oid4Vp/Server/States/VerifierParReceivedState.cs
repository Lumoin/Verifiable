using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;

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
[DebuggerDisplay("VerifierParReceived FlowId={FlowId} ParHandle={ParHandle}")]
public sealed record VerifierParReceivedState: OAuthFlowState
{
    /// <summary>
    /// The PAR response carrying the generated <c>request_uri</c> and
    /// <c>expires_in</c>.
    /// </summary>
    /// <remarks>
    /// <see cref="ParResponse.ExpiresIn"/> is the lifetime of the
    /// <c>request_uri</c> handle per RFC 9126 §2.2. It is not the lifetime
    /// of the JAR's <c>exp</c> claim — the two are distinct windows. The
    /// JAR is composed at JAR-fetch time and gets its own timing claims at
    /// that point per OID4VP 1.0 §5.2.
    /// </remarks>
    public required ParResponse Par { get; init; }

    /// <summary>
    /// The opaque per-flow token embedded in the <c>request_uri</c> URL the
    /// Wallet dereferences. The same value is written as the JAR's <c>state</c>
    /// claim and echoed by the Wallet as the <c>state</c> form field in the
    /// direct_post per OID4VP 1.0 §6.1 and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// </summary>
    /// <remarks>
    /// The token is unrelated to <see cref="OAuthFlowState.FlowId"/>; the flow
    /// identifier never leaves the server process. The application's
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/>
    /// maps inbound tokens back to flow identifiers.
    /// </remarks>
    public required string ParHandle { get; init; }

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

    /// <summary>
    /// Optional <c>transaction_data</c> descriptors to bind into the JAR per
    /// OID4VP 1.0 §8.4. Carried through to the JAR-signing action and to the
    /// response-verification step so the hashes returned by the Wallet can be
    /// validated against the verifier's own recomputation.
    /// </summary>
    public IReadOnlyList<string>? TransactionData { get; init; }

    /// <summary>
    /// Optional additional JOSE header claims to merge into the JAR header at
    /// JAR-sign time per OID4VP 1.0 §5.9.3 — the <c>trust_chain</c> array for
    /// the <c>openid_federation:</c> prefix, the <c>x5c</c> array for
    /// <c>x509_san_dns:</c>, the <c>jwt</c> attestation for
    /// <c>verifier_attestation:</c>.
    /// </summary>
    public JwtHeader? JarAdditionalHeaderClaims { get; init; }

    /// <summary>
    /// Optional <c>response_mode</c> override for the JAR's response_mode
    /// claim. <see langword="null"/> defers to the library default
    /// (<c>direct_post.jwt</c>, HAIP 1.0 §5.1). Set this to
    /// <see cref="WellKnownResponseModes.DirectPost"/> for the OID4VP 1.0
    /// §8.2 plaintext-direct_post path.
    /// </summary>
    public string? ResponseMode { get; init; }

}
