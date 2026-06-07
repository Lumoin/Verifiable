using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Action produced by <see cref="States.VerifierResponseReceivedState"/> indicating that
/// the encrypted Authorization Response JWE must be decrypted and the VP token
/// verified before the flow can advance to
/// <see cref="Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState"/>.
/// </summary>
/// <remarks>
/// Carries exactly the per-flow values needed for decryption and verification.
/// <see cref="AllowedEncAlgorithms"/> is the set the Verifier advertised in
/// <c>encrypted_response_enc_values_supported</c>; the handler validates the JWE
/// <c>enc</c> header against this set before decrypting per
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0 §5.1</see>.
/// </remarks>
/// <param name="EncryptedResponseJwt">
/// The compact JWE received in the <c>direct_post.jwt</c> request body.
/// </param>
/// <param name="DecryptionKeyId">
/// The identifier of the ephemeral private key. The handler resolves this to live
/// key material via the decryption key resolver delegate.
/// </param>
/// <param name="Nonce">
/// The transaction nonce carried forward for KB-JWT nonce verification.
/// </param>
/// <param name="AllowedEncAlgorithms">
/// The content encryption algorithms the Verifier advertised in
/// <c>encrypted_response_enc_values_supported</c>. The JWE <c>enc</c> header must
/// be one of these values.
/// </param>
/// <param name="CredentialQueries">
/// The DCQL credential queries the Verifier expects to receive presentations
/// for — one per credential queried in the JAR's DCQL query. Each query's
/// <see cref="CredentialQuery.Id"/> is the lookup key when extracting compact
/// presentations from the decrypted <c>vp_token</c> JSON object, and its
/// <see cref="CredentialQuery.Format"/> selects the per-format verifier, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#response-parameters">OID4VP 1.0 §8.1</see>.
/// Multi-credential presentations carry multiple entries; single-credential
/// flows carry one.
/// </param>
/// <param name="TransactionData">
/// The <c>transaction_data</c> descriptors the Verifier bound into the JAR per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
/// The handler hashes these to populate
/// <see cref="Verifiable.OAuth.Validation.ValidationContext.ExpectedTransactionDataHashes"/>
/// for round-trip validation against the Wallet's KB-JWT
/// <c>transaction_data_hashes</c> claim.
/// </param>
public sealed record DecryptResponseAction(
    string EncryptedResponseJwt,
    KeyId DecryptionKeyId,
    TransactionNonce Nonce,
    IReadOnlyList<string> AllowedEncAlgorithms,
    IReadOnlyList<CredentialQuery> CredentialQueries,
    IReadOnlyList<string>? TransactionData = null): OAuthAction;
