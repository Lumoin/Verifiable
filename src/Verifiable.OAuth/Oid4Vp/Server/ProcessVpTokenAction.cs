using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Action produced by <see cref="States.VerifierUnencryptedResponseReceivedState"/>
/// indicating that the plaintext <c>vp_token</c> must be parsed and the
/// presentation verified before the flow can advance to
/// <see cref="Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState"/>.
/// </summary>
/// <remarks>
/// Sibling to <see cref="DecryptResponseAction"/> for the unencrypted
/// <c>direct_post</c> path per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
/// The handler skips decryption (the JSON is already plaintext) and runs
/// the same verification pipeline as the encrypted path:
/// <see cref="SdJwtVpTokenVerification.VerifyAsync"/> against the
/// extracted compact presentation, followed by the HAIP profile's claim
/// rules.
/// </remarks>
/// <param name="VpTokenJson">
/// The plaintext <c>vp_token</c> JSON string the Wallet POSTed.
/// </param>
/// <param name="Nonce">
/// The transaction nonce carried forward for KB-JWT nonce verification.
/// </param>
/// <param name="CredentialQueries">
/// The DCQL credential queries the Verifier expects to receive presentations
/// for — one per credential queried in the JAR's DCQL query. Each query's
/// <see cref="CredentialQuery.Id"/> is the lookup key when extracting compact
/// presentations from the parsed <c>vp_token</c> JSON object, and its
/// <see cref="CredentialQuery.Format"/> selects the per-format verifier, per OID4VP 1.0 §8.1.
/// </param>
/// <param name="TransactionData">
/// The <c>transaction_data</c> descriptors the Verifier bound into the JAR
/// per OID4VP 1.0 §8.4. The handler hashes these to populate
/// <see cref="Verifiable.OAuth.Validation.ValidationContext.ExpectedTransactionDataHashes"/>
/// for round-trip validation against the Wallet's KB-JWT
/// <c>transaction_data_hashes</c> claim.
/// </param>
public sealed record ProcessVpTokenAction(
    string VpTokenJson,
    TransactionNonce Nonce,
    IReadOnlyList<CredentialQuery> CredentialQueries,
    IReadOnlyList<string>? TransactionData = null): OAuthAction;
