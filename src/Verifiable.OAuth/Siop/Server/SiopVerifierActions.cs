using Verifiable.Cryptography;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// The effectful action produced by <see cref="States.SiopResponseReceivedState"/>: validate the
/// received Self-Issued ID Token per SIOPv2 §11.1 against the transaction's expected audience,
/// nonce, and algorithm allow-list. Run by the registered handler on the
/// <see cref="OAuthActionExecutor"/> between two pure PDA transitions — keeping the cryptographic
/// verification out of the transition function so the automaton stays deterministic.
/// </summary>
/// <param name="IdToken">The compact Self-Issued ID Token the Wallet POSTed.</param>
/// <param name="ExpectedAudience">The RP's <c>client_id</c> — the required <c>aud</c>.</param>
/// <param name="ExpectedNonce">The transaction nonce the token MUST echo.</param>
/// <param name="AllowedAlgorithms">The signing algorithms the RP accepts (<c>none</c> is always rejected).</param>
public sealed record ValidateSelfIssuedIdToken(
    string IdToken,
    string ExpectedAudience,
    string ExpectedNonce,
    IReadOnlyList<string> AllowedAlgorithms): OAuthAction;


/// <summary>
/// The effectful action produced by <see cref="States.SiopCombinedResponseReceivedState"/>: validate
/// a SIOPv2 §12 combined response, where one Authorization Response carries BOTH a Self-Issued ID
/// Token (<c>id_token</c>, §11.1) AND a Verifiable Presentation (<c>vp_token</c>). Run by the
/// registered handler on the <see cref="OAuthActionExecutor"/> between two pure PDA transitions, so
/// neither the cryptographic verification nor the §12 binding decision leaks into the transition
/// function.
/// </summary>
/// <remarks>
/// SIOPv2 §12 requires BOTH artifacts to be bound to the SAME <c>nonce</c> and the RP's Client ID:
/// the id_token echoes the nonce in its <c>nonce</c> claim, and the vp_token's KB-JWT carries the
/// nonce in <c>nonce</c> and the Client ID in <c>aud</c>. The action record carries only the
/// per-transaction data; the handler obtains the vp_token-verification seams (issuer-key lookup,
/// SD-JWT parser, hash-input function, digest function) from the registration closure, the same way
/// the OID4VP <c>ProcessVpTokenAction</c> handler does.
/// </remarks>
/// <param name="IdToken">The compact Self-Issued ID Token the Wallet POSTed.</param>
/// <param name="VpToken">The <c>vp_token</c> presentation (SD-JWT VC + KB-JWT) the Wallet POSTed.</param>
/// <param name="ExpectedAudience">The RP's <c>client_id</c> — the required id_token <c>aud</c> and the vp_token KB-JWT <c>aud</c>.</param>
/// <param name="ExpectedNonce">The transaction nonce BOTH artifacts MUST echo.</param>
/// <param name="AllowedAlgorithms">The signing algorithms the RP accepts for the id_token (<c>none</c> is always rejected).</param>
public sealed record ValidateCombinedSiopResponse(
    string IdToken,
    string VpToken,
    string ExpectedAudience,
    string ExpectedNonce,
    IReadOnlyList<string> AllowedAlgorithms): OAuthAction;


/// <summary>
/// The effectful action produced by <see cref="States.SiopEncryptedResponseReceivedState"/>: decrypt
/// the compact JWE the Wallet returned as the encrypted Self-Issued ID Token, then validate the
/// recovered inner id_token per SIOPv2 §11.1. Run by the registered handler on the
/// <see cref="OAuthActionExecutor"/> between two pure PDA transitions, so neither the JWE decryption
/// nor the §11.1 verification leaks into the transition function. The encrypted-response sibling of
/// <see cref="ValidateSelfIssuedIdToken"/>; mirrors the OID4VP
/// <see cref="Oid4Vp.Server.DecryptResponseAction"/> shape.
/// </summary>
/// <remarks>
/// <see cref="AllowedEncAlgorithms"/> is the set the Relying Party advertised as its encryption
/// metadata; the handler peeks the JWE <c>enc</c> header and validates it against this set BEFORE
/// any cryptographic operation, failing closed when the value is missing or unadvertised. The header
/// is authenticated cryptographically by AES-GCM tag verification inside the decrypt step.
/// </remarks>
/// <param name="EncryptedIdToken">The compact JWE (five dot-separated segments) the Wallet POSTed.</param>
/// <param name="DecryptionKeyId">The decryption private key id; resolved to live key material via the server's <c>DecryptionKeyResolver</c>.</param>
/// <param name="AllowedEncAlgorithms">The content encryption algorithms the RP advertised; the JWE <c>enc</c> header must be one of these.</param>
/// <param name="ExpectedAudience">The RP's <c>client_id</c> — the required <c>aud</c> of the recovered inner token.</param>
/// <param name="ExpectedNonce">The transaction nonce the recovered inner token MUST echo.</param>
/// <param name="AllowedAlgorithms">The signing algorithms the RP accepts for the recovered inner token (<c>none</c> is always rejected).</param>
public sealed record DecryptSiopResponse(
    string EncryptedIdToken,
    KeyId DecryptionKeyId,
    IReadOnlyList<string> AllowedEncAlgorithms,
    string ExpectedAudience,
    string ExpectedNonce,
    IReadOnlyList<string> AllowedAlgorithms): OAuthAction;
