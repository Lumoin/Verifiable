using System.Diagnostics;

namespace Verifiable.OAuth.Pkce;

/// <summary>
/// The Base64url-encoded verifier and challenge for one PKCE exchange.
/// </summary>
/// <remarks>
/// <para>
/// PKCE (Proof Key for Code Exchange) is specified in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see>.
/// The verifier is a cryptographically random nonce held by the initiating
/// party throughout the exchange. Only the challenge — the SHA-256 digest
/// of the Base64url-encoded verifier — is transmitted to the authorization
/// server at the authorization endpoint. The verifier is sent at the token
/// endpoint to prove the two requests originate from the same party.
/// </para>
/// <para>
/// Both values are Base64url-encoded strings without padding. The raw bytes
/// used during generation are discarded after encoding — this type carries
/// only the wire-ready string values needed by the protocol.
/// </para>
/// <para>
/// Use <see cref="PkceGeneration.Generate"/> to produce a cryptographically valid pair.
/// </para>
/// </remarks>
[DebuggerDisplay("PkceParameters Method={Method} VerifierLength={EncodedVerifier.Length}")]
public sealed record PkceParameters(
    string EncodedVerifier,
    string EncodedChallenge,
    PkceMethod Method);