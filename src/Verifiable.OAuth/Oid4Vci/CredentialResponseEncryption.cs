using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The OID4VCI 1.0 §8.2 <c>credential_response_encryption</c> request object — the Wallet's
/// instruction to encrypt the (Deferred) Credential Response per §10, carrying the public key
/// the response is encrypted to and the content encryption algorithm.
/// </summary>
/// <remarks>
/// §8.3 / §9.2: when the request carries this object, the Issuer MUST encrypt the response —
/// regardless of its content — as a JWE with media type <c>application/jwt</c>. The endpoint
/// validates the §8.2 REQUIRED members (<see cref="Jwk"/>, <see cref="Enc"/>) and refuses with
/// <c>invalid_encryption_parameters</c> when they are missing or the deployment cannot satisfy
/// them; the application's
/// <see cref="Server.AuthorizationServerIntegration.EncryptCredentialResponseAsync"/> seam owns
/// the JWE composition (§10: the JWE <c>alg</c> comes from the <c>alg</c> member of the JWK,
/// the <c>kid</c> is copied when present).
/// </remarks>
[DebuggerDisplay("CredentialResponseEncryption Enc={Enc} JwkMembers={Jwk?.Count}")]
public sealed record CredentialResponseEncryption
{
    /// <summary>
    /// §8.2 <c>jwk</c> (REQUIRED): the single public key, as its JWK members, used for
    /// encrypting the response. §10 requires the JWK to carry an <c>alg</c> member naming the
    /// JWE key management algorithm. <see langword="null"/> when the request object omitted it
    /// — the endpoint then refuses with <c>invalid_encryption_parameters</c>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Jwk { get; init; }

    /// <summary>
    /// §8.2 <c>enc</c> (REQUIRED): the JWE content encryption algorithm for the response.
    /// <see langword="null"/> when omitted — refused with <c>invalid_encryption_parameters</c>.
    /// </summary>
    public string? Enc { get; init; }

    /// <summary>
    /// §8.2 <c>zip</c> (OPTIONAL): the JWE compression algorithm applied before encryption,
    /// or <see langword="null"/> — compression MUST NOT be used then.
    /// </summary>
    public string? Zip { get; init; }


    /// <summary>
    /// §10 <c>alg</c>: the JWE key management algorithm, read off the <c>alg</c> member of the
    /// <see cref="Jwk"/> ("The alg parameter MUST be present. The JWE alg algorithm used MUST be
    /// equal to the alg value of the chosen JWK." —
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10">§10</see>).
    /// <see langword="null"/> when the JWK omits <c>alg</c> or carries a non-string value — the
    /// endpoint then refuses with <c>invalid_encryption_parameters</c>, as §10's "MUST be present"
    /// requires.
    /// </summary>
    public string? Alg =>
        Jwk is not null
            && Jwk.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algValue)
            && algValue is string alg
                ? alg
                : null;

    /// <summary>
    /// §10 <c>kid</c>: the key identifier carried by the <see cref="Jwk"/>, copied into the JWE
    /// protected header so the recipient can identify the encryption key ("If the selected public
    /// key contains a kid parameter, the JWE MUST include the same value in the kid JWE Header
    /// Parameter." —
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10">§10</see>).
    /// <see langword="null"/> when the JWK carries no <c>kid</c> — the JWE then omits it.
    /// </summary>
    public string? Kid =>
        Jwk is not null
            && Jwk.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
            && kidValue is string kid
                ? kid
                : null;


    /// <summary>
    /// Whether the §8.2 REQUIRED members are present AND the §10 <c>alg</c> MUST is satisfiable —
    /// <see cref="Jwk"/> populated, <see cref="Enc"/> set, and the JWK carrying the §10-REQUIRED
    /// <c>alg</c> member. The deployment's seam may still refuse an unsupported <see cref="Enc"/>
    /// or key type.
    /// </summary>
    public bool IsShapeValid =>
        Jwk is { Count: > 0 } && !string.IsNullOrWhiteSpace(Enc) && !string.IsNullOrWhiteSpace(Alg);
}
