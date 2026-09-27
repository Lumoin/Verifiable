using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Decides whether a key named by a presented token's <c>kid</c> is one the registration issues that
/// kind of token with, so the server verifies a token as its own only under a key it signs that kind
/// of token with.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "If more than
/// one kind of JWT can be issued by the same issuer, the validation rules for those JWTs MUST be
/// written such that they are mutually exclusive, rejecting JWTs of the wrong kind", with, among the
/// strategies it names, "Use different keys for different kinds of JWTs. Then the keys used to
/// validate one kind of JWT will fail to validate other kinds of JWTs."
/// </para>
/// <para>
/// The library signs each kind of token only under the key set the registration lists for that
/// kind's <see cref="KeyUsageContext"/>: <see cref="SigningKeySelection"/> falls back to
/// <see cref="ClientRecord.GetDefaultSigningKeyId"/>, which reads that usage's
/// <see cref="SigningKeySet"/>. That set across its rotation slots
/// (<see cref="SigningKeySet.AllKnownKeys"/>: incoming, current, retiring and historical) is therefore
/// exactly the set the server's own verification of that kind may accept. The
/// <see cref="ServerVerificationKeyResolverDelegate"/> resolves a key by its identifier alone and names
/// no usage, so it can answer a key the application holds for another purpose (a client's assertion
/// key, another registration's key, the key of another token kind); this admission runs before the
/// resolver and refuses such a key whatever the resolver would answer.
/// </para>
/// </remarks>
internal static class IssuedKeyAdmission
{
    /// <summary>
    /// Whether <paramref name="keyId"/> is listed in any rotation slot of the key set
    /// <paramref name="registration"/> holds for <paramref name="usage"/>.
    /// </summary>
    /// <param name="registration">The registration whose signing-key inventory is consulted.</param>
    /// <param name="usage">The token kind's key usage, for example <see cref="KeyUsageContext.AccessTokenIssuance"/>.</param>
    /// <param name="keyId">The key identifier the presented token's protected header names.</param>
    /// <returns>
    /// <see langword="true"/> when the registration lists a key set for <paramref name="usage"/> and
    /// that set's <see cref="SigningKeySet.AllKnownKeys"/> contains <paramref name="keyId"/> under
    /// ordinal comparison; <see langword="false"/> otherwise, including when no set is listed for the
    /// usage at all.
    /// </returns>
    public static bool IsListedFor(ClientRecord registration, KeyUsageContext usage, KeyId keyId)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return registration.SigningKeys.TryGetValue(usage, out SigningKeySet? keySet)
            && keySet.AllKnownKeys.Contains(keyId);
    }
}
