using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Decides whether a key named by a presented token's <c>kid</c> is one the registration lists for
/// issuing that kind of token, so the server verifies a token as its own only under a key listed for
/// that kind.
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
/// The admission is the library's security policy: a kind of token verifies as this server's own only
/// under the keys the registration lists for issuing that kind, the <see cref="SigningKeySet"/> it
/// holds for the kind's <see cref="KeyUsageContext"/>. RFC 8725 §3.12 names separate keys as one of
/// several strategies for keeping the kinds' validation rules mutually exclusive; the library applies
/// this one beside explicit typing. Every rotation slot of the set
/// (<see cref="SigningKeySet.AllKnownKeys"/>) is admitted, each for its own reason. An incoming key is
/// admitted because the server alone holds its private half and relying parties already cache its
/// public half, so a token signed at a cutover observed elsewhere first is not refused. A current key
/// is admitted because it is the key the server signs that kind with now. A retiring key is admitted
/// for the grace window in which tokens signed just before the cutover are still in flight. A
/// historical key is admitted because the application opted to keep it for tokens issued before an
/// earlier rotation; an access token verified under it is still bounded by its <c>exp</c>. A
/// withdrawn or compromised key is removed from the set, and that removal is what revokes its
/// admission.
/// </para>
/// <para>
/// The <see cref="ServerVerificationKeyResolverDelegate"/> is told the usage the key is expected
/// under, the same <see cref="KeyUsageContext"/> this admission checks, so an application's key store
/// that keeps keys apart per kind answers only a key it holds for that usage. A resolver may still
/// answer by the key identifier alone and return a key the application holds for another purpose (a
/// client's assertion key, another registration's key, the key of another token kind); this admission
/// runs first and refuses such a key whatever the resolver would answer. The admission stays the
/// library's guarantee: the usage lets a resolver narrow what verifies, never widen it.
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
