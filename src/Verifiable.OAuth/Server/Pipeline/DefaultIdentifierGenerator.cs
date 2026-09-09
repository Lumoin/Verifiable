using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Library default backing for
/// <see cref="AuthorizationServerIntegration.GenerateIdentifierAsync"/>:
/// purpose-aware identifier generation. Credential-shaped purposes — values
/// an attacker could present, such as authorization codes, refresh tokens,
/// and PAR handles — get 32 bytes (256 bits) of CSPRNG output as hex,
/// clearing RFC 6749 §10.10's required 2⁻¹²⁸ guessing bound and its
/// recommended 2⁻¹⁶⁰. Correlation-shaped purposes get a v7 GUID's
/// 32-character hex string, whose timestamp prefix is sourced from the
/// supplied <see cref="TimeProvider"/> so deployments running against a
/// virtual clock (event-sourced replay, distributed time-skew correction)
/// get identifiers stamped with the configured time rather than the BCL
/// wall-clock.
/// </summary>
/// <remarks>
/// <para>
/// A v7 GUID carries only 62 random bits behind a predictable timestamp
/// (RFC 9562 §5.7) — fine for correlation keys that never leave the server's
/// trust boundary as credentials, far below §10.10 for anything a client
/// presents back. Purposes this class does not recognise are treated as
/// credentials — fail closed toward the stronger form.
/// </para>
/// <para>
/// This default draws credential bytes from the caller-supplied
/// <see cref="FillEntropyDelegate"/> rather than the platform CSPRNG
/// directly, so a deployment that tracks entropy through its own providers
/// (or a TPM/HSM-backed source) gets that provenance for free; a deployment
/// needing purpose-specific formats, audit-log emission, or
/// replay-deterministic identifier injection still replaces the whole
/// integration delegate (the seam exists for exactly that). Stored as a
/// factory taking <see cref="TimeProvider"/>, <see cref="FillEntropyDelegate"/>,
/// and <see cref="BaseMemoryPool"/> rather than a static method because none
/// of the three is ambiently available — the caller (typically
/// <see cref="EndpointServer"/> construction) binds all three.
/// </para>
/// </remarks>
public static class DefaultIdentifierGenerator
{
    /// <summary>
    /// The CSPRNG byte length for credential-shaped identifiers: 32 bytes
    /// (256 bits) clears RFC 6749 §10.10's MUST (guessing probability at
    /// most 2⁻¹²⁸) and SHOULD (at most 2⁻¹⁶⁰) with margin.
    /// </summary>
    public const int CredentialByteLength = 32;


    /// <summary>
    /// Returns a <see cref="GenerateIdentifierDelegate"/> that emits a
    /// 64-character hex string drawn from <paramref name="fillEntropy"/> for
    /// credential-shaped purposes and a v7 GUID's 32-character hex string for
    /// correlation-shaped purposes, ignoring the per-call request context.
    /// </summary>
    /// <param name="timeProvider">The time source for the v7 GUID's encoded timestamp. Required.</param>
    /// <param name="fillEntropy">The entropy source the credential-shaped branch draws its bytes from. Required.</param>
    /// <param name="pool">The pool the credential-shaped branch rents its scratch buffer from. Required.</param>
    public static GenerateIdentifierDelegate For(TimeProvider timeProvider, FillEntropyDelegate fillEntropy, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(pool);

        return (purpose, context, cancellationToken) =>
        {
            if(IsCredentialShaped(purpose))
            {
                using IMemoryOwner<byte> owner = pool.Rent(CredentialByteLength);
                Span<byte> bytes = owner.Memory.Span[..CredentialByteLength];
                fillEntropy(bytes);
                string credential = Convert.ToHexStringLower(bytes);

                return ValueTask.FromResult(credential);
            }

            //v7 GUID — the 48-bit prefix encodes Unix milliseconds, the
            //following 12 bits encode version + the random "ver A" field
            //per RFC 9562 §5.7, and the remaining 62 bits are random. The
            //"N" format strips hyphens and braces; result is exactly 32
            //hex characters.
            string identifier = Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N");

            return ValueTask.FromResult(identifier);
        };
    }


    /// <summary>
    /// Whether <paramref name="purpose"/> names a value an attacker could
    /// present as a credential — and so must meet RFC 6749 §10.10. Only the
    /// known correlation-shaped purposes (server-internal keys, public
    /// identifiers, uniqueness-only claims) get the v7 form; an unrecognised
    /// purpose is treated as a credential.
    /// </summary>
    private static bool IsCredentialShaped(IdentifierPurpose purpose) =>
        !(purpose.Equals(WellKnownIdentifierPurposes.OAuthFlowId)
            || purpose.Equals(WellKnownIdentifierPurposes.OAuthRefreshFlowId)
            || purpose.Equals(WellKnownIdentifierPurposes.OAuthJti)
            || purpose.Equals(WellKnownIdentifierPurposes.OAuthClientId)
            || purpose.Equals(WellKnownIdentifierPurposes.OAuthCorrelationId)
            || purpose.Equals(WellKnownIdentifierPurposes.Oid4VpWalletFlowId));
}
