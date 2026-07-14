namespace Verifiable.Fido2;

/// <summary>
/// Factory methods for creating <see cref="SelectAttestationVerifierDelegate"/> implementations
/// backed by a dictionary of (format identifier, delegate) registrations.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the dict-of-delegates shape of <c>DidMethodSelectors.FromResolvers</c>: registrations
/// are supplied as (key, delegate) pairs — ideally static method groups closing over no caller
/// state — and dispatch is by exact key lookup.
/// </para>
/// <para>
/// Unlike that DID resolver selector, a duplicate format identifier here is rejected outright
/// rather than silently overwritten by the later registration, since two verification
/// procedures registered under the same <c>fmt</c> value is a configuration mistake a caller
/// should learn about immediately.
/// </para>
/// </remarks>
public static class Fido2AttestationSelectors
{
    /// <summary>
    /// Creates a verifier selector from one or more (format, delegate) registrations.
    /// </summary>
    /// <param name="verifiers">
    /// Pairs of attestation statement format identifier (e.g.
    /// <see cref="WellKnownWebAuthnAttestationFormats.Packed"/>) and the corresponding
    /// <see cref="AttestationVerifyDelegate"/>.
    /// </param>
    /// <returns>
    /// A <see cref="SelectAttestationVerifierDelegate"/> that dispatches by an ordinal (USASCII
    /// case-sensitive) match on the format identifier, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids">W3C Web Authentication
    /// Level 3, section 8.1: Attestation Statement Format Identifiers</see>. Returns
    /// <see langword="null"/> for a format with no registration.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="verifiers"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when a delegate is <see langword="null"/>, or when two registrations share the
    /// same format identifier.
    /// </exception>
    public static SelectAttestationVerifierDelegate FromFormats(
        params (string Format, AttestationVerifyDelegate Verifier)[] verifiers)
    {
        ArgumentNullException.ThrowIfNull(verifiers);

        var lookup = new Dictionary<string, AttestationVerifyDelegate>(verifiers.Length, StringComparer.Ordinal);
        foreach((string format, AttestationVerifyDelegate verifier) in verifiers)
        {
            if(verifier is null)
            {
                throw new ArgumentException($"The verifier delegate for format '{format}' is null.", nameof(verifiers));
            }

            if(!lookup.TryAdd(format, verifier))
            {
                throw new ArgumentException($"The format '{format}' is registered more than once.", nameof(verifiers));
            }
        }

        return format => lookup.TryGetValue(format, out AttestationVerifyDelegate? found) ? found : null;
    }
}
