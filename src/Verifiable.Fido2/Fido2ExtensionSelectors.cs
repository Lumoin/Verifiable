namespace Verifiable.Fido2;

/// <summary>
/// Factory methods for creating <see cref="SelectExtensionOutputProcessorDelegate"/> implementations
/// backed by a dictionary of (extension identifier, delegate) registrations.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the dict-of-delegates shape of <see cref="Fido2AttestationSelectors.FromFormats"/>:
/// registrations are supplied as (key, delegate) pairs — ideally static method groups closing over
/// no caller state — and dispatch is by exact key lookup.
/// </para>
/// <para>
/// The lookup dictionary is keyed with <see cref="StringComparer.Ordinal"/>, which is itself the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">W3C Web Authentication Level 3,
/// section 9.1: Extension Identifiers</see> case-sensitive-match MUST — "Implementations MUST match
/// WebAuthn extension identifiers in a case-sensitive fashion" — satisfied structurally, the same
/// way <see cref="Fido2AttestationSelectors.FromFormats"/> satisfies the parallel attestation
/// statement format identifier MUST in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids">section 8.1</see>. A duplicate
/// identifier is rejected outright rather than silently overwritten by the later registration,
/// since two processors registered under the same identifier is a configuration mistake a caller
/// should learn about immediately.
/// </para>
/// </remarks>
public static class Fido2ExtensionSelectors
{
    /// <summary>
    /// Creates an extension-output processor selector from one or more (identifier, delegate)
    /// registrations.
    /// </summary>
    /// <param name="processors">
    /// Pairs of extension identifier (e.g. <c>credProps</c>, case-sensitive per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">section 9.1</see>) and the
    /// corresponding <see cref="ExtensionOutputProcessDelegate"/>.
    /// </param>
    /// <returns>
    /// A <see cref="SelectExtensionOutputProcessorDelegate"/> that dispatches by an ordinal
    /// (case-sensitive) match on the identifier. Returns <see langword="null"/> for an identifier
    /// with no registration.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="processors"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when a delegate is <see langword="null"/>, or when two registrations share the
    /// same identifier.
    /// </exception>
    public static SelectExtensionOutputProcessorDelegate FromIdentifiers(
        params (string Identifier, ExtensionOutputProcessDelegate Processor)[] processors)
    {
        ArgumentNullException.ThrowIfNull(processors);

        var lookup = new Dictionary<string, ExtensionOutputProcessDelegate>(processors.Length, StringComparer.Ordinal);
        foreach((string identifier, ExtensionOutputProcessDelegate processor) in processors)
        {
            if(processor is null)
            {
                throw new ArgumentException($"The processor delegate for identifier '{identifier}' is null.", nameof(processors));
            }

            if(!lookup.TryAdd(identifier, processor))
            {
                throw new ArgumentException($"The identifier '{identifier}' is registered more than once.", nameof(processors));
            }
        }

        return identifier => lookup.TryGetValue(identifier, out ExtensionOutputProcessDelegate? found) ? found : null;
    }
}
