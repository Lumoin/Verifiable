using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// Processes one extension's outputs for a ceremony, producing the claims that extension's own
/// semantics warrant.
/// </summary>
/// <param name="request">The extension identifier and its still-encoded output slices.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The claims this extension's processing produced.</returns>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-specification">W3C Web
/// Authentication Level 3, section 9.2: Defining Extensions</see>: "A definition of an extension
/// MUST specify ... the client extension processing rules". A thrown exception (other than genuine
/// cancellation) is treated by <see cref="Fido2ExtensionChecks"/> as this extension's processing
/// having failed — the surrounding ceremony extension-output claim reports
/// <see cref="ClaimOutcome.Failure"/> — fail-closed, mirroring how
/// <see cref="AttestationVerifyDelegate"/> failures surface.
/// </remarks>
public delegate ValueTask<List<Claim>> ExtensionOutputProcessDelegate(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken);


/// <summary>
/// Selects the <see cref="ExtensionOutputProcessDelegate"/> registered for an extension
/// identifier.
/// </summary>
/// <param name="identifier">The extension identifier to look up.</param>
/// <returns>The registered <see cref="ExtensionOutputProcessDelegate"/>, or <see langword="null"/> when <paramref name="identifier"/> is not registered.</returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">W3C Web Authentication Level 3,
/// section 9.1: Extension Identifiers</see>: "Implementations MUST match WebAuthn extension
/// identifiers in a case-sensitive fashion." An implementation built with
/// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> satisfies this by dispatching through an
/// ordinal (case-sensitive) dictionary lookup, the structural twin of how
/// <see cref="SelectAttestationVerifierDelegate"/>/<see cref="Fido2AttestationSelectors.FromFormats"/>
/// satisfy the corresponding attestation-format-identifier MUST in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids">section 8.1</see>.
/// </para>
/// <para>
/// Returning <see langword="null"/> for an unregistered identifier is not itself a failure: per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9</see>'s "Relying Parties
/// MUST be prepared to handle cases where some or all of those extensions are ignored",
/// <see cref="Fido2ExtensionChecks"/> ignores an unregistered identifier by default, only failing
/// when the ceremony input opts into <c>RejectUnregisteredExtensionOutputs</c>.
/// </para>
/// </remarks>
public delegate ExtensionOutputProcessDelegate? SelectExtensionOutputProcessorDelegate(string identifier);
