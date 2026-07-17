using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// One extension output present in a ceremony response, keyed by its wire identifier.
/// </summary>
/// <param name="Identifier">
/// The extension identifier exactly as it appeared on the wire (a member name of
/// <c>clientExtensionResults</c>, or a key of the authenticator data <c>extensions</c> CBOR map).
/// </param>
/// <param name="Value">
/// The still-encoded value slice for this extension: raw UTF-8 JSON for a client extension output,
/// raw CBOR for an authenticator extension output. Not interpreted here — a registered
/// <see cref="ExtensionOutputProcessDelegate"/> decodes it.
/// </param>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level 3,
/// section 9: WebAuthn Extensions</see> and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">section 9.1: Extension
/// Identifiers</see>, whose "Implementations MUST match WebAuthn extension identifiers in a
/// case-sensitive fashion" is why <see cref="Identifier"/> is compared ordinally everywhere this
/// type is consumed (<see cref="Fido2ExtensionSelectors.FromIdentifiers"/> and
/// <see cref="Fido2ExtensionChecks"/>).
/// </para>
/// <para>
/// A ceremony's decoded extension outputs are carried as a list of these — one entry per
/// extension identifier present on that side (client or authenticator) — computed upstream of
/// <see cref="RegistrationCeremonyInput"/>/<see cref="AssertionCeremonyInput"/> construction, the
/// same way <see cref="AssertionCeremonyInput.ExpectedRpIdHash"/> is computed upstream rather than
/// derived by a rule.
/// </para>
/// </remarks>
[DebuggerDisplay("Fido2ExtensionOutput(Identifier={Identifier,nq}, Value={Value.Length} bytes)")]
public sealed record Fido2ExtensionOutput(string Identifier, ReadOnlyMemory<byte> Value);
