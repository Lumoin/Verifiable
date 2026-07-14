using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> decode-and-claim processor for the <c>appidExclude</c>
/// extension's registration client extension output, matching
/// <see cref="ExtensionOutputProcessDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">W3C Web
/// Authentication Level 3, section 10.1.2: FIDO AppID Exclusion Extension (appidExclude)</see>: the
/// client extension output "Returns the value TRUE to indicate to the Relying Party that the
/// extension was acted upon" — the only value the specification defines for this member; no FALSE
/// case is specified. Section 10.1.2 defines no RFC2119 keyword for this extension (its
/// FacetID-authorization algorithm is client-only processing, sourced from an external, non-CR
/// document), so this processor closes a feature-completeness gap rather than a normative clause —
/// see <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/>.
/// </para>
/// <para>
/// Lives beside <see cref="ClientExtensionOutputsJsonReader"/> for the same reason
/// <see cref="LargeBlobExtensionProcessor"/> does: decoding the still-encoded
/// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> slice needs
/// <see cref="System.Text.Json"/>, which <c>Verifiable.Fido2</c> is architecturally barred from
/// referencing. Registration-only: <c>appidExclude</c> defines no assertion-side processing.
/// </para>
/// <para>
/// Not wired into <c>Fido2ValidationProfiles</c>' default rule list — registration is opt-in,
/// exactly like <see cref="LargeBlobExtensionProcessor"/>, via the relying party's own
/// <see cref="RegistrationCeremonyInput.ExtensionOutputProcessor"/> selector built with
/// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> keyed on
/// <see cref="WellKnownWebAuthnExtensionIdentifiers.AppIdExclude"/>. It composes with the relying
/// party's own <c>excludeCredentials</c> request (assembled upstream of the ceremony, on the
/// options-construction side); there is no post-hoc <c>excludeCredentials</c> response field for a
/// verifier to cross-check.
/// </para>
/// </remarks>
public static class AppIdExcludeExtensionProcessor
{
    /// <summary>
    /// Bounds JSON nesting depth for the untrusted <c>appidExclude</c> client extension output
    /// value, which is a single boolean.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 1 };


    /// <summary>
    /// Decodes the registration ceremony's <c>appidExclude</c> client extension output, reporting
    /// <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim, <see cref="Fido2ClaimIds.Fido2RegistrationAppIdExclude"/>:
    /// <see cref="ClaimOutcome.Success"/> when the decoded value is <see langword="true"/> — the
    /// only value the specification defines — <see cref="ClaimOutcome.Failure"/> when it decodes
    /// cleanly but is <see langword="false"/>, a defensive check against a non-conformant or
    /// adversarial client.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is absent, is not valid JSON,
    /// is not a boolean, or carries content trailing the boolean value — all fail-closed via the
    /// ceremony-level extension-processing claim, per <see cref="ExtensionOutputProcessDelegate"/>'s
    /// own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessRegistrationOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlyMemory<byte> clientOutputJson = request.ClientOutputJson ?? throw new Fido2FormatException(
            "The appidExclude extension output carries no client extension output to decode.");

        bool actedUpon = ReadBoolean(clientOutputJson);

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(Fido2ClaimIds.Fido2RegistrationAppIdExclude, actedUpon ? ClaimOutcome.Success : ClaimOutcome.Failure)
        ]);
    }


    /// <summary>
    /// Reads <paramref name="json"/> as a single top-level JSON boolean value.
    /// </summary>
    private static bool ReadBoolean(ReadOnlyMemory<byte> json)
    {
        try
        {
            Utf8JsonReader reader = new(json.Span, ReaderOptions);
            if(!reader.Read() || (reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False))
            {
                throw new Fido2FormatException("The appidExclude extension output MUST be a boolean.");
            }

            bool value = reader.GetBoolean();
            if(reader.Read())
            {
                throw new Fido2FormatException("The appidExclude extension output carries content trailing its boolean value.");
            }

            return value;
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The appidExclude extension output is not valid JSON.", exception);
        }
    }
}
