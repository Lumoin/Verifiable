using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// Default CBOR decode-and-claim processor for the <c>credProtect</c> extension's registration
/// authenticator extension output, matching <see cref="ExtensionOutputProcessDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
/// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see>: the authenticator extension
/// output is a single CBOR unsigned integer, one of the three registered wire values {1, 2, 3}
/// (snapshot line 12609's value table). Lives in <c>Verifiable.Cbor</c>, not <c>Verifiable.Json</c>,
/// because its payload is <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> —
/// the SAME layering rule that puts JSON-decoding processors (<c>AppIdExcludeExtensionProcessor</c>,
/// <c>LargeBlobExtensionProcessor</c>) in <c>Verifiable.Json</c>, mirrored beside
/// <see cref="AuthenticatorExtensionOutputsCborReader"/>, which already produces the
/// <see cref="ReadOnlyMemory{T}"/> slice this processor decodes.
/// </para>
/// <para>
/// A well-formed CBOR unsigned integer OUTSIDE the three registered values is a processing failure,
/// not a pass-through: <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/> reports
/// <see cref="ClaimOutcome.Failure"/> with no context, since a non-conformant or adversarial
/// authenticator's out-of-set level carries no trustworthy policy meaning. Malformed CBOR (wrong
/// major type, trailing bytes) fails closed via a thrown <see cref="Fido2FormatException"/>, which
/// <see cref="Fido2ExtensionChecks"/> converts into the ceremony-level extension-processing claim's
/// own failure.
/// </para>
/// <para>
/// Registration-only: credProtect defines no <c>authenticatorGetAssertion</c>-side authenticator
/// extension output (CTAP 2.3 §12.1's own extension-input section covers only <c>create()</c>). Not
/// wired into <c>Fido2ValidationProfiles</c>' default rule list — registration is opt-in, mirroring
/// <c>AppIdExcludeExtensionProcessor</c>/<c>LargeBlobExtensionProcessor</c>.
/// </para>
/// </remarks>
public static class CredProtectExtensionProcessor
{
    /// <summary>
    /// Decodes the registration ceremony's <c>credProtect</c> authenticator extension output,
    /// reporting <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim, <see cref="Fido2ClaimIds.Fido2RegistrationCredProtect"/>:
    /// <see cref="ClaimOutcome.Success"/> carrying a <see cref="CredProtectLevelContext"/> when the
    /// decoded level is one of {1, 2, 3}; <see cref="ClaimOutcome.Failure"/> with no context for a
    /// well-formed but out-of-set level.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> is absent, is not a
    /// single CTAP2 canonical CBOR unsigned integer, or carries content trailing that integer — all
    /// fail-closed via the ceremony-level extension-processing claim, per
    /// <see cref="ExtensionOutputProcessDelegate"/>'s own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessRegistrationOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlyMemory<byte> authenticatorOutputCbor = request.AuthenticatorOutputCbor ?? throw new Fido2FormatException(
            "The credProtect extension output carries no authenticator extension output to decode.");

        int level = ReadUnsignedInteger(authenticatorOutputCbor);
        bool isRegisteredLevel = level is 1 or 2 or 3;

        return ValueTask.FromResult<List<Claim>>(
        [
            isRegisteredLevel
                ? new Claim(Fido2ClaimIds.Fido2RegistrationCredProtect, ClaimOutcome.Success, new CredProtectLevelContext { Level = level }, Claim.NoSubClaims)
                : new Claim(Fido2ClaimIds.Fido2RegistrationCredProtect, ClaimOutcome.Failure)
        ]);
    }


    /// <summary>
    /// Reads <paramref name="value"/> as a single top-level CTAP2 canonical CBOR unsigned integer.
    /// </summary>
    private static int ReadUnsignedInteger(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new CborReader(value, CborConformanceMode.Ctap2Canonical);
            ulong level = reader.ReadUInt64();
            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException("The credProtect extension output carries content trailing its integer value.");
            }

            return checked((int)level);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The credProtect extension output is not a valid CBOR unsigned integer.", exception);
        }
    }
}
