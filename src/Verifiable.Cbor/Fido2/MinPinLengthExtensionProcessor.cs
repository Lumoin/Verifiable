using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// Default CBOR decode-and-claim processor for the <c>minPinLength</c> extension's registration
/// authenticator extension output, matching <see cref="ExtensionOutputProcessDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
/// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see>: the authenticator
/// extension output is a single CBOR unsigned integer, the current minimum PIN length in Unicode
/// code points — no restricted value set (unlike <see cref="CredProtectExtensionProcessor"/>'s three
/// registered levels), so any successfully decoded non-negative integer is reported as
/// <see cref="ClaimOutcome.Success"/>. Lives in <c>Verifiable.Cbor</c>, not <c>Verifiable.Json</c>,
/// for the identical layering reason as <see cref="CredProtectExtensionProcessor"/>: its payload is
/// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/>.
/// </para>
/// <para>
/// Malformed CBOR (wrong major type, trailing bytes) fails closed via a thrown
/// <see cref="Fido2FormatException"/>, which <see cref="Fido2ExtensionChecks"/> converts into the
/// ceremony-level extension-processing claim's own failure.
/// </para>
/// <para>
/// Registration-only: minPinLength's own text is explicit — "This extension is only applicable
/// during credential creation" — so it defines no <c>authenticatorGetAssertion</c>-side authenticator
/// extension output. Not wired into <c>Fido2ValidationProfiles</c>' default rule list — registration
/// is opt-in, mirroring <see cref="CredProtectExtensionProcessor"/>.
/// </para>
/// </remarks>
public static class MinPinLengthExtensionProcessor
{
    /// <summary>
    /// Decodes the registration ceremony's <c>minPinLength</c> authenticator extension output,
    /// reporting <see cref="Fido2ClaimIds.Fido2RegistrationMinPinLength"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim, <see cref="Fido2ClaimIds.Fido2RegistrationMinPinLength"/>, always
    /// <see cref="ClaimOutcome.Success"/> carrying a <see cref="MinPinLengthContext"/> when it decodes
    /// cleanly.
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
            "The minPinLength extension output carries no authenticator extension output to decode.");

        int length = ReadUnsignedInteger(authenticatorOutputCbor);

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(Fido2ClaimIds.Fido2RegistrationMinPinLength, ClaimOutcome.Success, new MinPinLengthContext { Length = length }, Claim.NoSubClaims)
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
            ulong length = reader.ReadUInt64();
            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException("The minPinLength extension output carries content trailing its integer value.");
            }

            return checked((int)length);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The minPinLength extension output is not a valid CBOR unsigned integer.", exception);
        }
    }
}
