using Lumoin.Veritas.Cbor;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// Default CBOR decode-and-claim processor for the <c>hmac-secret</c> and <c>hmac-secret-mc</c>
/// extensions' authenticator extension outputs, matching <see cref="ExtensionOutputProcessDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see>: at
/// <c>authenticatorMakeCredential</c> time the authenticator extension output is a single CBOR
/// boolean acknowledging whether the authenticator generated and associated the credential's
/// <c>CredRandomWithUV</c>/<c>CredRandomWithoutUV</c> pair; at <c>authenticatorGetAssertion</c> time
/// the output is a single CBOR byte string — the one or two 32-byte HMAC-SHA-256 values, encrypted
/// under the PIN/UV auth protocol's own <c>encrypt</c> operation. <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension">
/// Section 12.8: HMAC Secret MakeCredential Extension (hmac-secret-mc)</see>'s own authenticator
/// extension output is, verbatim, "Same as the hmac secret extension's getAssertion output" — the
/// identical byte-string shape, at <c>authenticatorMakeCredential</c> time. Lives in
/// <c>Verifiable.Cbor</c>, not <c>Verifiable.Json</c>, for the identical layering reason as
/// <see cref="CredProtectExtensionProcessor"/>/<see cref="MinPinLengthExtensionProcessor"/>: its
/// payload is <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/>.
/// </para>
/// <para>
/// <see cref="ProcessAssertionOutput"/> checks the decoded byte string's length against the two
/// PIN/UV auth protocols' own encrypted-output lengths. PIN/UV auth protocol one's <c>encrypt</c> is
/// AES-256-CBC with no length-changing prefix, so a one-salt output is 32 bytes and a two-salt
/// output is 64. PIN/UV auth protocol two's <c>encrypt</c> prefixes a 16-byte random IV ahead of the
/// same AES-256-CBC ciphertext, so a one-salt output is 48 bytes and a two-salt output is 80. A
/// well-formed byte string of any other length is a processing failure, not a pass-through —
/// mirroring <see cref="CredProtectExtensionProcessor"/>'s out-of-set-level rule — since this
/// processor is not told which protocol the caller negotiated, and a length outside every protocol's
/// own output shape carries no trustworthy evidentiary meaning.
/// </para>
/// <para>
/// Malformed CBOR (wrong major type, trailing bytes) fails closed via a thrown
/// <see cref="Fido2FormatException"/>, which <see cref="Fido2ExtensionChecks"/> converts into the
/// ceremony-level extension-processing claim's own failure. Not wired into
/// <c>Fido2ValidationProfiles</c>' default rule list — mirroring every other processor in this
/// family, both methods are opt-in.
/// </para>
/// </remarks>
public static class HmacSecretExtensionProcessor
{
    /// <summary>The one-salt encrypted-output length under PIN/UV auth protocol one.</summary>
    private const int ProtocolOneOneSaltLength = 32;

    /// <summary>The two-salt encrypted-output length under PIN/UV auth protocol one.</summary>
    private const int ProtocolOneTwoSaltLength = 64;

    /// <summary>The one-salt encrypted-output length under PIN/UV auth protocol two (a 16-byte IV prefix plus 32 bytes of ciphertext).</summary>
    private const int ProtocolTwoOneSaltLength = 48;

    /// <summary>The two-salt encrypted-output length under PIN/UV auth protocol two (a 16-byte IV prefix plus 64 bytes of ciphertext).</summary>
    private const int ProtocolTwoTwoSaltLength = 80;


    /// <summary>
    /// Decodes the registration ceremony's <c>hmac-secret</c> <c>authenticatorMakeCredential</c>-time
    /// authenticator extension output, reporting <see cref="Fido2ClaimIds.Fido2RegistrationHmacSecret"/>.
    /// Matches <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim, <see cref="Fido2ClaimIds.Fido2RegistrationHmacSecret"/>, always
    /// <see cref="ClaimOutcome.Success"/> carrying a <see cref="HmacSecretSupportedContext"/> — both
    /// <see langword="true"/> and <see langword="false"/> are legitimate authenticator states.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> is absent, is not a
    /// single CTAP2 canonical CBOR boolean, or carries content trailing that boolean — all
    /// fail-closed via the ceremony-level extension-processing claim, per
    /// <see cref="ExtensionOutputProcessDelegate"/>'s own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessRegistrationOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlyMemory<byte> authenticatorOutputCbor = request.AuthenticatorOutputCbor ?? throw new Fido2FormatException(
            "The hmac-secret extension output carries no authenticator extension output to decode.");

        bool isSupported = ReadBoolean(authenticatorOutputCbor);

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(Fido2ClaimIds.Fido2RegistrationHmacSecret, ClaimOutcome.Success, new HmacSecretSupportedContext { Supported = isSupported }, Claim.NoSubClaims)
        ]);
    }


    /// <summary>
    /// Decodes the <c>hmac-secret</c> <c>authenticatorGetAssertion</c>-time, or <c>hmac-secret-mc</c>
    /// <c>authenticatorMakeCredential</c>-time, authenticator extension output — the same encrypted
    /// byte-string shape either way — reporting <see cref="Fido2ClaimIds.Fido2AssertionHmacSecret"/>.
    /// Matches <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim, <see cref="Fido2ClaimIds.Fido2AssertionHmacSecret"/>:
    /// <see cref="ClaimOutcome.Success"/> carrying a <see cref="HmacSecretEncryptedOutputContext"/>
    /// when the decoded byte string's length is one PIN/UV auth protocol one or two allows (32, 48,
    /// 64, or 80 bytes); <see cref="ClaimOutcome.Failure"/> with no context for a well-formed byte
    /// string of any other length.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> is absent, is not a
    /// single CTAP2 canonical CBOR byte string, or carries content trailing that byte string — all
    /// fail-closed via the ceremony-level extension-processing claim, per
    /// <see cref="ExtensionOutputProcessDelegate"/>'s own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessAssertionOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlyMemory<byte> authenticatorOutputCbor = request.AuthenticatorOutputCbor ?? throw new Fido2FormatException(
            "The hmac-secret extension output carries no authenticator extension output to decode.");

        ReadOnlyMemory<byte> encryptedOutput = ReadByteString(authenticatorOutputCbor);
        bool isAllowedLength = encryptedOutput.Length is ProtocolOneOneSaltLength or ProtocolOneTwoSaltLength or ProtocolTwoOneSaltLength or ProtocolTwoTwoSaltLength;

        return ValueTask.FromResult<List<Claim>>(
        [
            isAllowedLength
                ? new Claim(Fido2ClaimIds.Fido2AssertionHmacSecret, ClaimOutcome.Success, new HmacSecretEncryptedOutputContext { EncryptedOutput = encryptedOutput }, Claim.NoSubClaims)
                : new Claim(Fido2ClaimIds.Fido2AssertionHmacSecret, ClaimOutcome.Failure)
        ]);
    }


    /// <summary>
    /// Reads <paramref name="value"/> as a single top-level CTAP2 canonical CBOR boolean.
    /// </summary>
    private static bool ReadBoolean(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new CborReader(value, CborOptions.Ctap2Canonical);
            bool result = reader.ReadBoolean();
            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException("The hmac-secret extension output carries content trailing its boolean value.");
            }

            return result;
        }
        catch(Exception exception) when(exception is CborException or InvalidOperationException)
        {
            throw new Fido2FormatException("The hmac-secret extension output is not a valid CBOR boolean.", exception);
        }
    }


    /// <summary>
    /// Reads <paramref name="value"/> as a single top-level CTAP2 canonical CBOR byte string, aliasing
    /// its content rather than copying it.
    /// </summary>
    private static ReadOnlyMemory<byte> ReadByteString(ReadOnlyMemory<byte> value)
    {
        try
        {
            var reader = new CborReader(value, CborOptions.Ctap2Canonical);
            ReadOnlyMemory<byte> result = reader.ReadByteStringMemory();
            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException("The hmac-secret extension output carries content trailing its byte string.");
            }

            return result;
        }
        catch(Exception exception) when(exception is CborException or InvalidOperationException)
        {
            throw new Fido2FormatException("The hmac-secret extension output is not a valid CBOR byte string.", exception);
        }
    }
}
