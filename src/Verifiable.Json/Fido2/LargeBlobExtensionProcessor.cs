using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> decode-and-claim processors for the <c>largeBlob</c> extension's
/// client extension outputs, matching <see cref="ExtensionOutputProcessDelegate"/> — the
/// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> registry's first production tenant.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>. Lives beside
/// <see cref="ClientExtensionOutputsJsonReader"/> for the same reason: decoding the still-encoded
/// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> slice needs
/// <see cref="System.Text.Json"/>, which <c>Verifiable.Fido2</c> is architecturally barred from
/// referencing.
/// </para>
/// <para>
/// <c>largeBlob</c> has no authenticator extension output at all — section 10.1.5's own words rule
/// out any authenticator-side relying-party obligation ("It thus does not specify any direct
/// authenticator interaction for Relying Parties") — so only
/// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is ever decoded here;
/// <see cref="ExtensionOutputProcessingRequest.AuthenticatorOutputCbor"/> is never consulted.
/// </para>
/// <para>
/// Neither processor is wired into <c>Fido2ValidationProfiles</c>' default rule lists — registration
/// is opt-in, exactly like every other extension, via the relying party's own
/// <see cref="RegistrationCeremonyInput.ExtensionOutputProcessor"/> /
/// <see cref="AssertionCeremonyInput.ExtensionOutputProcessor"/> selector built with
/// <see cref="Fido2ExtensionSelectors.FromIdentifiers"/> keyed on
/// <see cref="WellKnownWebAuthnExtensionIdentifiers.LargeBlob"/>. A ceremony that never registers
/// this processor is unaffected — the "works with nothing" default posture is unchanged.
/// </para>
/// </remarks>
public static class LargeBlobExtensionProcessor
{
    /// <summary>The registration-only <c>supported</c> member name.</summary>
    private const string SupportedMember = "supported";

    /// <summary>The authentication-only <c>blob</c> member name.</summary>
    private const string BlobMember = "blob";

    /// <summary>The authentication-only <c>written</c> member name.</summary>
    private const string WrittenMember = "written";

    /// <summary>
    /// Bounds JSON nesting depth for the untrusted <c>largeBlob</c> client extension output value,
    /// which is a flat object of boolean/string members.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 4 };


    /// <summary>
    /// Decodes the registration ceremony's <c>largeBlob</c> client extension output, reporting
    /// <see cref="Fido2ClaimIds.Fido2RegistrationLargeBlobSupported"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A single claim, <see cref="Fido2ClaimIds.Fido2RegistrationLargeBlobSupported"/>, always <see cref="ClaimOutcome.Success"/> when it decodes cleanly.</returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is absent, is not valid JSON,
    /// is not a JSON object, or does not carry a boolean <c>supported</c> member — all fail-closed
    /// via the ceremony-level extension-processing claim, per <see cref="ExtensionOutputProcessDelegate"/>'s
    /// own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessRegistrationOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        LargeBlobOutputMembers members = ReadMembers(RequireClientOutputJson(request));
        if(members.Supported is not bool supported)
        {
            throw new Fido2FormatException($"The largeBlob extension output member '{SupportedMember}' is required.");
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(
                Fido2ClaimIds.Fido2RegistrationLargeBlobSupported,
                ClaimOutcome.Success,
                new LargeBlobSupportedContext { Supported = supported },
                Claim.NoSubClaims)
        ]);
    }


    /// <summary>
    /// Decodes the assertion ceremony's <c>largeBlob</c> client extension output, reporting
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> and
    /// <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// Two claims. <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobRead"/> is
    /// <see cref="ClaimOutcome.Success"/>, carrying the decoded bytes in a
    /// <see cref="LargeBlobReadContext"/>, when a <c>blob</c> member is present, otherwise
    /// <see cref="ClaimOutcome.NotApplicable"/> — a present <c>largeBlob</c> output with no
    /// <c>blob</c> member is section 10.1.5's own documented "read failed" (or read-not-requested)
    /// case, not a wire defect. <see cref="Fido2ClaimIds.Fido2AssertionLargeBlobWritten"/> is
    /// <see cref="ClaimOutcome.Success"/>, carrying the decoded boolean in a
    /// <see cref="LargeBlobWrittenContext"/>, when a <c>written</c> member is present, otherwise
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is absent, is not valid JSON,
    /// is not a JSON object, a present <c>blob</c> member is not valid base64url, or a present
    /// <c>written</c> member is not a boolean — all fail-closed via the ceremony-level
    /// extension-processing claim.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessAssertionOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        LargeBlobOutputMembers members = ReadMembers(RequireClientOutputJson(request));

        List<Claim> claims = [];
        if(members.Blob is string blobBase64Url)
        {
            byte[] buffer = new byte[Base64Url.GetMaxDecodedLength(blobBase64Url.Length)];
            if(!Base64Url.TryDecodeFromChars(blobBase64Url, buffer, out int bytesWritten))
            {
                throw new Fido2FormatException($"The largeBlob extension output member '{BlobMember}' is not valid base64url.");
            }

            byte[] blobBytes = bytesWritten == buffer.Length ? buffer : buffer[..bytesWritten];
            claims.Add(new Claim(
                Fido2ClaimIds.Fido2AssertionLargeBlobRead,
                ClaimOutcome.Success,
                new LargeBlobReadContext { Blob = new TaggedMemory<byte>(blobBytes, Fido2BufferTags.LargeBlob) },
                Claim.NoSubClaims));
        }
        else
        {
            claims.Add(new Claim(Fido2ClaimIds.Fido2AssertionLargeBlobRead, ClaimOutcome.NotApplicable));
        }

        claims.Add(members.Written is bool written
            ? new Claim(
                Fido2ClaimIds.Fido2AssertionLargeBlobWritten,
                ClaimOutcome.Success,
                new LargeBlobWrittenContext { Written = written },
                Claim.NoSubClaims)
            : new Claim(Fido2ClaimIds.Fido2AssertionLargeBlobWritten, ClaimOutcome.NotApplicable));

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Returns <paramref name="request"/>'s <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/>,
    /// rejecting an absent slice: <c>largeBlob</c> has no authenticator extension output, so a
    /// processor invocation carrying no client output slice has nothing to decode.
    /// </summary>
    private static ReadOnlyMemory<byte> RequireClientOutputJson(ExtensionOutputProcessingRequest request)
    {
        return request.ClientOutputJson ?? throw new Fido2FormatException(
            "The largeBlob extension output carries no client extension output to decode.");
    }


    /// <summary>
    /// Reads every member <see cref="ProcessRegistrationOutput"/>/<see cref="ProcessAssertionOutput"/>
    /// may need from the <c>largeBlob</c> client extension output's flat JSON object in one pass. A
    /// member absent from the wire is <see langword="null"/>; an unrecognised member is skipped
    /// rather than rejected — the client MAY report additional information alongside this
    /// extension's own members, mirroring <see cref="ClientDataJsonReader"/>'s forward-compatibility
    /// posture for a spec-defined wire dictionary.
    /// </summary>
    private static LargeBlobOutputMembers ReadMembers(ReadOnlyMemory<byte> objectJson)
    {
        try
        {
            Utf8JsonReader reader = new(objectJson.Span, ReaderOptions);
            if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new Fido2FormatException("The largeBlob extension output MUST be a JSON object.");
            }

            HashSet<string> seenMembers = new(StringComparer.Ordinal);
            bool? supported = null;
            string? blob = null;
            bool? written = null;

            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The largeBlob extension output member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The largeBlob extension output member '{memberName}' is truncated.");
                }

                if(string.Equals(memberName, SupportedMember, StringComparison.Ordinal))
                {
                    supported = ReadBooleanValue(ref reader, memberName);
                }
                else if(string.Equals(memberName, BlobMember, StringComparison.Ordinal))
                {
                    blob = ReadStringValue(ref reader, memberName);
                }
                else if(string.Equals(memberName, WrittenMember, StringComparison.Ordinal))
                {
                    written = ReadBooleanValue(ref reader, memberName);
                }
                else
                {
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The largeBlob extension output object is not terminated.");
            }

            if(reader.Read())
            {
                throw new Fido2FormatException("The largeBlob extension output carries content trailing its closing brace.");
            }

            return new LargeBlobOutputMembers(supported, blob, written);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The largeBlob extension output is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Reads the reader's current value as a boolean, naming <paramref name="memberName"/> in the
    /// rejection when the value is not boolean-shaped.
    /// </summary>
    private static bool ReadBooleanValue(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False)
        {
            throw new Fido2FormatException($"The largeBlob extension output member '{memberName}' MUST be a boolean.");
        }

        return reader.GetBoolean();
    }


    /// <summary>
    /// Reads the reader's current value as a string, naming <paramref name="memberName"/> in the
    /// rejection when the value is not string-shaped.
    /// </summary>
    private static string ReadStringValue(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The largeBlob extension output member '{memberName}' MUST be a string.");
        }

        return reader.GetString()!;
    }


    /// <summary>
    /// The subset of the <c>largeBlob</c> client extension output's members either processor cares
    /// about, decoded in one pass over the wire object.
    /// </summary>
    /// <param name="Supported">The registration-only <c>supported</c> member, or <see langword="null"/> when absent.</param>
    /// <param name="Blob">The authentication-only <c>blob</c> member's still base64url-encoded string, or <see langword="null"/> when absent.</param>
    /// <param name="Written">The authentication-only <c>written</c> member, or <see langword="null"/> when absent.</param>
    private readonly record struct LargeBlobOutputMembers(bool? Supported, string? Blob, bool? Written);
}
