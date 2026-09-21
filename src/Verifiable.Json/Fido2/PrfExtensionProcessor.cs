using System.Text.Json;
using Verifiable.Core.Assessment;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> decode-and-claim processors for the <c>prf</c> extension's
/// client extension outputs, matching <see cref="ExtensionOutputProcessDelegate"/> — siblings of
/// <see cref="LargeBlobExtensionProcessor"/>'s in every respect.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>. Lives beside
/// <see cref="ClientExtensionOutputsJsonReader"/> for the same reason as
/// <see cref="LargeBlobExtensionProcessor"/>: decoding the still-encoded
/// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> slice needs
/// <see cref="System.Text.Json"/>, which <c>Verifiable.Fido2</c> is architecturally barred from
/// referencing.
/// </para>
/// <para>
/// <strong>This never touches the secret.</strong> Section 10.1.4's own dictionary
/// <c>AuthenticationExtensionsPRFOutputs</c> carries <c>enabled</c> (a boolean) and <c>results</c> (the
/// pseudo-random function's SECRET output). This processor reports only what is safe to carry through
/// the claim/audit pipeline: whether the passkey supports <c>prf</c> (<see cref="PrfEnabledContext.Enabled"/>)
/// and whether <c>results</c> was present (<see cref="PrfResultsPresentContext.HasResults"/>). It reads
/// far enough into <c>results</c> to confirm its members are shaped as
/// <c>AuthenticationExtensionsPRFValuesJSON</c> requires — a JSON object whose <c>first</c> member is a
/// string, and whose optional <c>second</c> member, if present, is also a string — but it never calls a
/// string-materializing reader method on either value, so the secret bytes never pass through this type.
/// A caller that needs the secret reads the same wire bytes again through
/// <see cref="PrfResultsJsonReader"/>, which hands them out as
/// <see cref="Verifiable.Cryptography.SymmetricKeyMemory"/>, the library's disposable carrier for
/// symmetric key material.
/// </para>
/// </remarks>
public static class PrfExtensionProcessor
{
    /// <summary>The registration-only <c>enabled</c> member name.</summary>
    private const string EnabledMember = "enabled";

    /// <summary>The <c>results</c> member name, present at either ceremony.</summary>
    private const string ResultsMember = "results";

    /// <summary>The required <c>results.first</c> member name.</summary>
    private const string FirstMember = "first";

    /// <summary>The optional <c>results.second</c> member name.</summary>
    private const string SecondMember = "second";

    /// <summary>
    /// Bounds JSON nesting depth for the untrusted <c>prf</c> client extension output value: the
    /// top-level object plus one nested <c>results</c> object.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 4 };


    /// <summary>
    /// Decodes the registration ceremony's <c>prf</c> client extension output, reporting
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/> and
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// Two claims. <see cref="Fido2ClaimIds.Fido2RegistrationPrfEnabled"/> is always
    /// <see cref="ClaimOutcome.Success"/> when the output decodes cleanly, carrying the decoded
    /// <c>enabled</c> value in a <see cref="PrfEnabledContext"/>.
    /// <see cref="Fido2ClaimIds.Fido2RegistrationPrfResultsPresent"/> is
    /// <see cref="ClaimOutcome.Success"/>, carrying <see langword="true"/> in a
    /// <see cref="PrfResultsPresentContext"/>, when a <c>results</c> member is present, otherwise
    /// <see cref="ClaimOutcome.NotApplicable"/> — section 10.1.4's own documented "outputs may not
    /// be available during registration" case, not a wire defect.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is absent, is not valid JSON,
    /// is not a JSON object, does not carry a boolean <c>enabled</c> member, or carries a
    /// <c>results</c> member that is not shaped as <c>AuthenticationExtensionsPRFValuesJSON</c>
    /// requires — all fail-closed via the ceremony-level extension-processing claim, per
    /// <see cref="ExtensionOutputProcessDelegate"/>'s own contract.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessRegistrationOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        PrfOutputMembers members = ReadMembers(RequireClientOutputJson(request));
        if(members.Enabled is not bool enabled)
        {
            throw new Fido2FormatException($"The prf extension output member '{EnabledMember}' is required.");
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(
                Fido2ClaimIds.Fido2RegistrationPrfEnabled,
                ClaimOutcome.Success,
                new PrfEnabledContext { Enabled = enabled },
                Claim.NoSubClaims),
            members.HasResults
                ? new Claim(
                    Fido2ClaimIds.Fido2RegistrationPrfResultsPresent,
                    ClaimOutcome.Success,
                    new PrfResultsPresentContext { HasResults = true },
                    Claim.NoSubClaims)
                : new Claim(Fido2ClaimIds.Fido2RegistrationPrfResultsPresent, ClaimOutcome.NotApplicable)
        ]);
    }


    /// <summary>
    /// Decodes the assertion ceremony's <c>prf</c> client extension output, reporting
    /// <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/>. Matches
    /// <see cref="ExtensionOutputProcessDelegate"/>.
    /// </summary>
    /// <param name="request">The extension identifier and its still-encoded output slices.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A single claim. <see cref="Fido2ClaimIds.Fido2AssertionPrfResultsPresent"/> is
    /// <see cref="ClaimOutcome.Success"/>, carrying <see langword="true"/> in a
    /// <see cref="PrfResultsPresentContext"/>, when a <c>results</c> member is present, otherwise
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/> is absent, is not valid JSON,
    /// is not a JSON object, or carries a <c>results</c> member that is not shaped as
    /// <c>AuthenticationExtensionsPRFValuesJSON</c> requires — all fail-closed via the
    /// ceremony-level extension-processing claim.
    /// </exception>
    public static ValueTask<List<Claim>> ProcessAssertionOutput(ExtensionOutputProcessingRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        PrfOutputMembers members = ReadMembers(RequireClientOutputJson(request));

        return ValueTask.FromResult<List<Claim>>(
        [
            members.HasResults
                ? new Claim(
                    Fido2ClaimIds.Fido2AssertionPrfResultsPresent,
                    ClaimOutcome.Success,
                    new PrfResultsPresentContext { HasResults = true },
                    Claim.NoSubClaims)
                : new Claim(Fido2ClaimIds.Fido2AssertionPrfResultsPresent, ClaimOutcome.NotApplicable)
        ]);
    }


    /// <summary>
    /// Returns <paramref name="request"/>'s <see cref="ExtensionOutputProcessingRequest.ClientOutputJson"/>,
    /// rejecting an absent slice: a processor invocation carrying no client output slice has nothing
    /// to decode.
    /// </summary>
    private static ReadOnlyMemory<byte> RequireClientOutputJson(ExtensionOutputProcessingRequest request)
    {
        return request.ClientOutputJson ?? throw new Fido2FormatException(
            "The prf extension output carries no client extension output to decode.");
    }


    /// <summary>
    /// Reads every member <see cref="ProcessRegistrationOutput"/>/<see cref="ProcessAssertionOutput"/>
    /// need from the <c>prf</c> client extension output's JSON object in one pass. Confirms
    /// <c>results</c>, when present, is shaped as <c>AuthenticationExtensionsPRFValuesJSON</c>
    /// requires, but reads only the TOKEN TYPE of <c>first</c>/<c>second</c> — never their string
    /// content — so the secret bytes never reach this method. An unrecognised top-level member is
    /// skipped rather than rejected, mirroring <see cref="LargeBlobExtensionProcessor"/>'s
    /// forward-compatibility posture.
    /// </summary>
    private static PrfOutputMembers ReadMembers(ReadOnlyMemory<byte> objectJson)
    {
        try
        {
            Utf8JsonReader reader = new(objectJson.Span, ReaderOptions);
            if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new Fido2FormatException("The prf extension output MUST be a JSON object.");
            }

            HashSet<string> seenMembers = new(StringComparer.Ordinal);
            bool? enabled = null;
            bool hasResults = false;

            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The prf extension output member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The prf extension output member '{memberName}' is truncated.");
                }

                if(string.Equals(memberName, EnabledMember, StringComparison.Ordinal))
                {
                    enabled = ReadBooleanValue(ref reader, memberName);
                }
                else if(string.Equals(memberName, ResultsMember, StringComparison.Ordinal))
                {
                    ValidateResultsShape(ref reader);
                    hasResults = true;
                }
                else
                {
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The prf extension output object is not terminated.");
            }

            if(reader.Read())
            {
                throw new Fido2FormatException("The prf extension output carries content trailing its closing brace.");
            }

            return new PrfOutputMembers(enabled, hasResults);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The prf extension output is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Confirms the reader's current <c>results</c> value is a JSON object whose required
    /// <c>first</c> member and optional <c>second</c> member are both string-shaped, per
    /// <c>AuthenticationExtensionsPRFValuesJSON</c>. Checks each value's <see cref="JsonTokenType"/>
    /// only — it never calls a string-materializing reader method, so the secret base64url text
    /// never reaches this method, let alone the bytes it encodes.
    /// </summary>
    private static void ValidateResultsShape(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        bool sawFirst = false;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is truncated.");
            }

            if(string.Equals(memberName, FirstMember, StringComparison.Ordinal))
            {
                RequireStringToken(ref reader, $"{ResultsMember}.{memberName}");
                sawFirst = true;
            }
            else if(string.Equals(memberName, SecondMember, StringComparison.Ordinal))
            {
                RequireStringToken(ref reader, $"{ResultsMember}.{memberName}");
            }
            else
            {
                reader.Skip();
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}' object is not terminated.");
        }

        if(!sawFirst)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{FirstMember}' is required.");
        }
    }


    /// <summary>
    /// Confirms the reader's current value token is a JSON string, naming
    /// <paramref name="memberPath"/> in the rejection otherwise. Never calls
    /// <see cref="Utf8JsonReader.GetString"/>: the token type alone is enough to validate shape.
    /// </summary>
    private static void RequireStringToken(ref Utf8JsonReader reader, string memberPath)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The prf extension output member '{memberPath}' MUST be a base64url string.");
        }
    }


    /// <summary>
    /// Reads the reader's current value as a boolean, naming <paramref name="memberName"/> in the
    /// rejection when the value is not boolean-shaped.
    /// </summary>
    private static bool ReadBooleanValue(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType is not JsonTokenType.True and not JsonTokenType.False)
        {
            throw new Fido2FormatException($"The prf extension output member '{memberName}' MUST be a boolean.");
        }

        return reader.GetBoolean();
    }


    /// <summary>
    /// The subset of the <c>prf</c> client extension output's members either processor cares about,
    /// decoded in one pass over the wire object.
    /// </summary>
    /// <param name="Enabled">The registration-only <c>enabled</c> member, or <see langword="null"/> when absent.</param>
    /// <param name="HasResults">Whether a <c>results</c> member was present.</param>
    private readonly record struct PrfOutputMembers(bool? Enabled, bool HasResults);
}
