using System.Buffers;
using System.Buffers.Text;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> writer for a <see cref="PublicKeyCredentialRequestOptions"/>,
/// producing the CR's own named wire shape (<c>PublicKeyCredentialRequestOptionsJSON</c>) rather than
/// a document this codebase invents.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON">W3C Web
/// Authentication Level 3, section 5.1.9: Deserialize Authentication ceremony options —
/// <c>PublicKeyCredential</c>'s <c>parseRequestOptionsFromJSON()</c> Method</see>, dictionary
/// <c>PublicKeyCredentialRequestOptionsJSON</c>. See
/// <see cref="PublicKeyCredentialCreationOptionsJsonWriter"/>'s remarks — the same reasoning (no
/// <c>version</c> member, Base64url binary members, the three named extension-input carve-outs written
/// under <c>extensions</c>) applies here. <c>prf</c>'s <c>evalByCredential</c> is written as a JSON
/// object keyed by each entry's base64url-encoded <see cref="CredentialId"/> — the CR's own
/// <c>record&lt;DOMString, AuthenticationExtensionsPRFValuesJSON&gt;</c> shape.
/// </remarks>
public static class PublicKeyCredentialRequestOptionsJsonWriter
{
    private const string ChallengeMember = "challenge";
    private const string TimeoutMember = "timeout";
    private const string RpIdMember = "rpId";
    private const string AllowCredentialsMember = "allowCredentials";
    private const string TypeMember = "type";
    private const string IdMember = "id";
    private const string TransportsMember = "transports";
    private const string UserVerificationMember = "userVerification";
    private const string HintsMember = "hints";
    private const string ExtensionsMember = "extensions";
    private const string ReadMember = "read";
    private const string WriteMember = "write";
    private const string EvalMember = "eval";
    private const string EvalByCredentialMember = "evalByCredential";
    private const string FirstMember = "first";
    private const string SecondMember = "second";


    /// <summary>
    /// Writes <paramref name="options"/> as UTF-8 JSON to <paramref name="destination"/>.
    /// </summary>
    /// <param name="options">The request options document to write.</param>
    /// <param name="destination">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><see cref="PublicKeyCredentialRequestOptions.Challenge"/> is <see langword="null"/>.</exception>
    public static void Write(PublicKeyCredentialRequestOptions options, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(destination);

        string challenge = options.Challenge ?? throw new InvalidOperationException("PublicKeyCredentialRequestOptions.Challenge is required.");

        using Utf8JsonWriter writer = new(destination);
        writer.WriteStartObject();

        writer.WriteString(ChallengeMember, challenge);

        if(options.Timeout is uint timeout)
        {
            writer.WriteNumber(TimeoutMember, timeout);
        }

        if(options.RpId is not null)
        {
            writer.WriteString(RpIdMember, options.RpId);
        }

        WriteDescriptors(writer, options.AllowCredentials);

        if(options.UserVerification is UserVerificationRequirement userVerification)
        {
            writer.WriteString(UserVerificationMember, WellKnownUserVerificationRequirements.ToWireValue(userVerification));
        }

        if(options.Hints is { Count: > 0 } hints)
        {
            writer.WriteStartArray(HintsMember);
            foreach(PublicKeyCredentialHint hint in hints)
            {
                writer.WriteStringValue(WellKnownPublicKeyCredentialHints.ToWireValue(hint));
            }
            writer.WriteEndArray();
        }

        WriteExtensions(writer, options.AppId, options.LargeBlob, options.Prf);

        writer.WriteEndObject();
        writer.Flush();
    }


    /// <summary>
    /// Writes the <c>extensions</c> member when at least one of the three named carve-outs this writer
    /// supports is populated; omits the member entirely otherwise.
    /// </summary>
    private static void WriteExtensions(Utf8JsonWriter writer, string? appId, Fido2LargeBlobAssertionExtensionInput? largeBlob, Fido2PrfAssertionExtensionInput? prf)
    {
        if(appId is null && largeBlob is null && prf is null)
        {
            return;
        }

        writer.WriteStartObject(ExtensionsMember);
        if(appId is not null)
        {
            writer.WriteString(WellKnownWebAuthnExtensionIdentifiers.AppId, appId);
        }

        if(largeBlob is not null)
        {
            writer.WriteStartObject(WellKnownWebAuthnExtensionIdentifiers.LargeBlob);
            if(largeBlob.Read is bool read)
            {
                writer.WriteBoolean(ReadMember, read);
            }

            if(largeBlob.Write is TaggedMemory<byte> write)
            {
                writer.WriteString(WriteMember, Base64Url.EncodeToString(write.Span));
            }
            writer.WriteEndObject();
        }

        if(prf is not null)
        {
            WritePrf(writer, prf);
        }
        writer.WriteEndObject();
    }


    /// <summary>
    /// Writes the <c>extensions.prf</c> member: <c>eval</c> when present, and <c>evalByCredential</c>
    /// keyed by each entry's base64url-encoded credential id when present.
    /// </summary>
    private static void WritePrf(Utf8JsonWriter writer, Fido2PrfAssertionExtensionInput prf)
    {
        writer.WriteStartObject(WellKnownWebAuthnExtensionIdentifiers.Prf);
        if(prf.Eval is Fido2PrfValues eval)
        {
            writer.WriteStartObject(EvalMember);
            WritePrfValues(writer, eval);
            writer.WriteEndObject();
        }

        if(prf.EvalByCredential is { Count: > 0 } evalByCredential)
        {
            writer.WriteStartObject(EvalByCredentialMember);
            foreach(KeyValuePair<CredentialId, Fido2PrfValues> entry in evalByCredential)
            {
                writer.WriteStartObject(Base64Url.EncodeToString(entry.Key.AsReadOnlySpan()));
                WritePrfValues(writer, entry.Value);
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }


    /// <summary>
    /// Writes <paramref name="values"/>' <c>first</c>/<c>second</c> members, base64url-encoded.
    /// </summary>
    private static void WritePrfValues(Utf8JsonWriter writer, Fido2PrfValues values)
    {
        writer.WriteString(FirstMember, Base64Url.EncodeToString(values.First.Span));
        if(values.Second is TaggedMemory<byte> second)
        {
            writer.WriteString(SecondMember, Base64Url.EncodeToString(second.Span));
        }
    }


    /// <summary>
    /// Writes a <c>PublicKeyCredentialDescriptorJSON</c> sequence under <c>allowCredentials</c> when
    /// <paramref name="descriptors"/> is non-empty; omits the member entirely when
    /// <see langword="null"/> or empty.
    /// </summary>
    private static void WriteDescriptors(Utf8JsonWriter writer, IReadOnlyList<PublicKeyCredentialDescriptor>? descriptors)
    {
        if(descriptors is not { Count: > 0 })
        {
            return;
        }

        writer.WriteStartArray(AllowCredentialsMember);
        foreach(PublicKeyCredentialDescriptor descriptor in descriptors)
        {
            writer.WriteStartObject();
            writer.WriteString(TypeMember, descriptor.Type);
            writer.WriteString(IdMember, Base64Url.EncodeToString(descriptor.Id.AsReadOnlySpan()));
            if(descriptor.Transports is { Count: > 0 } transports)
            {
                writer.WriteStartArray(TransportsMember);
                foreach(string transport in transports)
                {
                    writer.WriteStringValue(transport);
                }
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
}
