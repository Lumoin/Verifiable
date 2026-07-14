using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
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
/// <c>version</c> member, Base64url binary members, the two named extension-input carve-outs written
/// under <c>extensions</c>) applies here.
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

        WriteExtensions(writer, options.AppId, options.LargeBlob);

        writer.WriteEndObject();
        writer.Flush();
    }


    /// <summary>
    /// Writes the <c>extensions</c> member when at least one of the two named carve-outs this wave
    /// ships is populated; omits the member entirely otherwise.
    /// </summary>
    private static void WriteExtensions(Utf8JsonWriter writer, string? appId, Fido2LargeBlobAssertionExtensionInput? largeBlob)
    {
        if(appId is null && largeBlob is null)
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
        writer.WriteEndObject();
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
