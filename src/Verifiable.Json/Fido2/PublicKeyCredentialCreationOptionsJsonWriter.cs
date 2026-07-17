using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> writer for a <see cref="PublicKeyCredentialCreationOptions"/>,
/// producing the CR's own named wire shape (<c>PublicKeyCredentialCreationOptionsJSON</c>) rather
/// than a document this codebase invents.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON">W3C Web
/// Authentication Level 3, section 5.1.8: Deserialize Registration ceremony options —
/// <c>PublicKeyCredential</c>'s <c>parseCreationOptionsFromJSON()</c> Method</see>, dictionary
/// <c>PublicKeyCredentialCreationOptionsJSON</c>. Lives beside
/// <see cref="PublicKeyCredentialCreationOptionsJsonReader"/> for the same reason
/// <see cref="Fido2CredentialRecordJsonWriter"/> lives here: <c>Verifiable.Fido2</c> stays
/// serialization-agnostic.
/// </para>
/// <para>
/// Unlike <see cref="Fido2CredentialRecordJsonWriter"/> (a shipped persistence format this codebase
/// invents and therefore version-stamps), this writer emits exactly the CR's own member set — no
/// <c>version</c> member, since a real browser's <c>parseCreationOptionsFromJSON()</c> expects this
/// exact shape and knows nothing of one. Every binary member (<c>user.id</c>, a descriptor's
/// <c>id</c>) is Base64url encoded, matching every other FIDO2 JSON writer in this project.
/// </para>
/// <para>
/// The four named extension-input carve-outs this writer emits (<see cref="PublicKeyCredentialCreationOptions.AppIdExclude"/>,
/// <see cref="PublicKeyCredentialCreationOptions.LargeBlob"/>, <see cref="PublicKeyCredentialCreationOptions.MinPinLength"/>,
/// <see cref="PublicKeyCredentialCreationOptions.CredProtect"/>) are written under <c>extensions</c>;
/// <c>appidExclude</c>/<c>largeBlob</c>/<c>minPinLength</c> are keyed by their own
/// <see cref="WellKnownWebAuthnExtensionIdentifiers"/> identifier, while <c>credProtect</c>'s two
/// members (<c>credentialProtectionPolicy</c>/<c>enforceCredentialProtectionPolicy</c>) are FLAT
/// top-level <c>extensions</c> members per CTAP 2.3 §12.1's own client-input IDL — no
/// <c>"credProtect"</c> wrapper key exists on the wire (see <see cref="Fido2CredProtectRegistrationExtensionInput"/>'s
/// own remarks). The <c>extensions</c> member itself is omitted entirely when no carve-out is
/// populated, since the generic <c>AuthenticationExtensionsClientInputsJSON</c> surface remains out of
/// scope.
/// </para>
/// </remarks>
public static class PublicKeyCredentialCreationOptionsJsonWriter
{
    /// <summary>The <c>rp</c> member name.</summary>
    private const string RpMember = "rp";

    /// <summary>The <c>rp.id</c> member name.</summary>
    private const string RpIdMember = "id";

    /// <summary>The <c>rp.name</c>/<c>user.name</c> member name.</summary>
    private const string NameMember = "name";

    /// <summary>The <c>user</c> member name.</summary>
    private const string UserMember = "user";

    /// <summary>The <c>user.id</c>/descriptor <c>id</c> member name.</summary>
    private const string IdMember = "id";

    /// <summary>The <c>user.displayName</c> member name.</summary>
    private const string DisplayNameMember = "displayName";

    /// <summary>The <c>challenge</c> member name.</summary>
    private const string ChallengeMember = "challenge";

    /// <summary>The <c>pubKeyCredParams</c> member name.</summary>
    private const string PubKeyCredParamsMember = "pubKeyCredParams";

    /// <summary>The descriptor <c>type</c> member name.</summary>
    private const string TypeMember = "type";

    /// <summary>The descriptor <c>alg</c> member name.</summary>
    private const string AlgMember = "alg";

    /// <summary>The <c>timeout</c> member name.</summary>
    private const string TimeoutMember = "timeout";

    /// <summary>The <c>excludeCredentials</c> member name.</summary>
    private const string ExcludeCredentialsMember = "excludeCredentials";

    /// <summary>The descriptor <c>transports</c> member name.</summary>
    private const string TransportsMember = "transports";

    /// <summary>The <c>authenticatorSelection</c> member name.</summary>
    private const string AuthenticatorSelectionMember = "authenticatorSelection";

    /// <summary>The <c>authenticatorSelection.authenticatorAttachment</c> member name.</summary>
    private const string AuthenticatorAttachmentMember = "authenticatorAttachment";

    /// <summary>The <c>authenticatorSelection.residentKey</c> member name.</summary>
    private const string ResidentKeyMember = "residentKey";

    /// <summary>The <c>authenticatorSelection.requireResidentKey</c> member name.</summary>
    private const string RequireResidentKeyMember = "requireResidentKey";

    /// <summary>The <c>authenticatorSelection.userVerification</c>/<c>userVerification</c> member name.</summary>
    private const string UserVerificationMember = "userVerification";

    /// <summary>The <c>hints</c> member name.</summary>
    private const string HintsMember = "hints";

    /// <summary>The <c>attestation</c> member name.</summary>
    private const string AttestationMember = "attestation";

    /// <summary>The <c>attestationFormats</c> member name.</summary>
    private const string AttestationFormatsMember = "attestationFormats";

    /// <summary>The <c>extensions</c> member name.</summary>
    private const string ExtensionsMember = "extensions";

    /// <summary>The <c>extensions.largeBlob.support</c> member name.</summary>
    private const string SupportMember = "support";

    /// <summary>The <c>extensions.credentialProtectionPolicy</c> member name — a flat top-level <c>extensions</c> member, not nested under a <c>credProtect</c> key.</summary>
    private const string CredentialProtectionPolicyMember = "credentialProtectionPolicy";

    /// <summary>The <c>extensions.enforceCredentialProtectionPolicy</c> member name — a flat top-level <c>extensions</c> member, not nested under a <c>credProtect</c> key.</summary>
    private const string EnforceCredentialProtectionPolicyMember = "enforceCredentialProtectionPolicy";


    /// <summary>
    /// Writes <paramref name="options"/> as UTF-8 JSON to <paramref name="destination"/>.
    /// </summary>
    /// <param name="options">The registration options document to write.</param>
    /// <param name="destination">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// A CR-required member (<see cref="PublicKeyCredentialCreationOptions.Rp"/>,
    /// <see cref="PublicKeyCredentialCreationOptions.User"/>,
    /// <see cref="PublicKeyCredentialCreationOptions.Challenge"/> or
    /// <see cref="PublicKeyCredentialCreationOptions.PubKeyCredParams"/>) is <see langword="null"/>.
    /// </exception>
    public static void Write(PublicKeyCredentialCreationOptions options, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(destination);

        PublicKeyCredentialRpEntity rp = options.Rp ?? throw new InvalidOperationException("PublicKeyCredentialCreationOptions.Rp is required.");
        PublicKeyCredentialUserEntity user = options.User ?? throw new InvalidOperationException("PublicKeyCredentialCreationOptions.User is required.");
        string challenge = options.Challenge ?? throw new InvalidOperationException("PublicKeyCredentialCreationOptions.Challenge is required.");
        IReadOnlyList<PublicKeyCredentialParameters> pubKeyCredParams = options.PubKeyCredParams ?? throw new InvalidOperationException("PublicKeyCredentialCreationOptions.PubKeyCredParams is required.");

        using Utf8JsonWriter writer = new(destination);
        writer.WriteStartObject();

        writer.WriteStartObject(RpMember);
        WriteOptionalString(writer, RpIdMember, rp.Id);
        writer.WriteString(NameMember, rp.Name);
        writer.WriteEndObject();

        writer.WriteStartObject(UserMember);
        writer.WriteString(IdMember, Base64Url.EncodeToString(user.Id.AsReadOnlySpan()));
        writer.WriteString(NameMember, user.Name);
        writer.WriteString(DisplayNameMember, user.DisplayName);
        writer.WriteEndObject();

        writer.WriteString(ChallengeMember, challenge);

        writer.WriteStartArray(PubKeyCredParamsMember);
        foreach(PublicKeyCredentialParameters parameter in pubKeyCredParams)
        {
            writer.WriteStartObject();
            writer.WriteString(TypeMember, parameter.Type);
            writer.WriteNumber(AlgMember, parameter.Alg);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        if(options.Timeout is uint timeout)
        {
            writer.WriteNumber(TimeoutMember, timeout);
        }

        WriteDescriptors(writer, ExcludeCredentialsMember, options.ExcludeCredentials);

        if(options.AuthenticatorSelection is AuthenticatorSelectionCriteria selection)
        {
            writer.WriteStartObject(AuthenticatorSelectionMember);
            WriteOptionalString(writer, AuthenticatorAttachmentMember, selection.AuthenticatorAttachment);
            if(selection.ResidentKey is ResidentKeyRequirement residentKey)
            {
                writer.WriteString(ResidentKeyMember, WellKnownResidentKeyRequirements.ToWireValue(residentKey));
            }
            writer.WriteBoolean(RequireResidentKeyMember, selection.RequireResidentKey);
            writer.WriteString(UserVerificationMember, WellKnownUserVerificationRequirements.ToWireValue(selection.UserVerification));
            writer.WriteEndObject();
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

        if(options.Attestation is AttestationConveyancePreference attestation)
        {
            writer.WriteString(AttestationMember, WellKnownAttestationConveyancePreferences.ToWireValue(attestation));
        }

        if(options.AttestationFormats is { Count: > 0 } attestationFormats)
        {
            writer.WriteStartArray(AttestationFormatsMember);
            foreach(string format in attestationFormats)
            {
                writer.WriteStringValue(format);
            }
            writer.WriteEndArray();
        }

        WriteExtensions(writer, options.AppIdExclude, options.LargeBlob, options.MinPinLength, options.CredProtect);

        writer.WriteEndObject();
        writer.Flush();
    }


    /// <summary>
    /// Writes the <c>extensions</c> member when at least one of the four named carve-outs this writer
    /// emits is populated; omits the member entirely otherwise.
    /// </summary>
    private static void WriteExtensions(
        Utf8JsonWriter writer, string? appIdExclude, Fido2LargeBlobRegistrationExtensionInput? largeBlob, bool? minPinLength,
        Fido2CredProtectRegistrationExtensionInput? credProtect)
    {
        if(appIdExclude is null && largeBlob is null && minPinLength is null && credProtect is null)
        {
            return;
        }

        writer.WriteStartObject(ExtensionsMember);
        if(appIdExclude is not null)
        {
            writer.WriteString(WellKnownWebAuthnExtensionIdentifiers.AppIdExclude, appIdExclude);
        }

        if(largeBlob is not null)
        {
            writer.WriteStartObject(WellKnownWebAuthnExtensionIdentifiers.LargeBlob);
            writer.WriteString(SupportMember, WellKnownLargeBlobSupports.ToWireValue(largeBlob.Support));
            writer.WriteEndObject();
        }

        if(minPinLength is bool minPinLengthValue)
        {
            writer.WriteBoolean(WellKnownWebAuthnExtensionIdentifiers.MinPinLength, minPinLengthValue);
        }

        if(credProtect is not null)
        {
            writer.WriteString(CredentialProtectionPolicyMember, credProtect.CredentialProtectionPolicy);
            writer.WriteBoolean(EnforceCredentialProtectionPolicyMember, credProtect.EnforceCredentialProtectionPolicy);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Writes a <c>PublicKeyCredentialDescriptorJSON</c> sequence under <paramref name="memberName"/>
    /// when <paramref name="descriptors"/> is non-empty; omits the member entirely when
    /// <see langword="null"/> or empty (the CR's own <c>[]</c> default applies either way on the
    /// reading side, so omission is equivalent and keeps the document smaller).
    /// </summary>
    private static void WriteDescriptors(Utf8JsonWriter writer, string memberName, IReadOnlyList<PublicKeyCredentialDescriptor>? descriptors)
    {
        if(descriptors is not { Count: > 0 })
        {
            return;
        }

        writer.WriteStartArray(memberName);
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


    /// <summary>
    /// Writes <paramref name="value"/> under <paramref name="memberName"/> when present; omits the
    /// member entirely when <see langword="null"/>.
    /// </summary>
    private static void WriteOptionalString(Utf8JsonWriter writer, string memberName, string? value)
    {
        if(value is not null)
        {
            writer.WriteString(memberName, value);
        }
    }
}
