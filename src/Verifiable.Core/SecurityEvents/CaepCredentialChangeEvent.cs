using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>credential-change</c> event (CAEP 1.0 §3.3.1).
/// </summary>
public static class CaepCredentialChangeClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="CredentialType"/>.</summary>
    public static ReadOnlySpan<byte> CredentialTypeUtf8 => "credential_type"u8;

    /// <summary><c>credential_type</c> — REQUIRED; see <see cref="CaepCredentialTypeValues"/>.</summary>
    public static readonly string CredentialType = Utf8Constants.ToInternedString(CredentialTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ChangeType"/>.</summary>
    public static ReadOnlySpan<byte> ChangeTypeUtf8 => "change_type"u8;

    /// <summary><c>change_type</c> — REQUIRED; see <see cref="CaepChangeTypeValues"/>.</summary>
    public static readonly string ChangeType = Utf8Constants.ToInternedString(ChangeTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FriendlyName"/>.</summary>
    public static ReadOnlySpan<byte> FriendlyNameUtf8 => "friendly_name"u8;

    /// <summary><c>friendly_name</c> — OPTIONAL; the credential's friendly name.</summary>
    public static readonly string FriendlyName = Utf8Constants.ToInternedString(FriendlyNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X509Issuer"/>.</summary>
    public static ReadOnlySpan<byte> X509IssuerUtf8 => "x509_issuer"u8;

    /// <summary><c>x509_issuer</c> — OPTIONAL; the X.509 certificate issuer (RFC 5280).</summary>
    public static readonly string X509Issuer = Utf8Constants.ToInternedString(X509IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X509Serial"/>.</summary>
    public static ReadOnlySpan<byte> X509SerialUtf8 => "x509_serial"u8;

    /// <summary><c>x509_serial</c> — OPTIONAL; the X.509 certificate serial number (RFC 5280).</summary>
    public static readonly string X509Serial = Utf8Constants.ToInternedString(X509SerialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido2Aaguid"/>.</summary>
    public static ReadOnlySpan<byte> Fido2AaguidUtf8 => "fido2_aaguid"u8;

    /// <summary><c>fido2_aaguid</c> — OPTIONAL; the FIDO2 Authenticator Attestation GUID (WebAuthn).</summary>
    public static readonly string Fido2Aaguid = Utf8Constants.ToInternedString(Fido2AaguidUtf8);
}


/// <summary>
/// The allowed <c>change_type</c> values (CAEP 1.0 §3.3.1) — a closed set.
/// </summary>
public static class CaepChangeTypeValues
{
    /// <summary>The UTF-8 source literal of <see cref="Create"/>.</summary>
    public static ReadOnlySpan<byte> CreateUtf8 => "create"u8;

    /// <summary><c>create</c> — the credential was created.</summary>
    public static readonly string Create = Utf8Constants.ToInternedString(CreateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Revoke"/>.</summary>
    public static ReadOnlySpan<byte> RevokeUtf8 => "revoke"u8;

    /// <summary><c>revoke</c> — the credential was revoked.</summary>
    public static readonly string Revoke = Utf8Constants.ToInternedString(RevokeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Update"/>.</summary>
    public static ReadOnlySpan<byte> UpdateUtf8 => "update"u8;

    /// <summary><c>update</c> — the credential was updated.</summary>
    public static readonly string Update = Utf8Constants.ToInternedString(UpdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Delete"/>.</summary>
    public static ReadOnlySpan<byte> DeleteUtf8 => "delete"u8;

    /// <summary><c>delete</c> — the credential was deleted.</summary>
    public static readonly string Delete = Utf8Constants.ToInternedString(DeleteUtf8);


    /// <summary>Whether <paramref name="value"/> is one of the four allowed values.</summary>
    public static bool IsAllowed(string value) =>
        Equals(value, Create) || Equals(value, Revoke) || Equals(value, Update) || Equals(value, Delete);


    /// <summary>Compares two values for equality (case-sensitive).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}


/// <summary>
/// The <c>credential_type</c> values CAEP 1.0 §3.3.1 enumerates. The set is
/// OPEN — "any other credential type supported mutually by the Transmitter and
/// the Receiver" is also valid — so there is deliberately no IsAllowed gate.
/// </summary>
public static class CaepCredentialTypeValues
{
    /// <summary>The UTF-8 source literal of <see cref="Password"/>.</summary>
    public static ReadOnlySpan<byte> PasswordUtf8 => "password"u8;

    /// <summary><c>password</c>.</summary>
    public static readonly string Password = Utf8Constants.ToInternedString(PasswordUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Pin"/>.</summary>
    public static ReadOnlySpan<byte> PinUtf8 => "pin"u8;

    /// <summary><c>pin</c>.</summary>
    public static readonly string Pin = Utf8Constants.ToInternedString(PinUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X509"/>.</summary>
    public static ReadOnlySpan<byte> X509Utf8 => "x509"u8;

    /// <summary><c>x509</c>.</summary>
    public static readonly string X509 = Utf8Constants.ToInternedString(X509Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido2Platform"/>.</summary>
    public static ReadOnlySpan<byte> Fido2PlatformUtf8 => "fido2-platform"u8;

    /// <summary><c>fido2-platform</c>.</summary>
    public static readonly string Fido2Platform = Utf8Constants.ToInternedString(Fido2PlatformUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Fido2Roaming"/>.</summary>
    public static ReadOnlySpan<byte> Fido2RoamingUtf8 => "fido2-roaming"u8;

    /// <summary><c>fido2-roaming</c>.</summary>
    public static readonly string Fido2Roaming = Utf8Constants.ToInternedString(Fido2RoamingUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoU2f"/>.</summary>
    public static ReadOnlySpan<byte> FidoU2fUtf8 => "fido-u2f"u8;

    /// <summary><c>fido-u2f</c>.</summary>
    public static readonly string FidoU2f = Utf8Constants.ToInternedString(FidoU2fUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerifiableCredential"/>.</summary>
    public static ReadOnlySpan<byte> VerifiableCredentialUtf8 => "verifiable-credential"u8;

    /// <summary><c>verifiable-credential</c>.</summary>
    public static readonly string VerifiableCredential = Utf8Constants.ToInternedString(VerifiableCredentialUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneVoice"/>.</summary>
    public static ReadOnlySpan<byte> PhoneVoiceUtf8 => "phone-voice"u8;

    /// <summary><c>phone-voice</c>.</summary>
    public static readonly string PhoneVoice = Utf8Constants.ToInternedString(PhoneVoiceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneSms"/>.</summary>
    public static ReadOnlySpan<byte> PhoneSmsUtf8 => "phone-sms"u8;

    /// <summary><c>phone-sms</c>.</summary>
    public static readonly string PhoneSms = Utf8Constants.ToInternedString(PhoneSmsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="App"/>.</summary>
    public static ReadOnlySpan<byte> AppUtf8 => "app"u8;

    /// <summary><c>app</c>.</summary>
    public static readonly string App = Utf8Constants.ToInternedString(AppUtf8);
}


/// <summary>
/// The typed view of a CAEP <c>credential-change</c> event (CAEP 1.0 §3.3):
/// a credential was created, changed, revoked, or deleted. When the common
/// <c>event_timestamp</c> is present it is the time the change occurred.
/// </summary>
public sealed record CaepCredentialChangeEvent
{
    /// <summary>The REQUIRED <c>credential_type</c> — an open set; see <see cref="CaepCredentialTypeValues"/>.</summary>
    public required string CredentialType { get; init; }

    /// <summary>The REQUIRED <c>change_type</c> — one of <see cref="CaepChangeTypeValues"/>.</summary>
    public required string ChangeType { get; init; }

    /// <summary>The OPTIONAL <c>friendly_name</c>.</summary>
    public string? FriendlyName { get; init; }

    /// <summary>The OPTIONAL <c>x509_issuer</c>.</summary>
    public string? X509Issuer { get; init; }

    /// <summary>The OPTIONAL <c>x509_serial</c>.</summary>
    public string? X509Serial { get; init; }

    /// <summary>The OPTIONAL <c>fido2_aaguid</c>.</summary>
    public string? Fido2Aaguid { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>credential-change</c>,
    /// a REQUIRED claim is absent or not a string, or <c>change_type</c> is
    /// outside its closed value set.
    /// </summary>
    public static CaepCredentialChangeEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsCredentialChange(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;
        if(!payload.TryGetValue(CaepCredentialChangeClaimNames.CredentialType, out object? credentialValue)
            || credentialValue is not string credentialType
            || credentialType.Length == 0)
        {
            return null;
        }

        if(!payload.TryGetValue(CaepCredentialChangeClaimNames.ChangeType, out object? changeValue)
            || changeValue is not string changeType
            || !CaepChangeTypeValues.IsAllowed(changeType))
        {
            return null;
        }

        return new CaepCredentialChangeEvent
        {
            CredentialType = credentialType,
            ChangeType = changeType,
            FriendlyName = EventPayloadReading.ReadOptionalString(payload, CaepCredentialChangeClaimNames.FriendlyName),
            X509Issuer = EventPayloadReading.ReadOptionalString(payload, CaepCredentialChangeClaimNames.X509Issuer),
            X509Serial = EventPayloadReading.ReadOptionalString(payload, CaepCredentialChangeClaimNames.X509Serial),
            Fido2Aaguid = EventPayloadReading.ReadOptionalString(payload, CaepCredentialChangeClaimNames.Fido2Aaguid),
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [CaepCredentialChangeClaimNames.CredentialType] = CredentialType,
            [CaepCredentialChangeClaimNames.ChangeType] = ChangeType
        };

        if(FriendlyName is not null)
        {
            payload[CaepCredentialChangeClaimNames.FriendlyName] = FriendlyName;
        }

        if(X509Issuer is not null)
        {
            payload[CaepCredentialChangeClaimNames.X509Issuer] = X509Issuer;
        }

        if(X509Serial is not null)
        {
            payload[CaepCredentialChangeClaimNames.X509Serial] = X509Serial;
        }

        if(Fido2Aaguid is not null)
        {
            payload[CaepCredentialChangeClaimNames.Fido2Aaguid] = Fido2Aaguid;
        }

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.CredentialChange, Payload = payload };
    }
}
