using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>credential-change</c> event (CAEP 1.0 §3.3.1).
/// </summary>
public static class CaepCredentialChangeClaimNames
{
    /// <summary><c>credential_type</c> — REQUIRED; see <see cref="CaepCredentialTypeValues"/>.</summary>
    public static readonly string CredentialType = "credential_type";

    /// <summary><c>change_type</c> — REQUIRED; see <see cref="CaepChangeTypeValues"/>.</summary>
    public static readonly string ChangeType = "change_type";

    /// <summary><c>friendly_name</c> — OPTIONAL; the credential's friendly name.</summary>
    public static readonly string FriendlyName = "friendly_name";

    /// <summary><c>x509_issuer</c> — OPTIONAL; the X.509 certificate issuer (RFC 5280).</summary>
    public static readonly string X509Issuer = "x509_issuer";

    /// <summary><c>x509_serial</c> — OPTIONAL; the X.509 certificate serial number (RFC 5280).</summary>
    public static readonly string X509Serial = "x509_serial";

    /// <summary><c>fido2_aaguid</c> — OPTIONAL; the FIDO2 Authenticator Attestation GUID (WebAuthn).</summary>
    public static readonly string Fido2Aaguid = "fido2_aaguid";
}


/// <summary>
/// The allowed <c>change_type</c> values (CAEP 1.0 §3.3.1) — a closed set.
/// </summary>
public static class CaepChangeTypeValues
{
    /// <summary><c>create</c> — the credential was created.</summary>
    public static readonly string Create = "create";

    /// <summary><c>revoke</c> — the credential was revoked.</summary>
    public static readonly string Revoke = "revoke";

    /// <summary><c>update</c> — the credential was updated.</summary>
    public static readonly string Update = "update";

    /// <summary><c>delete</c> — the credential was deleted.</summary>
    public static readonly string Delete = "delete";


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
    /// <summary><c>password</c>.</summary>
    public static readonly string Password = "password";

    /// <summary><c>pin</c>.</summary>
    public static readonly string Pin = "pin";

    /// <summary><c>x509</c>.</summary>
    public static readonly string X509 = "x509";

    /// <summary><c>fido2-platform</c>.</summary>
    public static readonly string Fido2Platform = "fido2-platform";

    /// <summary><c>fido2-roaming</c>.</summary>
    public static readonly string Fido2Roaming = "fido2-roaming";

    /// <summary><c>fido-u2f</c>.</summary>
    public static readonly string FidoU2f = "fido-u2f";

    /// <summary><c>verifiable-credential</c>.</summary>
    public static readonly string VerifiableCredential = "verifiable-credential";

    /// <summary><c>phone-voice</c>.</summary>
    public static readonly string PhoneVoice = "phone-voice";

    /// <summary><c>phone-sms</c>.</summary>
    public static readonly string PhoneSms = "phone-sms";

    /// <summary><c>app</c>.</summary>
    public static readonly string App = "app";
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
