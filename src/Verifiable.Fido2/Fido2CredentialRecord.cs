using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// The WebAuthn credential record a relying party stores after a successful registration
/// ceremony, and updates after each subsequent authentication ceremony.
/// </summary>
/// <param name="Type">
/// The credential type, always <see cref="WellKnownPublicKeyCredentialTypes.PublicKey"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-credentialType">W3C Web Authentication Level
/// 3, section 5.8.2: Credential Type Enumeration</see> — currently the only defined value of the
/// <c>PublicKeyCredentialType</c> enumeration.
/// </param>
/// <param name="Id">
/// The credential identifier, per <see href="https://www.w3.org/TR/webauthn-3/#credential-id">W3C
/// Web Authentication Level 3, section 4: Terminology, "Credential ID"</see> — at most 1023 bytes.
/// A fresh, independently-owned copy of <see cref="Fido2.AttestedCredentialData.CredentialId"/>:
/// this record is expected to outlive the ceremony-scoped <see cref="AuthenticatorData"/> it was
/// built from (a relying party stores it across future authentication ceremonies), so it cannot
/// share that shorter-lived object's carrier.
/// </param>
/// <param name="PublicKey">
/// The credential public key, per <see href="https://www.w3.org/TR/webauthn-3/#credential-public-key">
/// W3C Web Authentication Level 3, section 4: Terminology, "Credential Public Key"</see>.
/// </param>
/// <param name="SignCount">
/// The latest signature counter value observed for this credential across every ceremony, per
/// <see href="https://www.w3.org/TR/webauthn-3/#credential-record">W3C Web Authentication Level 3,
/// section 4: Terminology, "Credential Record"</see>.
/// </param>
/// <param name="UvInitialized">
/// Whether any ceremony using this credential has had the <c>UV</c> flag set, per the "Credential
/// Record" terminology entry linked on <see cref="SignCount"/>.
/// </param>
/// <param name="Transports">
/// The transports reported by <c>AuthenticatorAttestationResponse.getTransports()</c> at
/// registration time, per the "Credential Record" terminology entry linked on
/// <see cref="SignCount"/>. These come from the client response, not <c>authData</c>, so a
/// verifier cannot derive them itself — the caller supplies them.
/// </param>
/// <param name="BackupEligible">
/// The <c>BE</c> flag value observed when this credential was created, per the "Credential Record"
/// terminology entry linked on <see cref="SignCount"/>.
/// </param>
/// <param name="BackupState">
/// The latest <c>BS</c> flag value observed for this credential, per the "Credential Record"
/// terminology entry linked on <see cref="SignCount"/>.
/// </param>
/// <param name="AuthenticatorAttachment">
/// The client-reported <c>authenticatorAttachment</c> value (<see cref="WellKnownAuthenticatorAttachments.Platform"/>
/// or <see cref="WellKnownAuthenticatorAttachments.CrossPlatform"/>), normalized at registration
/// time, or <see langword="null"/> when absent or unrecognized. Defaults to <see langword="null"/>.
/// Unlike <see cref="SignCount"/>'s sibling members, this is <em>not</em> one of credential-record's
/// own named RECOMMENDED/OPTIONAL items (see the type-level remarks) — it is licensed only by that
/// terminology entry's generic "Relying Parties MAY also include any additional items as needed"
/// catch-all, anchored instead to
/// <see href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">W3C Web Authentication Level 3,
/// section 5.1: PublicKeyCredential Interface</see>'s <c>authenticatorAttachment</c> attribute,
/// which this member stores for a relying party that chooses to.
/// </param>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#credential-record">W3C Web Authentication Level 3,
/// section 4: Terminology, "Credential Record"</see> defines this struct abstractly; it is built
/// concretely by <see cref="Fido2RegistrationVerifier"/> at
/// <see href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-create-credential-record">section
/// 7.1: Registering a New Credential, step 27</see> and is expected to be updated by the relying
/// party after each authentication ceremony.
/// </para>
/// <para>
/// Only the REQUIRED contents are modelled here. The OPTIONAL
/// <c>attestationObject</c>/<c>attestationClientDataJSON</c>/<c>rpId</c> items are a relying
/// party's own storage concern, not part of this library's verification surface.
/// </para>
/// </remarks>
[DebuggerDisplay("Fido2CredentialRecord(Type={Type}, Id={Id}, SignCount={SignCount}, UvInitialized={UvInitialized}, BackupEligible={BackupEligible}, BackupState={BackupState}, AuthenticatorAttachment={AuthenticatorAttachment})")]
public sealed record Fido2CredentialRecord(
    string Type,
    CredentialId Id,
    CoseKey PublicKey,
    uint SignCount,
    bool UvInitialized,
    IReadOnlyList<string> Transports,
    bool BackupEligible,
    bool BackupState,
    string? AuthenticatorAttachment = null): IDisposable
{
    /// <summary>
    /// Determines whether this record and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Transports"/> by reference
    /// (it is typed <see cref="IReadOnlyList{T}"/>, not a value-equatable collection), which would
    /// report two independently-built records carrying byte-identical transport lists — for
    /// example the same credential record reloaded from storage twice — as unequal; this override
    /// compares <see cref="Transports"/> ordinally and element-wise instead. Every other member
    /// already carries correct value semantics under the default synthesized comparison
    /// (<see cref="Id"/> and <see cref="PublicKey"/> implement <see cref="IEquatable{T}"/>; the
    /// remaining members are strings and value types), so this override reproduces that same
    /// default comparison for them explicitly — including <see cref="AuthenticatorAttachment"/>,
    /// compared ordinally and null-safely like <see cref="Type"/>. Because this equality is
    /// hand-rolled rather than compiler-synthesized, adding a new primary-constructor parameter does
    /// NOT automatically join it: every member above must be listed here explicitly.
    /// </summary>
    /// <param name="other">The other record to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when every member matches, including a value-wise (not
    /// reference-wise), ordinal, order-sensitive comparison of <see cref="Transports"/>.
    /// </returns>
    public bool Equals(Fido2CredentialRecord? other) =>
        other is not null
        && Type == other.Type
        && Id.Equals(other.Id)
        && PublicKey.Equals(other.PublicKey)
        && SignCount == other.SignCount
        && UvInitialized == other.UvInitialized
        && BackupEligible == other.BackupEligible
        && BackupState == other.BackupState
        && Transports.SequenceEqual(other.Transports, StringComparer.Ordinal)
        && string.Equals(AuthenticatorAttachment, other.AuthenticatorAttachment, StringComparison.Ordinal);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(Fido2CredentialRecord?)"/> —
    /// combining the scalar members with each <see cref="Transports"/> entry's ordinal value in
    /// order — so two value-equal records never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Type, StringComparer.Ordinal);
        hash.Add(Id);
        hash.Add(PublicKey);
        hash.Add(SignCount);
        hash.Add(UvInitialized);
        hash.Add(BackupEligible);
        hash.Add(BackupState);
        foreach(string transport in Transports)
        {
            hash.Add(transport, StringComparer.Ordinal);
        }

        hash.Add(AuthenticatorAttachment, StringComparer.Ordinal);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Releases <see cref="Id"/>.
    /// </summary>
    public void Dispose() => Id.Dispose();
}
