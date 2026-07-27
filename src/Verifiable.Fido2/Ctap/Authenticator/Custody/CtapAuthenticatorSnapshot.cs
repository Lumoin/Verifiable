using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// A parsed CTAP authenticator state-custody snapshot: exactly the PERSISTENT subset of
/// <see cref="CtapAuthenticatorState"/> contract ruling R-2 names, plus the personalization fingerprint
/// R-2b requires rehydration to verify before restoring it into a freshly composed authenticator.
/// </summary>
/// <remarks>
/// <para>
/// Produced only by a <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> implementation. Every
/// reference-typed member owns freshly rented/copied memory independent of whatever
/// <see cref="CtapAuthenticatorState"/> the snapshot was originally encoded from (R-3: the custody seam
/// copies at the boundary, never handing a live <c>IMemoryOwner&lt;byte&gt;</c> reference across a real
/// process boundary) — so a caller either transfers that ownership into a rehydrated
/// <see cref="CtapAuthenticatorState"/> via a <c>with</c> overlay, or disposes this instance directly if
/// rehydration is abandoned (for example, a fingerprint mismatch).
/// </para>
/// <para>
/// Deliberately excludes every volatile field CTAP 2.3 section 6 items 1-3 name (the six
/// <c>Remembered*</c>/<c>PendingUserPresenceWait</c> slots, both <c>CtapPinUvAuthTokenState</c>s, both
/// key-agreement pairs, <c>ConsecutivePinMismatches</c>, <c>IsPowerCycleRequired</c>,
/// <c>PoweredOnAt</c>) — R-1 restores those by composing <see cref="CtapAuthenticatorState.Initial"/>
/// with the SAME personalization the snapshot's fingerprint was checked against, exactly the state
/// <c>PowerCycle</c>'s own volatile-refresh semantics would produce, rather than serializing them here.
/// </para>
/// </remarks>
/// <param name="FormatVersion">
/// The snapshot wire-format version this instance was parsed under. A rehydrating caller compares this
/// against the codec's own current version and fails closed on any mismatch (R-5) before ever reading
/// the fields below.
/// </param>
/// <param name="Aaguid">
/// The AAGUID of the authenticator this snapshot was captured from — half of R-2b's personalization
/// fingerprint. Rehydration fails closed unless this equals the freshly composed authenticator's own
/// <see cref="CtapAuthenticatorState.Aaguid"/>.
/// </param>
/// <param name="FirmwareVersion">
/// The firmware version of the authenticator this snapshot was captured from — the other half of R-2b's
/// personalization fingerprint.
/// </param>
/// <param name="NextCredentialSequence">The persisted <see cref="CtapAuthenticatorState.NextCredentialSequence"/> value.</param>
/// <param name="CurrentStoredPin">The persisted <see cref="CtapAuthenticatorState.CurrentStoredPin"/> value, or <see langword="null"/> when no PIN was set.</param>
/// <param name="PinCodePointLength">The persisted <see cref="CtapAuthenticatorState.PinCodePointLength"/> value.</param>
/// <param name="PinRetries">The persisted <see cref="CtapAuthenticatorState.PinRetries"/> value.</param>
/// <param name="UvRetries">The persisted <see cref="CtapAuthenticatorState.UvRetries"/> value.</param>
/// <param name="IsForcePinChangeRequired">The persisted <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/> value.</param>
/// <param name="MinPinCodePointLength">The persisted <see cref="CtapAuthenticatorState.MinPinCodePointLength"/> value.</param>
/// <param name="MinPinLengthRpIds">The persisted <see cref="CtapAuthenticatorState.MinPinLengthRpIds"/> value.</param>
/// <param name="IsAlwaysUvEnabled">The persisted <see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/> value.</param>
/// <param name="IsEnterpriseAttestationEnabled">The persisted <see cref="CtapAuthenticatorState.IsEnterpriseAttestationEnabled"/> value.</param>
/// <param name="SerializedLargeBlobArray">The persisted <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> value. Owned by this instance.</param>
/// <param name="CredentialsByCredentialId">The persisted <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/> value. Every entry is owned by this instance.</param>
/// <param name="BioEnrollmentTemplatesByTemplateId">The persisted <see cref="CtapAuthenticatorState.BioEnrollmentTemplatesByTemplateId"/> value. Every entry is owned by this instance.</param>
public sealed record CtapAuthenticatorSnapshot(
    int FormatVersion,
    Guid Aaguid,
    int FirmwareVersion,
    ulong NextCredentialSequence,
    DigestValue? CurrentStoredPin,
    int PinCodePointLength,
    int PinRetries,
    int UvRetries,
    bool IsForcePinChangeRequired,
    int MinPinCodePointLength,
    IReadOnlyList<string> MinPinLengthRpIds,
    bool IsAlwaysUvEnabled,
    bool IsEnterpriseAttestationEnabled,
    PooledMemory SerializedLargeBlobArray,
    ImmutableDictionary<string, CtapCredentialRecord> CredentialsByCredentialId,
    ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord> BioEnrollmentTemplatesByTemplateId): IDisposable
{
    /// <summary>
    /// Releases every carrier this snapshot owns: the stored PIN digest (if any), the serialized
    /// large-blob array, every credential record, and every bio enrollment template record. Safe to call
    /// whether or not ownership of these values was ever transferred into a rehydrated
    /// <see cref="CtapAuthenticatorState"/> — a caller that DID transfer ownership must not call this
    /// afterward (the same single-owner discipline every other disposable record in this codebase
    /// follows).
    /// </summary>
    public void Dispose()
    {
        CurrentStoredPin?.Dispose();
        SerializedLargeBlobArray.Dispose();

        foreach(CtapCredentialRecord credential in CredentialsByCredentialId.Values)
        {
            credential.Dispose();
        }

        foreach(CtapBioEnrollmentTemplateRecord template in BioEnrollmentTemplatesByTemplateId.Values)
        {
            template.Dispose();
        }
    }
}
