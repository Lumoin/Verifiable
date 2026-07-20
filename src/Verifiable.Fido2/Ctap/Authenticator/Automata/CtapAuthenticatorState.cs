using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The complete state of the CTAP2 authenticator simulator's pushdown automaton: the authenticator's
/// fixed identity and personalization, its credential store, and the logical response produced by the
/// command just processed.
/// </summary>
/// <remarks>
/// This is the single "fat" operational record carried by one <c>PushdownAutomaton</c> per simulated
/// authenticator, mirroring <c>Verifiable.Tpm.Automata.TpmSimulatorState</c> and
/// <c>Verifiable.Apdu.Automata.CardSimulatorState</c>'s shape. <see cref="Aaguid"/> is a value fixed for
/// the simulator's whole lifetime, drawn once at construction from the injected entropy provider, never
/// an inline magic value; <see cref="SupportedExtensions"/> is an authenticator model's advertised
/// extension-identifier list — a personalization knob, the same role <c>CardSimulator</c>'s
/// constructor-supplied elementary files play. <see cref="CredentialsByCredentialId"/> is the credential
/// store <c>authenticatorMakeCredential</c> and <c>authenticatorGetAssertion</c> mint into and read from —
/// an immutable collection updated only via <c>with</c> copies, never mutated in place, so the credential
/// store shares the same "with copies, not a mutable field" discipline as every other member of this
/// record. <see cref="RememberedGetAssertion"/> is the one exception to "the credential store is the only
/// cross-command state": it persists an in-progress multi-account <c>authenticatorGetAssertion</c>
/// sequence for <c>authenticatorGetNextAssertion</c>, following the same "state via record fields, not the
/// stack" precedent the credential store itself already establishes.
/// </remarks>
/// <param name="Aaguid">The authenticator's claimed AAGUID, fixed for the simulator's lifetime.</param>
/// <param name="SupportedExtensions">
/// The extension identifiers this authenticator model advertises in <c>authenticatorGetInfo</c>'s
/// <c>extensions</c> member, or <see langword="null"/> to omit the member entirely.
/// </param>
/// <param name="NextAction">The effectful action the runner must execute next; <see cref="NullAction.Instance"/> when none.</param>
/// <param name="ResponseIntent">The logical response produced by the last command, or <see langword="null"/> before the first command.</param>
/// <param name="CredentialsByCredentialId">
/// Every credential this authenticator has minted, keyed by a lowercase-hex encoding of its
/// <see cref="CredentialId"/> bytes — resident and non-resident credentials alike, since CTAP 2.3 section
/// 6.2.2 locates an <c>allowList</c>-denoted credential by ID regardless of discoverability. This is the
/// sole credential index: a discoverable (<c>rk</c>) credential is located later by scanning this same
/// dictionary for <see cref="CtapCredentialRecord.IsResident"/> entries matching a relying party
/// identifier, rather than through a second, separately maintained index keyed by relying party.
/// </param>
/// <param name="ResidentCredentialCapacity">
/// The maximum number of resident (discoverable) credentials this authenticator can hold at once,
/// fixed for the simulator's lifetime. A resident <c>authenticatorMakeCredential</c> that would exceed
/// this bound answers <c>CTAP2_ERR_KEY_STORE_FULL</c> (CTAP 2.3, section 6.1.2: "If authenticator does
/// not have enough internal storage to persist the new credential..."); a same-(<c>rp.id</c>, account)
/// overwrite never counts against it, since it does not grow the store.
/// </param>
/// <param name="PoweredOnAt">
/// The instant this simulator was last considered powered on: stamped by <see cref="Initial"/> at
/// construction and RESTAMPED by <see cref="PowerCycle"/> — a power cycle IS "powering up" again. CTAP
/// 2.3 §6.6 (lines 6365-6366) measures <c>authenticatorReset</c>'s 10-second power-up window from this
/// value; a successful reset does NOT restamp it (nothing in §6.6's text makes reset itself a power-up).
/// </param>
/// <param name="NextCredentialSequence">
/// The monotonic counter <see cref="CtapCredentialRecord.CreationSequence"/> draws from at mint time,
/// incremented by one every time a credential is inserted into <see cref="CredentialsByCredentialId"/>.
/// Never a wall-clock timestamp — the pure transition function reads no time.
/// </param>
/// <param name="RememberedGetAssertion">
/// The remembered <c>authenticatorGetAssertion</c> parameters a multi-account
/// <c>authenticatorGetAssertion</c> left behind for <c>authenticatorGetNextAssertion</c> to consume, or
/// <see langword="null"/> when no such sequence is in progress (no multi-account
/// <c>authenticatorGetAssertion</c> has run yet, the sequence was exhausted, its timer expired, an
/// intervening authenticator operation discarded it, or the authenticator power-cycled).
/// </param>
/// <param name="RememberedEnumerateRps">
/// The remembered <c>enumerateRPsBegin</c> parameters an in-progress RP enumeration left behind for
/// <c>enumerateRPsGetNextRP</c> to consume, or <see langword="null"/> when no such sequence is in
/// progress. The credMgmt sibling of <see cref="RememberedGetAssertion"/> — same discard/discard-on-power-cycle
/// discipline, a second dedicated slot rather than a shared "any pending stateful sequence" union.
/// </param>
/// <param name="RememberedEnumerateCredentials">
/// The remembered <c>enumerateCredentialsBegin</c> parameters an in-progress per-RP credential
/// enumeration left behind for <c>enumerateCredentialsGetNextCredential</c> to consume, or
/// <see langword="null"/> when no such sequence is in progress — the credMgmt sibling of
/// <see cref="RememberedGetAssertion"/> for the OTHER stateful credMgmt sequence.
/// </param>
/// <param name="ProtocolOneKeyAgreementKeyPair">
/// PIN/UV auth protocol one's key-agreement key pair (CTAP 2.3 §6.5.6), minted at construction and
/// refreshed by <see cref="PowerCycle"/> (<c>initialize()</c>'s <c>regenerate()</c> half). Each
/// protocol maintains its own key-agreement key material.
/// </param>
/// <param name="ProtocolTwoKeyAgreementKeyPair">
/// PIN/UV auth protocol two's key-agreement key pair (CTAP 2.3 §6.5.7) — see
/// <see cref="ProtocolOneKeyAgreementKeyPair"/>.
/// </param>
/// <param name="ProtocolOneToken">
/// PIN/UV auth protocol one's <c>pinUvAuthToken</c> lifecycle state (CTAP 2.3 §6.5.2.1/§6.5.3), minted
/// at construction and refreshed by <see cref="PowerCycle"/> (<c>initialize()</c>'s
/// <c>resetPinUvAuthToken()</c> half).
/// </param>
/// <param name="ProtocolTwoToken">
/// PIN/UV auth protocol two's <c>pinUvAuthToken</c> lifecycle state — see <see cref="ProtocolOneToken"/>.
/// </param>
/// <param name="CurrentStoredPin">
/// The authenticator's stored <c>LEFT(SHA-256(newPin), 16)</c> (CTAP 2.3 §6.5.5.5, line 5592,
/// <c>CurrentStoredPIN</c>), or <see langword="null"/> when no PIN has been set. Never the PIN itself,
/// and never a naked byte array.
/// </param>
/// <param name="PinCodePointLength">
/// The stored PIN's length in Unicode CODE POINTS (CTAP 2.3 §6.5.5.5, line 5590,
/// <c>PINCodePointLength</c>) — not UTF-8 byte length. 0 when <see cref="CurrentStoredPin"/> is
/// <see langword="null"/>.
/// </param>
/// <param name="PinRetries">
/// The number of PIN attempts remaining before lockout (CTAP 2.3 §6.5.5.2's <c>pinRetries</c>), seeded
/// at construction to <see cref="MaxPinRetries"/> and reported as-is by <c>getPINRetries</c>.
/// </param>
/// <param name="UvRetries">
/// The number of built-in-UV attempts remaining before lockout (CTAP 2.3 §6.5.5.3's <c>uvRetries</c>,
/// backed by the spec's <c>maxUvRetries</c>, "MUST be in the range of 1 to 25 inclusive"), seeded at
/// construction to <see cref="MaxUvRetries"/> and reported as-is by <c>getUVRetries</c> —
/// <c>performBuiltInUv</c> (§6.5.3.1) decrements it before every simulated gesture, resets it to
/// <see cref="MaxUvRetries"/> on a successful gesture, and a correct clientPIN entry (line 5071-5072)
/// restores it alongside <see cref="PinRetries"/>.
/// </param>
/// <param name="ConsecutivePinMismatches">
/// The number of consecutive wrong-PIN attempts since the last correct entry or power cycle (CTAP 2.3,
/// line 5680-5683/5893/5995). Reaching 3 sets <see cref="IsPowerCycleRequired"/>; a correct PIN entry
/// resets this to 0.
/// </param>
/// <param name="IsPowerCycleRequired">
/// The power-cycle latch (CTAP 2.3, line 5680-5683/5434-5437): <see langword="true"/> once three
/// consecutive PIN mismatches have occurred, until <see cref="PowerCycle"/> clears it. Reported as
/// <c>powerCycleState</c> by <c>getPINRetries</c>.
/// </param>
/// <param name="IsAlwaysUvEnabled">
/// Whether the Always Require User Verification feature is enabled (<c>authenticatorConfig</c>'s
/// <c>toggleAlwaysUv</c> subcommand, CTAP 2.3 §6.11.2) — reported as the <c>alwaysUv</c> getInfo
/// option. Survives <see cref="PowerCycle"/>: CTAP 2.3 §7.2.3 (lines 8318-8323) reverts this to its
/// default only "after an authenticator reset" — <see cref="FactoryReset"/> performs that reversion
/// for <c>authenticatorReset</c> (0x07).
/// </param>
/// <param name="MinPinCodePointLength">
/// The minimum accepted PIN length in Unicode CODE POINTS this authenticator currently enforces
/// (CTAP 2.3 §6.4, line 4459, "the current minimum PIN length"; §6.11.4's <c>setMinPINLength</c>
/// subcommand is the only way to raise it). Seeded to <see cref="DefaultMinPinCodePointLength"/> by
/// <see cref="Initial"/>. Survives <see cref="PowerCycle"/>: CTAP 2.3 §7.4.3 (lines 8419-8422) reverts
/// this to its pre-configured default only "after an authenticator reset" — <see cref="FactoryReset"/>
/// performs that reversion for <c>authenticatorReset</c> (0x07).
/// </param>
/// <param name="IsForcePinChangeRequired">
/// Whether a PIN change is required before <c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>/<c>changePIN</c> will proceed (CTAP 2.3 §6.4, line
/// 4443, the <c>forcePINChange</c> getInfo member). Set by <c>setMinPINLength</c>'s
/// <c>forceChangePin</c> parameter or its own raised-minimum comparison (§6.11.4 steps 4/6), cleared
/// by a successful <c>changePIN</c> (line 5708). Survives <see cref="PowerCycle"/>: CTAP 2.3 §7.4.3
/// (line 8426) reverts this to <see langword="false"/> only "after an authenticator reset" —
/// <see cref="FactoryReset"/> performs that reversion for <c>authenticatorReset</c> (0x07).
/// </param>
/// <param name="MinPinLengthRpIds">
/// The RP IDs currently authorized to receive the <c>minPinLength</c> extension's current-minimum-PIN-
/// length output (CTAP 2.3 §6.11.4 <c>setMinPINLength</c>, steps 8179-8190; §12.5's own "checks whether
/// the... <c>rp.id</c> parameter is present on its <c>minPinLengthRPIDs</c> list"). This simulator has
/// no pre-configured immutable list, so a supplied <c>minPinLengthRPIDs</c> REPLACES this list wholesale
/// (line 8184's posture — the only one available when no pre-configured list exists), never merges.
/// Seeded to an empty list by <see cref="Initial"/>. Survives <see cref="PowerCycle"/>: CTAP 2.3 §7.4.3
/// (line 8424) reverts this to the immutable pre-configured list (empty, here) only "after an
/// authenticator reset" — <see cref="FactoryReset"/> performs that reversion for
/// <c>authenticatorReset</c> (0x07), mirroring <see cref="MinPinCodePointLength"/>'s own reset/power-
/// cycle treatment.
/// </param>
/// <param name="BioEnrollmentTemplatesByTemplateId">
/// Every fingerprint template this authenticator has provisioned via <c>authenticatorBioEnrollment</c>'s
/// <c>enrollBegin</c>/<c>enrollCaptureNextSample</c> flow, keyed a lowercase-hex encoding of the
/// template's identifier bytes — mirroring <see cref="CredentialsByCredentialId"/>'s own keying
/// convention exactly (R6). <see cref="HasProvisionedBioEnrollments"/> derives from this collection's
/// emptiness; <c>enumerateEnrollments</c>/<c>setFriendlyName</c>/<c>removeEnrollment</c> read and mutate
/// it through the standard <c>with</c>-copy discipline. Survives <see cref="PowerCycle"/> (a persistent
/// store, the <see cref="CredentialsByCredentialId"/> analogy — CTAP 2.3 §6.7 names no power-cycle
/// clearing obligation); cleared, disposing every record, by <see cref="FactoryReset"/> (a documented
/// profile-security posture over §6.6's own silence on bio enrollment, bio scout Finding 8).
/// </param>
/// <param name="RememberedBioEnrollment">
/// The in-progress fingerprint enrollment <c>enrollCaptureNextSample</c> continues, or
/// <see langword="null"/> when no enrollment is currently in progress — the FOURTH remembered-sequence
/// slot (R7), independent of <see cref="RememberedGetAssertion"/>/<see cref="RememberedEnumerateRps"/>/
/// <see cref="RememberedEnumerateCredentials"/> and NOT discarded by those three's own shared
/// "every other command discards it" convention: only <c>cancelCurrentEnrollment</c>, a fresh
/// <c>enrollBegin</c>'s own auto-cancel step, <see cref="PowerCycle"/>, and <see cref="FactoryReset"/>
/// discard it (CTAP 2.3 §6.7 names no broader intervening-operation rule for this sequence).
/// </param>
/// <param name="SerializedLargeBlobArray">
/// The <c>authenticatorLargeBlobs</c> serialized large-blob array (CTAP 2.3 §6.10, line 7539): a
/// CBOR-encoded array of large-blob maps concatenated with a trailing 16-byte truncated SHA-256 hash —
/// an opaque, checksum-guarded byte string this authenticator stores and returns substrings of, never
/// parsing its contents (line 7704's MUST NOT). A NEW KIND of persistent field: unlike
/// <see cref="CurrentStoredPin"/>'s fixed-16 digest, this is a VARIABLE-length owned buffer. Seeded to
/// <see cref="InitialSerializedLargeBlobArray"/> by <see cref="Initial"/>, SURVIVES <see cref="PowerCycle"/>
/// (a persistent store, the <see cref="CredentialsByCredentialId"/> analogy), and restored to
/// <see cref="InitialSerializedLargeBlobArray"/> by <see cref="FactoryReset"/> (line 7705's MUST).
/// </param>
/// <param name="RememberedLargeBlobWrite">
/// The in-progress <c>authenticatorLargeBlobs</c> <c>set</c> sequence's volatile
/// <c>expectedLength</c>/<c>expectedNextOffset</c> pair and not-yet-committed pending buffer, or
/// <see langword="null"/> when no such sequence is in progress — the FIFTH remembered-sequence slot
/// (R7), sibling to <see cref="RememberedGetAssertion"/>/<see cref="RememberedEnumerateRps"/>/
/// <see cref="RememberedEnumerateCredentials"/>/<see cref="RememberedBioEnrollment"/>, but discarded on
/// the GLOBAL discipline those first three share (CTAP 2.3 section 6 item 2, line 2871) rather than
/// <see cref="RememberedBioEnrollment"/>'s own narrower one: any command other than a continuing
/// <c>authenticatorLargeBlobs set</c> fragment discards it. See
/// <see cref="CtapRememberedLargeBlobWriteState"/>.
/// </param>
/// <param name="EnterpriseAttestationProvisioning">
/// The vendor-burned-in enterprise attestation material (CTAP 2.3 §7.1, snapshot line 8251), or
/// <see langword="null"/> when this authenticator was never provisioned with any — the SOLE source
/// <see cref="IsEnterpriseAttestationCapable"/> derives from (R2: never a second stored capability
/// flag). Seeded once, optionally, by <see cref="Initial"/>; survives <see cref="PowerCycle"/> AND
/// <see cref="FactoryReset"/> unchanged (§7.1.3, line 8256: "burned into the authenticator by the
/// vendor" — reset disables the FEATURE, never the capability).
/// </param>
/// <param name="PendingUserPresenceWait">
/// A parked <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> user-presence wait (CTAP
/// 2.3 :2840, R2), or <see langword="null"/> when none is in progress. Discarded, disposing its parked
/// request's carriers, by ANY new command input arriving while a wait is pending (a supersede), by
/// <see cref="PowerCycle"/>, and by <see cref="FactoryReset"/> — the SIXTH remembered-sequence slot,
/// joining the five <c>Remembered*</c> fields on the same "state SHOULD NOT be maintained across power
/// cycles" discipline (CTAP 2.3, section 6, item 1, line 2869), but discarded — unlike them — by ANY
/// superseding command rather than only the ones outside its own narrow continuation set: a user-presence
/// wait has no "continuing command" of its own the way <c>authenticatorGetNextAssertion</c> continues a
/// remembered <c>authenticatorGetAssertion</c>.
/// </param>
/// <param name="IsEnterpriseAttestationEnabled">
/// Whether the enterprise attestation feature is currently enabled — reported as the <c>ep</c> getInfo
/// option's value when <see cref="IsEnterpriseAttestationCapable"/>. Mirrors
/// <see cref="IsAlwaysUvEnabled"/>'s own lifecycle shape: default <see langword="false"/>, NO
/// constructor seed of its own (the only way to <see langword="true"/> is a real
/// <c>enableEnterpriseAttestation</c> call). Survives <see cref="PowerCycle"/>; reverted to
/// <see langword="false"/> by <see cref="FactoryReset"/> (CTAP 2.3 §7.1.3, lines 8276-8278: "If an
/// enterprise attestation capable authenticator receives an <c>authenticatorReset</c> command, it MUST
/// disable the enterprise attestation feature") while <see cref="EnterpriseAttestationProvisioning"/>
/// itself survives untouched.
/// </param>
/// <param name="FirmwareVersion">
/// The authenticator model's firmware version (getInfo member <c>0x0E</c>, CTAP 2.3 snapshot lines
/// 4469-4475), seeded by <see cref="Initial"/> — device identity, the same fixed-for-the-simulator's-
/// lifetime posture as <see cref="Aaguid"/>: neither <see cref="PowerCycle"/> nor
/// <see cref="FactoryReset"/> names it in their own <c>with</c> copies, so it survives both implicitly.
/// </param>
[DebuggerDisplay("Aaguid={Aaguid}, NextAction={NextAction}, Credentials={CredentialsByCredentialId.Count}")]
public sealed record CtapAuthenticatorState(
    Guid Aaguid,
    IReadOnlyList<string>? SupportedExtensions,
    PdaAction NextAction,
    CtapAuthenticatorResponseIntent? ResponseIntent,
    ImmutableDictionary<string, CtapCredentialRecord> CredentialsByCredentialId,
    int ResidentCredentialCapacity,
    DateTimeOffset PoweredOnAt,
    ulong NextCredentialSequence,
    CtapRememberedGetAssertionState? RememberedGetAssertion,
    CtapRememberedEnumerateRpsState? RememberedEnumerateRps,
    CtapRememberedEnumerateCredentialsState? RememberedEnumerateCredentials,
    CtapPinUvAuthKeyAgreementKeyPair ProtocolOneKeyAgreementKeyPair,
    CtapPinUvAuthKeyAgreementKeyPair ProtocolTwoKeyAgreementKeyPair,
    CtapPinUvAuthTokenState ProtocolOneToken,
    CtapPinUvAuthTokenState ProtocolTwoToken,
    DigestValue? CurrentStoredPin,
    int PinCodePointLength,
    int PinRetries,
    int UvRetries,
    int ConsecutivePinMismatches,
    bool IsPowerCycleRequired,
    bool IsAlwaysUvEnabled,
    int MinPinCodePointLength,
    bool IsForcePinChangeRequired,
    IReadOnlyList<string> MinPinLengthRpIds,
    ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord> BioEnrollmentTemplatesByTemplateId,
    CtapRememberedBioEnrollmentState? RememberedBioEnrollment,
    PooledMemory SerializedLargeBlobArray,
    CtapRememberedLargeBlobWriteState? RememberedLargeBlobWrite,
    CtapEnterpriseAttestationProvisioning? EnterpriseAttestationProvisioning,
    bool IsEnterpriseAttestationEnabled,
    CtapPendingUserPresenceState? PendingUserPresenceWait,
    int FirmwareVersion)
{
    /// <summary>
    /// The maximum value <see cref="PinRetries"/> (and, in this simulator, <see cref="UvRetries"/>) is
    /// seeded to and restored to on a correct PIN entry. CTAP 2.3 §6.5.2.3 (line 5069) states
    /// authenticators "MUST allow no more than 8 retries but MAY set a lower maximum" — a CEILING, not
    /// a mandated default; 8 is this simulator's chosen maximum, which also satisfies
    /// <c>maxUvRetries</c>'s separate 1-to-25 range (line 5087).
    /// </summary>
    public static int MaxPinRetries => 8;

    /// <summary>
    /// The maximum value <see cref="UvRetries"/> is seeded to and restored to on a successful
    /// <c>performBuiltInUv</c> gesture (CTAP 2.3 §6.5.3.1 step 9) or a correct clientPIN entry (line
    /// 5071-5072). Single-sourced (R10) — currently aliases <see cref="MaxPinRetries"/> (8), which
    /// already satisfies <c>maxUvRetries</c>' own separate 1-to-25 range (line 5087); a future change to
    /// either maximum only ever needs one literal edited.
    /// </summary>
    public static int MaxUvRetries => MaxPinRetries;

    /// <summary>
    /// The fixed <c>maxUvAttemptsForInternalRetries</c> value this authenticator model uses (CTAP 2.3
    /// §6.5.2.3, line 5090): the number of internal attempts <c>performBuiltInUv(internalRetry: true)</c>
    /// makes before returning an error. Legal range 1-5 inclusive here, since
    /// <see cref="PreferredPlatformUvAttempts"/> is not 1 (line 5090's second MUST). Chosen as 2 so a
    /// scripted [fail, success] sequence inside ONE <c>getPinUvAuthTokenUsingUvWithPermissions</c> or
    /// mc/ga call is genuinely observable (R10) — the internal-retry loop consumes two decrements before
    /// resetting on success, rather than collapsing to a single-attempt case.
    /// </summary>
    public static int MaxUvAttemptsForInternalRetries => 2;

    /// <summary>
    /// The pre-configured default minimum PIN length in Unicode CODE POINTS, used to seed
    /// <see cref="MinPinCodePointLength"/> (CTAP 2.3 §6.5.1, line 4994: "Minimum PIN Length: 4 code
    /// points"; §6.4, line 4463: "The default pre-configured minimum PIN length is at least 4 Unicode
    /// code points").
    /// </summary>
    public static int DefaultMinPinCodePointLength => 4;

    /// <summary>
    /// The maximum accepted PIN length in UTF-8 bytes (CTAP 2.3 §6.5.1, line 4997: "Maximum PIN
    /// Length: 63 bytes").
    /// </summary>
    public static int MaxPinByteLength => 63;

    /// <summary>
    /// The extension identifiers this authenticator model advertises by default: exactly
    /// <c>["credProtect", "hmac-secret", "hmac-secret-mc", "largeBlobKey", "minPinLength"]</c>,
    /// alphabetical (CBOR arrays carry no canonical-order rule of their own, and CTAP itself places no
    /// ordering requirement on this member — §6.4 line 4380-4383's own definition is just "Array of
    /// strings" / "List of supported extensions", no keyword, no sort rule — this ordering is this
    /// codebase's determinism convention, not a spec mandate). CTAP 2.3 §7.4.3
    /// line 8414's MUST ("the extension identifier minpinlength in the extensions member... MUST be
    /// present") and §9 item 6, line 9086 (same identifier, same gate) both spell the identifier
    /// <c>minpinlength</c> in their own prose — an editorial-case artifact of those two clauses'
    /// hyperlinks into §12.5, whose own canonical spelling is mixed-case
    /// (<see cref="WellKnownWebAuthnExtensionIdentifiers.MinPinLength"/>); this array uses the mixed-case
    /// spelling everywhere, matching the identifier actually placed on the <c>authenticatorMakeCredential</c>
    /// wire. <see cref="WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey"/> joins because §12.3's own
    /// feature detection requires BOTH this identifier's presence here AND <c>largeBlobs:true</c> in
    /// <c>authenticatorGetInfo</c>'s <c>options</c> (lines 12832-12834) — the command and the extension
    /// advertise together, or the advertisement is dishonest. <see cref="WellKnownWebAuthnExtensionIdentifiers.HmacSecret"/>
    /// joins because §9 item 1 (snapshot line 9074) MUST-mandates it for every <c>FIDO_2_3</c> claimant,
    /// which this authenticator unconditionally is; <see cref="WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc"/>
    /// joins alongside it (§12.8 is pure delegation over §12.7's own machinery — contract R1) even though
    /// §12.8 itself never separately MUST-mandates advertisement here (its own getInfo behaviors section
    /// names no advertisement rule of its own; this authenticator advertises it anyway, since it supports
    /// the extension). <see cref="Initial"/> resolves this value
    /// when its own <c>supportedExtensions</c> parameter
    /// is omitted or explicitly <see langword="null"/> — the personalization knob itself stays available
    /// for wire-shape tests that need a different (or absent) advertised list.
    /// </summary>
    public static IReadOnlyList<string> DefaultSupportedExtensions =>
        [
            WellKnownWebAuthnExtensionIdentifiers.CredProtect,
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret,
            WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc,
            WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey,
            WellKnownWebAuthnExtensionIdentifiers.MinPinLength
        ];

    /// <summary>
    /// The fixed <c>maxRPIDsForSetMinPINLength</c> capacity this authenticator model advertises and
    /// enforces: 8, mirroring <see cref="ResidentCredentialCapacity"/>'s own construction-time-fixed
    /// shape, but a single build-wide constant rather than a per-instance constructor parameter, since
    /// nothing in this profile personalizes it. Single-sourced for both the <c>authenticatorGetInfo</c>
    /// <c>maxRPIDsForSetMinPINLength</c> (<c>0x10</c>) emission and the <c>setMinPINLength</c> subcommand's
    /// own bound check against a supplied <c>minPinLengthRPIDs</c> list (CTAP 2.3 §6.11.4, line 8182).
    /// </summary>
    public static int MaxRpIdsForSetMinPinLengthCapacity => 8;

    /// <summary>
    /// The fixed <c>maxCredentialCountInList</c> capacity this authenticator model advertises and
    /// enforces: 8, mirroring <see cref="MaxRpIdsForSetMinPinLengthCapacity"/>'s own single-sourced-getter
    /// shape. Single-sourced for BOTH the <c>authenticatorGetInfo</c> <c>maxCredentialCountInList</c>
    /// (<c>0x07</c>) emission and <c>authenticatorMakeCredential</c>'s/<c>authenticatorGetAssertion</c>'s
    /// own <c>excludeList</c>/<c>allowList</c> bound check (CTAP 2.3, snapshot lines 4405-4409: "Maximum
    /// number of credentials supported in credentialID list at a time by the authenticator. MUST be
    /// greater than zero if present" — 8 satisfies the MUST).
    /// </summary>
    public static int MaxCredentialCountInListCapacity => 8;

    /// <summary>
    /// The fixed <c>maxCaptureSamplesRequiredForEnroll</c> value this authenticator model reports via
    /// <c>getFingerprintSensorInfo</c> (CTAP 2.3 §6.7.3, response member <c>0x03</c>): the number of
    /// good samples one fingerprint enrollment needs. A determinism choice (D4), not a spec-mandated
    /// number — the spec only requires the authenticator to report SOME value here.
    /// </summary>
    public static int MaxCaptureSamplesRequiredForEnroll => 4;

    /// <summary>
    /// The fixed <c>fingerprintKind</c> value this authenticator model reports via
    /// <c>getFingerprintSensorInfo</c> (CTAP 2.3 §6.7.3, response member <c>0x02</c>):
    /// <see cref="WellKnownCtapFingerprintKinds.Touch"/> — this simulator models a touch-type sensor,
    /// never a swipe-type one.
    /// </summary>
    public static int FingerprintKind => WellKnownCtapFingerprintKinds.Touch;

    /// <summary>
    /// The maximum <c>templateFriendlyName</c> length in UTF-8 BYTES this authenticator accepts (CTAP
    /// 2.3 §6.7, response member <c>maxTemplateFriendlyName</c> <c>0x08</c>; §6.7.7's own SHOULD,
    /// snapshot line 6863, "the lessor of 64 bytes or the value of maxTemplateFriendlyName" — both are
    /// 64 here, so the SHOULD is satisfied by construction). Single-sourced for BOTH
    /// <c>getFingerprintSensorInfo</c>'s own emission and <c>setFriendlyName</c>'s length-bound check,
    /// mirroring <see cref="MaxPinByteLength"/>'s "maximum accepted string byte length" shape.
    /// </summary>
    public static int MaxTemplateFriendlyNameByteLength => 64;

    /// <summary>
    /// The fixed <c>preferredPlatformUvAttempts</c> value this authenticator advertises (getInfo member
    /// <c>0x11</c>; CTAP 2.3, snapshot lines 4497-4501: MUST be greater than zero; a value of 1 makes
    /// every <c>uvRetries</c> attempt internal, a value greater than 1 makes
    /// <c>internalRetry</c> <see langword="false"/> in <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s
    /// own step 6). Chosen as 3 so the built-in-UV cluster's internal-retry loop stays genuinely
    /// observable rather than collapsing to the single-attempt case.
    /// </summary>
    public static int PreferredPlatformUvAttempts => 3;

    /// <summary>
    /// The fixed <c>uvModality</c> bit-flags value this authenticator advertises (getInfo member
    /// <c>0x12</c>; CTAP 2.3, snapshot lines 4504-4508). Value <c>0x00000002</c>,
    /// <c>USER_VERIFY_FINGERPRINT_INTERNAL</c> — confirmed against the FIDO Registry of Predefined
    /// Values (<see href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-transports">
    /// FIDO Registry v2.2, section 3.1: User Verification Methods</see>), NOT the CTAP snapshot itself
    /// (which only cross-references the registry, per <c>uvModality</c>'s own dfn-less table cell). The
    /// snapshot's own MUST NOT (line 4508, "If clientPin is supported it MUST NOT be included in the
    /// bit-flags") is satisfied: this value carries no clientPIN bit.
    /// </summary>
    public static int UvModality => 0x00000002;

    /// <summary>
    /// Whether the fingerprint template store holds at least one provisioned enrollment — the single
    /// source both the <c>bioEnroll</c> and <c>uv</c> getInfo tri-state option values derive from
    /// (wavebio R2). A derivation SEAM: <c>BuildGetInfoResponse</c> threads this getter's value as a
    /// parameter (never a literal), so <see cref="BioEnrollmentTemplatesByTemplateId"/>'s own shape can
    /// change without touching any caller.
    /// </summary>
    public bool HasProvisionedBioEnrollments => !BioEnrollmentTemplatesByTemplateId.IsEmpty;

    /// <summary>
    /// Whether this authenticator is enterprise attestation capable (CTAP 2.3 §7.1, snapshot line
    /// 8251's "enterprise attestation capable authenticators") — derived from
    /// <see cref="EnterpriseAttestationProvisioning"/>'s presence, and ONLY from it (R2, trap 15): no
    /// second stored flag exists, so this predicate is the single source every consumer (the <c>ep</c>
    /// getInfo option's presence, the conditional <c>authenticatorConfigCommands</c> array, the config
    /// step-2 support gate's third disjunct, and mc Step 9's own capability test) reads.
    /// </summary>
    public bool IsEnterpriseAttestationCapable => EnterpriseAttestationProvisioning is not null;

    /// <summary>
    /// The maximum number of fingerprint templates <see cref="BioEnrollmentTemplatesByTemplateId"/> can
    /// hold at once, fixed for the simulator's lifetime — single-sourced for BOTH <c>enrollBegin</c>'s
    /// own storage-space check (CTAP 2.3 §6.7.4, snapshot line 6711: "If there is no space available, the
    /// authenticator returns CTAP2_ERR_FP_DATABASE_FULL") and test math, mirroring
    /// <see cref="MaxRpIdsForSetMinPinLengthCapacity"/>'s own single-sourced-getter shape. A determinism
    /// choice (D4), not a spec-mandated number — the spec only requires SOME finite capacity to exist.
    /// </summary>
    public static int MaxEnrolledTemplatesCapacity => 8;

    /// <summary>
    /// The maximum size, in bytes, of the serialized large-blob array this authenticator model can
    /// store (the <c>maxSerializedLargeBlobArray</c> getInfo member, CTAP 2.3 §6.10.1, line 4429; MUST
    /// be ≥ 1024, line 4435). Single-sourced for BOTH that emission and the <c>set</c> algorithm's own
    /// <c>length &gt; 1024 AND exceeds capacity → CTAP2_ERR_LARGE_BLOB_STORAGE_FULL</c> check (line
    /// 7620). 4096 is chosen — not spec-mandated beyond the 1024 floor — so a full-capacity write spans
    /// AT LEAST five <see cref="MaxFragmentLength"/>-sized fragments, keeping the multi-fragment write
    /// state machine genuinely exercised by a capstone that only writes a handful of fragments.
    /// </summary>
    public static int MaxSerializedLargeBlobArrayCapacity => 4096;

    /// <summary>
    /// The per-authenticator constant <c>maxFragmentLength</c> (CTAP 2.3 §6.10.2, line 7585): "the value
    /// of <c>maxMsgSize</c> ... minus 64 ... If no <c>maxMsgSize</c> is given in the
    /// authenticatorGetInfo response then it defaults to 1024, leaving <c>maxFragmentLength</c> to
    /// default to 960." This authenticator never advertises <c>maxMsgSize</c> (<c>0x05</c>) in
    /// <c>authenticatorGetInfo</c> — doing so would couple NFC transport framing claims this profile
    /// does not make (the wave-0 audit's DECLINED disposition) — so the spec's own default rule pins
    /// this value to 960, documented here as a named constant rather than an inline literal.
    /// Single-sourced for BOTH the <c>get</c> length check (line 7603) and the <c>set</c> fragment
    /// length check (line 7613): 960 is legal without advertising anything.
    /// </summary>
    public static int MaxFragmentLength => 960;

    /// <summary>
    /// The initial serialized large-blob array (CTAP 2.3 §6.10, line 7540): "an empty CBOR array
    /// (<c>80</c>) followed by <c>LEFT(SHA-256(h'80'), 16)</c>" — a byte-exact 17-byte known-answer
    /// constant, hand-verified against the snapshot literal <c>h'8076be8b528d0075f7aae98d6fa57a6d3c'</c>
    /// (line 7540). This is the value of the serialized large-blob array on a fresh authenticator
    /// (seeded by <see cref="Initial"/>) AND immediately after <see cref="FactoryReset"/> restores it
    /// (line 7705's MUST); the minimum legal length of a serialized large-blob array is these same 17
    /// bytes (line 7541's note), which is why <c>set</c>'s own <c>length &lt; 17 → InvalidParameter</c>
    /// check exists.
    /// </summary>
    public static ReadOnlySpan<byte> InitialSerializedLargeBlobArray =>
        [0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c];


    /// <summary>
    /// Creates the initial state of a freshly constructed simulator: no command processed yet, empty
    /// credential store, no remembered <c>authenticatorGetAssertion</c> sequence, a fresh per-protocol
    /// key-agreement key pair and <c>pinUvAuthToken</c> for each of PIN/UV auth protocol one and two, no
    /// PIN set, and both retry counters seeded to <see cref="MaxPinRetries"/>.
    /// </summary>
    /// <param name="aaguid">The authenticator's claimed AAGUID.</param>
    /// <param name="poweredOnAt">
    /// The instant this simulator is considered powered on — construction IS power-on. Seeds
    /// <see cref="PoweredOnAt"/>, the value <c>authenticatorReset</c>'s 10-second power-up window (CTAP
    /// 2.3 §6.6, lines 6365-6366) measures elapsed time from.
    /// </param>
    /// <param name="supportedExtensions">
    /// The extension identifiers this authenticator model advertises. Omitted or explicitly
    /// <see langword="null"/> resolves to <see cref="DefaultSupportedExtensions"/> — the real,
    /// unconditionally advertised list — rather than omitting the <c>extensions</c> member entirely;
    /// the parameter itself stays available so a wire-shape test can supply a different advertised list.
    /// </param>
    /// <param name="residentCredentialCapacity">
    /// The maximum number of resident credentials this authenticator can hold at once.
    /// </param>
    /// <param name="keyAgreementPool">
    /// The memory pool the two PIN/UV auth protocol key-agreement key pairs, their two
    /// <c>pinUvAuthToken</c>s, and the seeded <see cref="SerializedLargeBlobArray"/> are minted from — a
    /// construction-time event, independent of any later command's own pool. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <param name="enterpriseAttestationProvisioning">
    /// The vendor-burned-in enterprise attestation material (R1), or <see langword="null"/> (the
    /// default) for a non-capable authenticator — the default profile's <c>ep</c> stays absent,
    /// <c>authenticatorConfigCommands</c> stays <c>[2, 3]</c>, and <c>enableEnterpriseAttestation</c>
    /// stays step-2-rejected, matching CTAP 2.3 §7.1's own vendor-provisioning reality (snapshot line
    /// 8251) that most authenticators are never enterprise attestation capable at all.
    /// </param>
    /// <param name="firmwareVersion">
    /// The authenticator model's firmware version, seeded once — device identity, the same
    /// fixed-for-the-simulator's-lifetime posture as <paramref name="aaguid"/>. Defaults to <c>1</c>.
    /// </param>
    /// <returns>The initial state.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both CtapPinUvAuthKeyAgreementKeyPair instances, both CtapPinUvAuthTokenState instances, and the seeded PooledMemory transfers to the returned CtapAuthenticatorState, which CtapAuthenticatorSimulator.Dispose disposes as part of its dispose walk.")]
    public static CtapAuthenticatorState Initial(
        Guid aaguid, DateTimeOffset poweredOnAt, IReadOnlyList<string>? supportedExtensions = null, int residentCredentialCapacity = 8, MemoryPool<byte>? keyAgreementPool = null,
        CtapEnterpriseAttestationProvisioning? enterpriseAttestationProvisioning = null, int firmwareVersion = 1)
    {
        MemoryPool<byte> resolvedKeyAgreementPool = keyAgreementPool ?? BaseMemoryPool.Shared;

        (CtapPinUvAuthKeyAgreementKeyPair protocolOneKeyPair, CtapPinUvAuthKeyAgreementKeyPair protocolTwoKeyPair) =
            MintKeyAgreementKeyPairs(resolvedKeyAgreementPool);

        (CtapPinUvAuthTokenState protocolOneToken, CtapPinUvAuthTokenState protocolTwoToken) = MintTokens(resolvedKeyAgreementPool, protocolOneKeyPair, protocolTwoKeyPair);

        return new(
            aaguid,
            supportedExtensions ?? DefaultSupportedExtensions,
            NullAction.Instance,
            null,
            ImmutableDictionary<string, CtapCredentialRecord>.Empty,
            residentCredentialCapacity,
            PoweredOnAt: poweredOnAt,
            NextCredentialSequence: 0,
            RememberedGetAssertion: null,
            RememberedEnumerateRps: null,
            RememberedEnumerateCredentials: null,
            ProtocolOneKeyAgreementKeyPair: protocolOneKeyPair,
            ProtocolTwoKeyAgreementKeyPair: protocolTwoKeyPair,
            ProtocolOneToken: protocolOneToken,
            ProtocolTwoToken: protocolTwoToken,
            CurrentStoredPin: null,
            PinCodePointLength: 0,
            PinRetries: MaxPinRetries,
            UvRetries: MaxUvRetries,
            ConsecutivePinMismatches: 0,
            IsPowerCycleRequired: false,
            IsAlwaysUvEnabled: false,
            MinPinCodePointLength: DefaultMinPinCodePointLength,
            IsForcePinChangeRequired: false,
            MinPinLengthRpIds: [],
            BioEnrollmentTemplatesByTemplateId: ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Empty,
            RememberedBioEnrollment: null,
            SerializedLargeBlobArray: PooledMemory.FromBytes(InitialSerializedLargeBlobArray, resolvedKeyAgreementPool, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload),
            RememberedLargeBlobWrite: null,
            EnterpriseAttestationProvisioning: enterpriseAttestationProvisioning,
            IsEnterpriseAttestationEnabled: false,
            PendingUserPresenceWait: null,
            FirmwareVersion: firmwareVersion);
    }


    /// <summary>
    /// Performs a power cycle: restamps <see cref="PoweredOnAt"/> (a power cycle IS "powering up" again,
    /// re-arming <c>authenticatorReset</c>'s 10-second power-up window), mints a fresh key-agreement key
    /// pair and a fresh <c>pinUvAuthToken</c> for both PIN/UV auth protocols (CTAP 2.3 §6.5.5.1's
    /// power-up <c>initialize()</c>, re-run against a simulator that already has PIN/credential state),
    /// disposing the material they replace, clears <see cref="ConsecutivePinMismatches"/> and
    /// <see cref="IsPowerCycleRequired"/>, and discards all FIVE remembered stateful-command sequences
    /// (<see cref="RememberedGetAssertion"/>, <see cref="RememberedEnumerateRps"/>,
    /// <see cref="RememberedEnumerateCredentials"/>, <see cref="RememberedBioEnrollment"/>,
    /// <see cref="RememberedLargeBlobWrite"/>) — CTAP 2.3, section 6, item 1 (line 2869): "The state
    /// SHOULD NOT be maintained across power cycles." R10: <see cref="RememberedGetAssertion"/> discards
    /// on the same basis as the other remembered sequences, a deliberate choice rather than an
    /// incidental one; R7 joins <see cref="RememberedBioEnrollment"/> and <see cref="RememberedLargeBlobWrite"/>
    /// to this same discard set — a pending large-blob write DIES across a power cycle, but the
    /// COMMITTED <see cref="SerializedLargeBlobArray"/> survives (the next bullet). Also discards
    /// <see cref="PendingUserPresenceWait"/> (R2), the SIXTH slot on this same discipline: a parked
    /// user-presence wait cannot survive the fresh <c>pinUvAuthToken</c>/key-agreement material this same
    /// power cycle just minted. Every other member —
    /// the PIN itself, both retry counters, the credential store,
    /// <see cref="BioEnrollmentTemplatesByTemplateId"/>, <see cref="SerializedLargeBlobArray"/>
    /// (CTAP 2.3 §6, line 7539's storage names no power-cycle-clearing obligation of its own), the
    /// AAGUID, <see cref="EnterpriseAttestationProvisioning"/>, <see cref="IsEnterpriseAttestationEnabled"/>
    /// (R3: neither the vendor-burned-in capability nor the enabled feature is named anywhere in CTAP
    /// 2.3's own power-cycle text, section 6 item 1, line 2869), and <see cref="FirmwareVersion"/>
    /// (device identity, the <see cref="Aaguid"/> analogy — absent from the <c>with</c> block below, so
    /// it survives implicitly) — is unaffected, matching
    /// CTAP 2.3's own distinction between a power cycle (recoverable) and an <c>authenticatorReset</c>
    /// (destructive; see <see cref="FactoryReset"/>).
    /// </summary>
    /// <param name="now">
    /// The instant this power cycle occurs — restamps <see cref="PoweredOnAt"/>, since a power cycle IS
    /// "powering up" again (CTAP 2.3 §6.6, lines 6365-6366), re-arming <c>authenticatorReset</c>'s
    /// 10-second power-up window.
    /// </param>
    /// <param name="keyAgreementPool">
    /// The memory pool the refreshed key-agreement key pairs and tokens are minted from. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <returns>The post-power-cycle state.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the four newly minted objects transfers to the returned CtapAuthenticatorState.")]
    public CtapAuthenticatorState PowerCycle(DateTimeOffset now, MemoryPool<byte>? keyAgreementPool = null)
    {
        MemoryPool<byte> resolvedPool = keyAgreementPool ?? BaseMemoryPool.Shared;

        (CtapPinUvAuthKeyAgreementKeyPair freshProtocolOneKeyPair, CtapPinUvAuthKeyAgreementKeyPair freshProtocolTwoKeyPair) =
            MintKeyAgreementKeyPairs(resolvedPool);

        (CtapPinUvAuthTokenState freshProtocolOneToken, CtapPinUvAuthTokenState freshProtocolTwoToken) =
            MintTokens(resolvedPool, freshProtocolOneKeyPair, freshProtocolTwoKeyPair);

        ProtocolOneKeyAgreementKeyPair.Dispose();
        ProtocolTwoKeyAgreementKeyPair.Dispose();
        ProtocolOneToken.Dispose();
        ProtocolTwoToken.Dispose();
        RememberedGetAssertion?.Dispose();
        RememberedBioEnrollment?.Dispose();
        RememberedLargeBlobWrite?.Dispose();
        PendingUserPresenceWait?.Dispose();

        return this with
        {
            PoweredOnAt = now,
            ProtocolOneKeyAgreementKeyPair = freshProtocolOneKeyPair,
            ProtocolTwoKeyAgreementKeyPair = freshProtocolTwoKeyPair,
            ProtocolOneToken = freshProtocolOneToken,
            ProtocolTwoToken = freshProtocolTwoToken,
            ConsecutivePinMismatches = 0,
            IsPowerCycleRequired = false,
            RememberedGetAssertion = null,
            RememberedEnumerateRps = null,
            RememberedEnumerateCredentials = null,
            RememberedBioEnrollment = null,
            RememberedLargeBlobWrite = null,
            PendingUserPresenceWait = null
        };
    }


    /// <summary>
    /// Performs <c>authenticatorReset</c>'s entropy-free factory-default transform (CTAP 2.3 §6.6, lines
    /// 6329-6359: "Resetting the authenticator back to a factory default state is done by performing at
    /// least the following steps"): disposes and empties the credential store — one clearing satisfies
    /// both line 6332 ("invalidates all generated credentials") and line 6334 ("erases all discoverable
    /// credentials") — zeroes <see cref="NextCredentialSequence"/>, disposes and empties
    /// <see cref="BioEnrollmentTemplatesByTemplateId"/> (a documented profile-security posture over
    /// §6.6's own silence on bio enrollment, bio scout Finding 8 — no MUST is claimed; §6.7.1's own
    /// feature-detection text and the <c>uv</c>-honesty argument justify the choice), discards all SIX
    /// remembered stateful-command sequences (joining <see cref="RememberedBioEnrollment"/>,
    /// <see cref="RememberedLargeBlobWrite"/>, and <see cref="PendingUserPresenceWait"/> (R2) to the
    /// existing three), disposes and unsets the stored PIN
    /// (<see cref="CurrentStoredPin"/>/<see cref="PinCodePointLength"/>), restores
    /// <see cref="PinRetries"/> to <see cref="MaxPinRetries"/> and <see cref="UvRetries"/> to
    /// <see cref="MaxUvRetries"/> and <see cref="ConsecutivePinMismatches"/> to 0 (CTAP 2.3, lines
    /// 5076-5078: reset is the PIN lockout's
    /// sole spec-named recovery; lines 5092-5093: one of two named recoveries for the uvRetries lockout),
    /// clears <see cref="IsPowerCycleRequired"/>, reverts <see cref="IsAlwaysUvEnabled"/> to
    /// <see langword="false"/> and <see cref="MinPinCodePointLength"/> to
    /// <see cref="DefaultMinPinCodePointLength"/> (§7.2.3 lines 8318-8323, §7.4.3 lines 8419-8427, and
    /// the <c>minPINLength</c> getInfo member's own line 4465: "On reset, minPINLength reverts to its
    /// original pre-configured value"), clears <see cref="IsForcePinChangeRequired"/> (§7.4.3 line
    /// 8426), and clears <see cref="MinPinLengthRpIds"/> back to empty (§7.4.3 line 8424: "Set the
    /// minPinLengthRPIDs parameter's list to the immutable pre-configured list, if any. Any previously
    /// added RP IDs are removed" — empty here, since this simulator has no pre-configured list).
    /// <c>makeCredUvNotRqd</c> needs no code of its own here: it reverts automatically once
    /// <see cref="IsAlwaysUvEnabled"/> is <see langword="false"/> again, through the same
    /// <c>!IsAlwaysUvEnabled</c> getInfo derivation §7.2.3 line 8321 names. Reverts
    /// <see cref="IsEnterpriseAttestationEnabled"/> to <see langword="false"/> (CTAP 2.3 §7.1.3, lines
    /// 8276-8278: "If an enterprise attestation capable authenticator receives an
    /// <c>authenticatorReset</c> command, it MUST disable the enterprise attestation feature" — the
    /// §6.6 line 6345 cross-reference into §7.1.3) while PRESERVING
    /// <see cref="EnterpriseAttestationProvisioning"/> completely unchanged (line 8256: the vendor's
    /// pre-configured material is "burned into the authenticator" — a reset disables the FEATURE, never
    /// the underlying capability; §7.1.3's own next sentence confirms the feature "may be re-enabled by
    /// invoking the <c>authenticatorConfig</c> command's enable-enterprise-attestation subcommand").
    /// Also disposes the current
    /// <see cref="SerializedLargeBlobArray"/> and restores it to
    /// <see cref="InitialSerializedLargeBlobArray"/> (line 7705's MUST; §6.6's own factory-default bullet,
    /// line 6336: "Resets the serialized large-blob array storage, if any, to the initial serialized
    /// large-blob array value") — the array's initial 17-byte constant is entropy-FREE (a spec literal,
    /// unlike the PIN/UV key material below), so this pure transform restores it DIRECTLY, with no
    /// executor round-trip: the fresh copy is rented from <paramref name="pool"/> (never a hardcoded
    /// <c>.Shared</c>, mirroring <see cref="Initial"/>/<see cref="PowerCycle"/>'s own optional-pool
    /// convention) and needs no crypto backend, no telemetry-bearing hash computation, and no entropy
    /// draw.
    /// </summary>
    /// <param name="pool">
    /// The memory pool the restored <see cref="SerializedLargeBlobArray"/> is rented from. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <remarks>
    /// <para>
    /// Leaves <see cref="Aaguid"/>, <see cref="SupportedExtensions"/>, <see cref="ResidentCredentialCapacity"/>,
    /// <see cref="PoweredOnAt"/>, <see cref="EnterpriseAttestationProvisioning"/>, and
    /// <see cref="FirmwareVersion"/> untouched — identity/personalization/boot facts (and, per
    /// §7.1.3's own line 8256, the vendor's burned-in enterprise attestation material; a firmware
    /// version is device identity, not clientPIN/config/large-blob state) a factory reset does not
    /// clear; <see cref="FirmwareVersion"/> is absent from the <c>with</c> block below, so it survives
    /// implicitly, the same posture as <see cref="Aaguid"/>. A reset is not itself a power-up,
    /// so the power-up window does not re-arm. Leaves both
    /// PIN/UV auth protocols' key-agreement key pairs and <c>pinUvAuthToken</c>s untouched too: those
    /// four fields are non-nullable and their replacement values are minted entropy, which this
    /// entropy-free transform cannot draw (CTAP 2.3 §6, line 2869-ish: the pure automaton draws no
    /// randomness) — <c>CtapAuthenticatorSimulator</c>'s own effectful executor disposes and replaces
    /// them once fresh material has been minted (CTAP 2.3, line 6138: the <c>pinUvAuthToken</c> "is
    /// generated afresh at power-on and reset"). <see cref="SerializedLargeBlobArray"/>'s restoration
    /// contrasts with that four-field carve-out precisely because its replacement value is a FIXED
    /// literal, not minted entropy — no executor round-trip is needed for it.
    /// </para>
    /// <para>
    /// The following §6.6 bullets and cross-section obligations degenerate to a documented no-op in this
    /// profile, none of them modeled as state on this record: the device identifier (line
    /// 6338 — a separate 128-bit value this simulator never models, distinct from <see cref="Aaguid"/>);
    /// credential store state (line 6340); persistent PUAT state (line 6355, §6.5.2.2 lines 5054-5060 —
    /// <c>persistentPinUvAuthToken</c> is structurally absent); long touch for reset (line 6357, §7.7.3
    /// lines 8679-8682 — the feature is unsupported); <c>pinComplexityPolicy</c> (§7.5.3 lines 8472-8478)
    /// — unmodeled (no getInfo member slot exists for it). <c>minPinLengthRPIDs</c> (line 8424) IS
    /// modeled, and is cleared by this method — see the summary above.
    /// </para>
    /// </remarks>
    /// <returns>The post-reset state, with every clientPIN/credential-store/config/large-blob field at its factory value.</returns>
    public CtapAuthenticatorState FactoryReset(MemoryPool<byte>? pool = null)
    {
        MemoryPool<byte> resolvedPool = pool ?? BaseMemoryPool.Shared;

        foreach(CtapCredentialRecord record in CredentialsByCredentialId.Values)
        {
            record.Dispose();
        }

        foreach(CtapBioEnrollmentTemplateRecord template in BioEnrollmentTemplatesByTemplateId.Values)
        {
            template.Dispose();
        }

        CurrentStoredPin?.Dispose();
        RememberedGetAssertion?.Dispose();
        RememberedBioEnrollment?.Dispose();
        RememberedLargeBlobWrite?.Dispose();
        PendingUserPresenceWait?.Dispose();
        SerializedLargeBlobArray.Dispose();

        return this with
        {
            CredentialsByCredentialId = ImmutableDictionary<string, CtapCredentialRecord>.Empty,
            NextCredentialSequence = 0,
            RememberedGetAssertion = null,
            RememberedEnumerateRps = null,
            RememberedEnumerateCredentials = null,
            RememberedLargeBlobWrite = null,
            PendingUserPresenceWait = null,
            CurrentStoredPin = null,
            PinCodePointLength = 0,
            PinRetries = MaxPinRetries,
            UvRetries = MaxUvRetries,
            ConsecutivePinMismatches = 0,
            IsPowerCycleRequired = false,
            IsAlwaysUvEnabled = false,
            MinPinCodePointLength = DefaultMinPinCodePointLength,
            IsForcePinChangeRequired = false,
            MinPinLengthRpIds = [],
            IsEnterpriseAttestationEnabled = false,
            BioEnrollmentTemplatesByTemplateId = ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Empty,
            RememberedBioEnrollment = null,
            SerializedLargeBlobArray = PooledMemory.FromBytes(InitialSerializedLargeBlobArray, resolvedPool, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload)
        };
    }


    /// <summary>
    /// Mints a fresh P-256 key-agreement key pair for each PIN/UV auth protocol, disposing protocol
    /// one's pair if protocol two's mint throws so neither leaks before either is handed to a
    /// <see cref="CtapAuthenticatorState"/> for the simulator's dispose walk.
    /// </summary>
    /// <param name="pool">The memory pool both key pairs are minted from.</param>
    /// <returns>Protocol one's and protocol two's freshly minted key-agreement key pairs.</returns>
    private static (CtapPinUvAuthKeyAgreementKeyPair ProtocolOne, CtapPinUvAuthKeyAgreementKeyPair ProtocolTwo) MintKeyAgreementKeyPairs(MemoryPool<byte> pool)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> protocolOneKeys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, pool);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> protocolTwoKeys;
        try
        {
            protocolTwoKeys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, pool);
        }
        catch
        {
            //Protocol one's key pair would otherwise leak if protocol two's mint fails: this method has
            //not yet handed either pair to a CtapAuthenticatorState for CtapAuthenticatorSimulator.Dispose
            //to walk.
            protocolOneKeys.PublicKey.Dispose();
            protocolOneKeys.PrivateKey.Dispose();

            throw;
        }

        return (
            new CtapPinUvAuthKeyAgreementKeyPair(protocolOneKeys.PublicKey, protocolOneKeys.PrivateKey),
            new CtapPinUvAuthKeyAgreementKeyPair(protocolTwoKeys.PublicKey, protocolTwoKeys.PrivateKey));
    }


    /// <summary>
    /// Mints a fresh <c>pinUvAuthToken</c> lifecycle state for each PIN/UV auth protocol, disposing
    /// <paramref name="protocolOneKeyPair"/>/<paramref name="protocolTwoKeyPair"/> (which the caller has
    /// already minted and would otherwise leak) and protocol one's token if a later mint throws.
    /// </summary>
    /// <param name="pool">The memory pool both tokens are minted from.</param>
    /// <param name="protocolOneKeyPair">Protocol one's already-minted key-agreement key pair, disposed on failure.</param>
    /// <param name="protocolTwoKeyPair">Protocol two's already-minted key-agreement key pair, disposed on failure.</param>
    /// <returns>Protocol one's and protocol two's freshly minted token states.</returns>
    private static (CtapPinUvAuthTokenState ProtocolOne, CtapPinUvAuthTokenState ProtocolTwo) MintTokens(
        MemoryPool<byte> pool, CtapPinUvAuthKeyAgreementKeyPair protocolOneKeyPair, CtapPinUvAuthKeyAgreementKeyPair protocolTwoKeyPair)
    {
        CtapPinUvAuthTokenState protocolOneToken;
        try
        {
            protocolOneToken = CtapPinUvAuthTokenState.Initial(pool);
        }
        catch
        {
            protocolOneKeyPair.Dispose();
            protocolTwoKeyPair.Dispose();

            throw;
        }

        CtapPinUvAuthTokenState protocolTwoToken;
        try
        {
            protocolTwoToken = CtapPinUvAuthTokenState.Initial(pool);
        }
        catch
        {
            protocolOneToken.Dispose();
            protocolOneKeyPair.Dispose();
            protocolTwoKeyPair.Dispose();

            throw;
        }

        return (protocolOneToken, protocolTwoToken);
    }
}
