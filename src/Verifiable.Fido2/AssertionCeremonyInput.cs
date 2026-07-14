using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// The surface-level fields a <see cref="Fido2AssertionChecks"/> rule compares, refined from a
/// verifier-parsed WebAuthn authentication ceremony response.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>.
/// </para>
/// <para>
/// This record carries only fields already derived upstream (rpIdHash, the stored credential
/// record's counters and backup flags) or copied verbatim from the wire (<see cref="ClientData"/>,
/// <see cref="AuthenticatorData"/>). The rules in <see cref="Fido2AssertionChecks"/> compare
/// these fields; deriving them — hashing the RP ID, computing the client data hash, verifying the
/// assertion signature itself, loading the stored credential record — is ceremony orchestration
/// and happens outside this rule list.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This record owns <see cref="AuthenticatorData"/>,
/// <see cref="ExpectedRpIdHash"/>, <see cref="CredentialId"/>, every entry of
/// <see cref="AllowedCredentialIds"/>, <see cref="ResponseUserHandle"/>,
/// <see cref="StoredUserHandle"/>, and <see cref="ExpectedAppIdHash"/> — disposing it disposes all
/// of them. The whole-ceremony
/// scope is the natural single-owner boundary: nothing outside this record needs any of these
/// carriers once <see cref="Fido2AssertionVerifier.VerifyAsync"/> returns, so a caller that
/// constructs one instance and disposes it when done never has to track the carriers
/// individually. <see cref="Fido2AssertionVerifier"/> itself only borrows this record — it does
/// not dispose it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AssertionCeremonyInput: IDisposable
{
    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>
    /// The parsed <c>CollectedClientData</c> for the ceremony.
    /// </summary>
    public required ClientData ClientData { get; init; }

    /// <summary>
    /// The parsed <c>authData</c> structure for the ceremony. Owned by this record (see the
    /// type-level remarks on ownership).
    /// </summary>
    public required AuthenticatorData AuthenticatorData { get; init; }

    /// <summary>
    /// The base64url-encoded challenge exactly as issued to the client, for ordinal comparison
    /// against <see cref="ClientData.Challenge"/>.
    /// </summary>
    public required string ExpectedChallenge { get; init; }

    /// <summary>
    /// The set of origins the relying party accepts for this ceremony.
    /// </summary>
    public required IReadOnlySet<string> ExpectedOrigins { get; init; }

    /// <summary>
    /// The SHA-256 hash of the relying party ID, computed upstream. Compared against
    /// <see cref="Fido2.AuthenticatorData.RpIdHash"/> with a fixed-time comparison. Owned by this
    /// record (see the type-level remarks on ownership).
    /// </summary>
    public required DigestValue ExpectedRpIdHash { get; init; }

    /// <summary>
    /// Whether the relying party accepts a cross-origin ceremony. Defaults to
    /// <see langword="false"/> — a secure default, since accepting cross-origin ceremonies widens
    /// the set of embedding contexts that can complete an authentication for this relying party.
    /// </summary>
    public bool AllowCrossOrigin { get; init; }

    /// <summary>
    /// The set of top-level origins the relying party expects to be sub-framed within, when it
    /// permits cross-origin iframe ceremonies. <see langword="null"/> when the relying party does
    /// not expect any top-level framing.
    /// </summary>
    public IReadOnlySet<string>? ExpectedTopOrigins { get; init; }

    /// <summary>
    /// The relying party's user-verification policy for this ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">W3C Web
    /// Authentication Level 3, section 5.8.6: User Verification Requirement Enumeration</see>.
    /// <see cref="Fido2AssertionChecks.CheckAssertionUserVerified"/> fails the ceremony on a clear
    /// <c>UV</c> bit only under <see cref="UserVerificationRequirement.Required"/>; the other two
    /// values always succeed and record the observed <c>UV</c> state in the claim's
    /// <see cref="Verifiable.Core.Assessment.Claim.Context"/> via <see cref="UserVerificationClaimContext"/>.
    /// </remarks>
    public required UserVerificationRequirement UserVerification { get; init; }

    /// <summary>
    /// The credential identifiers the relying party's <c>allowCredentials</c> listed, or
    /// <see langword="null"/> when no allowlist was supplied — the discoverable-credential path,
    /// where any registered credential the authenticator selected is acceptable. Every entry is
    /// owned by this record (see the type-level remarks on ownership).
    /// </summary>
    public IReadOnlyList<CredentialId>? AllowedCredentialIds { get; init; }

    /// <summary>
    /// The credential identifier asserted by the authenticator for this ceremony, compared
    /// against <see cref="AllowedCredentialIds"/> when an allowlist is present. Owned by this
    /// record when present (see the type-level remarks on ownership).
    /// </summary>
    public CredentialId? CredentialId { get; init; }

    /// <summary>
    /// The signature counter value stored for this credential from the previous ceremony,
    /// compared against <see cref="Fido2.AuthenticatorData.SignCount"/>.
    /// </summary>
    public required uint StoredSignCount { get; init; }

    /// <summary>
    /// The stored credential record's <c>uvInitialized</c> value from before this ceremony.
    /// Required — unlike <see cref="StoredBackupEligible"/>/<see cref="StoredBackupState"/>, which
    /// model "the relying party does not track this", every stored credential record always
    /// carries a <c>uvInitialized</c> value (it is a REQUIRED credential-record item, not OPTIONAL).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 24's
    /// "update credentialRecord" step. Compared against the current <c>UV</c> flag by
    /// <see cref="Fido2AssertionChecks.CheckAssertionUvInitializedUpgrade"/>.
    /// </remarks>
    public required bool StoredUvInitialized { get; init; }

    /// <summary>
    /// The stored credential record's backup eligibility, or <see langword="null"/> when the
    /// relying party does not track backup eligibility for this credential.
    /// </summary>
    public bool? StoredBackupEligible { get; init; }

    /// <summary>
    /// The stored credential record's backup state, or <see langword="null"/> when the relying
    /// party does not track backup state for this credential.
    /// </summary>
    public bool? StoredBackupState { get; init; }

    /// <summary>
    /// The <c>response.userHandle</c> the authenticator returned for this assertion, or
    /// <see langword="null"/> when the wire response omitted it. Owned by this record when
    /// present (see the type-level remarks on ownership).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 6.
    /// </remarks>
    public UserHandle? ResponseUserHandle { get; init; }

    /// <summary>
    /// The relying party's stored user handle for the account the asserted credential belongs
    /// to, or <see langword="null"/> when no such record was looked up. Owned by this record
    /// when present (see the type-level remarks on ownership).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web
    /// Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 6.
    /// </remarks>
    public UserHandle? StoredUserHandle { get; init; }

    /// <summary>
    /// The decoded client extension outputs from <c>clientExtensionResults</c>, one entry per
    /// extension identifier present, or <see langword="null"/>/empty when none were requested or
    /// none were honored. Computed upstream — typically via a <c>clientExtensionResults</c> JSON
    /// reader in the serialization layer above this library — the same way
    /// <see cref="ExpectedRpIdHash"/> is computed upstream rather than derived by a rule.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level
    /// 3, section 9: WebAuthn Extensions</see>.
    /// </remarks>
    public IReadOnlyList<Fido2ExtensionOutput>? ClientExtensionOutputs { get; init; }

    /// <summary>
    /// The decoded authenticator extension outputs from <c>authData</c>'s <c>extensions</c> CBOR
    /// map, one entry per extension identifier present, or <see langword="null"/>/empty when none
    /// were requested or none were honored. Computed upstream, the same way
    /// <see cref="ClientExtensionOutputs"/> is.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level
    /// 3, section 9: WebAuthn Extensions</see>.
    /// </remarks>
    public IReadOnlyList<Fido2ExtensionOutput>? AuthenticatorExtensionOutputs { get; init; }

    /// <summary>
    /// Selects the processor for a given extension identifier, or <see langword="null"/> when the
    /// relying party has registered no extension processors at all — the default, matching
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9</see>'s
    /// OPTIONAL-for-everyone framing.
    /// </summary>
    public SelectExtensionOutputProcessorDelegate? ExtensionOutputProcessor { get; init; }

    /// <summary>
    /// Whether an extension output present on the wire with no registered processor fails
    /// <see cref="Fido2ClaimIds.Fido2AssertionExtensionOutputs"/>. Defaults to
    /// <see langword="false"/>: <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section
    /// 9</see>'s "Relying Parties MUST be prepared to handle cases where some or all of those
    /// extensions are ignored" makes silently ignoring an unrecognized output the conformant
    /// default; a relying party that wants strict enforcement opts in.
    /// </summary>
    public bool RejectUnregisteredExtensionOutputs { get; init; }

    /// <summary>
    /// The memory pool a registered <see cref="ExtensionOutputProcessDelegate"/> receives on its
    /// <see cref="ExtensionOutputProcessingRequest"/> for working-buffer allocation. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/>, the library-wide default pool, so a relying party
    /// only supplies one to route processor allocations through its own pool.
    /// </summary>
    public MemoryPool<byte> ExtensionProcessingPool { get; init; } = BaseMemoryPool.Shared;

    /// <summary>
    /// The decoded <c>appid</c> client extension output boolean, or <see langword="false"/> when
    /// the extension was not used. Computed upstream from <c>clientExtensionResults</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">W3C Web Authentication
    /// Level 3, section 10.1.1: FIDO AppID Extension (appid)</see>: "If true, the AppID was used
    /// and thus, when verifying the assertion, the Relying Party MUST expect the
    /// <c>rpIdHash</c> to be the hash of the AppID, not the RP ID." Consumed by
    /// <see cref="Fido2AssertionChecks.CheckAssertionRpIdHash"/>, which stays a pure field
    /// comparison: it selects between <see cref="ExpectedRpIdHash"/> and
    /// <see cref="ExpectedAppIdHash"/> rather than deriving the AppID hash itself.
    /// </remarks>
    public bool AppIdExtensionOutput { get; init; }

    /// <summary>
    /// The SHA-256 hash of the relying party's legacy FIDO AppID, computed upstream, or
    /// <see langword="null"/> when the relying party has not configured one. Compared against
    /// <see cref="Fido2.AuthenticatorData.RpIdHash"/> in place of <see cref="ExpectedRpIdHash"/>
    /// when <see cref="AppIdExtensionOutput"/> is <see langword="true"/>. Owned by this record
    /// when present (see the type-level remarks on ownership).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">W3C Web Authentication
    /// Level 3, section 10.1.1: FIDO AppID Extension (appid)</see>.
    /// </remarks>
    public DigestValue? ExpectedAppIdHash { get; init; }


    /// <summary>
    /// A debugger-friendly summary of the challenge (truncated), the accepted origin count, and
    /// whether an <see cref="AllowedCredentialIds"/> allowlist is present — not every field, since
    /// this record carries two dozen-plus members.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            string challengePreview = ExpectedChallenge.Length > 16
                ? string.Concat(ExpectedChallenge.AsSpan(0, 16), "...")
                : ExpectedChallenge;

            string allowlistSummary = AllowedCredentialIds is null
                ? "none"
                : AllowedCredentialIds.Count.ToString(CultureInfo.InvariantCulture);

            return $"AssertionCeremonyInput(ExpectedChallenge={challengePreview}, ExpectedOrigins={ExpectedOrigins.Count}, AllowedCredentialIds={allowlistSummary})";
        }
    }


    /// <summary>
    /// Releases <see cref="AuthenticatorData"/>, <see cref="ExpectedRpIdHash"/>,
    /// <see cref="CredentialId"/>, every entry of <see cref="AllowedCredentialIds"/>,
    /// <see cref="ResponseUserHandle"/>, <see cref="StoredUserHandle"/>, and
    /// <see cref="ExpectedAppIdHash"/>.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        AuthenticatorData.Dispose();
        ExpectedRpIdHash.Dispose();
        CredentialId?.Dispose();
        if(AllowedCredentialIds is not null)
        {
            foreach(CredentialId allowedCredentialId in AllowedCredentialIds)
            {
                allowedCredentialId.Dispose();
            }
        }

        ResponseUserHandle?.Dispose();
        StoredUserHandle?.Dispose();
        ExpectedAppIdHash?.Dispose();

        disposed = true;
    }
}
