using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>AuthenticatorStatus</c> enumeration values a FIDO Metadata Service BLOB payload entry's
/// <c>statusReports</c> carry, plus the default trust-terminating subset a caller's status
/// evaluation policy applies unless overridden.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-authnr-stat">FIDO
/// Metadata Service v3.1, section 3.1.4: AuthenticatorStatus enum</see> defines all nineteen values
/// below, verified against the specification's own IDL block rather than assumed from the RD or CR.
/// </remarks>
public static class WellKnownAuthenticatorStatuses
{
    /// <summary>The UTF-8 source literal of <see cref="NotFidoCertified"/>.</summary>
    public static ReadOnlySpan<byte> NotFidoCertifiedUtf8 => "NOT_FIDO_CERTIFIED"u8;

    /// <summary>
    /// The authenticator is not FIDO certified.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>. No RP
    /// instruction is given for this value.
    /// </remarks>
    public static readonly string NotFidoCertified = Utf8Constants.ToInternedString(NotFidoCertifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertified"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedUtf8 => "FIDO_CERTIFIED"u8;

    /// <summary>
    /// The authenticator has passed FIDO functional certification (the certification scheme this
    /// tier belongs to is phased out in favor of <see cref="FidoCertifiedL1"/>).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertified = Utf8Constants.ToInternedString(FidoCertifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserVerificationBypass"/>.</summary>
    public static ReadOnlySpan<byte> UserVerificationBypassUtf8 => "USER_VERIFICATION_BYPASS"u8;

    /// <summary>
    /// Malware is able to bypass the authenticator's user verification, so the authenticator could
    /// be used without the user's consent or knowledge.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-sec-not-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.2: Security Notification Statuses</see>. The enum entry
    /// itself carries no RFC2119 RP instruction — the actionable guidance is the section 3.1.3
    /// StatusReport note's lower-case "recommended" increased-risk framing — but this is one of the
    /// values <see cref="DefaultTrustTerminating"/> treats as trust-terminating by default, a secure
    /// default this specification authorizes without itself requiring it.
    /// </remarks>
    public static readonly string UserVerificationBypass = Utf8Constants.ToInternedString(UserVerificationBypassUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AttestationKeyCompromise"/>.</summary>
    public static ReadOnlySpan<byte> AttestationKeyCompromiseUtf8 => "ATTESTATION_KEY_COMPROMISE"u8;

    /// <summary>
    /// An attestation key for this authenticator is known to be compromised.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-sec-not-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.2: Security Notification Statuses</see>: "The relying
    /// party SHOULD check the certificate field and use it to identify the compromised
    /// authenticator batch. If neither the batchCertificate nor the certificate field are set, the
    /// relying party should reject all new registrations of the compromised authenticator."
    /// </remarks>
    public static readonly string AttestationKeyCompromise = Utf8Constants.ToInternedString(AttestationKeyCompromiseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserKeyRemoteCompromise"/>.</summary>
    public static ReadOnlySpan<byte> UserKeyRemoteCompromiseUtf8 => "USER_KEY_REMOTE_COMPROMISE"u8;

    /// <summary>
    /// The authenticator has identified weaknesses that allow registered keys to be compromised
    /// remotely.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-sec-not-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.2: Security Notification Statuses</see>: "This
    /// authenticator has identified weaknesses that allow registered keys to be compromised and
    /// should not be trusted."
    /// </remarks>
    public static readonly string UserKeyRemoteCompromise = Utf8Constants.ToInternedString(UserKeyRemoteCompromiseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserKeyPhysicalCompromise"/>.</summary>
    public static ReadOnlySpan<byte> UserKeyPhysicalCompromiseUtf8 => "USER_KEY_PHYSICAL_COMPROMISE"u8;

    /// <summary>
    /// The authenticator has known weaknesses in its key protection mechanism(s) that allow user
    /// keys to be extracted by an adversary in physical possession of the device.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-sec-not-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.2: Security Notification Statuses</see>. No explicit
    /// SHOULD/MUST is given for this value either, but it is one of the values
    /// <see cref="DefaultTrustTerminating"/> treats as trust-terminating by default.
    /// </remarks>
    public static readonly string UserKeyPhysicalCompromise = Utf8Constants.ToInternedString(UserKeyPhysicalCompromiseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UpdateAvailable"/>.</summary>
    public static ReadOnlySpan<byte> UpdateAvailableUtf8 => "UPDATE_AVAILABLE"u8;

    /// <summary>
    /// A software or firmware update is available for the device.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-info-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.3: Info Statuses</see>: "The Relying party MUST reject
    /// the Metadata Statement if the authenticatorVersion has not increased" — a self-consistency
    /// check against the metadata statement's own <c>authenticatorVersion</c> field, which this
    /// library's typed payload surface does not currently parse (see
    /// <see cref="MetadataBlobPayloadEntry.RawMetadataStatement"/>), so this value is exposed as
    /// data only and is NOT in <see cref="DefaultTrustTerminating"/> — it is not itself an
    /// authenticator-trust-terminating status.
    /// </remarks>
    public static readonly string UpdateAvailable = Utf8Constants.ToInternedString(UpdateAvailableUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Revoked"/>.</summary>
    public static ReadOnlySpan<byte> RevokedUtf8 => "REVOKED"u8;

    /// <summary>
    /// The FIDO Alliance has determined that this authenticator should not be trusted for any
    /// reason.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>: "Relying
    /// parties SHOULD reject any future registration of this authenticator model." The SHOULD, not
    /// MUST, is the specification's own wording; this library's default status policy raises it to
    /// a hard rejection as a deliberate, documented secure default (see
    /// <see cref="DefaultTrustTerminating"/>), not because the specification itself mandates it.
    /// </remarks>
    public static readonly string Revoked = Utf8Constants.ToInternedString(RevokedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SelfAssertionSubmitted"/>.</summary>
    public static ReadOnlySpan<byte> SelfAssertionSubmittedUtf8 => "SELF_ASSERTION_SUBMITTED"u8;

    /// <summary>
    /// The authenticator vendor has completed and submitted the self-certification checklist to the
    /// FIDO Alliance.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>. No RP
    /// instruction is given for this value.
    /// </remarks>
    public static readonly string SelfAssertionSubmitted = Utf8Constants.ToInternedString(SelfAssertionSubmittedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL1"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL1Utf8 => "FIDO_CERTIFIED_L1"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 1.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL1 = Utf8Constants.ToInternedString(FidoCertifiedL1Utf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL1Plus"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL1PlusUtf8 => "FIDO_CERTIFIED_L1plus"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 1+.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL1Plus = Utf8Constants.ToInternedString(FidoCertifiedL1PlusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL2"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL2Utf8 => "FIDO_CERTIFIED_L2"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 2.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL2 = Utf8Constants.ToInternedString(FidoCertifiedL2Utf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL2Plus"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL2PlusUtf8 => "FIDO_CERTIFIED_L2plus"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 2+.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL2Plus = Utf8Constants.ToInternedString(FidoCertifiedL2PlusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL3"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL3Utf8 => "FIDO_CERTIFIED_L3"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 3.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL3 = Utf8Constants.ToInternedString(FidoCertifiedL3Utf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoCertifiedL3Plus"/>.</summary>
    public static ReadOnlySpan<byte> FidoCertifiedL3PlusUtf8 => "FIDO_CERTIFIED_L3plus"u8;

    /// <summary>The authenticator has passed FIDO Authenticator certification at level 3+.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string FidoCertifiedL3Plus = Utf8Constants.ToInternedString(FidoCertifiedL3PlusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Fips140CertifiedL1"/>.</summary>
    public static ReadOnlySpan<byte> Fips140CertifiedL1Utf8 => "FIPS140_CERTIFIED_L1"u8;

    /// <summary>The authenticator has passed FIPS 140 certification at overall level 1.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string Fips140CertifiedL1 = Utf8Constants.ToInternedString(Fips140CertifiedL1Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fips140CertifiedL2"/>.</summary>
    public static ReadOnlySpan<byte> Fips140CertifiedL2Utf8 => "FIPS140_CERTIFIED_L2"u8;

    /// <summary>The authenticator has passed FIPS 140 certification at overall level 2.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string Fips140CertifiedL2 = Utf8Constants.ToInternedString(Fips140CertifiedL2Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fips140CertifiedL3"/>.</summary>
    public static ReadOnlySpan<byte> Fips140CertifiedL3Utf8 => "FIPS140_CERTIFIED_L3"u8;

    /// <summary>The authenticator has passed FIPS 140 certification at overall level 3.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string Fips140CertifiedL3 = Utf8Constants.ToInternedString(Fips140CertifiedL3Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Fips140CertifiedL4"/>.</summary>
    public static ReadOnlySpan<byte> Fips140CertifiedL4Utf8 => "FIPS140_CERTIFIED_L4"u8;

    /// <summary>The authenticator has passed FIPS 140 certification at overall level 4.</summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">FIDO
    /// Metadata Service v3.1, section 3.1.4.1: Certification Related Statuses</see>.
    /// </remarks>
    public static readonly string Fips140CertifiedL4 = Utf8Constants.ToInternedString(Fips140CertifiedL4Utf8);


    /// <summary>
    /// The default trust-terminating status subset a caller's
    /// <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/> call applies unless it supplies its
    /// own set: <see cref="Revoked"/>, <see cref="UserVerificationBypass"/>,
    /// <see cref="AttestationKeyCompromise"/>, <see cref="UserKeyRemoteCompromise"/>, and
    /// <see cref="UserKeyPhysicalCompromise"/>.
    /// </summary>
    /// <remarks>
    /// This is a deliberately stricter-than-specified secure default, not a restatement of a
    /// specification MUST: only <see cref="Revoked"/> carries an explicit (SHOULD-level) RP
    /// instruction to reject in
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-cert-stats">section
    /// 3.1.4.1</see>, and <see cref="UpdateAvailable"/> carries the only unconditional MUST in the
    /// enumeration's own section — but that MUST binds a metadata-statement self-consistency check
    /// (see <see cref="UpdateAvailable"/>'s remarks), not authenticator trust, so it is deliberately
    /// excluded here. The specification itself states "it is up to the relying party to specify
    /// behavior for authenticators with status reports that indicate a lack of certification, or
    /// known security issues" (section 3.2, item 8.ii) — this default is the policy choice this
    /// library makes on that open question; a caller overrides it via
    /// <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/>'s <c>trustTerminating</c> parameter.
    /// </remarks>
    public static IReadOnlySet<string> DefaultTrustTerminating { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        Revoked,
        UserVerificationBypass,
        AttestationKeyCompromise,
        UserKeyRemoteCompromise,
        UserKeyPhysicalCompromise
    };


    /// <summary>Determines whether <paramref name="status"/> is <see cref="NotFidoCertified"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="NotFidoCertified"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsNotFidoCertified(string status) => Equals(NotFidoCertified, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertified"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertified"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertified(string status) => Equals(FidoCertified, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="UserVerificationBypass"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="UserVerificationBypass"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserVerificationBypass(string status) => Equals(UserVerificationBypass, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="AttestationKeyCompromise"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="AttestationKeyCompromise"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsAttestationKeyCompromise(string status) => Equals(AttestationKeyCompromise, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="UserKeyRemoteCompromise"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="UserKeyRemoteCompromise"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserKeyRemoteCompromise(string status) => Equals(UserKeyRemoteCompromise, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="UserKeyPhysicalCompromise"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="UserKeyPhysicalCompromise"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserKeyPhysicalCompromise(string status) => Equals(UserKeyPhysicalCompromise, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="UpdateAvailable"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="UpdateAvailable"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUpdateAvailable(string status) => Equals(UpdateAvailable, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="Revoked"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="Revoked"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsRevoked(string status) => Equals(Revoked, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="SelfAssertionSubmitted"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="SelfAssertionSubmitted"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsSelfAssertionSubmitted(string status) => Equals(SelfAssertionSubmitted, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL1"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL1"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL1(string status) => Equals(FidoCertifiedL1, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL1Plus"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL1Plus"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL1Plus(string status) => Equals(FidoCertifiedL1Plus, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL2"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL2"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL2(string status) => Equals(FidoCertifiedL2, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL2Plus"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL2Plus"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL2Plus(string status) => Equals(FidoCertifiedL2Plus, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL3"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL3"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL3(string status) => Equals(FidoCertifiedL3, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="FidoCertifiedL3Plus"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="FidoCertifiedL3Plus"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFidoCertifiedL3Plus(string status) => Equals(FidoCertifiedL3Plus, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="Fips140CertifiedL1"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="Fips140CertifiedL1"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFips140CertifiedL1(string status) => Equals(Fips140CertifiedL1, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="Fips140CertifiedL2"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="Fips140CertifiedL2"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFips140CertifiedL2(string status) => Equals(Fips140CertifiedL2, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="Fips140CertifiedL3"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="Fips140CertifiedL3"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFips140CertifiedL3(string status) => Equals(Fips140CertifiedL3, status);

    /// <summary>Determines whether <paramref name="status"/> is <see cref="Fips140CertifiedL4"/>.</summary>
    /// <param name="status">The <c>AuthenticatorStatus</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <see cref="Fips140CertifiedL4"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsFips140CertifiedL4(string status) => Equals(Fips140CertifiedL4, status);


    /// <summary>
    /// Returns a value that indicates if the authenticator statuses are the same.
    /// </summary>
    /// <param name="statusA">The first status to compare.</param>
    /// <param name="statusB">The second status to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="statusA"/> and <paramref name="statusB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string statusA, string statusB)
    {
        return object.ReferenceEquals(statusA, statusB) || StringComparer.Ordinal.Equals(statusA, statusB);
    }
}
