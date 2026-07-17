using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The subset of <c>authenticatorGetInfo</c>'s <c>options</c> member this library models.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>. Each member is <see langword="null"/>
/// when the authenticator omits the option ID entirely (the spec's own default then applies);
/// present with an explicit value when the authenticator reports it. <see cref="Ep"/> (<c>ep</c>),
/// <see cref="ResidentKey"/> (<c>rk</c>), <see cref="Uv"/> (<c>uv</c>), <see cref="Platform"/> (<c>plat</c>),
/// <see cref="AlwaysUv"/> (<c>alwaysUv</c>), <see cref="CredMgmt"/> (<c>credMgmt</c>),
/// <see cref="AuthnrCfg"/> (<c>authnrCfg</c>), <see cref="BioEnroll"/> (<c>bioEnroll</c>),
/// <see cref="ClientPin"/> (<c>clientPin</c>), <see cref="LargeBlobs"/> (<c>largeBlobs</c>),
/// <see cref="UvBioEnroll"/> (<c>uvBioEnroll</c>),
/// <see cref="PinUvAuthToken"/> (<c>pinUvAuthToken</c>), <see cref="SetMinPinLength"/>
/// (<c>setMinPINLength</c>), and <see cref="MakeCredUvNotRqd"/> (<c>makeCredUvNotRqd</c>) are modeled,
/// in the record's own declaration order matching the canonical CBOR wire order documented on
/// <see cref="Verifiable.Cbor.Ctap.CtapGetInfoResponseCborWriter"/> — <see cref="Ep"/> declares FIRST
/// because <c>"ep"</c> (length 2, <c>'e'</c> 0x65) sorts before every other modeled option ID
/// including the other length-2 pair <c>"rk"</c>/<c>"uv"</c> (R10; CTAP2 canonical CBOR sorts map keys
/// shorter-first, then bytewise lexically for ties) — the remaining option-ID table
/// entries (<c>uvAcfg</c>, <c>noMcGaPermissionsWithClientPin</c>, and so on) describe built-in
/// user-verification surface this authenticator does not implement.
/// </remarks>
/// <param name="Ep">
/// The <c>ep</c> option (CTAP 2.3 §7.1.1, snapshot lines 4730-4748): Enterprise Attestation feature
/// support, a three-way switch faithfully round-tripped by the codec (R9's getInfo half) — present and
/// <see langword="true"/> ("the authenticator is enterprise attestation capable, and enterprise
/// attestation is enabled", line 4738-4740), present and <see langword="false"/> ("...capable, and
/// enterprise attestation is disabled", line 4741-4743), or absent ("the Enterprise Attestation feature
/// is NOT supported", line 4744-4746, the Default column value). This authenticator sources it as
/// <c>capable ? enabled : null</c> — never a second stored flag (R2).
/// </param>
/// <param name="ResidentKey">
/// The <c>rk</c> option: whether the authenticator can create discoverable credentials. Default
/// <see langword="false"/> when absent.
/// </param>
/// <param name="Uv">
/// The <c>uv</c> option (CTAP 2.3, snapshot lines 4658-4673): whether the authenticator has a built-in
/// user verification method and, if so, whether it is presently configured. This authenticator always
/// reports this option (never absent), from the wave the fingerprint-enrollment surface ships: DERIVED
/// from <c>CtapAuthenticatorState.HasProvisionedBioEnrollments</c> (the SAME single source
/// <see cref="BioEnroll"/> derives from) — <see langword="false"/> with zero enrollments,
/// <see langword="true"/> with at least one.
/// </param>
/// <param name="Platform">
/// The <c>plat</c> option: whether the authenticator is a platform device attached to the client.
/// Default <see langword="false"/> when absent.
/// </param>
/// <param name="AlwaysUv">
/// The <c>alwaysUv</c> option: support for the Always Require User Verification feature. This
/// authenticator always reports this option (never absent): <see langword="false"/> until
/// <c>authenticatorConfig</c>'s <c>toggleAlwaysUv</c> subcommand enables it,
/// <see langword="true"/> afterward.
/// </param>
/// <param name="CredMgmt">
/// The <c>credMgmt</c> option: <c>authenticatorCredentialManagement</c> command support. Reported
/// <see langword="true"/> unconditionally — support is a static capability of this build.
/// </param>
/// <param name="AuthnrCfg">
/// The <c>authnrCfg</c> option: <c>authenticatorConfig</c> command support. Reported
/// <see langword="true"/> unconditionally — support is a static capability of this build.
/// </param>
/// <param name="BioEnroll">
/// The <c>bioEnroll</c> option (CTAP 2.3, snapshot lines 4750-4766): a THREE-valued tri-state richer
/// than any other option this type models — present-true ("supports the commands, and has at least one
/// bio enrollment presently provisioned"), present-false ("supports the commands, and does not yet have
/// any bio enrollments provisioned"), absent ("the commands are NOT supported"). This authenticator
/// always reports this option present, DERIVED from <c>CtapAuthenticatorState.HasProvisionedBioEnrollments</c>
/// (R2's single source, shared with <see cref="Uv"/>) — never absent, since
/// <c>authenticatorBioEnrollment</c> is unconditionally supported from this wave on.
/// </param>
/// <param name="ClientPin">
/// The <c>clientPin</c> option: <see langword="true"/> if a PIN has been set,
/// <see langword="false"/> if the authenticator can accept a PIN but none is set yet, absent if the
/// authenticator cannot accept a PIN at all. CTAP 2.3 §9 item 2: MUST be an explicit boolean (never
/// absent) once <c>versions</c> claims <c>FIDO_2_3</c> and <c>rk</c> is <see langword="true"/>.
/// </param>
/// <param name="LargeBlobs">
/// The <c>largeBlobs</c> option (CTAP 2.3, snapshot lines 4714-4728): whether the authenticator supports
/// the <c>authenticatorLargeBlobs</c> command. BINARY, never tri-state (present-false and absent both
/// mean "not supported", line 4725) — unlike <see cref="BioEnroll"/>'s three-valued shape. This
/// authenticator reports it <see langword="true"/> unconditionally — support is a static capability of
/// this build, and the only meaningful advertisement per the option's own two-valued table. Line 4727's
/// MUST NOT ("MUST NOT be set to <see langword="true"/> if the largeBlob extension is supported
/// instead") is satisfied by construction: this authenticator never advertises the UNRELATED §12.4
/// <c>largeBlob</c> direct extension.
/// </param>
/// <param name="UvBioEnroll">
/// The <c>uvBioEnroll</c> option (CTAP 2.3, snapshot lines 4788-4794): whether
/// <c>getPinUvAuthTokenUsingUvWithPermissions</c> can grant the <c>be</c> permission. This
/// authenticator reports it <see langword="true"/> unconditionally — support is a static capability of
/// this build (0x06's own <c>be</c> gate bullet, snapshot line 6068, is wired). Line 4794's MUST ("only
/// present if <c>bioEnroll</c> is also present") is satisfied since <see cref="BioEnroll"/> is always
/// present too.
/// </param>
/// <param name="PinUvAuthToken">
/// The <c>pinUvAuthToken</c> option: whether <c>authenticatorClientPIN</c>'s token-issuing
/// subcommands are supported. CTAP 2.3 §9 item 5: MUST be <see langword="true"/> once
/// <see cref="ClientPin"/> or <see cref="Uv"/> is present at all.
/// </param>
/// <param name="SetMinPinLength">
/// The <c>setMinPINLength</c> option: support for the <c>authenticatorConfig</c>
/// <c>setMinPINLength</c> subcommand. Reported <see langword="true"/> unconditionally — its own
/// gating condition (the <see cref="ClientPin"/> option being present) is always satisfied once a
/// PIN-capable authenticator has run <c>Initial()</c>.
/// </param>
/// <param name="MakeCredUvNotRqd">
/// The <c>makeCredUvNotRqd</c> option: whether the authenticator allows creation of non-discoverable
/// credentials without requiring some form of user verification, when the platform requests that
/// behaviour. DERIVED as the logical negation of <see cref="AlwaysUv"/> (CTAP 2.3, line 4951: "If the
/// alwaysUv option ID is present and true the authenticator MUST set the value of makeCredUvNotRqd to
/// false") — <see langword="true"/> while <c>alwaysUv</c> is <see langword="false"/>, closing the
/// spec's separate "Authenticators SHOULD include this option with the value true" for that state.
/// </param>
[DebuggerDisplay("CtapGetInfoOptions(ep={Ep}, rk={ResidentKey}, uv={Uv}, plat={Platform}, alwaysUv={AlwaysUv}, credMgmt={CredMgmt}, authnrCfg={AuthnrCfg}, bioEnroll={BioEnroll}, clientPin={ClientPin}, largeBlobs={LargeBlobs}, uvBioEnroll={UvBioEnroll}, pinUvAuthToken={PinUvAuthToken}, setMinPINLength={SetMinPinLength}, makeCredUvNotRqd={MakeCredUvNotRqd})")]
public sealed record CtapGetInfoOptions(
    bool? Ep = null,
    bool? ResidentKey = null,
    bool? Uv = null,
    bool? Platform = null,
    bool? AlwaysUv = null,
    bool? CredMgmt = null,
    bool? AuthnrCfg = null,
    bool? BioEnroll = null,
    bool? ClientPin = null,
    bool? LargeBlobs = null,
    bool? UvBioEnroll = null,
    bool? PinUvAuthToken = null,
    bool? SetMinPinLength = null,
    bool? MakeCredUvNotRqd = null);
