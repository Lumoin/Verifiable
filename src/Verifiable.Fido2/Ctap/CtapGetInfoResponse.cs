using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The subset of the <c>authenticatorGetInfo</c> response structure this library models: the two
/// Required members plus the Optional members the authenticator simulator and RP-side client
/// exercise, including the <c>authenticatorConfig</c>-adjacent surface (<see cref="ForcePinChange"/>,
/// <see cref="MinPinLength"/>, <see cref="MaxRpIdsForSetMinPinLength"/>,
/// <see cref="AuthenticatorConfigCommands"/>), the <c>authenticatorCredentialManagement</c>-adjacent
/// <see cref="RemainingDiscoverableCredentials"/>, and the <c>authenticatorLargeBlobs</c>-adjacent
/// <see cref="MaxSerializedLargeBlobArray"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>. The response structure has roughly
/// thirty members; this type models the two Required members plus every Optional member a shipped
/// client currently consumes (the summary above names each). The capabilities the REMAINING Optional
/// members describe are not, in general, unimplemented here: <c>bioEnroll</c>/<c>uvBioEnroll</c>/
/// <c>credMgmt</c>/<c>largeBlobs</c> themselves are reported on <see cref="CtapGetInfoOptions"/> rather
/// than as members of this type, and <c>authenticatorBioEnrollment</c>/
/// <c>authenticatorCredentialManagement</c>/<c>authenticatorLargeBlobs</c> are all fully implemented
/// commands; members such as <c>firmwareVersion</c> (<c>0x0E</c>), <c>attestationFormats</c>
/// (<c>0x16</c>), <c>vendorPrototypeConfigCommands</c>, <c>maxPINLength</c>, <c>transports</c>,
/// <c>algorithms</c>, and <c>certifications</c> are omitted because no shipped client reads them yet,
/// independent of whether the underlying capability exists. A CBOR reader decoding a response that
/// carries unmodeled members ignores them, per section 8's forward-compatibility rule (<c>"If map keys
/// are present that an implementation does not understand, they MUST be ignored"</c>).
/// </remarks>
/// <param name="Versions">
/// Required. The supported CTAP/U2F version strings (<see cref="WellKnownCtapVersions"/>). MUST
/// include <c>"FIDO_2_3"</c> for an authenticator claiming CTAP2.3 conformance.
/// </param>
/// <param name="Aaguid">
/// Required. The claimed AAGUID, 16 bytes, encoded the same way as
/// <c>AuthenticatorData</c>'s AAGUID field.
/// </param>
/// <param name="Extensions">
/// Optional. The list of supported extension identifiers, or <see langword="null"/> when omitted.
/// </param>
/// <param name="Options">
/// Optional. The supported option IDs (<see cref="CtapGetInfoOptions"/>), or <see langword="null"/>
/// when the member is omitted entirely (every option then takes its spec default).
/// </param>
/// <param name="PinUvAuthProtocols">
/// Optional (member <c>0x06</c>). The list of supported PIN/UV auth protocols, in order of decreasing
/// authenticator preference; MUST NOT be empty or contain duplicates if present. CTAP 2.3 §9 item 6:
/// MUST include <c>2</c> if this member is present at all. <see langword="null"/> when omitted.
/// </param>
/// <param name="MaxSerializedLargeBlobArray">
/// Optional (member <c>0x0B</c>). The maximum size, in bytes, of the serialized large-blob array this
/// authenticator can store — MUST be specified iff <c>authenticatorLargeBlobs</c> is supported (line
/// 4434) and MUST be ≥ 1024 when present (line 4435). This authenticator always reports this member,
/// <c>CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity</c>. <see langword="null"/> when
/// omitted.
/// </param>
/// <param name="ForcePinChange">
/// Optional (member <c>0x0C</c>). Present and <see langword="true"/> until a successful PIN change,
/// forcing <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c> to fail.
/// <see langword="null"/> when omitted (no PIN change is required).
/// </param>
/// <param name="MinPinLength">
/// Optional (member <c>0x0D</c>). The current minimum PIN length, in Unicode code points, this
/// authenticator enforces for ClientPIN. <see langword="null"/> when omitted.
/// </param>
/// <param name="MaxRpIdsForSetMinPinLength">
/// Optional (member <c>0x10</c>). The maximum number of RP IDs this authenticator will accept via the
/// <c>setMinPINLength</c> subcommand; <c>0</c> if it does not support adding additional RP IDs.
/// <see langword="null"/> when omitted.
/// </param>
/// <param name="PreferredPlatformUvAttempts">
/// Optional (member <c>0x11</c>). The preferred number of <c>getPinUvAuthTokenUsingUvWithPermissions</c>
/// invocations before the platform falls back to the PIN path or an error (CTAP 2.3, snapshot lines
/// 4497-4501). This authenticator always reports this member,
/// <c>CtapAuthenticatorState.PreferredPlatformUvAttempts</c>. <see langword="null"/> when omitted.
/// </param>
/// <param name="UvModality">
/// Optional (member <c>0x12</c>). The FIDO Registry user-verification-method bit-flags this
/// authenticator's built-in UV surfaces via <c>getPinUvAuthTokenUsingUvWithPermissions</c> (CTAP 2.3,
/// snapshot lines 4504-4508). This authenticator always reports this member,
/// <c>CtapAuthenticatorState.UvModality</c>. <see langword="null"/> when omitted.
/// </param>
/// <param name="RemainingDiscoverableCredentials">
/// Optional (member <c>0x14</c>). The estimated number of additional discoverable credentials that
/// can still be stored; zero is a legal value. <see langword="null"/> when omitted.
/// </param>
/// <param name="AuthenticatorConfigCommands">
/// Optional (member <c>0x1F</c>). Present if <c>authenticatorConfig</c> is supported: the list of its
/// subCommand values this authenticator implements (which MAY be empty). <see langword="null"/> when
/// omitted.
/// </param>
[DebuggerDisplay("CtapGetInfoResponse(Versions={Versions.Count}, Aaguid={Aaguid})")]
public sealed record CtapGetInfoResponse(
    IReadOnlyList<string> Versions,
    Guid Aaguid,
    IReadOnlyList<string>? Extensions = null,
    CtapGetInfoOptions? Options = null,
    IReadOnlyList<int>? PinUvAuthProtocols = null,
    int? MaxSerializedLargeBlobArray = null,
    bool? ForcePinChange = null,
    int? MinPinLength = null,
    int? MaxRpIdsForSetMinPinLength = null,
    int? PreferredPlatformUvAttempts = null,
    int? UvModality = null,
    int? RemainingDiscoverableCredentials = null,
    IReadOnlyList<int>? AuthenticatorConfigCommands = null);
