using Verifiable.Fido2.Ctap;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The logical response a CTAP2 authenticator simulator transition produced, framed into wire bytes
/// by <see cref="CtapAuthenticatorSimulator"/> after the automaton step completes — the CTAP2
/// authenticator-side analogue of <c>Verifiable.Apdu.Automata.CardResponseIntent</c>. Keeping the
/// intent as a pure value (rather than framing bytes inside the transition function) is what lets
/// the CTAP2-canonical CBOR encode step live behind a delegate seam instead of inside the pure PDA.
/// </summary>
public abstract record CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorGetInfo</c> command: the response model ready to be
/// CBOR-encoded.
/// </summary>
/// <param name="Response">The <c>authenticatorGetInfo</c> response model.</param>
public sealed record GetInfoResponseReady(CtapGetInfoResponse Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorClientPIN</c> command: the response model ready to be
/// CBOR-encoded.
/// </summary>
/// <param name="Response">The <c>authenticatorClientPIN</c> response model.</param>
public sealed record ClientPinResponseReady(CtapClientPinResponse Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of an <see cref="UnsupportedCtapCommandReceived"/> input: a bare
/// <see cref="WellKnownCtapStatusCodes.InvalidCommand"/> status, no CBOR body.
/// </summary>
/// <param name="CommandByte">The unrecognized command byte, retained for tracing.</param>
public sealed record UnsupportedCommandResponse(byte CommandByte): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorMakeCredential</c> command: the response model ready to be
/// CBOR-encoded.
/// </summary>
/// <param name="Response">The <c>authenticatorMakeCredential</c> response model.</param>
public sealed record MakeCredentialResponseReady(CtapMakeCredentialResponse Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorGetAssertion</c> command: the response model ready to be
/// CBOR-encoded.
/// </summary>
/// <param name="Response">The <c>authenticatorGetAssertion</c> response model.</param>
public sealed record GetAssertionResponseReady(CtapGetAssertionResponse Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// A rejected command: a bare non-<c>CTAP2_OK</c> status byte, no CBOR body — the general-purpose shape
/// every wave-2 <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> error path produces,
/// per <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// CTAP 2.3, section 8.2: Status codes</see>.
/// </summary>
/// <param name="StatusCode">The CTAP2 status code to report, one of <see cref="WellKnownCtapStatusCodes"/>'s non-<see cref="WellKnownCtapStatusCodes.Ok"/> values.</param>
public sealed record CtapErrorResponse(byte StatusCode): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorConfig</c> command: a bare <see cref="WellKnownCtapStatusCodes.Ok"/>
/// status, no CBOR body.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>: "Parameters may be passed into
/// subcommands, and only status codes are returned (i.e. no response map is defined)." Framed identically
/// to <see cref="CtapErrorResponse"/>'s bare-status shape, not <see cref="ClientPinResponseReady"/>'s
/// CBOR-body shape.
/// </remarks>
public sealed record AuthenticatorConfigResponseReady: CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorCredentialManagement</c> command.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. <see langword="null"/>
/// <see cref="Response"/> frames a bare <see cref="WellKnownCtapStatusCodes.Ok"/> status with no CBOR
/// body — <c>deleteCredential</c>'s step 9 ("Delete the credential and return CTAP2_OK.", line 7392) and
/// <c>updateUserInformation</c>'s step 13 (line 7450) both return no response map, mirroring
/// <see cref="AuthenticatorConfigResponseReady"/>'s bare-status shape; a non-<see langword="null"/>
/// <see cref="Response"/> (every other subcommand) is framed as a CBOR body, mirroring
/// <see cref="ClientPinResponseReady"/>'s shape.
/// </remarks>
/// <param name="Response">The response model to CBOR-encode, or <see langword="null"/> for a bare <c>CTAP2_OK</c>.</param>
public sealed record CredentialManagementResponseReady(CtapCredentialManagementResponse? Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorReset</c> command: a bare <see cref="WellKnownCtapStatusCodes.Ok"/>
/// status, no CBOR body.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset">
/// CTAP 2.3, section 6.6: authenticatorReset (0x07)</see>, the disposition paragraph (lines 6370-6374):
/// every outcome is a status code alone, no response map is ever defined. Framed identically to
/// <see cref="AuthenticatorConfigResponseReady"/>'s bare-status shape.
/// </remarks>
public sealed record AuthenticatorResetResponseReady: CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorBioEnrollment</c> command.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. <see langword="null"/>
/// <see cref="Response"/> frames a bare <see cref="WellKnownCtapStatusCodes.Ok"/> status with no CBOR
/// body — <c>cancelCurrentEnrollment</c>'s own "cancels current ongoing enrollment, if any, and returns
/// CTAP2_OK" (snapshot line 6799) and a gated subcommand's own bare-success dispositions
/// (<c>setFriendlyName</c>, <c>removeEnrollment</c>) produce no response map, mirroring
/// <see cref="CredentialManagementResponseReady"/>'s identical nullable-<c>Response</c> shape; a
/// non-<see langword="null"/> <see cref="Response"/> (<c>getModality</c>, <c>getFingerprintSensorInfo</c>,
/// <c>enrollBegin</c>, <c>enrollCaptureNextSample</c>, <c>enumerateEnrollments</c>) is framed as a CBOR
/// body.
/// </remarks>
/// <param name="Response">The response model to CBOR-encode, or <see langword="null"/> for a bare <c>CTAP2_OK</c>.</param>
public sealed record BioEnrollmentResponseReady(CtapBioEnrollmentResponse? Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// The result of a successful <c>authenticatorLargeBlobs</c> command.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10: authenticatorLargeBlobs (0x0C)</see>. <see langword="null"/>
/// <see cref="Response"/> frames a bare <see cref="WellKnownCtapStatusCodes.Ok"/> status with no CBOR
/// body — BOTH <c>set</c> success shapes (a continuation awaiting further writes, line 7676-7678, and a
/// completed commit, line 7670) return an empty response, mirroring
/// <see cref="CredentialManagementResponseReady"/>/<see cref="BioEnrollmentResponseReady"/>'s identical
/// nullable-<c>Response</c> shape; a non-<see langword="null"/> <see cref="Response"/> (<c>get</c> only)
/// is framed as a one-member CBOR body.
/// </remarks>
/// <param name="Response">The response model to CBOR-encode, or <see langword="null"/> for a bare <c>CTAP2_OK</c>.</param>
public sealed record LargeBlobsResponseReady(CtapLargeBlobsResponse? Response): CtapAuthenticatorResponseIntent;

/// <summary>
/// An <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> user-presence wait remains
/// parked (CTAP 2.3 :2840, R2): no gesture has been collected yet and the request's transport allows
/// deferral. Carries no CBOR body — <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>/
/// <see cref="CtapAuthenticatorSimulator.PollDeferredTransceiveAsync"/> frame this intent as a
/// zero-length <see cref="PooledMemory"/> "still pending" marker, never a legal final CTAP2 response
/// envelope. Plain <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> never sees this intent — the
/// inputs it builds never allow deferral (<see cref="MakeCredentialRequested.IsUserPresenceDeferralAllowed"/>/
/// <see cref="GetAssertionRequested.IsUserPresenceDeferralAllowed"/> stay <see langword="false"/>).
/// </summary>
public sealed record UserPresencePending: CtapAuthenticatorResponseIntent;
