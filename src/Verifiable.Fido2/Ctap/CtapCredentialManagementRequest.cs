using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorCredentialManagement</c> request structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. Mirrors
/// <see cref="CtapAuthenticatorConfigRequest"/>'s shape and custody: one outer
/// <see cref="SubCommand"/>-dispatching request type, with <see cref="SubCommandParams"/> carrying the
/// RAW, still-CBOR-encoded <c>subCommandParams</c> map bytes AS RECEIVED (a slice of the request
/// buffer, never re-encoded) — preserved because the platform-side <c>pinUvAuthParam</c> verify message
/// for <c>enumerateCredentialsBegin</c>/<c>deleteCredential</c>/<c>updateUserInformation</c> (CTAP 2.3,
/// lines 7265/7367/7417: <c>uint8(subCommand) || subCommandParams</c>) covers these EXACT bytes, not a
/// re-serialization of the decoded fields below. <see cref="RpIdHash"/>/<see cref="CredentialId"/>/
/// <see cref="User"/> are <see cref="SubCommandParams"/>'s own three members, decoded via the shared
/// entity codec for convenience (<see langword="null"/> when <see cref="SubCommandParams"/> is absent or
/// the individual member itself was omitted).
/// </remarks>
/// <param name="SubCommand">Required (<c>0x01</c>). The requested action, one of <see cref="WellKnownCtapCredentialManagementSubCommands"/>.</param>
/// <param name="SubCommandParams">
/// Optional (<c>0x02</c>). The RAW, still-CBOR-encoded <c>subCommandParams</c> map bytes as received —
/// <see langword="null"/> when the member was omitted entirely.
/// </param>
/// <param name="RpIdHash">Decoded from <see cref="SubCommandParams"/>'s member <c>0x01</c>. <see langword="null"/> when absent.</param>
/// <param name="CredentialId">Decoded from <see cref="SubCommandParams"/>'s member <c>0x02</c>. <see langword="null"/> when absent.</param>
/// <param name="User">Decoded from <see cref="SubCommandParams"/>'s member <c>0x03</c>. <see langword="null"/> when absent.</param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x03</c>). The PIN/UV auth protocol version the platform selected.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x04</c>). The output of calling <c>authenticate</c> on the subcommand-specific verify
/// message; <see langword="null"/> when omitted.
/// </param>
[DebuggerDisplay("CtapCredentialManagementRequest(SubCommand={SubCommand})")]
public sealed record CtapCredentialManagementRequest(
    int SubCommand,
    ReadOnlyMemory<byte>? SubCommandParams = null,
    ReadOnlyMemory<byte>? RpIdHash = null,
    PublicKeyCredentialDescriptor? CredentialId = null,
    CtapPublicKeyCredentialUserEntity? User = null,
    int? PinUvAuthProtocol = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null);
