using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorConfig</c> request structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>. Mirrors <see cref="CtapClientPinRequest"/>'s
/// shape and custody: one outer <see cref="SubCommand"/>-dispatching request type, with
/// <see cref="SubCommandParams"/> carrying the RAW, still-CBOR-encoded <c>subCommandParams</c> map bytes
/// AS RECEIVED (a slice of the request buffer, never re-encoded) — preserved because the platform-side
/// <c>pinUvAuthParam</c> verify message (CTAP 2.3, line 7947: <c>32×0xff || 0x0d || uint8(subCommand) ||
/// subCommandParams</c>) covers these EXACT bytes, not a re-serialization of the decoded fields below.
/// <see cref="NewMinPinLength"/>/<see cref="MinPinLengthRpIds"/>/<see cref="ForceChangePin"/>/
/// <see cref="PinComplexityPolicy"/> are <see cref="SubCommandParams"/>'s own four members, decoded for
/// <c>setMinPINLength</c>'s convenience (<see langword="null"/> when <see cref="SubCommandParams"/> is
/// absent or the individual member itself was omitted).
/// </remarks>
/// <param name="SubCommand">Required (<c>0x01</c>). The requested action, one of <see cref="WellKnownCtapAuthenticatorConfigSubCommands"/>.</param>
/// <param name="SubCommandParams">
/// Optional (<c>0x02</c>). The RAW, still-CBOR-encoded <c>subCommandParams</c> map bytes as received —
/// <see langword="null"/> when the member was omitted entirely.
/// </param>
/// <param name="NewMinPinLength">Decoded from <see cref="SubCommandParams"/>'s member <c>0x01</c>. <see langword="null"/> when absent.</param>
/// <param name="MinPinLengthRpIds">Decoded from <see cref="SubCommandParams"/>'s member <c>0x02</c>. <see langword="null"/> when absent.</param>
/// <param name="ForceChangePin">Decoded from <see cref="SubCommandParams"/>'s member <c>0x03</c>. <see langword="null"/> when absent.</param>
/// <param name="PinComplexityPolicy">Decoded from <see cref="SubCommandParams"/>'s member <c>0x04</c>. <see langword="null"/> when absent.</param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x03</c>). The PIN/UV auth protocol version the platform selected.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x04</c>). The output of calling <c>authenticate</c> on the subcommand-specific verify
/// message; <see langword="null"/> when omitted.
/// </param>
[DebuggerDisplay("CtapAuthenticatorConfigRequest(SubCommand={SubCommand})")]
public sealed record CtapAuthenticatorConfigRequest(
    int SubCommand,
    ReadOnlyMemory<byte>? SubCommandParams = null,
    int? NewMinPinLength = null,
    IReadOnlyList<string>? MinPinLengthRpIds = null,
    bool? ForceChangePin = null,
    bool? PinComplexityPolicy = null,
    int? PinUvAuthProtocol = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null);
