using System;
using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorClientPIN</c> request structure: every parameter this library models, per
/// §2.1's full table, so wave-b/c subcommands extend data, not structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. This wave's
/// authenticator reads only <see cref="SubCommand"/> and <see cref="PinUvAuthProtocol"/> (for
/// <c>getKeyAgreement</c>); <see cref="KeyAgreement"/>, <see cref="PinUvAuthParam"/>,
/// <see cref="NewPinEnc"/>, <see cref="PinHashEnc"/>, <see cref="Permissions"/>, and
/// <see cref="RpId"/> decode opaquely for the PIN-establishment/token-issuing subcommands a later
/// wave implements.
/// </remarks>
/// <param name="SubCommand">
/// Required (<c>0x02</c>). The requested action, one of <see cref="WellKnownCtapClientPinSubCommands"/>.
/// </param>
/// <param name="PinUvAuthProtocol">
/// Optional (<c>0x01</c>). The PIN/UV auth protocol version the platform selected. Contextually
/// Required for <c>getKeyAgreement</c>.
/// </param>
/// <param name="KeyAgreement">Optional (<c>0x03</c>). The platform's key-agreement COSE_Key.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x04</c>). The output of calling <c>authenticate</c> on a subcommand-specific
/// context; <see langword="null"/> when omitted.
/// </param>
/// <param name="NewPinEnc">Optional (<c>0x05</c>). An encrypted PIN; <see langword="null"/> when omitted.</param>
/// <param name="PinHashEnc">Optional (<c>0x06</c>). An encrypted proof-of-knowledge of a PIN; <see langword="null"/> when omitted.</param>
/// <param name="Permissions">Optional (<c>0x09</c>). A bitfield of requested permissions. MUST NOT be 0 if present.</param>
/// <param name="RpId">Optional (<c>0x0A</c>). The relying party identifier to assign as the permissions RP ID.</param>
[DebuggerDisplay("CtapClientPinRequest(SubCommand={SubCommand}, PinUvAuthProtocol={PinUvAuthProtocol})")]
public sealed record CtapClientPinRequest(
    int SubCommand,
    int? PinUvAuthProtocol = null,
    CoseKey? KeyAgreement = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null,
    ReadOnlyMemory<byte>? NewPinEnc = null,
    ReadOnlyMemory<byte>? PinHashEnc = null,
    int? Permissions = null,
    string? RpId = null);
