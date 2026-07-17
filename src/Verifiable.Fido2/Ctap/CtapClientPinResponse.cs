using System;
using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorClientPIN</c> response structure: every Optional member this library models,
/// per §2.1's full table, so wave-b/c subcommands extend data, not structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. This wave's
/// authenticator emits only <see cref="KeyAgreement"/> (<c>getKeyAgreement</c>),
/// <see cref="PinRetries"/> (<c>getPINRetries</c>), and <see cref="UvRetries"/> (<c>getUVRetries</c>);
/// <see cref="PinUvAuthToken"/> and <see cref="PowerCycleState"/> are modeled for the token-issuing
/// subcommands and <c>powerCycleState</c> reporting a later wave implements.
/// </remarks>
/// <param name="KeyAgreement">
/// Optional (<c>0x01</c>). The authenticator's key-agreement COSE_Key, the result of calling
/// <c>getPublicKey</c> for the selected protocol.
/// </param>
/// <param name="PinUvAuthToken">Optional (<c>0x02</c>). The issued token, encrypted under the shared secret.</param>
/// <param name="PinRetries">Optional (<c>0x03</c>). The number of PIN attempts remaining before lockout.</param>
/// <param name="PowerCycleState">
/// Optional (<c>0x04</c>). Present and <see langword="true"/> if a power cycle is required before any
/// future PIN operation. Only valid on a <c>getPINRetries</c> response.
/// </param>
/// <param name="UvRetries">Optional (<c>0x05</c>). The number of built-in-UV attempts remaining before lockout.</param>
[DebuggerDisplay("CtapClientPinResponse(PinRetries={PinRetries}, UvRetries={UvRetries})")]
public sealed record CtapClientPinResponse(
    CoseKey? KeyAgreement = null,
    ReadOnlyMemory<byte>? PinUvAuthToken = null,
    int? PinRetries = null,
    bool? PowerCycleState = null,
    int? UvRetries = null);
