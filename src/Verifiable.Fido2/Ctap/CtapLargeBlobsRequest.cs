using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorLargeBlobs</c> request structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>. A flat six-member request with NO
/// <c>subCommand</c> and no nesting — the simplest request shape this library models. <see cref="Offset"/>
/// is spec-Required (lines 7565-7568) but modeled NULLABLE here rather than enforced at the decode
/// boundary: its absence maps to <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (line 7590), a
/// DIFFERENT status than the config/credMgmt decode-boundary <see cref="Fido2FormatException"/> →
/// <see cref="WellKnownCtapStatusCodes.MissingParameter"/> catch those two commands use for their own
/// Required <c>subCommand</c> member — so presence must reach the pure transition rather than being
/// thrown away at decode time. <see cref="Set"/>/<see cref="PinUvAuthParam"/> are raw slices of the
/// decoded request buffer (never independently pooled), mirroring
/// <see cref="CtapAuthenticatorConfigRequest.SubCommandParams"/>'s own custody.
/// </remarks>
/// <param name="Get">Optional (<c>0x01</c>). The number of bytes requested to read. <see langword="null"/> when absent.</param>
/// <param name="Set">Optional (<c>0x02</c>). A fragment to write. <see langword="null"/> when absent.</param>
/// <param name="Offset">Required by spec (<c>0x03</c>), modeled nullable. The byte offset at which to read/write; <see langword="null"/> when the member was omitted from the wire.</param>
/// <param name="Length">Optional (<c>0x04</c>). The total length of a write operation. <see langword="null"/> when absent.</param>
/// <param name="PinUvAuthParam">Optional (<c>0x05</c>). The output of calling <c>authenticate</c> on the per-fragment verify message. <see langword="null"/> when absent.</param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x06</c>). The PIN/UV auth protocol version the platform selected. <see langword="null"/> when absent.</param>
[DebuggerDisplay("CtapLargeBlobsRequest(Get={Get}, Set={Set.HasValue}, Offset={Offset})")]
public sealed record CtapLargeBlobsRequest(
    int? Get = null,
    ReadOnlyMemory<byte>? Set = null,
    int? Offset = null,
    int? Length = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null,
    int? PinUvAuthProtocol = null);
