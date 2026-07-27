using System;
using System.Buffers;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Decodes a versioned CBOR CTAP authenticator state-custody snapshot payload into its parsed,
/// caller-owned form.
/// </summary>
/// <param name="snapshotCbor">The CBOR-encoded snapshot payload, as produced by an <see cref="EncodeCtapAuthenticatorSnapshotDelegate"/>.</param>
/// <param name="pool">The memory pool the returned snapshot's owned carriers rent from.</param>
/// <returns>
/// The parsed snapshot. The caller owns it: either transfer ownership of its members into a rehydrated
/// <see cref="Automata.CtapAuthenticatorState"/> via a <c>with</c> overlay, or dispose it directly.
/// </returns>
/// <remarks>
/// Mirrors <see cref="EncodeCtapAuthenticatorSnapshotDelegate"/>'s own remarks: this is a custody-internal
/// format, not a wire format, so the shipped default (<see cref="CtapAuthenticatorSnapshotCborReader"/>)
/// lives directly in this subfolder rather than in <c>Verifiable.Cbor</c>. Parsing is bounded and
/// iterative (R-5): every length-prefixed value is checked against a fixed maximum before any allocation,
/// and no recursive descent is used anywhere in the shipped default, since this format's nesting depth is
/// fixed by its own schema (a snapshot header, an array of credential entries, an array of bio-template
/// entries — never arbitrarily nested).
/// </remarks>
/// <exception cref="CtapAuthenticatorSnapshotException">
/// <paramref name="snapshotCbor"/> does not parse as a well-formed instance of this codec's format (a
/// truncated buffer, a malformed CBOR header, or a length/count that exceeds this codec's bounds) — never
/// the fingerprint check, which the rehydrating caller performs separately once the format version and
/// shape have already parsed successfully (R-2b, R-5: both are fail-closed, but personalization mismatch
/// is a caller-side decision since the composed identity to compare against is not known to the codec).
/// </exception>
public delegate CtapAuthenticatorSnapshot DecodeCtapAuthenticatorSnapshotDelegate(ReadOnlyMemory<byte> snapshotCbor, MemoryPool<byte> pool);
