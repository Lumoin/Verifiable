using System.Buffers;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Encodes the PERSISTENT subset of a <see cref="CtapAuthenticatorState"/> (contract ruling R-2), plus
/// its R-2b personalization fingerprint, into a versioned CBOR snapshot payload.
/// </summary>
/// <param name="state">
/// The live authenticator state to read the persistent subset and fingerprint (<see cref="CtapAuthenticatorState.Aaguid"/>,
/// <see cref="CtapAuthenticatorState.FirmwareVersion"/>) from. Not mutated, and no ownership of its
/// members transfers — every field this delegate reads is copied into the returned payload.
/// </param>
/// <param name="pool">The memory pool the returned scrubbing payload buffer is rented from, and any scratch allocation the encoder needs.</param>
/// <returns>
/// The CBOR-encoded snapshot payload in a <see cref="PooledMemory"/> — a SCRUBBING carrier (its dispose
/// clears the buffer before returning it to the pool), NOT the non-secret <see cref="TaggedMemory{T}"/>
/// the wire-codec encode delegates return. A snapshot serializes raw credential signing keys, the stored
/// PIN digest, and both credRandom secrets, so it rides the same zeroing carrier discipline as the state
/// records those secrets came from (contract R-5); the caller owns and must dispose the returned payload.
/// </returns>
/// <remarks>
/// <para>
/// Mirrors the CTAP wire-codec delegate seam's own shape exactly (scout §3's last bullet), but this
/// format is custody-internal — it is never sent to, or parsed by, a real CTAP2 client, so it carries no
/// wire-interop obligation the way <c>authenticatorGetInfo</c>'s own canonical-CBOR response does.
/// <c>Verifiable.Fido2</c> stays serialization-agnostic for WIRE formats by composing their
/// concrete codecs from <c>Verifiable.Cbor</c> at the edge; this internal-only snapshot format instead
/// ships its own minimal RFC 8949 encoder (<see cref="CtapAuthenticatorSnapshotCborWriter"/>) directly in
/// this subfolder, so a custody-composed simulator needs no additional codec wiring beyond a
/// <see cref="CtapStateCustody"/> bundle — see that shipped default's own remarks for why this does not
/// widen <c>Verifiable.Fido2</c>'s dependency surface.
/// </para>
/// <para>
/// A leading format-version integer and the R-2b fingerprint are the FIRST bytes written, so
/// <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> can reject an unknown version or a mismatched
/// personalization before parsing anything else (fail closed).
/// </para>
/// </remarks>
public delegate PooledMemory EncodeCtapAuthenticatorSnapshotDelegate(CtapAuthenticatorState state, MemoryPool<byte> pool);
