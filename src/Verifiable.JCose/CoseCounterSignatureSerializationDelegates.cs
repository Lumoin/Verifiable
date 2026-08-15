using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Delegate for building the RFC 9338 §3.3 Countersign_structure ToBeSigned bytes.
/// </summary>
/// <param name="input">The resolved Countersign_structure field set.</param>
/// <returns>The serialized Countersign_structure bytes ready for signing or verification.</returns>
public delegate byte[] BuildCountersignStructureDelegate(CountersignStructureInput input);


/// <summary>
/// Delegate for the read of a <see cref="CounterSignatureV2"/> value (COSE header label 11)
/// from CBOR bytes.
/// </summary>
/// <remarks>
/// Read-tolerant of a leading CBOR tag 19 (<c>COSE_Countersignature_Tagged</c>);
/// never itself emits one — see
/// <see cref="WriteCounterSignatureV2Delegate"/>. Throws on malformed bytes; the fail-closed
/// boundary is <see cref="ParseCounterSignatureHeaderValueDelegate"/>.
/// </remarks>
/// <param name="valueBytes">The CBOR-encoded countersignature value bytes.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <returns>The decoded countersignature.</returns>
public delegate CounterSignatureV2 ReadCounterSignatureV2Delegate(ReadOnlyMemory<byte> valueBytes, BaseMemoryPool pool);


/// <summary>
/// Delegate for writing a <see cref="CounterSignatureV2"/> value to CBOR bytes, untagged —
/// never emits the CBOR tag 19 wrapper.
/// </summary>
/// <param name="counterSignature">The countersignature to write.</param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The serialized value (the COSE_Signature-shaped 3-array, untagged), pool-routed.</returns>
public delegate EncodedCoseCounterSignature WriteCounterSignatureV2Delegate(CounterSignatureV2 counterSignature, BaseMemoryPool pool);


/// <summary>
/// Delegate for the read of a <see cref="CounterSignature0V2"/> value (COSE header label 12)
/// from CBOR bytes. Throws on malformed bytes; the fail-closed boundary is
/// <see cref="ParseCounterSignatureHeaderValueDelegate"/>.
/// </summary>
/// <param name="valueBytes">The CBOR-encoded countersignature value bytes (a bare bstr).</param>
/// <param name="pool">Memory pool the decoded signature carrier rents its buffer from.</param>
/// <returns>The decoded countersignature.</returns>
public delegate CounterSignature0V2 ReadCounterSignature0V2Delegate(ReadOnlyMemory<byte> valueBytes, BaseMemoryPool pool);


/// <summary>
/// Delegate for writing a <see cref="CounterSignature0V2"/> value to CBOR bytes.
/// </summary>
/// <param name="counterSignature">The countersignature to write.</param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The serialized value (a bare bstr), pool-routed.</returns>
public delegate EncodedCoseCounterSignature WriteCounterSignature0V2Delegate(CounterSignature0V2 counterSignature, BaseMemoryPool pool);


/// <summary>
/// Delegate for the fail-closed dispatch of a COSE header-parameter value to its version 2
/// countersignature form, by label.
/// </summary>
/// <remarks>
/// Rejects the deprecated RFC 8152 V1 countersignature labels fail-closed: see
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-1">RFC 9338 §1</see> — "uses of
/// 'CounterSignature' will migrate to 'CounterSignatureV2', and uses of 'CounterSignature0'
/// will migrate to 'CounterSignature0V2'"; this substrate and TS 119 152-1's own CDDL model
/// version 2 exclusively (labels 11/12 only).
/// </remarks>
/// <param name="label">
/// The COSE header-parameter label the value was found under
/// (<see cref="CoseHeaderParameters.CounterSignature"/>, <see cref="CoseHeaderParameters.CounterSignature0"/>,
/// <see cref="CoseHeaderParameters.CounterSignatureVersion2"/>, or
/// <see cref="CoseHeaderParameters.Countersignature0Version2"/>).
/// </param>
/// <param name="valueBytes">The CBOR-encoded header-parameter value bytes.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <returns>The parse result.</returns>
public delegate CoseCounterSignatureParseResult ParseCounterSignatureHeaderValueDelegate(int label, ReadOnlyMemory<byte> valueBytes, BaseMemoryPool pool);
