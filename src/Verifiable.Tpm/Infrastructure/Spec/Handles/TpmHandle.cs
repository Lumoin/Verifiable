using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Handles;

/// <summary>
/// TPM handle (TPM_HANDLE).
/// </summary>
/// <remarks>
/// <para>
/// Handles are 32-bit values used to reference shielded locations of various types
/// within the TPM. The most-significant octet (MSO) encodes the handle type
/// (<see cref="TpmHt"/>), and the remaining 24 bits encode an index within that type.
/// </para>
/// <para>
/// <b>Handle structure:</b>
/// </para>
/// <code>
/// Bits 31-24: Handle type (TpmHt)
/// Bits 23-0:  Handle index
/// </code>
/// <para>
/// Handles may refer to objects (keys or data blobs), authorization sessions
/// (HMAC and policy), NV Indexes, permanent TPM locations, and PCR.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 7.1, Table 34.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmHandle
{
    /// <summary>
    /// Gets the raw 32-bit handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a new handle from a raw value.
    /// </summary>
    /// <param name="value">The 32-bit handle value.</param>
    public TpmHandle(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Gets whether this is a transient object handle.
    /// </summary>
    public bool IsTransient => HandleType == TpmHt.TPM_HT_TRANSIENT;

    /// <summary>
    /// Gets whether this is a persistent object handle.
    /// </summary>
    public bool IsPersistent => HandleType == TpmHt.TPM_HT_PERSISTENT;

    /// <summary>
    /// Gets whether this is a permanent handle (TPM_RH_*).
    /// </summary>
    public bool IsPermanent => HandleType == TpmHt.TPM_HT_PERMANENT;

    /// <summary>
    /// Gets whether this is an HMAC session handle.
    /// </summary>
    public bool IsHmacSession => HandleType == TpmHt.TPM_HT_HMAC_SESSION;

    /// <summary>
    /// Gets whether this is a policy session handle.
    /// </summary>
    public bool IsPolicySession => HandleType == TpmHt.TPM_HT_POLICY_SESSION;

    /// <summary>
    /// Gets whether this is an NV index handle.
    /// </summary>
    public bool IsNvIndex => HandleType == TpmHt.TPM_HT_NV_INDEX;

    /// <summary>
    /// Gets whether this is a PCR handle.
    /// </summary>
    public bool IsPcr => HandleType == TpmHt.TPM_HT_PCR;

    /// <summary>
    /// Creates a handle from type and index.
    /// </summary>
    /// <param name="type">The handle type.</param>
    /// <param name="index">The 24-bit index.</param>
    /// <returns>The constructed handle.</returns>
    public static TpmHandle Create(TpmHt type, uint index) => new(TpmHandleRanges.MakeHandle(type, index));

    /// <summary>
    /// Creates a transient handle from an index.
    /// </summary>
    /// <param name="index">The 24-bit index.</param>
    /// <returns>The transient handle.</returns>
    public static TpmHandle Transient(uint index) => Create(TpmHt.TPM_HT_TRANSIENT, index);

    /// <summary>
    /// Creates a persistent handle from an index.
    /// </summary>
    /// <param name="index">The 24-bit index.</param>
    /// <returns>The persistent handle.</returns>
    public static TpmHandle Persistent(uint index) => Create(TpmHt.TPM_HT_PERSISTENT, index);

    /// <summary>
    /// Implicit conversion from <see cref="TpmRh"/> permanent handle.
    /// </summary>
    public static implicit operator TpmHandle(TpmRh permanentHandle) => new((uint)permanentHandle);

    /// <summary>
    /// Parses a handle from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed handle.</returns>
    public static TpmHandle Parse(ref TpmReader reader) => new(reader.ReadUInt32());

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    private string DebuggerDisplay => $"TPM_HANDLE(0x{Value:X8}, {HandleType})";
}