using System;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// A sized buffer carrying an optional, unencrypted sensitive area (TPM2B_SENSITIVE).
/// </summary>
/// <remarks>
/// <para>
/// TPM 2.0 Library Part 2, clause 12.3.3, Table 241: "The Table 241 TPM2B_SENSITIVE Structure is used as a
/// parameter in TPM2_LoadExternal(). It is an unencrypted sensitive area but it may be encrypted using
/// parameter encryption." "When this structure is unmarshaled, the sensitiveType determines what type of value
/// is unmarshaled. Each value of sensitiveType is associated with a TPM2B. It is the maximum size for each of
/// the TPM2B values that will determine if the unmarshal operation is successful." "The unmarshaling function
/// validates that size equals the size of the value that is unmarshaled."
/// </para>
/// <para>
/// A declared size of zero carries no <see cref="TpmtSensitive"/> at all — the public-only form of
/// <c>TPM2_LoadExternal()</c> — and is represented by the dispose-immune <see cref="Absent"/> singleton rather
/// than a null carrier, mirroring <see cref="Tpm2bPrivate.Empty"/> and <see cref="Tpm2bPublicKeyRsa.Empty"/>.
/// A nonzero size that the inner <see cref="TpmtSensitive"/> does not consume exactly — a shortfall or an
/// overrun — is not a well-formed value and is refused with <c>TPM_RC_SIZE</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16          size;          // Size of sensitiveArea, 0 for the public-only form.
///     TPMT_SENSITIVE  sensitiveArea; // [size]; an unencrypted sensitive area.
/// } TPM2B_SENSITIVE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.3.3, Table 241.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSensitive: IDisposable
{
    /// <summary>The shared size-zero instance <see cref="Absent"/> answers, exempt from disposal.</summary>
    private static Tpm2bSensitive AbsentInstance { get; } = new();

    /// <summary>Whether <see cref="Dispose"/> has already released the owned sensitive area.</summary>
    private bool disposed;

    /// <summary>
    /// Initializes the public-only, absent form: no sensitive area, no rented carriers.
    /// </summary>
    private Tpm2bSensitive()
    {
        SensitiveArea = null;
    }

    /// <summary>
    /// Initializes a sensitive area carrier; ownership of <paramref name="sensitiveArea"/> transfers here.
    /// </summary>
    /// <param name="sensitiveArea">The unencrypted sensitive area.</param>
    private Tpm2bSensitive(TpmtSensitive sensitiveArea)
    {
        SensitiveArea = sensitiveArea;
    }

    /// <summary>
    /// Gets the shared absent instance — the public-only form of <c>TPM2_LoadExternal()</c>'s <c>inPrivate</c>.
    /// It owns no rented storage, so its disposal is a no-op.
    /// </summary>
    public static Tpm2bSensitive Absent => AbsentInstance;

    /// <summary>
    /// Gets whether this value carries no sensitive area.
    /// </summary>
    public bool IsAbsent => SensitiveArea is null;

    /// <summary>
    /// Gets the unencrypted sensitive area, or <see langword="null"/> when <see cref="IsAbsent"/>.
    /// </summary>
    public TpmtSensitive? SensitiveArea { get; }

    /// <summary>
    /// Gets the serialized size (2-byte size prefix, plus the inner TPMT_SENSITIVE when present).
    /// </summary>
    public int SerializedSize => IsAbsent ? sizeof(ushort) : sizeof(ushort) + SensitiveArea!.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(IsAbsent)
        {
            writer.WriteUInt16(0);

            return;
        }

        writer.WriteUInt16((ushort)SensitiveArea!.SerializedSize);
        SensitiveArea.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sensitive area carrier from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The inner <see cref="TpmtSensitive"/> is parsed over a window of exactly <c>size</c> octets, and the
    /// window's remaining octets are checked to be zero afterward — Table 241's "the unmarshaling function
    /// validates that size equals the size of the value that is unmarshaled" — the same posture
    /// <see cref="TpmtSensitive"/>'s own duplication-recovery caller applies (a <c>reader.Remaining != 0</c>
    /// check after the inner parse). A structural refusal from the inner parse (an unmodeled selector, an
    /// over-wide field) propagates as-is; a shortfall or overrun of the declared size answers
    /// <see cref="InvalidOperationException"/>, and the inner carriers are released either way.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed carrier; ownership transfers to the caller.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    /// <exception cref="InvalidOperationException">The inner <c>TPMT_SENSITIVE</c> consumed fewer or more octets than the declared size.</exception>
    public static Tpm2bSensitive Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Absent;
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), (int)size, $"TPM2B_SENSITIVE size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        var window = new TpmReader(reader.ReadBytes(size));
        TpmtSensitive sensitiveArea = TpmtSensitive.Parse(ref window, pool);
        if(window.Remaining != 0)
        {
            sensitiveArea.Dispose();

            throw new InvalidOperationException($"TPM2B_SENSITIVE declared {size} octets but its TPMT_SENSITIVE consumed {size - window.Remaining}; the unmarshaled size does not equal the declared size.");
        }

        return new Tpm2bSensitive(sensitiveArea);
    }

    /// <summary>
    /// Releases the memory owned by the inner sensitive area. The shared <see cref="Absent"/> instance is
    /// exempt: it owns no rented storage, and every consumer holds the same instance.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != AbsentInstance)
        {
            SensitiveArea?.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the structure and its area's width, or its absence.</summary>
    private string DebuggerDisplay => IsAbsent ? "TPM2B_SENSITIVE(absent)" : $"TPM2B_SENSITIVE({SensitiveArea!.SerializedSize} bytes)";
}
