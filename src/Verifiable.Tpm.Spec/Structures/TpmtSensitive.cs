using System;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// The sensitive area of an object (TPMT_SENSITIVE).
/// </summary>
/// <remarks>
/// <para>
/// The structure a Protected Storage blob wraps: the object's authorization value, its protection seed, and the
/// type-selected sensitive composite. It is marshaled inside a <c>TPM2B_SENSITIVE</c>, symmetrically encrypted
/// under a key derived from the Storage Parent's seed, and integrity-protected by the outer HMAC that binds it
/// to the object's Name (TPM 2.0 Library Part 1, Clause 19). This carrier models the
/// <c>TPM_ALG_KEYEDHASH</c> arm — the sealed-data-object shape, whose composite is a
/// <c>TPM2B_SENSITIVE_DATA</c> and whose <c>seedValue</c> is the object's obfuscation value.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_PUBLIC           sensitiveType; // Selector; TPM_ALG_KEYEDHASH for a sealed data object.
///     TPM2B_AUTH                authValue;     // The object's authorization value.
///     TPM2B_DIGEST              seedValue;     // Obfuscation value for a data object.
///     TPMU_SENSITIVE_COMPOSITE  sensitive;     // [sensitiveType]; TPM2B_SENSITIVE_DATA for KEYEDHASH.
/// } TPMT_SENSITIVE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.3.2, Table 240; the obfuscation-value role of
/// <c>seedValue</c> is Part 1, Clause 24.7.4.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtSensitive: IDisposable
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the sensitive-area type selector. This carrier models <see cref="TpmAlgIdConstants.TPM_ALG_KEYEDHASH"/>,
    /// the sealed-data-object arm.
    /// </summary>
    public TpmAlgIdConstants SensitiveType { get; }

    /// <summary>
    /// Gets the object's authorization value.
    /// </summary>
    public Tpm2bAuth AuthValue { get; }

    /// <summary>
    /// Gets the object's protection seed — the obfuscation value for a sealed data object (TPM 2.0 Library
    /// Part 1, Clause 24.7.4), sized to the object's Name algorithm digest.
    /// </summary>
    public Tpm2bDigest SeedValue { get; }

    /// <summary>
    /// Gets the type-selected sensitive composite — the sealed data for the <c>TPM_ALG_KEYEDHASH</c> arm.
    /// </summary>
    public Tpm2bSensitiveData Data { get; }

    /// <summary>
    /// Initializes a sensitive area over owned carriers; ownership of every carrier transfers to this structure.
    /// </summary>
    /// <param name="authValue">The object's authorization value.</param>
    /// <param name="seedValue">The object's protection seed.</param>
    /// <param name="data">The sealed data.</param>
    public TpmtSensitive(Tpm2bAuth authValue, Tpm2bDigest seedValue, Tpm2bSensitiveData data)
    {
        SensitiveType = TpmAlgIdConstants.TPM_ALG_KEYEDHASH;
        AuthValue = authValue;
        SeedValue = seedValue;
        Data = data;
    }

    /// <summary>
    /// Gets the serialized size of the inner TPMT_SENSITIVE.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + AuthValue.SerializedSize + SeedValue.SerializedSize + Data.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer as a bare <c>TPMT_SENSITIVE</c>; a <c>TPM2B_SENSITIVE</c> frame
    /// adds its own size prefix outside this call.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)SensitiveType);
        AuthValue.WriteTo(ref writer);
        SeedValue.WriteTo(ref writer);
        Data.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sensitive area from a TPM reader.
    /// </summary>
    /// <remarks>
    /// Structural refusals — an unmodeled selector, an over-wide field, a truncated frame — THROW, and which
    /// exception depends on the failing read. A caller feeding octets whose integrity its own wrap proved (the
    /// storage unwrap) treats a throw as unreachable; a caller feeding genuinely attacker-shapeable octets (an
    /// imported duplication interior, whose sender knew the transported seed) catches the throws and answers
    /// the sensitive-area refusal code.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive area; ownership transfers to the caller.</returns>
    public static TpmtSensitive Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ushort sensitiveType = reader.ReadUInt16();
        if(sensitiveType != (ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
        {
            throw new NotSupportedException($"Sensitive-area type '0x{sensitiveType:X4}' is not modeled; only TPM_ALG_KEYEDHASH sealed data objects are.");
        }

        var authValue = Tpm2bAuth.Parse(ref reader, pool);
        var seedValue = Tpm2bDigest.Empty;
        try
        {
            //The protection seed is copied into a PINNED rental the carrier adopts, so the recovered secret
            //never rests in relocatable memory the runtime could copy without clearing.
            ushort seedSize = reader.ReadUInt16();
            if(seedSize > Tpm2bDigest.MaxSize)
            {
                throw new NotSupportedException($"A sensitive-area seedValue of {seedSize} octets exceeds the digest union's {Tpm2bDigest.MaxSize}-octet bound.");
            }

            if(seedSize > 0)
            {
                var seedStorage = pool.Rent(seedSize, AllocationKind.Pinned);
                try
                {
                    reader.ReadBytes(seedSize).CopyTo(seedStorage.Memory.Span[..seedSize]);
                    seedValue = new Tpm2bDigest(seedStorage);
                }
                catch
                {
                    seedStorage.Dispose();
                    throw;
                }
            }

            var data = Tpm2bSensitiveData.Parse(ref reader, pool);

            return new TpmtSensitive(authValue, seedValue, data);
        }
        catch
        {
            //These carriers' only owner is this frame until the constructed structure adopts them, so a failing
            //later read (a truncated frame throws from the reader) must release them or the pinned rentals are
            //orphaned.
            seedValue.Dispose();
            authValue.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the carriers owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!Disposed)
        {
            AuthValue.Dispose();
            SeedValue.Dispose();
            Data.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMT_SENSITIVE(type=KEYEDHASH, auth={AuthValue.Length}, seed={SeedValue.Size}, data={Data.Length})";
}
