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
/// to the object's Name (TPM 2.0 Library Part 1, Clause 19).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_PUBLIC           sensitiveType; // Selector; TPM_ALG_RSA, TPM_ALG_ECC or TPM_ALG_KEYEDHASH here.
///     TPM2B_AUTH                authValue;     // The object's authorization value.
///     TPM2B_DIGEST              seedValue;     // Protection seed: a parent's KDF seed, or an obfuscation value.
///     TPMU_SENSITIVE_COMPOSITE  sensitive;     // [sensitiveType]; the type-specific private data.
/// } TPMT_SENSITIVE;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.3.2, Table 240; the obfuscation-value role of
/// <c>seedValue</c> for a data object is Part 1, Clause 24.7.4.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtSensitive: IDisposable
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the sensitive-area type selector — <see cref="Sensitive"/>'s <see cref="TpmuSensitiveComposite.Type"/>.
    /// </summary>
    public TpmAlgIdConstants SensitiveType { get; }

    /// <summary>
    /// Gets the object's authorization value.
    /// </summary>
    public Tpm2bAuth AuthValue { get; }

    /// <summary>
    /// Gets the object's protection seed — a parent's protection seed for other objects (TPM 2.0 Library Part 2,
    /// clause 12.3.2.4, Table 240) or the obfuscation value for a sealed data object (Part 1, Clause 24.7.4),
    /// sized to the object's Name algorithm digest.
    /// </summary>
    public Tpm2bDigest SeedValue { get; }

    /// <summary>
    /// Gets the type-selected sensitive composite (TPMU_SENSITIVE_COMPOSITE).
    /// </summary>
    public TpmuSensitiveComposite Sensitive { get; }

    /// <summary>
    /// Initializes a sensitive area over owned carriers; ownership of every carrier transfers to this structure.
    /// </summary>
    /// <param name="authValue">The object's authorization value.</param>
    /// <param name="seedValue">The object's protection seed.</param>
    /// <param name="sensitive">The type-selected sensitive composite; its <see cref="TpmuSensitiveComposite.Type"/> becomes <see cref="SensitiveType"/>.</param>
    public TpmtSensitive(Tpm2bAuth authValue, Tpm2bDigest seedValue, TpmuSensitiveComposite sensitive)
    {
        ArgumentNullException.ThrowIfNull(sensitive);

        SensitiveType = sensitive.Type;
        AuthValue = authValue;
        SeedValue = seedValue;
        Sensitive = sensitive;
    }

    /// <summary>
    /// Creates a sensitive area over the <c>TPM_ALG_KEYEDHASH</c> arm — the sealed-data-object and HMAC-key
    /// shape, whose composite is a <see cref="Tpm2bSensitiveData"/>.
    /// </summary>
    /// <param name="authValue">The object's authorization value.</param>
    /// <param name="seedValue">The object's obfuscation value.</param>
    /// <param name="data">The private data.</param>
    /// <returns>The KEYEDHASH-selected sensitive area.</returns>
    public static TpmtSensitive ForKeyedHash(Tpm2bAuth authValue, Tpm2bDigest seedValue, Tpm2bSensitiveData data)
    {
        return new TpmtSensitive(authValue, seedValue, TpmuSensitiveComposite.FromBits(data));
    }

    /// <summary>
    /// Gets the serialized size of the inner TPMT_SENSITIVE.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + AuthValue.SerializedSize + SeedValue.SerializedSize + Sensitive.GetSerializedSize();

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
        Sensitive.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sensitive area from a TPM reader.
    /// </summary>
    /// <remarks>
    /// Structural refusals — an unmodeled selector, an over-wide field, a truncated frame — THROW, and which
    /// exception depends on the failing read. A caller feeding octets whose integrity its own wrap proved (the
    /// storage unwrap) treats a throw as unreachable; a caller feeding genuinely attacker-shapeable octets (an
    /// imported duplication interior, whose sender knew the transported seed) catches the throws and answers
    /// the sensitive-area refusal code. <c>TPM_ALG_SYMCIPHER</c>, <c>TPM_ALG_MLDSA</c>, <c>TPM_ALG_HASH_MLDSA</c>,
    /// <c>TPM_ALG_MLKEM</c> and any other selector are refused before any carrier is rented.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive area; ownership transfers to the caller.</returns>
    public static TpmtSensitive Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ushort sensitiveTypeValue = reader.ReadUInt16();
        var sensitiveType = (TpmAlgIdConstants)sensitiveTypeValue;
        switch(sensitiveType)
        {
            case TpmAlgIdConstants.TPM_ALG_RSA:
            case TpmAlgIdConstants.TPM_ALG_ECC:
            case TpmAlgIdConstants.TPM_ALG_KEYEDHASH:
            {
                break;
            }
            default:
            {
                throw new NotSupportedException($"Sensitive-area type '0x{sensitiveTypeValue:X4}' is not modeled; only TPM_ALG_RSA, TPM_ALG_ECC and TPM_ALG_KEYEDHASH sensitive areas are.");
            }
        }

        var authValue = Tpm2bAuth.Parse(ref reader, pool);
        var seedValue = Tpm2bDigest.Empty;
        TpmuSensitiveComposite? sensitive = null;
        try
        {
            //The protection seed is copied into a PINNED rental the carrier adopts, so the recovered secret
            //never rests in relocatable memory the runtime could copy without clearing.
            ushort seedSize = reader.ReadUInt16();
            if(seedSize > Tpm2bDigest.MaxSize)
            {
                //The TPM2B_DIGEST bound (TPM 2.0 Library Part 2, clause 10.3.2, Table 90), which a TPM answers with
                //TPM_RC_SIZE — the same channel every sized field of this structure takes for an over-wide size.
                throw new InvalidOperationException($"A sensitive-area seedValue of {seedSize} octets exceeds the digest union's {Tpm2bDigest.MaxSize}-octet bound.");
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

            sensitive = TpmuSensitiveComposite.Parse(sensitiveType, ref reader, pool);

            return new TpmtSensitive(authValue, seedValue, sensitive);
        }
        catch
        {
            //These carriers' only owner is this frame until the constructed structure adopts them, so a failing
            //later read (a truncated frame throws from the reader) must release them or the pinned rentals are
            //orphaned.
            sensitive?.Dispose();
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
            Sensitive.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMT_SENSITIVE(type={SensitiveType}, auth={AuthValue.Length}, seed={SeedValue.Size})";
}
