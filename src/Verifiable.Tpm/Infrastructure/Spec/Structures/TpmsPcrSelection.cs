using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Specifies a selection of PCRs for a specific hash algorithm (TPMS_PCR_SELECTION).
/// </summary>
/// <remarks>
/// <para>
/// Used in commands like <c>TPM2_PCR_Read()</c>, <c>TPM2_PolicyPCR()</c>, and
/// <c>TPM2_Quote()</c> to specify which PCRs to include. Also returned by
/// <c>TPM2_GetCapability(capability == TPM_CAP_PCRS)</c> to report PCR bank configuration.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_HASH hash;                      // Hash algorithm for this bank.
///     UINT8 sizeofSelect;                      // Size of pcrSelect array in bytes.
///     BYTE pcrSelect[sizeofSelect];            // Bitmap of selected PCRs.
/// } TPMS_PCR_SELECTION;
/// </code>
/// <para>
/// <b>PCR bitmap encoding:</b>
/// PCR N is selected if bit (N mod 8) of byte (N / 8) is set.
/// For example, to select PCR 7: pcrSelect[0] bit 7 = 1 (0x80).
/// To select PCR 16: pcrSelect[2] bit 0 = 1 (0x01).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.6.2, Table 106.
/// </para>
/// </remarks>
/// <param name="HashAlgorithm">The hash algorithm associated with this PCR bank.</param>
/// <param name="PcrSelect">The bitmap of selected PCRs.</param>
/// <seealso cref="TpmsPcrSelectionExtensions"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsPcrSelection(TpmAlgIdConstants HashAlgorithm, ReadOnlyMemory<byte> PcrSelect)
{
    private string DebuggerDisplay
    {
        get
        {
            int selectedCount = CountSelectedPcrs();
            return $"{HashAlgorithm}: {selectedCount} PCRs selected";
        }
    }

    private int CountSelectedPcrs()
    {
        int count = 0;
        ReadOnlySpan<byte> span = PcrSelect.Span;

        for(int i = 0; i < span.Length; i++)
        {
            count += BitCount(span[i]);
        }

        return count;
    }

    private static int BitCount(byte value)
    {
        int count = 0;

        while(value != 0)
        {
            count += value & 1;
            value >>= 1;
        }

        return count;
    }
}
