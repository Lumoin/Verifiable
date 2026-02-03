using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_SequenceComplete() or TPM2_Hash() (TPMT_TK_HASHCHECK).
/// </summary>
/// <remarks>
/// <para>
/// Produced when the message that was digested did not start with TPM_GENERATED_VALUE.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_HASHCHECK).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_HASHCHECK;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.7.6, Table 112.
/// </para>
/// </remarks>
/// <param name="Tag">Ticket structure tag (must be TPM_ST_HASHCHECK).</param>
/// <param name="Hierarchy">The hierarchy.</param>
/// <param name="Digest">The HMAC produced using a proof value of hierarchy.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtTkHashcheck(ushort Tag, uint Hierarchy, ReadOnlyMemory<byte> Digest)
{
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull())
            {
                return "TPMT_TK_HASHCHECK: (null)";
            }

            string hierarchyName = TpmValueConversions.GetHandleDescription(Hierarchy);
            return $"TPMT_TK_HASHCHECK: {hierarchyName}, {Digest.Length} bytes";
        }
    }

    /// <summary>
    /// Determines if this is a NULL ticket.
    /// </summary>
    public bool IsNull() => Hierarchy == (uint)TpmRh.TPM_RH_NULL && Digest.IsEmpty;
}