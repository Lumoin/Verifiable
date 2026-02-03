using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_VerifySignature() (TPMT_TK_VERIFIED).
/// </summary>
/// <remarks>
/// <para>
/// Provides evidence that the TPM has validated that a digest was signed by a key.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_VERIFIED).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy containing keyName.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_VERIFIED;
/// </code>
/// <para>
/// A NULL Verified Ticket is: (TPM_ST_VERIFIED, TPM_RH_NULL, 0x0000).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.7.4, Table 110.
/// </para>
/// </remarks>
/// <param name="Tag">Ticket structure tag (must be TPM_ST_VERIFIED).</param>
/// <param name="Hierarchy">The hierarchy containing the keyName.</param>
/// <param name="Digest">The HMAC produced using a proof value of hierarchy.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtTkVerified(ushort Tag, uint Hierarchy, ReadOnlyMemory<byte> Digest)
{
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull())
            {
                return "TPMT_TK_VERIFIED: (null)";
            }

            string hierarchyName = TpmValueConversions.GetHandleDescription(Hierarchy);
            return $"TPMT_TK_VERIFIED: {hierarchyName}, {Digest.Length} bytes";
        }
    }

    /// <summary>
    /// Determines if this is a NULL ticket.
    /// </summary>
    public bool IsNull() => Hierarchy == (uint)TpmRh.TPM_RH_NULL && Digest.IsEmpty;
}
