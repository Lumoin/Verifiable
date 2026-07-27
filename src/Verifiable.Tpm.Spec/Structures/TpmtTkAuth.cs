using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;


/// <summary>
/// A ticket produced by TPM2_PolicySigned() and TPM2_PolicySecret() (TPMT_TK_AUTH).
/// </summary>
/// <remarks>
/// <para>
/// Produced when the authorization has an expiration time.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ST tag;                  // Ticket structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET).
///     TPMI_RH_HIERARCHY hierarchy; // The hierarchy of the object used to produce the ticket.
///     TPM2B_DIGEST digest;         // HMAC using proof value of hierarchy.
/// } TPMT_TK_AUTH;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.7.5, Table 111.
/// </para>
/// </remarks>
/// <param name="Tag">Ticket structure tag (TPM_ST_AUTH_SIGNED or TPM_ST_AUTH_SECRET).</param>
/// <param name="Hierarchy">The hierarchy of the object used to produce the ticket.</param>
/// <param name="Digest">The HMAC produced using a proof value of hierarchy.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtTkAuth(ushort Tag, uint Hierarchy, ReadOnlyMemory<byte> Digest)
{
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull())
            {
                return "TPMT_TK_AUTH: (null)";
            }

            string hierarchyName = TpmValueConversions.GetHandleDescription(Hierarchy);
            return $"TPMT_TK_AUTH: ST_0x{Tag:X4}, {hierarchyName}, {Digest.Length} bytes";
        }
    }

    /// <summary>
    /// Determines if this is a NULL ticket.
    /// </summary>
    public bool IsNull() => Hierarchy == (uint)TpmRh.TPM_RH_NULL && Digest.IsEmpty;

    /// <summary>
    /// Determines if this is from TPM2_PolicySigned().
    /// </summary>
    public bool IsPolicySigned() => Tag == (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED;

    /// <summary>
    /// Determines if this is from TPM2_PolicySecret().
    /// </summary>
    public bool IsPolicySecret() => Tag == (ushort)TpmStConstants.TPM_ST_AUTH_SECRET;
}
