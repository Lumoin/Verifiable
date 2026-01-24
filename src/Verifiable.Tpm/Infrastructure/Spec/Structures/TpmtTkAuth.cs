using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;


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
    //TPM_ST_AUTH_SIGNED = 0x8002, TPM_ST_AUTH_SECRET = 0x8003.
    private const ushort TpmStAuthSigned = 0x8002;
    private const ushort TpmStAuthSecret = 0x8003;

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
    public bool IsPolicySigned() => Tag == TpmStAuthSigned;

    /// <summary>
    /// Determines if this is from TPM2_PolicySecret().
    /// </summary>
    public bool IsPolicySecret() => Tag == TpmStAuthSecret;
}
