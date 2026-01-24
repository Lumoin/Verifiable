using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Reports the policy associated with a permanent handle (TPMS_TAGGED_POLICY).
/// </summary>
/// <remarks>
/// <para>
/// Returned by <c>TPM2_GetCapability(capability == TPM_CAP_AUTH_POLICIES)</c> to report
/// authorization policy values for permanent handles.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_HANDLE handle;     // A permanent handle.
///     TPMT_HA policyHash;    // The policy algorithm and hash.
/// } TPMS_TAGGED_POLICY;
/// </code>
/// <para>
/// The policy hash is computed using the specified algorithm and defines the
/// authorization policy for the handle. An empty policy (zero-length hash)
/// indicates no policy restriction.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.8.4, Table 116.
/// </para>
/// </remarks>
/// <param name="Handle">A permanent handle.</param>
/// <param name="PolicyHashAlgorithm">The hash algorithm used for the policy.</param>
/// <param name="PolicyHash">The policy hash digest.</param>
/// <seealso cref="TpmsTaggedPolicyExtensions"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsTaggedPolicy(
    uint Handle,
    ushort PolicyHashAlgorithm,
    ReadOnlyMemory<byte> PolicyHash)
{
    private string DebuggerDisplay
    {
        get
        {
            string handleName = TpmValueConversions.GetHandleDescription(Handle);

            if(PolicyHash.IsEmpty)
            {
                return $"{handleName}: no policy";
            }

            return $"{handleName}: ALG_0x{PolicyHashAlgorithm:X4}, {PolicyHash.Length} bytes";
        }
    }
}