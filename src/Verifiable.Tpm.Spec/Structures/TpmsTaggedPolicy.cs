using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

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
///     TPMT_HA    policyHash; // The policy algorithm and hash.
/// } TPMS_TAGGED_POLICY;
/// </code>
/// <para>
/// The policy hash is computed using the specified algorithm and defines the
/// authorization policy for the handle. An empty policy (zero-length hash)
/// indicates no policy restriction.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.7.4, Table 119.
/// </para>
/// </remarks>
/// <param name="Handle">A permanent handle.</param>
/// <param name="PolicyHash">The policy in a <c>TPMT_HA</c>: the hash algorithm selector and the digest it sizes, the one field Table 119 names for the policy. <see cref="TpmtHa.Null"/> reports a handle with no policy restriction. As a struct field it is also what <c>default(TpmsTaggedPolicy)</c> leaves unset, so every accessor reads it as <see cref="TpmtHa.Null"/> when it is unset — the default-valued structure reports the same "no policy restriction" a NULL <c>TPMT_HA</c> does.</param>
/// <seealso cref="TpmsTaggedPolicyExtensions"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsTaggedPolicy(
    uint Handle,
    TpmtHa PolicyHash)
{
    /// <summary>
    /// The debugger's one-line rendering: the handle's friendly name and either the policy's algorithm and
    /// digest width or a statement that the handle carries no policy. Metadata only — the digest octets
    /// themselves are never rendered.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            string handleName = TpmValueConversions.GetHandleDescription(Handle);
            TpmtHa policyHash = PolicyHash ?? TpmtHa.Null;

            if(policyHash.IsNull || policyHash.Size == 0)
            {
                return $"{handleName}: no policy";
            }

            return $"{handleName}: {policyHash.HashAlg.Value}, {policyHash.Size} bytes";
        }
    }
}
