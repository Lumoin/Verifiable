using System;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsTaggedPolicy"/>.
/// </summary>
/// <remarks>
/// Provides interpretation methods for tagged policy structures.
/// </remarks>
public static class TpmsTaggedPolicyExtensions
{
    /// <summary>
    /// Gets a human-readable description of the tagged policy.
    /// </summary>
    /// <param name="policy">The tagged policy to describe.</param>
    /// <returns>A human-readable description.</returns>
    public static string GetDescription(this TpmsTaggedPolicy policy)
    {
        string handleName = TpmValueConversions.GetHandleDescription(policy.Handle);

        if(policy.HasEmptyPolicy())
        {
            return $"{handleName}: no policy (empty authorization)";
        }

        TpmtHa policyHash = policy.PolicyHash ?? TpmtHa.Null;
        string hashHex = Convert.ToHexString(policyHash.Digest);

        return $"{handleName}: {policyHash.HashAlg.Value} policy {hashHex}";
    }

    /// <summary>
    /// Determines if the handle has an empty policy (no restrictions), which a default-valued
    /// <see cref="TpmsTaggedPolicy"/> — whose <c>PolicyHash</c> field was never set — also is.
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns><c>true</c> if the policy is empty; otherwise, <c>false</c>.</returns>
    public static bool HasEmptyPolicy(this TpmsTaggedPolicy policy)
    {
        TpmtHa policyHash = policy.PolicyHash ?? TpmtHa.Null;

        return policyHash.IsNull || policyHash.Size == 0;
    }

    /// <summary>
    /// Gets the policy hash as a hex string, the empty string for a handle with no policy restriction.
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns>The policy hash as a hex string.</returns>
    public static string GetPolicyHashHex(this TpmsTaggedPolicy policy)
    {
        TpmtHa policyHash = policy.PolicyHash ?? TpmtHa.Null;

        return Convert.ToHexString(policyHash.Digest);
    }

    /// <summary>
    /// Gets a friendly name for the handle.
    /// </summary>
    /// <param name="policy">The tagged policy.</param>
    /// <returns>A friendly name for the handle.</returns>
    public static string GetHandleName(this TpmsTaggedPolicy policy)
    {
        return TpmValueConversions.GetHandleDescription(policy.Handle);
    }
}
