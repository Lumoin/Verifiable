using System;
using System.Collections.Immutable;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// One block of a command's authorization area as it arrived on the wire (<c>TPMS_AUTH_COMMAND</c>, TPM 2.0
/// Library Part 2, clause 10.12.2, Table 156): the session handle, the caller nonce, the session attributes, and
/// the <c>hmac</c> field — a <c>TPM_RS_PW</c> slot's plaintext password, a real session's command HMAC.
/// </summary>
/// <remarks>
/// The slot OWNS its two carriers. A password slot's nonce is the dispose-immune shared empty (Part 1, clause
/// 16.6.4: a password authorization carries no nonce). The consuming transition releases the supplied hmac once
/// its compare or verification has read it and transfers the nonce into the slot's response entry; a refusing
/// arm releases both through <see cref="Dispose"/>.
/// </remarks>
/// <param name="SessionHandle">The slot's session handle: <c>TPM_RS_PW</c>, an HMAC session, or a policy session (<c>TPMI_SH_AUTH_SESSION</c>, Part 2, clause 9.8).</param>
/// <param name="NonceCaller">The slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.3.4, Table 92) — equation 17's nonceNewer for the command and nonceOlder for the response; owned.</param>
/// <param name="SessionAttributes">The slot's command session attributes (<c>TPMA_SESSION</c>, Part 2, clause 8.4, Table 38).</param>
/// <param name="SuppliedHmac">The slot's <c>hmac</c> field (<c>TPM2B_AUTH</c>) — the password in the clear for a <c>TPM_RS_PW</c> slot, the command HMAC otherwise; owned.</param>
public sealed record TpmAuthorizationSlot(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth SuppliedHmac): IDisposable
{
    /// <summary>
    /// Gets whether the slot is a <c>TPM_RS_PW</c> password authorization, whose <see cref="SuppliedHmac"/> is
    /// compared inline rather than verified as an HMAC (TPM 2.0 Library Part 1, clause 16.6.4).
    /// </summary>
    public bool IsPassword => SessionHandle.IsPasswordSession;

    /// <summary>
    /// Releases the owned nonce and hmac carriers.
    /// </summary>
    public void Dispose()
    {
        SuppliedHmac.Dispose();
        NonceCaller.Dispose();
    }
}

/// <summary>
/// A command's whole authorization area as parsed from the wire (TPM 2.0 Library Part 1, clause 15.6.1: "at least
/// one but no more than three" blocks): the first <see cref="AuthorizingCount"/> slots authorize the command's
/// authorized handles in handle order (Table 12: "authorization sessions come before sessions used only for
/// encryption, decryption, or audit"), and every slot after them is a companion that authorizes nothing and
/// rides the area for its <c>decrypt</c>, <c>encrypt</c>, or <c>audit</c> attribute alone.
/// </summary>
/// <remarks>
/// Owns its slots; the consuming transition is the terminal owner of every slot's supplied hmac and transfers
/// each slot's nonce into its response entry, while a refusing arm releases everything through
/// <see cref="Dispose"/>.
/// </remarks>
/// <param name="Slots">The blocks in wire order.</param>
/// <param name="AuthorizingCount">How many leading slots authorize a handle — the command's own count of <c>@</c>-marked handles.</param>
public sealed record TpmAuthorizationArea(
    ImmutableArray<TpmAuthorizationSlot> Slots,
    int AuthorizingCount): IDisposable
{
    /// <summary>
    /// The most blocks an authorization area may hold (TPM 2.0 Library Part 1, clause 15.6.1).
    /// </summary>
    public const int MaxSlots = 3;

    /// <summary>
    /// Gets the number of blocks the area holds.
    /// </summary>
    public int Count => Slots.Length;

    /// <summary>
    /// Gets the slot at a wire position.
    /// </summary>
    /// <param name="index">The zero-based wire position.</param>
    /// <returns>The slot.</returns>
    public TpmAuthorizationSlot this[int index] => Slots[index];

    /// <summary>
    /// Finds the wire position of the slot claiming an attribute, or <c>-1</c> when none does.
    /// </summary>
    /// <param name="attribute">The attribute bit to search for.</param>
    /// <returns>The claiming slot's position, or <c>-1</c>.</returns>
    public int FindClaimingSlot(TpmaSession attribute)
    {
        for(int index = 0; index < Slots.Length; index++)
        {
            if((Slots[index].SessionAttributes & attribute) != 0)
            {
                return index;
            }
        }

        return -1;
    }

    /// <summary>
    /// Releases every slot's supplied hmac once its compare or verification has read it — the accepting
    /// transition's terminal-owner step, taken when each slot's nonce has been TRANSFERRED into its response
    /// entry and must therefore survive.
    /// </summary>
    public void ReleaseCredentials()
    {
        foreach(TpmAuthorizationSlot slot in Slots)
        {
            slot.SuppliedHmac.Dispose();
        }
    }

    /// <summary>
    /// Releases every slot's owned carriers.
    /// </summary>
    public void Dispose()
    {
        foreach(TpmAuthorizationSlot slot in Slots)
        {
            slot.Dispose();
        }
    }
}
