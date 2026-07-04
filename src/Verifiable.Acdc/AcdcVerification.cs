using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Keri;

namespace Verifiable.Acdc;

/// <summary>
/// Verifies an ACDC message and, on success, mints a <see cref="Verified{T}"/> of
/// <see cref="AcdcMessage"/> — the mint-only trust carrier that separates the authenticated value from a
/// freely-constructible wire one, exactly as the credential and DIDComm verify paths mint a
/// <see cref="Verified{T}"/>. A trusted consumer that requires a <see cref="Verified{AcdcMessage}"/> therefore
/// cannot be handed an unverified ACDC: the distinction is enforced by the compiler, not by convention.
/// </summary>
/// <remarks>
/// <para>
/// This is the direct-issuance case (no issuance/revocation registry). Establishing an ACDC's authenticity has two
/// parts, both required before a <see cref="Verified{AcdcMessage}"/> is minted:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Content integrity</strong> — the ACDC's top-level SAID MUST verify over its received bytes
/// (<see cref="AcdcSaid.VerifyAsync"/>), so the decoded <paramref name="message"/> is bound to
/// <paramref name="acdcBytes"/>: a tampered body cannot reproduce the claimed SAID.
/// </description></item>
/// <item><description>
/// <strong>Issuer binding</strong> — the Issuer's verified KEL MUST anchor a direct issuance proof digest seal of
/// that SAID (<see cref="AcdcKeriBinding.FindDirectIssuanceSeal"/>), the Issuer's nonrepudiable commitment to the
/// ACDC that survives later key rotation (ACDC specification,
/// <see href="https://trustoverip.github.io/kswg-acdc-specification/#binding-to-key-state-at-time-of-acdc-state-change">
/// binding to key state</see>). Locating the Issuer's KEL and replaying it to its verified anchors is the
/// cross-log step the caller performs and supplies as <paramref name="issuerAnchors"/>, exactly as
/// <see cref="AcdcKeriBinding"/> separates the seal match from the cross-log replay.
/// </description></item>
/// </list>
/// <para>
/// The verification context carried by the minted value records the Issuer AID whose key state anchored the
/// issuance, so provenance is visible at the decision point.
/// </para>
/// </remarks>
public static class AcdcVerification
{
    /// <summary>
    /// Verifies an ACDC's direct issuance and mints a <see cref="Verified{AcdcMessage}"/> when it is both
    /// internally authentic (its SAID verifies over its received bytes) and anchored in the Issuer's verified key
    /// state (a direct issuance proof seal of its SAID appears among the Issuer's verified KEL anchors).
    /// </summary>
    /// <param name="acdcBytes">The ACDC's received serialization bytes, in the most-compact form its top-level SAID is taken over.</param>
    /// <param name="message">The ACDC message decoded from <paramref name="acdcBytes"/> (the serialization-specific bytes-to-message decode is the caller's; the SAID check binds this message to the bytes).</param>
    /// <param name="issuerAnchors">The seals anchored in the Issuer's verified KEL (obtained by replaying it), read by <see cref="KeriSealReader"/>.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>A <see cref="Verified{AcdcMessage}"/> when both checks hold; otherwise <see langword="null"/>.</returns>
    /// <exception cref="CesrFormatException">The ACDC's claimed SAID does not begin with a supported digest code.</exception>
    public static async ValueTask<Verified<AcdcMessage>?> VerifyDirectIssuanceAsync(
        ReadOnlyMemory<byte> acdcBytes,
        AcdcMessage message,
        IEnumerable<KeriSeal> issuerAnchors,
        ComputeDigestDelegate computeDigest,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(issuerAnchors);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        //Content integrity: verify before trusting the value. The SAID recomputes over the received bytes with the
        //field reset to its placeholder, binding the decoded message to those exact bytes.
        if(!await AcdcSaid.VerifyAsync(acdcBytes, message.Said, computeDigest, pool, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        //Issuer binding: the Issuer's verified KEL must anchor a direct issuance proof seal of this ACDC's SAID.
        if(AcdcKeriBinding.FindDirectIssuanceSeal(issuerAnchors, message.Said) is null)
        {
            return null;
        }

        return new Verified<AcdcMessage>(message, VerificationContextTag.Create(message.Issuer));
    }
}
