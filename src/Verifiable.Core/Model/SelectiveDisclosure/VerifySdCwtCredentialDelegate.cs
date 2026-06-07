using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Verifies an embedded presentation SD-CWT in full: the issuer COSE_Sign1 signature
/// plus per-disclosure digest binding, per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is the crypto-plus-CBOR step the <c>KbCwtVerification</c> orchestrator
/// composes but does not perform itself: signature verification and digest binding both
/// reach through CBOR parsing the orchestrator must not import. Wired by the application
/// to the existing SD-CWT verification reachable on <see cref="SdToken{TEnvelope}"/> —
/// typically <c>SdCwtVerificationExtensions.VerifyAsync</c> — which is reused, not
/// reimplemented.
/// </para>
/// </remarks>
/// <param name="sdCwt">The embedded presentation SD-CWT (issuer COSE_Sign1 plus holder-selected disclosures).</param>
/// <param name="issuerVerificationKey">The issuer's public key resolved from the credential's <c>iss</c> claim.</param>
/// <param name="pool">Memory pool the verification rents its transient buffers from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// <see langword="true"/> when the issuer signature verifies and every holder-selected
/// disclosure binds to a digest in the issuer-signed payload; otherwise <see langword="false"/>.
/// </returns>
public delegate ValueTask<bool> VerifySdCwtCredentialDelegate(
    SdToken<System.ReadOnlyMemory<byte>> sdCwt,
    PublicKeyMemory issuerVerificationKey,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
