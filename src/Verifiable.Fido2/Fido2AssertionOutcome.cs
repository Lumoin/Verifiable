using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// The result of <see cref="Fido2AssertionVerifier.VerifyAsync"/>: the raw assertion-signature
/// verification outcome, the WebAuthn L3 §7.2 ceremony rule claims, and a policy-neutral summary
/// of whether the assertion is acceptable.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>.
/// </remarks>
/// <param name="SignatureValid">
/// Whether the assertion signature (step 21) verified against the stored credential public key.
/// <see langword="false"/> both on a genuine cryptographic mismatch and on any thrown
/// crypto/format error encountered while verifying — signature verification is fail-closed.
/// </param>
/// <param name="Claims">
/// The <see cref="ClaimIssueResult"/> produced by running the configured
/// <see cref="Fido2ValidationProfiles.AssertionRules"/> rule list against the ceremony's surface
/// fields.
/// </param>
/// <param name="IsAcceptable">
/// <see langword="true"/> when <see cref="SignatureValid"/> holds and no claim in
/// <see cref="Claims"/> carries <see cref="ClaimOutcome.Failure"/>.
/// <see cref="ClaimOutcome.Inconclusive"/> (e.g. a possible-clone <c>signCount</c> signal, a
/// changed backup state) and <see cref="ClaimOutcome.NotApplicable"/> do not affect this value —
/// they are signals for relying-party policy to act on, never automatic failures.
/// </param>
[DebuggerDisplay("Fido2AssertionOutcome(SignatureValid={SignatureValid}, IsAcceptable={IsAcceptable})")]
public sealed record Fido2AssertionOutcome(bool SignatureValid, ClaimIssueResult Claims, bool IsAcceptable);
