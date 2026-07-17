using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// The surface-level fields a <see cref="Fido2RegistrationChecks"/> rule compares, refined from a
/// verifier-parsed WebAuthn registration ceremony response.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>.
/// </para>
/// <para>
/// This record carries only fields already derived upstream (rpIdHash, clientDataHash-adjacent
/// challenge) or copied verbatim from the wire (<see cref="ClientData"/>,
/// <see cref="AuthenticatorData"/>). The rules in <see cref="Fido2RegistrationChecks"/> compare
/// these fields; deriving them — hashing the RP ID, computing the client data hash, walking the
/// attestation trust path, checking credential-id uniqueness in storage — is ceremony
/// orchestration and happens outside this rule list.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This record owns <see cref="AuthenticatorData"/> and
/// <see cref="ExpectedRpIdHash"/> — disposing it disposes both. The whole-ceremony scope is the
/// natural single-owner boundary: nothing outside this record needs either carrier once
/// <see cref="Fido2RegistrationVerifier.VerifyAsync"/> returns, so a caller that constructs one
/// instance and disposes it when done never has to track the carriers individually.
/// <see cref="Fido2RegistrationVerifier"/> itself only borrows this record — it does not dispose
/// it, including the internal <c>with</c>-derived copy it builds to attach the attestation
/// result, which is never itself disposed.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record RegistrationCeremonyInput: IDisposable
{
    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>
    /// The parsed <c>CollectedClientData</c> for the ceremony.
    /// </summary>
    public required ClientData ClientData { get; init; }

    /// <summary>
    /// The parsed <c>authData</c> structure for the ceremony. Owned by this record (see the
    /// type-level remarks on ownership).
    /// </summary>
    public required AuthenticatorData AuthenticatorData { get; init; }

    /// <summary>
    /// The base64url-encoded challenge exactly as issued to the client, for ordinal comparison
    /// against <see cref="ClientData.Challenge"/>.
    /// </summary>
    public required string ExpectedChallenge { get; init; }

    /// <summary>
    /// The set of origins the relying party accepts for this ceremony.
    /// </summary>
    public required IReadOnlySet<string> ExpectedOrigins { get; init; }

    /// <summary>
    /// The SHA-256 hash of the relying party ID, computed upstream. Compared against
    /// <see cref="Fido2.AuthenticatorData.RpIdHash"/> with a fixed-time comparison. Owned by this
    /// record (see the type-level remarks on ownership).
    /// </summary>
    public required DigestValue ExpectedRpIdHash { get; init; }

    /// <summary>
    /// Whether the relying party accepts a cross-origin ceremony. Defaults to
    /// <see langword="false"/> — a secure default, since accepting cross-origin ceremonies widens
    /// the set of embedding contexts that can complete a registration for this relying party.
    /// </summary>
    public bool AllowCrossOrigin { get; init; }

    /// <summary>
    /// The set of top-level origins the relying party expects to be sub-framed within, when it
    /// permits cross-origin iframe ceremonies. <see langword="null"/> when the relying party does
    /// not expect any top-level framing.
    /// </summary>
    public IReadOnlySet<string>? ExpectedTopOrigins { get; init; }

    /// <summary>
    /// The relying party's user-verification policy for this ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">W3C Web
    /// Authentication Level 3, section 5.8.6: User Verification Requirement Enumeration</see>.
    /// <see cref="Fido2RegistrationChecks.CheckRegistrationUserVerified"/> fails the ceremony on a
    /// clear <c>UV</c> bit only under <see cref="UserVerificationRequirement.Required"/>; the other
    /// two values always succeed and record the observed <c>UV</c> state in the claim's
    /// <see cref="Verifiable.Core.Assessment.Claim.Context"/> via <see cref="UserVerificationClaimContext"/>.
    /// </remarks>
    public required UserVerificationRequirement UserVerification { get; init; }

    /// <summary>
    /// Whether the relying party permits the <c>UP</c> bit to be absent, per the conditional-create
    /// exception in
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 15: the
    /// <c>UP</c> check applies only when the ceremony's <c>mediation</c> is not
    /// <c>conditional</c>. Defaults to <see langword="false"/> (the bit is required).
    /// </summary>
    public bool AllowUserPresenceAbsent { get; init; }

    /// <summary>
    /// The COSE algorithm identifiers the relying party's <c>pubKeyCredParams</c> requested, for
    /// step 20's algorithm match.
    /// </summary>
    public required IReadOnlyList<int> AllowedAlgorithms { get; init; }

    /// <summary>
    /// The outcome of the attestation statement format's verification procedure, or
    /// <see langword="null"/> when no attestation verification was attempted.
    /// </summary>
    public AttestationResult? AttestationResult { get; init; }

    /// <summary>
    /// Whether <see cref="NoneAttestationResult"/> satisfies the relying party's attestation
    /// trust policy. Defaults to <see langword="true"/>: attestation is optional in the WebAuthn
    /// ecosystem and step 24 explicitly leaves the trust decision to relying party policy, so a
    /// relying party that has not opted into an attestation requirement should not silently fail
    /// registrations that carry no attestation at all.
    /// </summary>
    public bool AcceptNoneAttestation { get; init; } = true;

    /// <summary>
    /// Whether <see cref="SelfAttestationResult"/> satisfies the relying party's attestation
    /// trust policy. Defaults to <see langword="true"/> for the same reason as
    /// <see cref="AcceptNoneAttestation"/> — self attestation is a normal, policy-acceptable
    /// outcome unless the relying party has opted into requiring a certified trust path.
    /// </summary>
    public bool AcceptSelfAttestation { get; init; } = true;

    /// <summary>
    /// The decoded client extension outputs from <c>clientExtensionResults</c>, one entry per
    /// extension identifier present, or <see langword="null"/>/empty when none were requested or
    /// none were honored. Computed upstream — typically via a <c>clientExtensionResults</c> JSON
    /// reader in the serialization layer above this library — the same way
    /// <see cref="ExpectedRpIdHash"/> is computed upstream rather than derived by a rule.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level
    /// 3, section 9: WebAuthn Extensions</see>.
    /// </remarks>
    public IReadOnlyList<Fido2ExtensionOutput>? ClientExtensionOutputs { get; init; }

    /// <summary>
    /// The decoded authenticator extension outputs from <c>authData</c>'s <c>extensions</c> CBOR
    /// map, one entry per extension identifier present, or <see langword="null"/>/empty when none
    /// were requested or none were honored. Computed upstream, the same way
    /// <see cref="ClientExtensionOutputs"/> is.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level
    /// 3, section 9: WebAuthn Extensions</see>.
    /// </remarks>
    public IReadOnlyList<Fido2ExtensionOutput>? AuthenticatorExtensionOutputs { get; init; }

    /// <summary>
    /// Selects the processor for a given extension identifier, or <see langword="null"/> when the
    /// relying party has registered no extension processors at all — the default, matching
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9</see>'s
    /// OPTIONAL-for-everyone framing.
    /// </summary>
    public SelectExtensionOutputProcessorDelegate? ExtensionOutputProcessor { get; init; }

    /// <summary>
    /// Whether an extension output present on the wire with no registered processor fails
    /// <see cref="Fido2ClaimIds.Fido2RegistrationExtensionOutputs"/>. Defaults to
    /// <see langword="false"/>: <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section
    /// 9</see>'s "Relying Parties MUST be prepared to handle cases where some or all of those
    /// extensions are ignored" makes silently ignoring an unrecognized output the conformant
    /// default; a relying party that wants strict enforcement opts in.
    /// </summary>
    public bool RejectUnregisteredExtensionOutputs { get; init; }

    /// <summary>
    /// The memory pool a registered <see cref="ExtensionOutputProcessDelegate"/> receives on its
    /// <see cref="ExtensionOutputProcessingRequest"/> for working-buffer allocation. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/>, the library-wide default pool, so a relying party
    /// only supplies one to route processor allocations through its own pool.
    /// </summary>
    public MemoryPool<byte> ExtensionProcessingPool { get; init; } = BaseMemoryPool.Shared;


    /// <summary>
    /// A debugger-friendly summary of the challenge (truncated), the accepted origin count, and
    /// whether user verification is required — not every field, since this record carries a
    /// dozen-plus members.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            string challengePreview = ExpectedChallenge.Length > 16
                ? string.Concat(ExpectedChallenge.AsSpan(0, 16), "...")
                : ExpectedChallenge;

            return $"RegistrationCeremonyInput(ExpectedChallenge={challengePreview}, ExpectedOrigins={ExpectedOrigins.Count}, UserVerification={UserVerification})";
        }
    }


    /// <summary>
    /// Releases <see cref="AuthenticatorData"/> and <see cref="ExpectedRpIdHash"/>.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        AuthenticatorData.Dispose();
        ExpectedRpIdHash.Dispose();
        disposed = true;
    }
}
