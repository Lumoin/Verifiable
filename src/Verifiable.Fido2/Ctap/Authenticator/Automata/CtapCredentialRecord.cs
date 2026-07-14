using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// A single credential minted by a <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorMakeCredential</c>
/// handler, persisted inside <see cref="CtapAuthenticatorState"/> and addressed later by
/// <c>authenticatorGetAssertion</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every credential is addressable by <see cref="CredentialId"/> — <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/>
/// is the complete store, resident and non-resident credentials alike. A credential minted with the
/// <c>rk</c> option is discoverable: it is located later by scanning that same store for
/// <see cref="IsResident"/> entries matching a relying party identifier (CTAP 2.3, section 6.2.2's
/// locate-credentials step), keyed by the pair (<see cref="RpId"/>, <see cref="UserId"/>) rather than by
/// <see cref="RpId"/> alone — an authenticator may hold resident credentials for multiple accounts at the
/// same relying party. A same-(<c>rp.id</c>, account) <c>rk</c> registration still overwrites the existing
/// credential unconditionally (CTAP 2.3, section 6.1.2, step 16).
/// </para>
/// <para>
/// <see cref="UserId"/> is an independent copy made when the credential is minted — never the same
/// <see cref="UserHandle"/> instance the decoded <c>authenticatorMakeCredential</c> request carried — so
/// this record's lifetime is fully decoupled from the request's own carriers, which the simulator disposes
/// once the command completes regardless of whether they were persisted from.
/// </para>
/// </remarks>
/// <param name="CredentialId">The credential identifier minted for this credential. Owned by this record.</param>
/// <param name="RpId">The relying party identifier this credential is scoped to.</param>
/// <param name="UserId">The user handle this credential is associated with. Owned by this record.</param>
/// <param name="UserName">The user name supplied at registration, or <see langword="null"/> if none was given.</param>
/// <param name="UserDisplayName">The user display name supplied at registration, or <see langword="null"/> if none was given.</param>
/// <param name="Algorithm">The COSE algorithm identifier the credential key was minted for.</param>
/// <param name="IsResident">Whether this credential is discoverable (was minted with <c>rk: true</c>).</param>
/// <param name="CredentialKey">The credential's private key, bound for signing. Owned by this record.</param>
/// <param name="SignCount">
/// The credential's signature counter: zero at registration, incremented by one on every successful
/// <c>authenticatorGetAssertion</c> (WebAuthn L3, section 6.1.1).
/// </param>
/// <param name="CreationSequence">
/// A monotonic mint-order number, assigned from the counter carried on
/// <see cref="CtapAuthenticatorState.NextCredentialSequence"/> at the moment this credential is inserted
/// into the store. Orders the applicable-credentials list for a multi-account
/// <c>authenticatorGetAssertion</c> (CTAP 2.3, section 6.2, step 12: "order... by the time when they were
/// created in reverse order... the first credential is the most recently created") without reading a
/// wall clock — <see cref="SignCount"/> cannot serve this role, since it starts at zero for every
/// credential and advances with assertion frequency rather than mint order.
/// </param>
/// <param name="PublicKey">
/// The credential's public key in COSE_Key form, minted alongside <see cref="CredentialKey"/> and
/// carried here so <c>authenticatorCredentialManagement</c>'s <c>enumerateCredentialsBegin</c>/
/// <c>enumerateCredentialsGetNextCredential</c> can report it (CTAP 2.3, section 6.8.4, the
/// <c>publicKey</c> (0x08) response field) without re-deriving it from <see cref="CredentialKey"/>.
/// <see cref="CoseKey"/> carries no pooled memory of its own, so this record's <see cref="Dispose"/>
/// needs no corresponding release.
/// </param>
/// <param name="CredProtectLevel">
/// The <c>credProtect</c> policy level persisted with this credential (CTAP 2.3, section 12.1): one of
/// the three wire values <c>1</c> (<c>userVerificationOptional</c>), <c>2</c>
/// (<c>userVerificationOptionalWithCredentialIDList</c>), or <c>3</c> (<c>userVerificationRequired</c>).
/// EVERY credential carries a level from the moment it is minted — line 12648's own SHOULD ("use the
/// default value of 1... if no credProtect extension was included in the request") is this profile's
/// adopted baseline, never left unset; line 12539's stricter MAY (a unilaterally enforced default above
/// 1) is deliberately not exercised, so an mc request that never mentions <c>credProtect</c> always
/// mints level 1.
/// </param>
/// <param name="CredRandomWithUV">
/// One of the credential's two fresh, independently random 32-byte <c>hmac-secret</c> keys — the one
/// <c>authenticatorGetAssertion</c>'s CredRandom-selection step (CTAP 2.3 §12.7, snapshot lines
/// 13313-13315) uses when that assertion's own <c>uv</c> bit is set. Pooled, owned by this record —
/// SECRET material, never exposed as a raw array or span and never echoed in any response (contract R2c;
/// <see cref="Verifiable.Fido2.Ctap.Authenticator.Automata.CtapAuthenticatorTransitions.BuildCredentialEnumerationResponse"/>
/// deliberately omits it despite echoing <see cref="LargeBlobKey"/>). REQUIRED, not optional: unlike
/// <see cref="LargeBlobKey"/>, this pair is minted unconditionally on every
/// <c>authenticatorMakeCredential</c> (snapshot line 13191's declarative generation step, line 13192's
/// SHOULD adopted) — a credential minted without requesting <c>hmac-secret</c> can still serve a later
/// <c>authenticatorGetAssertion</c> that does. Never derived (no HKDF over other key material): CredRandom
/// is fresh random, the same posture <see cref="LargeBlobKey"/>'s own remarks describe.
/// </param>
/// <param name="CredRandomWithoutUV">
/// The sibling of <see cref="CredRandomWithUV"/>, selected when the assertion's own <c>uv</c> bit is
/// clear (CTAP 2.3 §12.7, snapshot lines 13313-13315). Same custody discipline, same unconditional mint,
/// same never-derived posture.
/// </param>
/// <param name="LargeBlobKey">
/// The credential's freshly generated 32-byte <c>largeBlobKey</c> (CTAP 2.3 §12.3, line 12851), or
/// <see langword="null"/> when the credential was minted without the extension. Pooled, owned by this
/// record — SECRET material (custody discipline; never exposed as a raw array beyond a response
/// writer's borrowed span). The derive-MAY (line 12827: "an authenticator MAY derive it as needed from
/// other key material") is DECLINED: this record always stores a fresh, independently random key rather
/// than deriving one, so both of that line's accompanying MUST NOTs (not plausibly derivable via other
/// means; not obtainable via hmac-secret with a predictable/constant salt) hold by construction — their
/// antecedent (derivation) never occurs. This authenticator now DOES model hmac-secret
/// (<see cref="CredRandomWithUV"/>/<see cref="CredRandomWithoutUV"/>), so the "not obtainable via
/// hmac-secret" MUST NOT is checked live by the two features' isolation, not merely by hmac-secret's
/// former absence.
/// </param>
[DebuggerDisplay("CtapCredentialRecord(RpId={RpId}, Resident={IsResident}, SignCount={SignCount}, CreationSequence={CreationSequence}, CredProtectLevel={CredProtectLevel})")]
public sealed record CtapCredentialRecord(
    CredentialId CredentialId,
    string RpId,
    UserHandle UserId,
    string? UserName,
    string? UserDisplayName,
    int Algorithm,
    bool IsResident,
    PrivateKey CredentialKey,
    uint SignCount,
    ulong CreationSequence,
    CoseKey PublicKey,
    int CredProtectLevel,
    IMemoryOwner<byte> CredRandomWithUV,
    IMemoryOwner<byte> CredRandomWithoutUV,
    IMemoryOwner<byte>? LargeBlobKey = null): IDisposable
{
    /// <summary>
    /// Releases the credential identifier, user handle, private key, both CredRandom values, and (when
    /// present) largeBlobKey this record owns.
    /// </summary>
    public void Dispose()
    {
        CredentialId.Dispose();
        UserId.Dispose();
        CredentialKey.Dispose();
        CredRandomWithUV.Dispose();
        CredRandomWithoutUV.Dispose();
        LargeBlobKey?.Dispose();
    }
}
