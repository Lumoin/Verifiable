using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a started bound, unsalted HMAC session with parameter encryption: the session hash
/// algorithm, the negotiated symmetric definition, the derived session key, and the current nonceTPM (TPM 2.0
/// Library Part 1, clauses 17.6 and 19). It is the smallest session model the encrypt-attributed command path
/// needs — the session key drives both the response HMAC and the parameter-encryption mask/keystream, and the
/// nonceTPM rolls once per command.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="TransientKeyState"/> and <see cref="PolicySessionState"/>, the session key and nonce are held
/// as plain <see cref="ReadOnlyMemory{T}"/>: durable model state owned by the live automaton for the lifetime of
/// the session (until <c>TPM2_FlushContext()</c> releases it), not hot wire-path memory. The session key is
/// sensitive — exactly as <see cref="TransientKeyState.PrivateKey"/> is — and is only ever replaced wholesale (the
/// nonceTPM rolls each command), never mutated in place.
/// </para>
/// <para>
/// This slice models bind entities whose authorization value is empty (the objects it creates carry empty auth),
/// so <c>sessionValue = sessionKey ‖ authValue</c> (Part 1, clause 19.1) reduces to the session key alone, which
/// is what both the response HMAC and the parameter encryption key on.
/// </para>
/// </remarks>
/// <param name="Handle">The session handle assigned at <c>TPM2_StartAuthSession()</c> (most-significant octet <c>TPM_HT_HMAC_SESSION</c>, TPM 2.0 Library Part 2, clause 7.2).</param>
/// <param name="SessionAlg">The session hash algorithm (the <c>authHash</c> supplied at start), which drives the KDFa derivations, the response HMAC width, and the nonce width.</param>
/// <param name="Symmetric">The symmetric definition negotiated at start (XOR obfuscation or AES-CFB), which keys parameter encryption of the first response parameter.</param>
/// <param name="SessionKey">The <c>KDFa</c>-derived session key (Part 1, clause 17.6.10 equation 20), used as the HMAC key and the parameter-encryption key seed.</param>
/// <param name="NonceTpm">The current nonceTPM: seeded by the initial value returned at start and rolled to a fresh value on each command response (Part 1, clause 17.6.7).</param>
public sealed record HmacSessionState(
    uint Handle,
    TpmAlgIdConstants SessionAlg,
    TpmtSymDef Symmetric,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> NonceTpm);
