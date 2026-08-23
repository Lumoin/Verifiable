using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The input alphabet of the TPM simulator's pushdown automaton. Inputs arrive from three sources: the
/// platform (<see cref="TpmInitSignal"/>), the command transport (the command-arrived records, parsed
/// from the wire by <see cref="TpmSimulator"/> before they enter the automaton), and the effectful
/// loop (the action-result records, such as <see cref="TpmRandomGenerated"/>, fed back after a
/// <see cref="TpmAction"/> has been executed by a backend).
/// </summary>
public abstract record TpmSimulatorInput;

/// <summary>
/// The platform <c>_TPM_Init</c> indication (TPM 2.0 Library Part 1, clause 10.2.2). It is not a TPM
/// command and produces no response; it moves the device into <see cref="TpmLifecyclePhase.Initializing"/>
/// and is the only exit from <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmInitSignal: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Startup()</c> command (TPM 2.0 Library Part 1, clause 10.2.3).
/// </summary>
/// <param name="StartupType">The startup type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmStartupRequested(TpmSuConstants StartupType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Shutdown()</c> command (TPM 2.0 Library Part 1, clause 10.2.4).
/// </summary>
/// <param name="ShutdownType">The shutdown type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmShutdownRequested(TpmSuConstants ShutdownType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_SelfTest()</c> command (TPM 2.0 Library Part 1, clause 10.3).
/// </summary>
/// <param name="IsFullTest">
/// Whether a full self-test of all algorithms was requested. The lifecycle skeleton does not track
/// per-algorithm test state, so this only records the request.
/// </param>
public sealed record TpmSelfTestRequested(bool IsFullTest): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetTestResult()</c> command (TPM 2.0 Library Part 1, clause 10.3). Permitted both
/// operationally and in <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmTestResultRequested: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1). Permitted only while
/// operational; on success it draws random octets through the action layer.
/// </summary>
/// <param name="BytesRequested">
/// The number of octets the caller requested. The transition clamps this to the largest digest the
/// simulated TPM can return before declaring the RNG action (clause 16.1: requesting more than fits
/// in a <c>TPM2B_DIGEST</c> is not an error — the TPM returns only what fits).
/// </param>
public sealed record TpmGetRandomRequested(ushort BytesRequested): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetCapability()</c> command (TPM 2.0 Library Part 3, clause 30.2). Permitted while
/// operational and in <see cref="TpmLifecyclePhase.FailureMode"/> (Part 1, clause 10.4).
/// </summary>
/// <param name="Capability">The capability category to query.</param>
/// <param name="Property">The first property (tag) to return.</param>
/// <param name="PropertyCount">The maximum number of properties to return.</param>
public sealed record TpmGetCapabilityRequested(TpmCapConstants Capability, uint Property, uint PropertyCount): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_DefineSpace()</c> command (TPM 2.0 Library Part 3, clause 31.3). Reserves space for an
/// NV Index with the given attributes and authorization value, authorized by the owner hierarchy. The
/// Name algorithm and access policy carried in the public area are retained (<see cref="NameAlg"/>,
/// <see cref="AuthPolicy"/>): the Index's own Name computation (TPM 2.0 Library Part 1, Table 6) and any
/// <c>TPM2_PolicyNV()</c> assertion against it need both fields verbatim, not a fixed assumption.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the definition (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="OwnerAuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It authorizes the provisioning hierarchy. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NvIndex">The handle of the NV Index to define, carried in the public area (<c>TPMS_NV_PUBLIC.nvIndex</c>, TPM 2.0 Library Part 2, clause 13.6, Table 235). That field's <c>TPMI_RH_NV_LEGACY_INDEX</c> type admits only the ordinary NV Index range (Part 2, clause 9.27, Table 74), the legacy public area's 32-bit-attribute indexes.</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>), whose <c>TPMA_NV_NO_DA</c> bit decides dictionary-attack protection.</param>
/// <param name="IndexAuth">The authorization value assigned to the new Index, in an owned <see cref="Tpm2bAuth"/> carrier rented at parse time holding the wire-exact octets; ownership transfers to the defined Index at install, and every refusing arm disposes it instead.</param>
/// <param name="DataSize">The size in octets of the Index data area.</param>
/// <param name="NameAlg">The Name algorithm carried in the public area (<c>TPMS_NV_PUBLIC.nameAlg</c>), retained on the defined Index.</param>
/// <param name="AuthPolicy">The access policy digest carried in the public area (<c>TPMS_NV_PUBLIC.authPolicy</c>, a <c>TPM2B_DIGEST</c> — TPM 2.0 Library Part 2, clause 10.4.2, Table 92), in an owned pooled carrier rented as the parse's last act; empty when no policy was supplied. Ownership transfers to the defined Index at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="IndexData">The new Index's data area, reserved at <paramref name="DataSize"/> octets in an owned pooled carrier rented as the parse's last act (Part 3, clause 31.7.1's reserved-then-merged-into model). Ownership transfers to the defined Index at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
public sealed record TpmNvDefineSpaceRequested(
    TpmiRhProvision AuthHandle,
    Tpm2bAuth OwnerAuthSupplied,
    TpmiRhNvLegacyIndex NvIndex,
    TpmaNv Attributes,
    Tpm2bAuth IndexAuth,
    ushort DataSize,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    TpmNvIndexData IndexData): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="IndexAuth"/>, <see cref="AuthPolicy"/> and <see cref="IndexData"/> carriers
    /// on a refusing path; the installing path transfers their ownership to the defined Index instead and never
    /// calls this. <see cref="OwnerAuthSupplied"/> is released on every refusing path; the authorizing
    /// transition disposes it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        IndexAuth.Dispose();
        AuthPolicy.Dispose();
        IndexData.Dispose();
        OwnerAuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Read()</c> command (TPM 2.0 Library Part 3, clause 31.13). Reads data from an NV Index
/// after authorizing against it. This slice models Index authorization (the authorization handle equals
/// the Index itself) and owner authorization (<c>TPM_RH_OWNER</c>, gated on <c>TPMA_NV_OWNERREAD</c>);
/// policy-authorized reads arrive later.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">The NV Index to read.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It is compared against the Index authValue or the owner authValue. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="Size">The number of octets requested.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
public sealed record TpmNvReadRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    Tpm2bAuth AuthSupplied,
    ushort Size,
    ushort Offset): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Write()</c> command (TPM 2.0 Library Part 3, clause 31.7). Writes data to an NV Index at
/// an offset after authorizing against it, then sets <c>TPMA_NV_WRITTEN</c>. This slice models Index
/// authorization (the authorization handle is the Index itself); owner- and policy-authorized writes
/// arrive later, mirroring <see cref="TpmNvReadRequested"/>.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>.</param>
/// <param name="NvIndex">The NV Index to write.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It is compared against the Index authValue. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="Data">The octets to write (<c>TPM2B_MAX_NV_BUFFER</c>, TPM 2.0 Library Part 2, clause 10.4.9, Table 99), in an owned pooled carrier rented as the parse's last act. The transition that performs the store is its terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="Offset">The octet offset into the Index data area at which to write.</param>
public sealed record TpmNvWriteRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    Tpm2bAuth AuthSupplied,
    Tpm2bMaxNvBuffer Data,
    ushort Offset): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="Data"/> carrier on a refusing path; the storing transition releases it
    /// itself once the octets have been merged into the Index's own data area. <see cref="AuthSupplied"/> is
    /// released on every refusing path; the authorizing transition disposes it per carrier once the compare
    /// that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        Data.Dispose();
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_UndefineSpace()</c> command (TPM 2.0 Library Part 3, clause 31.4). Removes an NV Index
/// definition and frees its handle. Owner authorization is modelled; the policy-delete variant
/// (<c>TPM2_NV_UndefineSpaceSpecial()</c>) is not.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the removal (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="NvIndex">The NV Index to undefine, typed <c>TPMI_RH_NV_DEFINED_INDEX</c> by the command's own handle area (TPM 2.0 Library Part 3, clause 31.4.2, Table 230). That interface type admits the ordinary and external NV Index ranges but not the permanent one (Part 2, clause 9.26, Table 73): a permanent NV Index is architecturally defined and so can never be removed by a command.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It is compared against the owner authValue. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
public sealed record TpmNvUndefineSpaceRequested(
    TpmiRhProvision AuthHandle,
    TpmiRhNvDefinedIndex NvIndex,
    Tpm2bAuth AuthSupplied): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Increment()</c> command (TPM 2.0 Library Part 3, clause 31.8). Increments an NV Counter
/// Index's 8-octet value by one after authorizing against it. This slice models Index authorization (the
/// authorization handle is the Index itself) and owner authorization, mirroring
/// <see cref="TpmNvWriteRequested"/>; policy- and platform-authorized increments arrive later.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">The NV Counter Index to increment.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It is compared against the Index authValue or the owner authValue. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
public sealed record TpmNvIncrementRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    Tpm2bAuth AuthSupplied): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_ReadPublic()</c> command (TPM 2.0 Library Part 3, clause 31.6). Reads an NV Index's public
/// area and computed Name. <c>Auth Index: None</c> — the command needs no authorization at all ("The public
/// area of an Index is not privacy-sensitive, and no authorization is required to read this data",
/// clause 31.6.1), so no auth area is parsed and no session ever accompanies it.
/// </summary>
/// <param name="NvIndex">The NV Index whose public area and Name are requested.</param>
public sealed record TpmNvReadPublicRequested(TpmiRhNvIndex NvIndex): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmComputeNvPublicNameAction"/>: the NV Index's marshaled public area
/// and computed Name, fed back so the transition can frame the <c>TPM2_NV_ReadPublic()</c> response (TPM 2.0
/// Library Part 3, clause 31.6). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="NvPublic">
/// The public area built from the Index's retained fields; ownership flows to the <c>TpmNvReadPublicResponse</c>
/// and is released once framed.
/// </param>
/// <param name="Name">The Index's computed Name as an owned <c>TPM2B_NAME</c> carrier (TPM 2.0 Library Part 2, clause 10.5.3, Table 104); ownership flows to the <c>TpmNvReadPublicResponse</c> and is released once framed.</param>
public sealed record TpmNvPublicNameComputed(
    TpmsNvPublic NvPublic,
    Tpm2bName Name): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Read()</c> command whose <c>authHandle</c> is authorized by an HMAC session rather than a
/// password (TPM 2.0 Library Part 3, clause 31.13; Part 1, clause 35.2.6.6's PIN-over-HMAC semantic). The wire
/// shape is identical to the password arm's (<see cref="TpmNvReadRequested"/>) except the authorization area
/// carries a real <c>TPMS_AUTH_COMMAND</c> instead of a <c>TPM_RS_PW</c> password body — <c>TryReadCommandSessionSpans</c>
/// parses both shapes uniformly, so which record this becomes is decided purely by whether the parsed
/// <c>sessionHandle</c> equals <c>TPM_RS_PW</c>, mirroring <c>TryParsePolicySecret</c>.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">The NV Index to read — also the cpHash Name2 term (the Index's computed Name), regardless of which arm authorizes.</param>
/// <param name="AuthorizingSessionHandle">The HMAC session that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>size ‖ offset</c> wire bytes exactly as received (Part 1, clause 16.7 equation 15's <c>parameters</c> term), captured before either field is decoded. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="Size">The number of octets requested.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
/// <param name="ResolvedIndexName">
/// The Index's computed Name (<c>TPM2B_NAME</c>), which cpHash's Name terms are laid out from while the
/// command HMAC is verified (Part 1, clause 16.7 equation 15). The Name is computed by an effect one step
/// ahead of that verification, so its carrier is TRANSFERRED onto this record in
/// <c>OnNvIndexNameComputed</c> and owned here for the rest of the command; the shared empty carrier is the
/// parse-time value.
/// </param>
/// <param name="ResolvedAuthValue">
/// The bind-omission-resolved authValue term to fold into the command and response HMAC keys — a borrowed
/// reference to the entity's live authValue carrier (the durable state stays the owner; the HMAC primitive
/// takes its trailing-zero-stripped view), or the shared empty carrier when the bind-omission applies.
/// Populated once the Index's computed Name is known (<c>OnNvIndexNameComputed</c>) and threaded unchanged
/// from there through verification into <c>ContinueNvReadOverSession</c>; <see langword="null"/> (the
/// parse-time default) until then, read as empty.
/// </param>
public sealed record TpmNvReadOverSessionRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    ushort Size,
    ushort Offset,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="ResolvedIndexName"/>,
    /// <see cref="NonceCaller"/> and <see cref="Hmac"/> carriers.
    /// <see cref="ResolvedAuthValue"/> is a borrow of durable state and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        ResolvedIndexName.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Write()</c> command whose owner <c>authHandle</c> is authorized by an HMAC session rather than
/// a password (TPM 2.0 Library Part 3, clause 31.7). Only the owner arm is modelled over a session (the
/// Index-authValue arm is password-only: a PIN Index forbids <c>TPMA_NV_AUTHWRITE</c> outright, so
/// its own authValue never reaches a write). Shape mirrors <see cref="TpmNvReadOverSessionRequested"/>.
/// </summary>
/// <param name="AuthHandle">The authorization handle; only <c>TPM_RH_OWNER</c> is modelled over a session.</param>
/// <param name="NvIndex">The NV Index to write — the cpHash Name2 term.</param>
/// <param name="AuthorizingSessionHandle">The HMAC session that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>data ‖ offset</c> wire bytes exactly as received, captured before either field is decoded. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="Data">The octets to write (<c>TPM2B_MAX_NV_BUFFER</c>, TPM 2.0 Library Part 2, clause 10.4.9, Table 99), in an owned pooled carrier rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the storing continuation once the octets have been merged into the Index's own data area.</param>
/// <param name="Offset">The octet offset into the Index data area at which to write.</param>
/// <param name="ResolvedIndexName">The Index's computed Name; see <see cref="TpmNvReadOverSessionRequested.ResolvedIndexName"/>.</param>
/// <param name="ResolvedAuthValue">The bind-omission-resolved authValue term; see <see cref="TpmNvReadOverSessionRequested.ResolvedAuthValue"/>.</param>
public sealed record TpmNvWriteOverSessionRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bMaxNvBuffer Data,
    ushort Offset,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="Data"/>,
    /// <see cref="ResolvedIndexName"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/> carriers.
    /// <see cref="ResolvedAuthValue"/> is a borrow of durable state and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        Data.Dispose();
        ResolvedIndexName.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_UndefineSpace()</c> command whose owner <c>authHandle</c> is authorized by an HMAC session
/// rather than a password (TPM 2.0 Library Part 3, clause 31.4). Shape mirrors
/// <see cref="TpmNvReadOverSessionRequested"/>, with no command parameters of its own.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the removal; only <c>TPM_RH_OWNER</c> is modelled over a session.</param>
/// <param name="NvIndex">The NV Index to undefine — the cpHash Name2 term. Typed as the command's handle area types it, <c>TPMI_RH_NV_DEFINED_INDEX</c> (TPM 2.0 Library Part 3, clause 31.4.2, Table 230; Part 2, clause 9.26, Table 73).</param>
/// <param name="AuthorizingSessionHandle">The HMAC session that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The (empty) parameter-area wire bytes — <c>TPM2_NV_UndefineSpace()</c> carries no parameters, so this is always zero-length. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="ResolvedIndexName">The Index's computed Name; see <see cref="TpmNvReadOverSessionRequested.ResolvedIndexName"/>.</param>
/// <param name="ResolvedAuthValue">The bind-omission-resolved authValue term; see <see cref="TpmNvReadOverSessionRequested.ResolvedAuthValue"/>.</param>
public sealed record TpmNvUndefineSpaceOverSessionRequested(
    TpmiRhProvision AuthHandle,
    TpmiRhNvDefinedIndex NvIndex,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="ResolvedIndexName"/>,
    /// <see cref="NonceCaller"/> and <see cref="Hmac"/> carriers.
    /// <see cref="ResolvedAuthValue"/> is a borrow of durable state and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        ResolvedIndexName.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_DefineSpace()</c> command whose owner <c>authHandle</c> is authorized by an HMAC session rather
/// than a password (TPM 2.0 Library Part 3, clause 31.3). Single-handle: there is no pre-existing Index yet, so
/// cpHash needs no Name2 term and no async Name-computation hop precedes the command-HMAC verification, unlike
/// <see cref="TpmNvReadOverSessionRequested"/>/<see cref="TpmNvWriteOverSessionRequested"/>/
/// <see cref="TpmNvUndefineSpaceOverSessionRequested"/>.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the definition; only <c>TPM_RH_OWNER</c> is modelled over a session.</param>
/// <param name="AuthorizingSessionHandle">The HMAC session that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>auth ‖ publicInfo</c> wire bytes exactly as received, captured before either field is decoded. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="IndexAuth">The authorization value assigned to the new Index, in an owned <see cref="Tpm2bAuth"/> carrier rented at parse time holding the wire-exact octets; ownership transfers to the defined Index at install, and every refusing arm disposes it instead.</param>
/// <param name="NvIndex">The handle of the NV Index to define, carried in the public area (<c>TPMS_NV_PUBLIC.nvIndex</c>, TPM 2.0 Library Part 2, clause 13.6, Table 235), whose <c>TPMI_RH_NV_LEGACY_INDEX</c> type admits only the ordinary NV Index range (Part 2, clause 9.27, Table 74).</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>).</param>
/// <param name="NameAlg">The Name algorithm carried in the public area.</param>
/// <param name="AuthPolicy">The access policy digest carried in the public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), in an owned pooled carrier rented as the parse's last act; ownership transfers to the defined Index at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="DataSize">The size in octets of the Index data area.</param>
/// <param name="IndexData">The new Index's data area, reserved at <paramref name="DataSize"/> octets in an owned pooled carrier rented as the parse's last act; ownership transfers to the defined Index at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="ResolvedAuthValue">
/// The bind-omission-resolved owner authValue term to fold into the command and response HMAC keys — a
/// borrowed carrier reference (see <see cref="TpmNvReadOverSessionRequested.ResolvedAuthValue"/>), resolved
/// synchronously in <c>OnNvDefineSpaceOverSession</c> (no async Name-computation hop precedes a
/// single-handle cpHash) and threaded onward through <c>ContinueNvDefineSpaceOverSession</c>;
/// <see langword="null"/> (the parse-time default) until then, read as empty.
/// </param>
public sealed record TpmNvDefineSpaceOverSessionRequested(
    TpmiRhProvision AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bAuth IndexAuth,
    TpmiRhNvLegacyIndex NvIndex,
    TpmaNv Attributes,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    ushort DataSize,
    TpmNvIndexData IndexData,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="IndexAuth"/>, <see cref="AuthPolicy"/>, <see cref="RawParameterArea"/> and
    /// <see cref="IndexData"/> carriers on a refusing path (or, on the decrypted-auth path, once the decrypt
    /// effect's own output supersedes the authValue); the plaintext installing path transfers the two
    /// authorization carriers' and the data area's ownership to the defined Index instead. The session
    /// slot's <see cref="NonceCaller"/> and <see cref="Hmac"/> are released here too.
    /// <see cref="ResolvedAuthValue"/> is a borrow and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        IndexAuth.Dispose();
        AuthPolicy.Dispose();
        RawParameterArea.Dispose();
        IndexData.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Increment()</c> command whose <c>authHandle</c> is authorized by an HMAC session rather than a
/// password (TPM 2.0 Library Part 3, clause 31.8). This record serves both authorization arms the password form
/// carries — the owner hierarchy and the Counter Index's own authValue — because a <c>TPMS_AUTH_COMMAND</c>'s
/// wire shape does not depend on which entity it authorizes, making the arm per-command rather than per-entity.
/// Shape mirrors <see cref="TpmNvUndefineSpaceOverSessionRequested"/>, the other two-handle NV command carrying
/// no parameters in either direction.
/// </summary>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm.</param>
/// <param name="NvIndex">
/// The NV Counter Index to increment — also the cpHash Name2 term, whose Name is computed from the Index as the
/// command found it rather than as the increment leaves it: cpHash covers the command as sent (Part 1, clause
/// 16.7 equation 15), and the Name hashes <c>TPMA_NV_WRITTEN</c>, which a first increment SETs (Part 1, clause
/// 35.2.6.3).
/// </param>
/// <param name="AuthorizingSessionHandle">The HMAC session that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The (empty) parameter-area wire bytes — <c>TPM2_NV_Increment()</c> carries no parameters, so this is always zero-length. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="ResolvedIndexName">The Index's computed Name; see <see cref="TpmNvReadOverSessionRequested.ResolvedIndexName"/>.</param>
/// <param name="ResolvedAuthValue">The bind-omission-resolved authValue term; see <see cref="TpmNvReadOverSessionRequested.ResolvedAuthValue"/>.</param>
public sealed record TpmNvIncrementOverSessionRequested(
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="ResolvedIndexName"/>,
    /// <see cref="NonceCaller"/> and <see cref="Hmac"/> carriers.
    /// <see cref="ResolvedAuthValue"/> is a borrow of durable state and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        ResolvedIndexName.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_ChangeAuth()</c> command (TPM 2.0 Library Part 3, clause 31.15): the atomic in-place
/// replacement of an NV Index's authorization value. Single-handle (<c>@nvIndex</c>, Auth Index 1, Auth Role
/// ADMIN) with one command parameter (<c>newAuth</c>, a <c>TPM2B_AUTH</c>), and no response parameters.
/// </summary>
/// <remarks>
/// <para>
/// There is deliberately no password-arm counterpart record. ADMIN role on an NV Index is policy-session-only:
/// clause 31.15.1 states unconditionally that "this command requires that a policy session be used for
/// authorization of nvIndex so that the ADMIN role may be asserted", and an NV Index — unlike an object, whose
/// <c>TPMA_OBJECT.adminWithPolicy</c> may be CLEAR — has no attribute that could open an authValue fallback
/// (Part 1, clause 17.2 versus clause 35.2.3). The wire shape of a <c>TPMS_AUTH_COMMAND</c> is identical for
/// every session kind, so this one record carries whatever the caller sent and the transition answers
/// <c>TPM_RC_AUTH_TYPE</c> for a <c>TPM_RS_PW</c> or HMAC session.
/// </para>
/// <para>
/// <see cref="HasDecryptSlot"/> is set when the caller supplied a SECOND session at all; whether that session
/// protects <see cref="NewAuth"/> in flight is its own <c>decrypt</c> attribute's business (Part 1, clause 19.1:
/// <c>newAuth</c> is the sole, and therefore first, sized command parameter, so it is encryptable). A decrypting
/// second session is never the authorizing session itself — a policy session that also carried <c>decrypt</c>
/// would derive its encryption key from the very authValue being rotated away from (clause 19.1's own Note), so
/// that shape is refused rather than modelled.
/// </para>
/// </remarks>
/// <param name="NvIndex">The NV Index whose authorization value is replaced — the sole handle, and so cpHash's only Name term.</param>
/// <param name="AuthorizingSessionHandle">The session presented to authorize <paramref name="NvIndex"/>; only a policy session can satisfy the ADMIN role.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HasDecryptSlot">
/// Whether the authorization area actually carried a second slot. The parser decides this structurally, from the
/// octets left inside <c>authorizationSize</c> once the authorizing slot has been read, and nothing downstream
/// re-derives it from a handle value: a block naming any handle at all is a block the caller sent, and it must
/// be resolved, validated, and answered with a response entry whatever it names (TPM 2.0 Library Part 3, clause
/// 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="DecryptSessionHandle">
/// The separate decrypt session's handle. Meaningful only when <paramref name="HasDecryptSlot"/> is set:
/// presence is a structural fact of the wire and is never inferred from this value, including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot's index rather than read as an absent slot.
/// </param>
/// <param name="DecryptNonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the shared empty carrier when <paramref name="HasDecryptSlot"/> is clear. The decrypt effect only BORROWS it. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting tail TRANSFERS it into that slot's response entry, whose framing effect releases it.</param>
/// <param name="DecryptSessionAttributes">The decrypt session's command session-attributes octet. Meaningful only when <paramref name="HasDecryptSlot"/> is set.</param>
/// <param name="DecryptHmac">The decrypt session's supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), verified like every other session in the area (Part 3, clause 5.6), in a pooled carrier this record OWNS, rented as the parse's last act; the shared empty carrier when <paramref name="HasDecryptSlot"/> is clear. The accepting tail is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>newAuth</c> wire bytes exactly as received — cpHash's <c>parameters</c> term, still carrying ciphertext when a decrypt session is present. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="NewAuth">
/// The parsed <c>newAuth</c> value in an owned <see cref="Tpm2bAuth"/> carrier rented at parse time holding
/// the wire-exact octets — the plaintext replacement authValue only when no decrypt session accompanied the
/// command (ciphertext otherwise, in which case the decrypt effect's output supersedes it). Ownership
/// transfers to the Index at install on the plaintext path; every other terminal arm disposes it.
/// </param>
/// <param name="ResolvedIndexName">The Index's computed Name; see <see cref="TpmNvReadOverSessionRequested.ResolvedIndexName"/>.</param>
/// <param name="ResolvedAuthValue">
/// The authValue term folded into the command HMAC key: a borrowed reference to the Index's CURRENT
/// (pre-rotation) authValue carrier when the authorizing policy session asserted
/// <c>TPM2_PolicyAuthValue()</c> (the HMAC primitive takes its trailing-zero-stripped view), and the shared
/// empty carrier otherwise (Part 1, clause 17.6.5's policy Note). Resolved once the Index's Name is known
/// and threaded onward; <see langword="null"/> (the parse-time default) until then, read as empty. The
/// RESPONSE HMAC deliberately does not reuse it — the rotation commits first, so the response is keyed on
/// the new value (clause 31.15.1).
/// </param>
public sealed record TpmNvChangeAuthOverSessionRequested(
    TpmiRhNvIndex NvIndex,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    bool HasDecryptSlot,
    TpmiShAuthSession DecryptSessionHandle,
    Tpm2bNonce DecryptNonceCaller,
    TpmaSession DecryptSessionAttributes,
    Tpm2bAuth DecryptHmac,
    TpmParameterArea RawParameterArea,
    Tpm2bAuth NewAuth,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NewAuth"/> carrier on a refusing path (or, on the decrypted path,
    /// once the decrypt effect's own output supersedes the ciphertext it holds); the plaintext installing
    /// path transfers its ownership to the Index instead. <see cref="RawParameterArea"/> and
    /// <see cref="ResolvedIndexName"/> are owned outright and always released here, as are both slots'
    /// credential carriers. <see cref="ResolvedAuthValue"/> is a borrow and is never touched here.
    /// </summary>
    /// <remarks>
    /// Each slot's two credentials are owned outright from the parse until a terminal arm takes them, and only
    /// the accepting tail takes them: it disposes both hmacs per carrier once the verification queue is done
    /// with them, and transfers each slot's caller nonce into that slot's response entry.
    /// </remarks>
    public void Dispose()
    {
        NewAuth.Dispose();
        RawParameterArea.Dispose();
        ResolvedIndexName.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
        DecryptNonceCaller.Dispose();
        DecryptHmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmComputeNvIndexNameAction"/>: an NV Index's computed Name, fed back
/// so the transition can build cpHash's Name1/Name2 terms and resolve the bind-omission-decided authValue for a
/// session-authorized NV command (TPM 2.0 Library Part 1, clause 16.7 equation 15; clause 17.6.10 equations
/// 21/22). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Name">The Index's computed Name in an owned <c>TPM2B_NAME</c> carrier (TPM 2.0 Library Part 2, clause 10.5.3, Table 104); <c>OnNvIndexNameComputed</c> TRANSFERS it onto the request being resumed, which holds it while the command HMAC is verified against a cpHash whose Name terms read it.</param>
/// <param name="Resume">The original session-authorized NV request to resume once the command-HMAC verification this feeds completes; its carriers are transferred onward by <c>OnNvIndexNameComputed</c> into that verification action and are never owned by this record.</param>
/// <remarks>
/// The record carries <see cref="Name"/> for the one step between the Name-computing effect and the resume
/// transition, which TRANSFERS it onto the resumed request; the request's <c>Dispose</c> is then the carrier's
/// terminal owner. The record itself is never disposed — a resume shape the transition does not recognize
/// releases <see cref="Name"/> explicitly on that arm — so a generic disposal here would release a carrier the
/// request already owns.
/// </remarks>
public sealed record TpmNvIndexNameComputed(
    Tpm2bName Name,
    TpmSimulatorInput Resume): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmFrameNvSessionResponseAction"/>: the rolled nonceTPM, framed
/// response parameter bytes (empty for <c>TPM2_NV_Write()</c>/<c>TPM2_NV_DefineSpace()</c>/
/// <c>TPM2_NV_UndefineSpace()</c>/<c>TPM2_NV_Increment()</c> and for every hierarchy and provisioning command,
/// or the read <c>TPM2B_MAX_NV_BUFFER</c> for <c>TPM2_NV_Read()</c>), and
/// response HMAC for a session-authorized command, fed back so the transition can roll the authorizing
/// session's stored nonceTPM and frame the response (TPM 2.0 Library Part 1, clause 16.6.1). Internal to the
/// effect loop; never arrives from the command transport.
/// </summary>
/// <param name="SessionHandle">The authorizing HMAC session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed as this entry's nonceNewer; ownership travels into the response intent, whose serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier the framing effect rents alongside <paramref name="NewNonceTpm"/>; the rolling transition transfers it onto the durable session record, and disposes it itself when the session has already left its table. Two carriers because the two owners' lifetimes are disjoint.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="ParameterArea">The framed response parameter bytes; disposed after framing.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154); owned, disposed after framing.</param>
public sealed record TpmNvSessionResponseFramed(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    TpmParameterArea ParameterArea,
    Tpm2bAuth Hmac): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptNvChangeAuthAction"/>: <c>TPM2_NV_ChangeAuth()</c>'s
/// <c>newAuth</c> first command parameter has been decrypted (TPM 2.0 Library Part 3, clause 31.15; Part 1,
/// clause 19.1) and its plaintext value read back, so the completing transition can size-check and install it as
/// the Index's authorization value. Reached strictly after every session in the authorization area has verified
/// (Part 3, clause 5.6 precedes clause 5.8). Internal to the effect loop; never arrives from the command
/// transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the encrypted <c>newAuth</c> parameter's own size field was consistent; otherwise the rejection (a wrong decryption key cannot itself be detected here — a corrupted authValue merely fails a later authorization).</param>
/// <param name="Request">The original parsed request, threaded through so the completing transition can rotate the authValue and frame the response.</param>
/// <param name="DecryptedNewAuth">The decrypted (plaintext) replacement authorization value in an owned <see cref="Tpm2bAuth"/> carrier rented by the decrypt effect, its trailing zeros NOT yet removed — the completing transition takes the stripped view for the size check (Part 1, clause 17.6.4.3), then transfers ownership to the Index at install; every refusing arm disposes it instead. The shared empty carrier on failure.</param>
public sealed record TpmNvChangeAuthDecrypted(
    TpmRcConstants ResponseCode,
    TpmNvChangeAuthOverSessionRequested Request,
    Tpm2bAuth DecryptedNewAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="DecryptedNewAuth"/> carrier and the threaded <see cref="Request"/>'s
    /// own carriers on a refusing path; the installing path transfers <see cref="DecryptedNewAuth"/> to the
    /// Index and releases the request's superseded ciphertext carrier itself.
    /// </summary>
    public void Dispose()
    {
        DecryptedNewAuth.Dispose();
        Request.Dispose();
    }
}

/// <summary>
/// One session's material for framing an authValue rotation's response entry — <c>TPM2_NV_ChangeAuth()</c> or
/// <c>TPM2_HierarchyChangeAuth()</c>: the effect rolls a fresh nonceTPM and computes a real response HMAC for
/// it, or emits the empty-nonce, empty-HMAC placeholder a <c>TPM_RS_PW</c> slot is owed. The NV-family
/// counterpart of <see cref="TpmCreateResponseSession"/>, needed because <c>TPM2_NV_ChangeAuth()</c> is the
/// first NV command whose authorization area can carry two sessions (the ADMIN policy session and a separate
/// decrypt session), each of which is owed its own entry (Part 1, clause 16.6.1).
/// </summary>
/// <param name="IsPasswordPlaceholder">
/// Whether this entry is a <c>TPM_RS_PW</c> slot's placeholder — an empty nonceTPM, the echoed attributes, and
/// an empty HMAC (Part 1, clause 17.6.4.1: a password authorization carries no session key to compute one with).
/// <paramref name="SessionAlg"/>, <paramref name="SessionKey"/>, and <paramref name="AuthValue"/> are
/// meaningless when it is set. Only <c>TPM2_HierarchyChangeAuth()</c> can ever set it: the NV rotation's
/// authorizing slot must be a policy session (Part 3, clause 5.6, check 5.2), never a password.
/// </param>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="IsPolicySession">Whether this session lives in the policy-session table rather than the HMAC-session table, which decides where the rolled nonce is stored and whether the policy context resets alongside it.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">
/// The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed
/// reference to the carrier the durable state owns (the effect reads its trailing-zero-stripped view at
/// the HMAC primitive and never disposes it). For the authorizing session this is the NEW authValue's
/// carrier whenever one is folded at all — the rotation commits before the response is generated, so the
/// response HMAC key is not the one the command HMAC used (Part 3, clause 31.15.1 for an NV Index, clause
/// 24.8.1 for a hierarchy) — and the shared empty carrier otherwise; for a decrypt session, which
/// authorizes no entity, it is always the shared empty carrier.
/// </param>
/// <param name="NonceCaller">This session's command caller nonce (the response HMAC's nonceOlder), in a pooled carrier this ENTRY owns: the completing tail transferred it out of the request record, and the framing effect releases it in its <c>finally</c>. A password placeholder carries the shared empty carrier, which owns nothing.</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
public sealed record TpmNvChangeAuthResponseSession(
    bool IsPasswordPlaceholder,
    TpmiShAuthSession SessionHandle,
    bool IsPolicySession,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes);

/// <summary>
/// One session's framed authValue-rotation response entry — the rolled nonceTPM and computed response HMAC
/// produced from a <see cref="TpmNvChangeAuthResponseSession"/>, or the empty-nonce, empty-HMAC placeholder for
/// a <c>TPM_RS_PW</c> slot.
/// </summary>
/// <param name="IsPasswordPlaceholder">Whether this entry is a password slot's placeholder; <paramref name="Hmac"/> is then <see langword="null"/> and both nonce carriers are the dispose-immune shared empty.</param>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>; meaningless for a placeholder.</param>
/// <param name="IsPolicySession">Whether the rolled nonce belongs in the policy-session table, carried through from <see cref="TpmNvChangeAuthResponseSession.IsPolicySession"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed as this entry's nonceNewer; the serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; the rolling transition transfers it onto the durable session record, and disposes it itself when that session has already left its table.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154), owned and disposed after framing; <see langword="null"/> for a placeholder, which owns nothing.</param>
public sealed record TpmNvChangeAuthFramedSessionEntry(
    bool IsPasswordPlaceholder,
    TpmiShAuthSession SessionHandle,
    bool IsPolicySession,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth? Hmac);

/// <summary>
/// The result of executing a <see cref="Automata.TpmFrameNvChangeAuthResponseAction"/>: every session's framed
/// response entry, fed back so the transition can roll each session's stored nonce (and reset the authorizing
/// policy session's context) and frame the response. Internal to the effect loop; never arrives from the command
/// transport.
/// </summary>
/// <remarks>
/// There is no parameter area: <c>TPM2_NV_ChangeAuth()</c>'s response carries no parameters at all (TPM 2.0
/// Library Part 3, clause 31.15, Table 253), so rpHash covers the empty parameter area and the entries are the
/// whole of what the response adds beyond its header.
/// </remarks>
/// <param name="Entries">Every session's framed response entry, in command-session order; each real entry owns its own <c>Hmac</c> buffer, released after framing, while a password placeholder owns none.</param>
public sealed record TpmNvChangeAuthResponseFramed(
    ImmutableArray<TpmNvChangeAuthFramedSessionEntry> Entries): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_EvictControl()</c> command (TPM 2.0 Library Part 3, clause 28.5). Persists a loaded transient
/// object to a persistent handle, or evicts a persistent object addressed by that handle.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the operation (<c>TPMI_RH_PROVISION</c>: <c>TPM_RH_OWNER</c> or <c>TPM_RH_PLATFORM</c>).</param>
/// <param name="SuppliedAuthPassword">
/// The plaintext authorization value the caller supplied for the provisioning-hierarchy slot (the password
/// session's <c>hmac</c> field), compared against the named hierarchy's retained authorization value — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="ObjectHandle">The transient object to persist, or the persistent handle to evict.</param>
/// <param name="PersistentHandle">The persistent handle to assign (when persisting) or evict (when <paramref name="ObjectHandle"/> is already persistent).</param>
public sealed record TpmEvictControlRequested(
    TpmiRhProvision AuthHandle,
    Tpm2bAuth SuppliedAuthPassword,
    TpmiDhObject ObjectHandle,
    TpmiDhPersistent PersistentHandle): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedAuthPassword"/> carrier on a refusing path; the consuming
    /// transition instead releases it itself once the hierarchy compare has consumed it, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedAuthPassword.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmRngAction"/>: the random octets produced by the RNG
/// backend, fed back into the automaton by the effectful loop so the transition can frame the
/// <c>TPM2_GetRandom()</c> response. This input is internal to the effect loop and never arrives from
/// the command transport.
/// </summary>
/// <param name="Bytes">
/// The produced octets in an owned <c>TPM2B_DIGEST</c> carrier, the type Table 72 gives
/// <c>randomBytes</c> (TPM 2.0 Library Part 2, clause 10.4.2, Table 92). Ownership flows to the
/// <see cref="TpmRandomResponse"/> the transition produces and is released by <see cref="TpmSimulator"/>
/// once the response is framed.
/// </param>
public sealed record TpmRandomGenerated(Tpm2bDigest Bytes): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command (TPM 2.0 Library Part 3, clause 24.1). Creates a primary signing
/// key in a hierarchy and returns its public area. Only the template fields the simulator's ECC signing
/// model carries are retained; the sensitive area, outsideInfo, and creation PCR selection are consumed
/// during parsing but not modelled.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="SuppliedHierarchyPassword">
/// The plaintext authorization value the caller supplied for the hierarchy slot (the password session's
/// <c>hmac</c> field), compared against the named hierarchy's retained authorization value — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="NameAlg">The Name algorithm carried in the public area (the hash whose digest forms the object Name).</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, echoed into the exported public area.</param>
/// <param name="Curve">The ECC curve the key is generated on.</param>
/// <param name="SchemeHashAlg">The ECDSA signing scheme's hash algorithm.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the template (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty when the key is authorized by its authValue alone), re-emitted into the exported public area. An owned pooled carrier rented at parse; the creation effect transfers it onto the durable key state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="UserAuth">The new object's authorization value from <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 17.6.4), an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the creation effect transfers it onto the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
public sealed record TpmCreatePrimaryRequested(
    TpmiRhHierarchy Hierarchy,
    Tpm2bAuth SuppliedHierarchyPassword,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    TpmiAlgHash SchemeHashAlg,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedHierarchyPassword"/>, <see cref="AuthPolicy"/> and
    /// <see cref="UserAuth"/> carriers on a refusing path. The consuming transition instead releases the
    /// password itself once the hierarchy compare has consumed it and threads the other two into the create
    /// action, whose effect installs them on the durable key state, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedHierarchyPassword.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an RSA signing key (TPM 2.0 Library Part 3, clause 24.1) — the
/// RSA counterpart of <see cref="TpmCreatePrimaryRequested"/>. Only the template fields the simulator's RSA
/// signing model carries are retained.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="SuppliedHierarchyPassword">
/// The plaintext authorization value the caller supplied for the hierarchy slot (the password session's
/// <c>hmac</c> field), compared against the named hierarchy's retained authorization value — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="NameAlg">The Name algorithm carried in the public area (the hash whose digest forms the object Name).</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, echoed into the exported public area.</param>
/// <param name="KeyBits">The RSA modulus size in bits the template requests.</param>
/// <param name="Scheme">The RSA signing scheme carried in the template.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the template (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty when the key is authorized by its authValue alone), re-emitted into the exported public area. An owned pooled carrier rented at parse; the creation effect transfers it onto the durable key state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="UserAuth">The new object's authorization value from <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 17.6.4), an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the creation effect transfers it onto the durable key state. The dispose-immune empty sentinel for an authValue-free key.</param>
public sealed record TpmCreateRsaPrimaryRequested(
    TpmiRhHierarchy Hierarchy,
    Tpm2bAuth SuppliedHierarchyPassword,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    TpmtRsaScheme Scheme,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedHierarchyPassword"/>, <see cref="AuthPolicy"/> and
    /// <see cref="UserAuth"/> carriers on a refusing path. The consuming transition instead releases the
    /// password itself once the hierarchy compare has consumed it and threads the other two into the create
    /// action, whose effect installs them on the durable key state, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedHierarchyPassword.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Sign()</c> command (TPM 2.0 Library Part 3, clause 20.2) over an externally-computed digest
/// with a NULL validation ticket. Signs the digest with a loaded transient signing key.
/// </summary>
/// <param name="KeyHandle">The handle of the signing key (a transient object created by <c>TPM2_CreatePrimary()</c>).</param>
/// <param name="SuppliedKeyPassword">
/// The plaintext authorization value the caller supplied for the signing-key slot (the password session's
/// <c>hmac</c> field), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the key-slot compare has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="Digest">The pre-computed digest to sign (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), in an owned pooled carrier rented as the parse's last act; the consuming transition transfers it into the signing action, whose effect is its terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="SignatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm, reported back inside the signature.</param>
public sealed record TpmSignRequested(
    TpmiDhObject KeyHandle,
    Tpm2bAuth SuppliedKeyPassword,
    Tpm2bDigest Digest,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedKeyPassword"/> and <see cref="Digest"/> carriers on a refusing
    /// path; the consuming transition instead releases the password itself once the key-slot compare has
    /// consumed it and threads the digest into the signing action, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedKeyPassword.Dispose();
        Digest.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmCreateEccKeyAction"/>: the exported public area and the durable
/// transient-key state the effectful loop produced from the generated key, fed back so the transition can
/// store the object and frame the <c>TPM2_CreatePrimary()</c> response. Internal to the effect loop; never
/// arrives from the command transport.
/// </summary>
/// <param name="OutPublic">
/// The exported public area carrying the generated point. Ownership flows to the
/// <c>TpmCreatePrimaryResponse</c> the transition produces and is released by <see cref="TpmSimulator"/>
/// once the response is framed.
/// </param>
/// <param name="KeyState">The durable transient-key state to store under its handle.</param>
/// <param name="CreationData">
/// The creation data the object was created with (<c>TPM2B_CREATION_DATA</c>, TPM 2.0 Library Part 2, clause
/// 15.2, Table 247) in an owned pooled carrier; ownership flows to the response intent and is released by
/// <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="CreationHash">
/// The Name-algorithm digest of <paramref name="CreationData"/> (<c>TPM2B_DIGEST</c>, Part 2, clause 10.4.2,
/// Table 92) in an owned pooled carrier, released with the rest of the by-products once the response is framed.
/// </param>
/// <param name="CreationTicket">
/// The creation ticket binding the creation data to the object (<c>TPMT_TK_CREATION</c>, Part 2, clause 10.7.3,
/// Table 109) in an owned pooled carrier, released with the rest of the by-products once the response is framed.
/// </param>
/// <param name="Name">
/// The created object's Name (<c>TPM2B_NAME</c>, Part 1, clause 14, Table 6) in an owned pooled carrier of its own —
/// separate from the copy the key state retains, so neither owner's disposal reaches the other's octets — and
/// released once the response is framed.
/// </param>
public sealed record TpmPrimaryKeyCreated(
    Tpm2bPublic OutPublic,
    TransientKeyState KeyState,
    Tpm2bCreationData CreationData,
    Tpm2bDigest CreationHash,
    TpmtTkCreation CreationTicket,
    Tpm2bName Name): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmEccSignAction"/> or <see cref="TpmRsaSignAction"/>: the produced
/// signature, fed back so the transition can frame the <c>TPM2_Sign()</c> response. Internal to the effect
/// loop; never arrives from the command transport.
/// </summary>
/// <param name="Signature">
/// The <c>TPMT_SIGNATURE</c> — its selector, hash algorithm, and the ECDSA <c>r</c>/<c>s</c> pair or the RSA
/// signature. Ownership flows to the <c>TpmSignResponse</c> the transition produces and is released by
/// <see cref="TpmSimulator"/> once the response is framed.
/// </param>
public sealed record TpmMessageSigned(TpmtSignature Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an ECC restricted storage key (TPM 2.0 Library Part 3, clause
/// 24.1) — a key that can act as the parent of <c>TPM2_Create()</c>. It is the parent-provisioning half of the
/// seal flow: the simulator models the storage parent as a handle-bearing restricted-storage object so a
/// subsequent <c>TPM2_Create()</c> / <c>TPM2_Load()</c> can resolve its parent and verify the parent's storage
/// attributes. The simulator does not wrap children under a parent key (it has no parent symmetric-key custody),
/// so the parent needs no generated key material; its exported public area is the storage template.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="SuppliedHierarchyPassword">
/// The plaintext authorization value the caller supplied for the hierarchy slot (the password session's
/// <c>hmac</c> field), compared against the named hierarchy's retained authorization value — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="NameAlg">The Name algorithm carried in the exported public area.</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, including <c>RESTRICTED</c> and <c>DECRYPT</c> (a storage key).</param>
/// <param name="Curve">The ECC curve the storage template names.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the template (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause
/// 10.4.2, Table 92; empty for the generic storage parent; a standard endorsement key's "PolicyA" for
/// <see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForEndorsementKey"/>), re-emitted into
/// the exported public area. An owned pooled carrier rented at parse; the creation effect transfers it onto the
/// durable key state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="UserAuth">The new object's authorization value from <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 17.6.4), an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the creation effect transfers it onto the durable key state. The dispose-immune empty sentinel for an authValue-free parent.</param>
public sealed record TpmCreateStorageParentRequested(
    TpmiRhHierarchy Hierarchy,
    Tpm2bAuth SuppliedHierarchyPassword,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiEccCurve Curve,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedHierarchyPassword"/>, <see cref="AuthPolicy"/> and
    /// <see cref="UserAuth"/> carriers on a refusing path. The consuming transition instead releases the
    /// password itself once the hierarchy compare has consumed it and threads the other two into the create
    /// action, whose effect installs them on the durable key state, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedHierarchyPassword.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_CreatePrimary()</c> command for an RSA restricted storage key (TPM 2.0 Library Part 3, clause 24.1)
/// — the RSA counterpart of <see cref="TpmCreateStorageParentRequested"/>, including the standard RSA
/// endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1). Unlike the RSA signing path
/// (<see cref="TpmCreateRsaPrimaryRequested"/>), the effectful loop retains the generated public modulus on the
/// durable key state so a later RSA-OAEP secret-transport command can use it.
/// </summary>
/// <param name="Hierarchy">The hierarchy authorizing the creation (<c>TPM_RH_ENDORSEMENT</c> for the standard EK).</param>
/// <param name="SuppliedHierarchyPassword">
/// The plaintext authorization value the caller supplied for the hierarchy slot (the password session's
/// <c>hmac</c> field), compared against the named hierarchy's retained authorization value — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="NameAlg">The Name algorithm carried in the exported public area.</param>
/// <param name="Attributes">The object attributes (<c>TPMA_OBJECT</c>) the template requests, including <c>RESTRICTED</c> and <c>DECRYPT</c> (a storage key).</param>
/// <param name="KeyBits">The RSA modulus size in bits the template requests.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="AuthPolicy">
/// The authorization policy digest carried in the template (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause
/// 10.4.2, Table 92; empty for a generic RSA storage parent; a standard RSA endorsement key's "PolicyA" for
/// <see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForRsaEndorsementKey"/>), re-emitted into
/// the exported public area. An owned pooled carrier rented at parse; the creation effect transfers it onto the
/// durable key state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="UserAuth">The new object's authorization value from <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 17.6.4), an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the creation effect transfers it onto the durable key state. The dispose-immune empty sentinel for an authValue-free parent.</param>
public sealed record TpmCreateRsaStorageParentRequested(
    TpmiRhHierarchy Hierarchy,
    Tpm2bAuth SuppliedHierarchyPassword,
    TpmiAlgHash NameAlg,
    TpmaObject Attributes,
    TpmiRsaKeyBits KeyBits,
    bool NoDa,
    Tpm2bDigest AuthPolicy,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedHierarchyPassword"/>, <see cref="AuthPolicy"/> and
    /// <see cref="UserAuth"/> carriers on a refusing path. The consuming transition instead releases the
    /// password itself once the hierarchy compare has consumed it and threads the other two into the create
    /// action, whose effect installs them on the durable key state, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedHierarchyPassword.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Create()</c> command that seals caller-supplied data into a KEYEDHASH object under a loaded storage
/// parent (TPM 2.0 Library Part 3, clause 12.1). The object is returned as a wrapped private blob plus its public
/// area; the TPM stores nothing, so the caller persists the blob and reloads it with <c>TPM2_Load()</c>.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent under which the object is sealed.</param>
/// <param name="SuppliedParentPassword">
/// The plaintext authorization value the caller supplied for the parent slot (the password session's
/// <c>hmac</c> field), compared against the parent's retained <see cref="TransientKeyState.AuthValue"/> —
/// both sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded.
/// An owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal
/// owner, releasing it once the parent-slot compare has consumed it. The dispose-immune empty sentinel for an
/// empty password.
/// </param>
/// <param name="NameAlg">The Name algorithm carried in the sealed object's public area.</param>
/// <param name="AuthPolicy">The authorization policy digest bound to the object (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty when the seal is authorized by its authValue alone), re-emitted into the exported public area. An owned pooled carrier rented at parse; the sealing effect transfers it onto the durable sealed-object state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NoDa">Whether the template sets <c>TPMA_OBJECT.noDA</c>, re-derived so the exported public area reproduces the caller's template.</param>
/// <param name="UserWithAuth">Whether the template sets <c>TPMA_OBJECT.userWithAuth</c>, re-derived so the exported public area reproduces the caller's template (TPM 2.0 Library Part 3, clause 5.6, check 7.1).</param>
/// <param name="SecretData">The data to seal, an owned pooled <see cref="Tpm2bSensitiveData"/> carrier rented at parse; the seal effect packs it into the wrapped private blob and releases it.</param>
/// <param name="UserAuth">The authorization value supplied in <c>inSensitive.userAuth</c> (TPM 2.0 Library Part 1, clause 17.6.4), an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the seal effect packs it through the wrapped private blob — so a later <c>TPM2_Load()</c> recovers it onto the sealed object's state — and releases it. The dispose-immune empty sentinel for an authValue-free seal.</param>
public sealed record TpmCreateSealedObjectRequested(
    TpmiDhObject ParentHandle,
    Tpm2bAuth SuppliedParentPassword,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedParentPassword"/>, <see cref="AuthPolicy"/>,
    /// <see cref="SecretData"/> and <see cref="UserAuth"/> carriers on a refusing path. The consuming
    /// transition instead releases the password itself once the parent-slot compare has consumed it and
    /// threads the other three into the seal action, whose effect packs the sensitive pair into the wrapped
    /// private blob and hands the policy digest onto the durable sealed-object state, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedParentPassword.Dispose();
        SecretData.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Load()</c> command that brings a wrapped sealed data object back into a transient slot under the
/// storage parent that produced it (TPM 2.0 Library Part 3, clause 12.2). The simulator recovers the sealed data
/// from its own private-blob encoding (it does not model parent-key unwrapping), stores the loaded object, and
/// returns its transient handle and Name.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent that wrapped the object.</param>
/// <param name="SuppliedParentPassword">
/// The plaintext authorization value the caller supplied for the parent slot (the password session's
/// <c>hmac</c> field), compared against the parent's retained <see cref="TransientKeyState.AuthValue"/> —
/// both sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded.
/// An owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal
/// owner, releasing it once the parent-slot compare has consumed it. The dispose-immune empty sentinel for an
/// empty password.
/// </param>
/// <param name="ObjectType">The public area's object type; only a sealed <c>TPM_ALG_KEYEDHASH</c> object is modelled this slice.</param>
/// <param name="NameAlg">The Name algorithm carried in the public area, used to compute the object Name.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty when the object is authorized by its authValue alone), retained on the loaded object so a policy-gated <c>TPM2_Unseal()</c> can check it. An owned pooled carrier rented at parse; the load effect transfers it onto the durable sealed-object state, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, retained on the loaded object to decide dictionary-attack protection (TPM 2.0 Library Part 2, clause 8.3.3).</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, retained on the loaded object to decide whether an HMAC session or password may authorize a USER-role action against it (TPM 2.0 Library Part 3, clause 5.6, check 7.1).</param>
/// <param name="InPublic">
/// The public area the caller supplied (<c>TPM2B_PUBLIC</c>, TPM 2.0 Library Part 2, clause 12.2.5, Table 220;
/// Part 3, clause 12.2's <c>inPublic</c> parameter) in the owned pooled carrier the parse built, kept whole so
/// the marshaled <c>TPMT_PUBLIC</c> the object Name is hashed over stays in pooled memory rather than being
/// flattened to the heap. The accepted arm transfers it into <see cref="Automata.TpmLoadObjectAction"/>, whose
/// effect is its terminal owner once the Name is computed; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PrivateBlob">The wrapped private blob carrying the authorization value and the sealed data (the simulator's own encoding of the sensitive area).</param>
public sealed record TpmLoadObjectRequested(
    TpmiDhObject ParentHandle,
    Tpm2bAuth SuppliedParentPassword,
    TpmiAlgPublic ObjectType,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bPublic InPublic,
    ReadOnlyMemory<byte> PrivateBlob): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedParentPassword"/>, <see cref="AuthPolicy"/> and
    /// <see cref="InPublic"/> carriers on a refusing path; the consuming transition instead releases the
    /// password itself once the parent-slot compare has consumed it and threads the policy digest and the public
    /// area into the load action, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedParentPassword.Dispose();
        AuthPolicy.Dispose();
        InPublic.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) that recovers the data sealed in a loaded
/// KEYEDHASH object, authorized by a plain <c>TPM_RS_PW</c> password session. The object must be loaded (its
/// transient handle is the command handle).
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
/// <param name="SuppliedPassword">
/// The plaintext authorization value the caller supplied (the password session's <c>hmac</c> field), compared
/// against the object's retained <see cref="SealedObjectState.UserAuth"/> — both sides trailing-zero-stripped
/// (TPM 2.0 Library Part 1, clause 17.6.4) — rather than discarded. It is the same <c>TPM2B_AUTH</c> wire field a
/// real session carries an HMAC in (Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an
/// EmptyAuth"), in a pooled carrier this record OWNS, rented as the parse's last act. The authorizing
/// transition is its terminal owner; every refusing path releases it through
/// <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmUnsealRequested(TpmiDhObject ItemHandle, Tpm2bAuth SuppliedPassword): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedPassword"/> carrier on a refusing path; the authorizing transition
    /// disposes it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        SuppliedPassword.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Unseal()</c> command (TPM 2.0 Library Part 3, clause 12.7) whose first session is either a satisfied
/// policy session or a bound HMAC session (the primary authorizer, USER role), optionally carrying a second bound
/// HMAC session with the <c>encrypt</c> attribute that protects the recovered <c>outData</c> (Part 1, clauses 16.7
/// and 19). Session 1's kind is resolved in the transition, not the parser (its handle may name either table):
/// a policy session's accumulated policyDigest authorizes the object directly (empty-HMAC authorization, the
/// policy itself is the authorization, Part 1, clause 17.6); an HMAC session is verified
/// by the shared command-HMAC helper with authValue = the object's <see cref="SealedObjectState.UserAuth"/> (Part
/// 3, clause 5.6). A present session 2 is always a bound HMAC session and is verified the same way, with no entity
/// (it authorizes nothing).
/// </summary>
/// <param name="ItemHandle">The transient handle of the loaded sealed data object.</param>
/// <param name="FirstSession">The first session's handle (a policy session or an HMAC session).</param>
/// <param name="FirstNonceCaller">The first session's caller nonce rolled for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act — the cpHash's per-session nonceNewer when the first session is an HMAC session. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the continuation that builds this slot's response-session entry TRANSFERS it there, and the branches that build no entry for the slot — the policy-only exit and a policy session sitting ahead of an encrypt slot — release it at the arm.</param>
/// <param name="PolicyAttributes">The first session's command session-attributes octet, echoed into its response session entry.</param>
/// <param name="FirstHmac">The first session's supplied <c>hmac</c> field (<c>TPM2B_AUTH</c>, Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Ignored when the first session is a policy session (its own command-HMAC verification is out of scope here). Everything downstream BORROWS it, so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HasEncryptSlot">
/// Whether the authorization area actually carried a second slot. The parser decides this structurally, from the
/// octets left inside <c>authorizationSize</c> once the first slot has been read, and nothing downstream
/// re-derives it from a handle value: a block naming any handle at all is a block the caller sent, and it must
/// be resolved, validated, and answered with a response entry whatever it names (TPM 2.0 Library Part 3, clause
/// 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="EncryptSession">
/// The second slot's session handle — the bound HMAC session whose <c>encrypt</c> attribute protects the
/// recovered <c>outData</c>. Meaningful only when <paramref name="HasEncryptSlot"/> is set: presence is a
/// structural fact of the wire and is never inferred from this value, including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot's index rather than read as an absent slot.
/// </param>
/// <param name="EncryptNonceCaller">The encrypt session's caller nonce rolled for this command (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2). The empty sentinel when there is no encrypt session. Released and transferred exactly as <paramref name="FirstNonceCaller"/> is.</param>
/// <param name="EncryptAttributes">The encrypt session's command session-attributes octet, echoed into the response session area and folded into the response HMAC. Zero when there is no encrypt session.</param>
/// <param name="EncryptHmac">The encrypt session's supplied <c>hmac</c> field (<c>TPM2B_AUTH</c>, Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act; the empty sentinel when there is no encrypt session. Borrowed downstream, terminal at the accepting continuation, exactly as <paramref name="FirstHmac"/> is.</param>
public sealed record TpmUnsealOverSessionsRequested(
    TpmiDhObject ItemHandle,
    TpmiShAuthSession FirstSession,
    Tpm2bNonce FirstNonceCaller,
    TpmaSession PolicyAttributes,
    Tpm2bAuth FirstHmac,
    bool HasEncryptSlot,
    TpmiShAuthSession EncryptSession,
    Tpm2bNonce EncryptNonceCaller,
    TpmaSession EncryptAttributes,
    Tpm2bAuth EncryptHmac): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases both slots' credential and caller-nonce carriers on every path that does not frame the
    /// command's response.
    /// </summary>
    /// <remarks>
    /// The four session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes both hmacs per carrier once the verification queue is
    /// done with them, and transfers each slot's caller nonce into that slot's response-session entry — or
    /// releases the nonce at the arm where no entry is built for the slot.
    /// </remarks>
    public void Dispose()
    {
        FirstNonceCaller.Dispose();
        FirstHmac.Dispose();
        EncryptNonceCaller.Dispose();
        EncryptHmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmUnsealDataAction"/>: the framed (possibly encrypted) response parameter
/// area and every real session's framed response entry, fed back so the transition can roll each session's stored
/// nonce and frame the response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled carrier the framing step disposes as the terminal owner; each
/// <see cref="TpmUnsealFramedSessionEntry"/> in <see cref="Entries"/> owns its own <c>Hmac</c> buffer the same way.
/// </remarks>
/// <param name="ParameterArea">The framed <c>TPM2B_SENSITIVE_DATA</c> response parameter (<c>outData</c>), its data portion encrypted when a session carries the <c>encrypt</c> attribute; disposed after framing.</param>
/// <param name="HasPolicyPlaceholder">Whether session index 0 needs the zero-nonce, empty-HMAC policy placeholder entry, threaded through from the declaring action.</param>
/// <param name="PolicyNonceLength">The width in octets of the policy session's response nonce (its hash digest width), framed as a zero placeholder. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="PolicyAttributes">The policy session's response session-attributes octet, framed into its response entry. Meaningful only when <see cref="HasPolicyPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the policy placeholder, when present).</param>
public sealed record TpmUnsealedOverSessions(
    TpmParameterArea ParameterArea,
    bool HasPolicyPlaceholder,
    int PolicyNonceLength,
    TpmaSession PolicyAttributes,
    ImmutableArray<TpmUnsealFramedSessionEntry> Entries): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmSealDataAction"/>: the wrapped private blob, the exported public area,
/// and the pre-framed creation by-products the effectful loop produced for a sealed object, fed back so the
/// transition can frame the <c>TPM2_Create()</c> response. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="PrivateBlob">The pooled buffer holding the wrapped private blob; ownership flows to the <c>TpmCreateResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="OutPublic">The exported public area of the sealed object; ownership flows to the <c>TpmCreateResponse</c> and is released once framed.</param>
/// <param name="CreationData">
/// The creation data the object was created with (<c>TPM2B_CREATION_DATA</c>, TPM 2.0 Library Part 2, clause
/// 15.2, Table 247) in an owned pooled carrier; ownership flows to the response intent and is released by
/// <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="CreationHash">
/// The Name-algorithm digest of <paramref name="CreationData"/> (<c>TPM2B_DIGEST</c>, Part 2, clause 10.4.2,
/// Table 92) in an owned pooled carrier, released with the rest of the by-products once the response is framed.
/// </param>
/// <param name="CreationTicket">
/// The creation ticket binding the creation data to the object (<c>TPMT_TK_CREATION</c>, Part 2, clause 10.7.3,
/// Table 109) in an owned pooled carrier, released with the rest of the by-products once the response is framed.
/// </param>
public sealed record TpmObjectSealed(
    Tpm2bPrivate PrivateBlob,
    Tpm2bPublic OutPublic,
    Tpm2bCreationData CreationData,
    Tpm2bDigest CreationHash,
    TpmtTkCreation CreationTicket): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmLoadObjectAction"/>: the object Name the effectful loop computed and
/// the recovered sealed data, fed back so the transition can store the loaded object and frame the
/// <c>TPM2_Load()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Handle">The transient handle the transition allocated for the loaded object.</param>
/// <param name="Name">The object Name (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>) in an owned <c>TPM2B_NAME</c> carrier (TPM 2.0 Library Part 2, clause 10.5.3, Table 104); ownership flows to the <c>TpmLoadResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="RetainedName">The same Name in a SECOND owned <c>TPM2B_NAME</c> carrier the load effect rents alongside <paramref name="Name"/>; ownership transfers to the stored <see cref="SealedObjectState"/> at install, and every refusing arm disposes it instead. Two carriers because the two owners' lifetimes are disjoint — the framed response's carrier dies with the response, the object's lives until eviction — so neither may dispose the other's buffer.</param>
/// <param name="Data">The recovered sealed data in an owned <see cref="Tpm2bSensitiveData"/> carrier rented by the load effect; ownership transfers to the stored <see cref="SealedObjectState"/> at install, and every refusing arm disposes it instead.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in the loaded public area (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty for an authValue-only object), retained on the loaded object for a policy-gated <c>TPM2_Unseal()</c>. An owned pooled carrier the load or seal effect hands on; the installing transition transfers it onto the durable sealed-object state, and the refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NoDa">Whether the loaded public area sets <c>TPMA_OBJECT.noDA</c>, retained on the loaded object to decide dictionary-attack protection.</param>
/// <param name="UserWithAuth">Whether the loaded public area sets <c>TPMA_OBJECT.userWithAuth</c>, retained on the loaded object to decide whether an HMAC session or password may authorize a USER-role action against it (TPM 2.0 Library Part 3, clause 5.6, check 7.1).</param>
/// <param name="UserAuth">The object's authorization value in an owned <see cref="Tpm2bAuth"/> carrier, recovered from the wrapped private blob wire-exact; ownership transfers to the stored <see cref="SealedObjectState"/> at install, and every refusing arm disposes it instead.</param>
public sealed record TpmObjectLoaded(
    TpmiDhObject Handle,
    Tpm2bName Name,
    Tpm2bName RetainedName,
    Tpm2bSensitiveData Data,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the two owned Name carriers and the <see cref="Data"/>/<see cref="AuthPolicy"/>/
    /// <see cref="UserAuth"/> carriers on a refusing path; the installing path transfers
    /// <see cref="RetainedName"/>/<see cref="Data"/>/<see cref="AuthPolicy"/>/<see cref="UserAuth"/> to the
    /// stored <see cref="SealedObjectState"/> and <see cref="Name"/> to the framed response instead.
    /// </summary>
    public void Dispose()
    {
        Name.Dispose();
        RetainedName.Dispose();
        Data.Dispose();
        UserAuth.Dispose();
        AuthPolicy.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Certify()</c> command (TPM 2.0 Library Part 3, clause 18.2): a signing key vouches that an object
/// with a given Name is loaded in the same TPM, over a caller nonce. Both handles require authorization
/// (<c>objectHandle</c> ADMIN role, <c>signHandle</c> USER role — Part 3, clause 18.2, Table 89), so the parser
/// consumes the two password sessions in handle order and retains both supplied values for the transition's
/// per-slot compares.
/// </summary>
/// <param name="ObjectHandle">The loaded object being certified (its Name is the attested binding).</param>
/// <param name="SuppliedObjectPassword">
/// The plaintext authorization value the caller supplied for the certified-object slot (session 0's
/// <c>hmac</c> field), compared against the object's retained <see cref="TransientKeyState.AuthValue"/> — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the object-slot compare has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="SuppliedSignPassword">
/// The plaintext authorization value the caller supplied for the signing-key slot (session 1's <c>hmac</c>
/// field), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both sides
/// trailing-zero-stripped — rather than discarded. An owned pooled <see cref="Tpm2bAuth"/> carrier rented at
/// parse; the consuming transition is its terminal owner. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming transition
/// transfers it into the certify action, whose effect is its terminal owner; every refusing arm releases it
/// through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
public sealed record TpmCertifyRequested(
    TpmiDhObject ObjectHandle,
    Tpm2bAuth SuppliedObjectPassword,
    TpmiDhObject SignHandle,
    Tpm2bAuth SuppliedSignPassword,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — both slots' supplied passwords and the qualifying data — on a
    /// refusing path. The consuming transition instead releases the two passwords itself once the per-slot
    /// compares have consumed them and transfers the qualifying data into the certify action, so it never calls
    /// this.
    /// </summary>
    public void Dispose()
    {
        SuppliedObjectPassword.Dispose();
        SuppliedSignPassword.Dispose();
        QualifyingData.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmCertifyAction"/>: the marshaled <c>TPMS_ATTEST</c> the effectful loop
/// built and the signature over its digest, fed back so the transition can frame the <c>TPM2_Certify()</c>
/// response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmCertifyResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmCertifyResponse</c> and is released once framed.</param>
public sealed record TpmObjectCertified(
    Tpm2bAttest CertifyInfo,
    TpmtSignature Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PCR_Read()</c> command (TPM 2.0 Library Part 3, clause 22.4): reads the current values of the
/// selected Platform Configuration Registers. The command takes no handles and no authorization, so only the
/// selection is parsed.
/// </summary>
/// <param name="SelectionBytes">The <c>TPML_PCR_SELECTION</c> wire bytes, captured verbatim to echo back as <c>pcrSelectionOut</c> and decoded against the PCR bank to gather the values.</param>
public sealed record TpmPcrReadRequested(ReadOnlyMemory<byte> SelectionBytes): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Quote()</c> command (TPM 2.0 Library Part 3, clause 18.4): a signing key attests the composite
/// digest of a selected set of Platform Configuration Registers, over a caller nonce. The single handle requires
/// authorization, so the password session is consumed by the parser and the supplied value is retained for the
/// transition's signing-key compare.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="SuppliedSignPassword">
/// The plaintext authorization value the caller supplied for the signing-key slot (the password session's
/// <c>hmac</c> field), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the sign-slot compare has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming transition
/// transfers it into the quote action, whose effect is its terminal owner; every refusing arm releases it through
/// this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm; the simulator computes both the attest digest and the PCR composite digest with it (TPM 2.0 Library Part 3, clause 18.4).</param>
/// <param name="PcrSelection">
/// The caller's <c>TPML_PCR_SELECTION</c> (TPM 2.0 Library Part 2, clause 10.9.7, Table 125), in an owned pooled
/// carrier rented as the parse's last act — decoded against the PCR bank and echoed into the attested
/// <c>TPMS_QUOTE_INFO.pcrSelect</c>. The consuming transition transfers it into the quote action, whose effect is
/// its terminal owner; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmQuoteRequested(
    TpmiDhObject SignHandle,
    Tpm2bAuth SuppliedSignPassword,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    TpmlPcrSelection PcrSelection): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — the sign slot's supplied password, the qualifying data, and the
    /// PCR selection — on a refusing path. The consuming transition instead releases the password itself once the
    /// sign-slot compare has consumed it and transfers the other two into the quote action, so it never calls
    /// this.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignPassword.Dispose();
        QualifyingData.Dispose();
        PcrSelection.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmQuoteAction"/>: the marshaled <c>TPMS_ATTEST</c> the effectful loop
/// built and the signature over its digest, fed back so the transition can frame the <c>TPM2_Quote()</c>
/// response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Quoted">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmQuoteResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over <c>H_hashAlg(quoted)</c>; ownership flows to the <c>TpmQuoteResponse</c> and is released once framed.</param>
public sealed record TpmObjectQuoted(
    Tpm2bAttest Quoted,
    TpmtSignature Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_CertifyCreation()</c> command (TPM 2.0 Library Part 3, clause 18.3): a signing key attests that the
/// object with a given Name was created by the TPM with a given creation hash, re-verified against the
/// caller-supplied creation ticket. Only <see cref="SignHandle"/> requires authorization, so the parser consumes
/// a single password session; <see cref="ObjectHandle"/> carries no session at all.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="SuppliedSignPassword">
/// The plaintext authorization value the caller supplied for the signing-key slot (the password session's
/// <c>hmac</c> field), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the sign-slot compare has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="ObjectHandle">The loaded object whose creation is certified (its Name is the attested binding).</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming transition
/// transfers it into the certify-creation action, whose effect is its terminal owner; every refusing arm releases
/// it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="CreationHash">
/// The creation hash the caller supplies (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92),
/// folded into the recomputed creation ticket and attested in <c>TPMS_CREATION_INFO.creationHash</c> — an owned
/// pooled carrier rented as the parse's last act, transferred by the consuming transition into the action whose
/// effect is its terminal owner, and released by this record's <see cref="IDisposable.Dispose"/> on a refusal.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="TicketDigest">
/// The digest carried by the caller-supplied <c>TPMT_TK_CREATION</c> (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2,
/// clause 10.7.3, Table 105), compared constant-time against the recomputed ticket — an owned pooled carrier
/// rented as the parse's last act, transferred into the action whose effect is its terminal owner, and released
/// by this record's <see cref="IDisposable.Dispose"/> on a refusal.
/// </param>
public sealed record TpmCertifyCreationRequested(
    TpmiDhObject SignHandle,
    Tpm2bAuth SuppliedSignPassword,
    TpmiDhObject ObjectHandle,
    Tpm2bData QualifyingData,
    Tpm2bDigest CreationHash,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    Tpm2bDigest TicketDigest): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — the sign slot's supplied password, the qualifying data, the
    /// creation hash, and the ticket digest — on a refusing path. The consuming transition instead releases the
    /// password itself once the sign-slot compare has consumed it and transfers the other three into the
    /// certify-creation action, so it never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignPassword.Dispose();
        QualifyingData.Dispose();
        CreationHash.Dispose();
        TicketDigest.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmCertifyCreationAction"/> or <see cref="TpmRsaCertifyCreationAction"/>.
/// Unlike <see cref="TpmObjectCertified"/>, the creation-ticket re-verification (TPM 2.0 Library Part 3, clause
/// 18.3) needs the asynchronous digest/HMAC seam, so it happens inside the effect rather than the pure
/// transition: a mismatched ticket yields <see cref="ResponseCode"/> <c>TPM_RC_TICKET</c> with no attestation
/// data, mirroring <c>TpmCredentialActivated</c>'s integrity-check outcome. Internal to the effect loop; never
/// arrives from the command transport.
/// </summary>
/// <param name="ResponseCode">
/// <c>TPM_RC_SUCCESS</c> when the supplied creation ticket reproduced, in which case <paramref name="CertifyInfo"/>
/// and <paramref name="Signature"/> carry the attestation; otherwise <c>TPM_RC_TICKET</c> with both null.
/// </param>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmCertifyCreationResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmCertifyCreationResponse</c> and is released once framed.</param>
public sealed record TpmObjectCreationCertified(
    TpmRcConstants ResponseCode,
    Tpm2bAttest? CertifyInfo,
    TpmtSignature? Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetTime()</c> command (TPM 2.0 Library Part 3, clause 18.7): a signing key attests the TPM's current
/// time, over a caller nonce. Requires Endorsement authorization on <see cref="PrivacyAdminHandle"/> in addition
/// to <see cref="SignHandle"/>'s own authorization, so the parser consumes two password sessions in handle order.
/// </summary>
/// <param name="PrivacyAdminHandle">The privacy administrator handle (TPMI_RH_ENDORSEMENT); only <c>TPM_RH_ENDORSEMENT</c> is a legal value.</param>
/// <param name="SuppliedPrivacyAdminPassword">
/// The plaintext authorization value the caller supplied for the privacy-administrator slot (session 0's
/// <c>hmac</c> field), compared against the endorsement hierarchy's retained authorization value — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the hierarchy compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="SuppliedSignPassword">
/// The plaintext authorization value the caller supplied for the signing-key slot (session 1's <c>hmac</c>
/// field), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both sides
/// trailing-zero-stripped — rather than discarded. An owned pooled <see cref="Tpm2bAuth"/> carrier rented at
/// parse; the consuming transition is its terminal owner. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming transition
/// transfers it into the time-attestation action, whose effect is its terminal owner; every refusing arm releases
/// it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
public sealed record TpmGetTimeRequested(
    TpmiRhEndorsement PrivacyAdminHandle,
    Tpm2bAuth SuppliedPrivacyAdminPassword,
    TpmiDhObject SignHandle,
    Tpm2bAuth SuppliedSignPassword,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — both slots' supplied passwords and the qualifying data — on a
    /// refusing path. The consuming transition instead releases the two passwords itself once the per-slot
    /// compares have consumed them and transfers the qualifying data into the time-attestation action, so it
    /// never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedPrivacyAdminPassword.Dispose();
        SuppliedSignPassword.Dispose();
        QualifyingData.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmGetTimeAction"/> or <see cref="TpmRsaGetTimeAction"/>: the marshaled
/// <c>TPMS_ATTEST</c> the effectful loop built and the signature over its digest, fed back so the transition can
/// frame the <c>TPM2_GetTime()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="TimeInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmGetTimeResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over <c>H_hashAlg(timeInfo)</c>; ownership flows to the <c>TpmGetTimeResponse</c> and is released once framed.</param>
public sealed record TpmTimeAttested(
    Tpm2bAttest TimeInfo,
    TpmtSignature Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ReadClock()</c> command (TPM 2.0 Library Part 3, clause 29.1). Reads the current
/// <c>TPMS_TIME_INFO</c> — uncertified, unsigned Time/Clock/resetCount/restartCount — with no handles and no
/// authorization.
/// </summary>
public sealed record TpmReadClockRequested: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ClockSet()</c> command (TPM 2.0 Library Part 3, clause 29.2). Advances <c>Clock</c> forward to
/// <see cref="NewTime"/>, authorized by the owner hierarchy; the Platform-hierarchy arm is not modelled this
/// slice.
/// </summary>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the set (<c>TPM_RH_OWNER</c> in this slice).</param>
/// <param name="OwnerAuthSupplied">The authorization value the caller supplied for the provisioning hierarchy — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153) — in a pooled carrier this record OWNS, rented as the parse's last act. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NewTime">The requested new <c>Clock</c> value, in milliseconds.</param>
public sealed record TpmClockSetRequested(
    TpmiRhProvision AuthHandle,
    Tpm2bAuth OwnerAuthSupplied,
    ulong NewTime): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="OwnerAuthSupplied"/> carrier on a refusing path; the authorizing transition
    /// disposes it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        OwnerAuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_DictionaryAttackLockReset()</c> command (TPM 2.0 Library Part 3, clause 25.2). Resets
/// <c>FailedTries</c> to zero, authorized by the lockout hierarchy; permitted even while the TPM is in general
/// Lockout mode (<see cref="TpmSimulatorState.IsInLockout"/>) — only <see cref="TpmSimulatorState.LockoutAuthEnabled"/>
/// gates it.
/// </summary>
/// <param name="LockHandle">The authorization handle (<c>TPMI_RH_LOCKOUT</c>); for this slice must equal <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="LockoutAuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153) — in a pooled carrier this record OWNS, rented as the parse's last act, compared against the lockout hierarchy's authorization value. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
public sealed record TpmDictionaryAttackLockResetRequested(
    TpmiRhLockout LockHandle,
    Tpm2bAuth LockoutAuthSupplied): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="LockoutAuthSupplied"/> carrier on a refusing path; the authorizing
    /// transition disposes it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        LockoutAuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_DictionaryAttackParameters()</c> command (TPM 2.0 Library Part 3, clause 25.3). Sets
/// <c>MaxTries</c>/<c>RecoveryTime</c>/<c>LockoutRecovery</c>, authorized by the lockout hierarchy exactly like
/// <see cref="TpmDictionaryAttackLockResetRequested"/>; deliberately does not reset <c>FailedTries</c>
/// (Part 1, clause 17.8.6's errata correction).
/// </summary>
/// <param name="LockHandle">The authorization handle (<c>TPMI_RH_LOCKOUT</c>); for this slice must equal <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="LockoutAuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153) — in a pooled carrier this record OWNS, rented as the parse's last act, compared against the lockout hierarchy's authorization value. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NewMaxTries">The new tolerated-failure count before Lockout mode engages.</param>
/// <param name="NewRecoveryTime">The new self-heal interval, in seconds; zero disables dictionary-attack protection.</param>
/// <param name="NewLockoutRecovery">The new lockoutAuth recovery wait, in seconds; zero means only a TPM Reset re-arms lockoutAuth.</param>
public sealed record TpmDictionaryAttackParametersRequested(
    TpmiRhLockout LockHandle,
    Tpm2bAuth LockoutAuthSupplied,
    uint NewMaxTries,
    uint NewRecoveryTime,
    uint NewLockoutRecovery): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="LockoutAuthSupplied"/> carrier on a refusing path; the authorizing
    /// transition disposes it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        LockoutAuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_NV_Certify()</c> command (TPM 2.0 Library Part 3, clause 31.16): a signing key attests the contents
/// of an NV Index at a caller-chosen offset and size, over a caller nonce. Both <see cref="SignHandle"/> and
/// <see cref="AuthHandle"/> require authorization, and this record is the form in which BOTH of the two
/// authorization slots the parser reads named <c>TPM_RS_PW</c>; anything else is
/// <see cref="TpmNvCertifyOverSessionRequested"/>. Only Index authorization (<see cref="AuthHandle"/> equal to
/// <see cref="NvIndex"/>) is modelled on this arm.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation.</param>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>.</param>
/// <param name="NvIndex">The NV Index whose contents are certified.</param>
/// <param name="SuppliedSignPassword">
/// The plaintext authorization value the caller supplied for the sign slot (session index 0's <c>hmac</c>
/// field), compared against the signing key's retained <see cref="TransientKeyState.AuthValue"/> — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned pooled
/// <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner, releasing
/// it once the sign-slot compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="SuppliedIndexPassword">
/// The plaintext authorization value the caller supplied for <paramref name="AuthHandle"/> (session index 1's
/// <c>hmac</c> field), compared against the Index's retained <see cref="NvIndexState.AuthValue"/> — both sides
/// trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3). An owned pooled <see cref="Tpm2bAuth"/>
/// carrier rented at parse; the consuming transition is its terminal owner, releasing it once the Index-slot
/// compare has consumed it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming transition
/// transfers it into the NV-certify action, whose effect is its terminal owner; every refusing arm releases it
/// through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="Size">The number of octets to certify.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
public sealed record TpmNvCertifyRequested(
    TpmiDhObject SignHandle,
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    Tpm2bAuth SuppliedSignPassword,
    Tpm2bAuth SuppliedIndexPassword,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    ushort Size,
    ushort Offset): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — both slots' supplied passwords and the qualifying data — on a
    /// refusing path. The consuming transition instead releases the two passwords itself once the per-slot
    /// compares have consumed them and transfers the qualifying data into the NV-certify action, so it never
    /// calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignPassword.Dispose();
        SuppliedIndexPassword.Dispose();
        QualifyingData.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmNvCertifyAction"/> or <see cref="TpmRsaNvCertifyAction"/>: the
/// marshaled <c>TPMS_ATTEST</c> the effectful loop built and the signature over its digest, fed back so the
/// transition can frame the <c>TPM2_NV_Certify()</c> response. Internal to the effect loop; never arrives from
/// the command transport.
/// </summary>
/// <param name="CertifyInfo">The <c>TPM2B_ATTEST</c> over the marshaled <c>TPMS_ATTEST</c> (the exact bytes the signature is over); ownership flows to the <c>TpmNvCertifyResponse</c> and is released by <see cref="TpmSimulator"/> once framed.</param>
/// <param name="Signature">The <c>TPMT_SIGNATURE</c> over <c>H_hashAlg(certifyInfo)</c>; ownership flows to the <c>TpmNvCertifyResponse</c> and is released once framed.</param>
public sealed record TpmNvIndexCertified(
    Tpm2bAttest CertifyInfo,
    TpmtSignature Signature): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_NV_Certify()</c> command at least one of whose two authorization slots carries a real session
/// rather than a password (TPM 2.0 Library Part 3, clause 31.16.2, Table 254). The all-password form remains
/// <see cref="TpmNvCertifyRequested"/>; anything else arrives here.
/// </summary>
/// <remarks>
/// <para>
/// The two slots are independent. Table 254 gives <c>@signHandle</c> Auth Index 1 and <c>@authHandle</c> Auth
/// Index 2, both USER role, and a <c>TPMS_AUTH_COMMAND</c>'s wire layout does not depend on the session's kind
/// (Part 1, clause 17.6.4.1: a password authorization is one way of presenting an authValue, an HMAC session
/// another), so all four slot combinations are legal wire. The parser records what arrived for BOTH slots and
/// the transition decides what each one authorizes — which is why every slot field is captured here.
/// </para>
/// <para>
/// BOTH slots' authorizations are verified: the signing key's own authValue is retained on
/// <see cref="TransientKeyState.AuthValue"/>, so a password sign slot's plaintext hmac is compared against it
/// and a real sign-slot HMAC session joins the command-HMAC verification queue at session index 0, folding that
/// authValue with bind omission (Part 1, clauses 17.6.5 and 17.6.10). Each real slot gets a genuine
/// rolled-nonceTPM response entry keyed on <see cref="ResolvedAuthValue"/> / <see cref="ResolvedSignAuthValue"/>
/// — the same value its own command HMAC used (clause 17.6.5) — so its response HMAC verifies exactly when its
/// command HMAC did.
/// </para>
/// </remarks>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation, and whose Name is cpHash's Name1 term (Part 1, clause 16.7 equation 15).</param>
/// <param name="AuthHandle">The authorization handle (<c>TPMI_RH_NV_AUTH</c>); for Index authorization this equals <paramref name="NvIndex"/>, or <c>TPM_RH_OWNER</c> for the owner arm. cpHash's Name2 term.</param>
/// <param name="NvIndex">The NV Index whose contents are certified — cpHash's Name3 term.</param>
/// <param name="SignSessionHandle">The session authorizing <paramref name="SignHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise a real session handle.</param>
/// <param name="SignNonceCaller">
/// The sign slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignSessionAttributes">The sign slot's command session-attributes octet.</param>
/// <param name="SuppliedSignHmac">The sign slot's supplied <c>hmac</c> field — the plaintext authValue for a password slot, the command HMAC for a real session — held in an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="AuthorizingSessionHandle">The session authorizing <paramref name="AuthHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise the HMAC session whose command HMAC is verified.</param>
/// <param name="AuthorizingNonceCaller">
/// The authorizing slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause
/// 10.4.4, Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="AuthorizingSessionAttributes">The authorizing slot's command session-attributes octet.</param>
/// <param name="SuppliedAuthorizingHmac">The authorizing slot's supplied <c>hmac</c> field — the plaintext authValue for a password slot, the command HMAC for a real session — held in an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming
/// continuation transfers it into the NV-certify action, whose effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="Size">The number of octets to certify.</param>
/// <param name="Offset">The octet offset into the Index data area.</param>
/// <param name="RawParameterArea">The <c>qualifyingData ‖ inScheme ‖ size ‖ offset</c> wire bytes captured verbatim at parse time — cpHash's <c>parameters</c> term (Part 1, clause 16.7 equation 15). Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="HasCompanionSlot">
/// Whether the authorization area actually carried the slot at the index after the last authorizing one. The
/// parser decides this structurally, from the octets left inside <c>authorizationSize</c> once the required
/// slots have been read, and nothing downstream re-derives it from a handle value: a block naming any handle at
/// all is a block the caller sent, and it must be resolved, validated, and answered with a response entry
/// whatever it names (TPM 2.0 Library Part 3, clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="CompanionSessionHandle">
/// The slot at the index after the last authorizing one (here index 2): a session that authorizes NO entity and
/// is carried only for parameter decryption, parameter encryption, or audit (TPM 2.0 Library Part 1, clause
/// 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption, decryption, or
/// audit", and an area holds at most three slots).
/// Meaningful only when <paramref name="HasCompanionSlot"/> is set: presence is a structural fact of the
/// wire and is never inferred from this value. Every value the slot can hold names a block the caller really did
/// send, which owes its own validation and its own response entry — including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot index, and <c>TPM_RS_PW</c>, a password slot arriving in the companion
/// position to be refused for the attributes it cannot carry.
/// </param>
/// <param name="CompanionNonceCaller">
/// The companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned pooled
/// carrier rented as part of the parse's last act; transferred into the companion's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no companion arrived.
/// </param>
/// <param name="CompanionSessionAttributes">The companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedCompanionHmac">
/// The companion slot's supplied <c>hmac</c> field. A companion presents a REAL command HMAC like every other
/// session in the area — clause 5.6 of Part 3 applies to the whole area — and only its authValue term is empty,
/// since it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ResolvedIndexName">The Index's computed Name, cpHash's <c>Name3</c> term (and <c>Name2</c> on the Index arm); see <see cref="TpmNvReadOverSessionRequested.ResolvedIndexName"/>.</param>
/// <param name="ResolvedAuthValue">The bind-omission-resolved authValue term for the authorizing slot (Auth Index 1) — a borrowed carrier reference; see <see cref="TpmNvReadOverSessionRequested.ResolvedAuthValue"/>.</param>
/// <param name="ResolvedSignAuthValue">The bind-omission-resolved authValue term for the sign slot (Auth Index 0), carrying the signing key's own authValue the sign-slot command HMAC verified (or the shared empty carrier when the session was bound to the signer, so its authValue was folded into the bind) — a borrowed carrier reference; the response framing keys the sign slot's HMAC on it exactly as the command HMAC keyed it (TPM 2.0 Library Part 1, clause 17.6.5, with the bind omission of clause 17.6.10 carried over unchanged). <see langword="null"/> until resolved and for a password sign slot, read as empty.</param>
public sealed record TpmNvCertifyOverSessionRequested(
    TpmiDhObject SignHandle,
    TpmiRhNvAuth AuthHandle,
    TpmiRhNvIndex NvIndex,
    TpmiShAuthSession SignSessionHandle,
    Tpm2bNonce SignNonceCaller,
    TpmaSession SignSessionAttributes,
    Tpm2bAuth SuppliedSignHmac,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce AuthorizingNonceCaller,
    TpmaSession AuthorizingSessionAttributes,
    Tpm2bAuth SuppliedAuthorizingHmac,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    ushort Size,
    ushort Offset,
    TpmParameterArea RawParameterArea,
    bool HasCompanionSlot,
    TpmiShAuthSession CompanionSessionHandle,
    Tpm2bNonce CompanionNonceCaller,
    TpmaSession CompanionSessionAttributes,
    Tpm2bAuth SuppliedCompanionHmac,
    Tpm2bName ResolvedIndexName,
    Tpm2bAuth? ResolvedAuthValue = null,
    Tpm2bAuth? ResolvedSignAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — all three slots' supplied HMACs and caller nonces, the
    /// qualifying data, the raw parameter area and the Index's computed Name — on a refusing path. The
    /// consuming continuation instead releases the supplied HMACs itself as their terminal owner and transfers
    /// each slot's nonce into that slot's response-session entry and the qualifying data into the NV-certify
    /// action, so it never calls this. The resolved-authValue references are borrowed and never released here.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignHmac.Dispose();
        SignNonceCaller.Dispose();
        SuppliedAuthorizingHmac.Dispose();
        AuthorizingNonceCaller.Dispose();
        SuppliedCompanionHmac.Dispose();
        CompanionNonceCaller.Dispose();
        QualifyingData.Dispose();
        RawParameterArea.Dispose();
        ResolvedIndexName.Dispose();
    }
}

/// <summary>
/// A session-authorized <c>TPM2_Quote()</c> command (TPM 2.0 Library Part 3, clause 18.4): the attest-family
/// counterpart of <see cref="TpmQuoteRequested"/> for an area whose single <c>@signHandle</c> slot names a real
/// HMAC session rather than <c>TPM_RS_PW</c>. The parser forks to this record only when the slot is real, so an
/// all-password area still parses to <see cref="TpmQuoteRequested"/> and this record always owes at least one
/// genuine response entry (TPM 2.0 Library Part 1, clause 16.6.1).
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation and whose Name is cpHash's <c>Name1</c> term (Part 1, clause 16.7 equation 15).</param>
/// <param name="SignSessionHandle">The session authorizing <paramref name="SignHandle"/> — a real HMAC session handle (never <c>TPM_RS_PW</c>, which the parser routes to the plain record).</param>
/// <param name="SignNonceCaller">
/// The sign slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94) — the response HMAC's nonceOlder — in an owned pooled carrier rented as part of the parse's last
/// act; transferred into the response-session entry the continuation builds, whose attest effect is its terminal
/// owner; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignSessionAttributes">The sign slot's command session-attributes octet, folded into the command and response HMACs and echoed into the response entry.</param>
/// <param name="SuppliedSignHmac">The sign slot's supplied <c>hmac</c> field — the command HMAC over cpHash, verified after entry — held in an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, and the refusing arms release it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming
/// continuation transfers it into the quote action, whose effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>, dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="PcrSelection">
/// The caller's <c>TPML_PCR_SELECTION</c> (TPM 2.0 Library Part 2, clause 10.9.7, Table 125), in an owned pooled
/// carrier rented as the parse's last act — decoded against the PCR bank and echoed into the attested
/// <c>TPMS_QUOTE_INFO.pcrSelect</c>. The consuming continuation transfers it into the quote action, whose effect
/// is its terminal owner; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="RawParameterArea">The <c>qualifyingData ‖ inScheme ‖ PCRselect</c> wire bytes captured verbatim at parse time — cpHash's <c>parameters</c> term (Part 1, clause 16.7 equation 15). Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="HasCompanionSlot">
/// Whether the authorization area actually carried the slot at the index after the last authorizing one. The
/// parser decides this structurally, from the octets left inside <c>authorizationSize</c> once the required
/// slots have been read, and nothing downstream re-derives it from a handle value: a block naming any handle at
/// all is a block the caller sent, and it must be resolved, validated, and answered with a response entry
/// whatever it names (TPM 2.0 Library Part 3, clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="CompanionSessionHandle">
/// The slot at the index after the last authorizing one (here index 1): a session that authorizes NO entity and
/// is carried only for parameter decryption, parameter encryption, or audit (TPM 2.0 Library Part 1, clause
/// 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption, decryption, or
/// audit").
/// Meaningful only when <paramref name="HasCompanionSlot"/> is set: presence is a structural fact of the
/// wire and is never inferred from this value. Every value the slot can hold names a block the caller really did
/// send, which owes its own validation and its own response entry — including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot index, and <c>TPM_RS_PW</c>, a password slot arriving in the companion
/// position to be refused for the attributes it cannot carry.
/// </param>
/// <param name="CompanionNonceCaller">
/// The companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned pooled
/// carrier rented as part of the parse's last act; transferred into the companion's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no companion arrived.
/// </param>
/// <param name="CompanionSessionAttributes">The companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedCompanionHmac">
/// The companion slot's supplied <c>hmac</c> field. A companion presents a REAL command HMAC like every other
/// session in the area — clause 5.6 of Part 3 applies to the whole area — and only its authValue term is empty,
/// since it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="HasSecondCompanionSlot">
/// Whether the authorization area actually carried a third slot. Decided structurally by the parser from the
/// remaining <c>authorizationSize</c> octets, exactly as <paramref name="HasCompanionSlot"/> is, and
/// presupposing it because the area is read positionally.
/// </param>
/// <param name="SecondCompanionSessionHandle">
/// The slot at index 2 — the third and last block an authorization area may hold, since an area carries "at least
/// one but no more than three" of them (TPM 2.0 Library Part 1, clause 16.6.1) and Table 9 marks positions 2 and 3
/// alike as an encryption, decryption, or audit session. This command authorizes one handle, so both companion
/// positions are open to it. The area is read positionally, so this slot presupposes
/// <paramref name="HasCompanionSlot"/>. Meaningful only when <paramref name="HasSecondCompanionSlot"/> is set:
/// presence is a structural fact of the wire and is never inferred from this value. Every value the slot can
/// hold names a block the caller really did send — including zero, which <c>TPMI_SH_AUTH_SESSION</c> does not
/// admit at all (Part 2, clause 9.8, Table 55) and which is refused with <c>TPM_RC_HANDLE</c> at this slot
/// index, and <c>TPM_RS_PW</c>, a password slot arriving in that position to be refused for the attributes it
/// cannot carry.
/// </param>
/// <param name="SecondCompanionNonceCaller">
/// The second companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned
/// pooled carrier rented as part of the parse's last act; transferred into that slot's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no second companion arrived.
/// </param>
/// <param name="SecondCompanionSessionAttributes">The second companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedSecondCompanionHmac">
/// The second companion slot's supplied <c>hmac</c> field — a real command HMAC like every other session in the
/// area (clause 5.6 of Part 3 applies to the whole area), keyed on its session key with an empty authValue term
/// because it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ResolvedSignAuthValue">The bind-omission-resolved authValue term the sign slot's command HMAC used — the signing key's own authValue, or the shared empty carrier when the session was bound to the signer; a borrowed reference the response framing keys the sign slot's HMAC on (Part 1, clause 17.6.5, with the bind omission of clause 17.6.10 carried over unchanged). <see langword="null"/> until resolved.</param>
public sealed record TpmQuoteOverSessionRequested(
    TpmiDhObject SignHandle,
    TpmiShAuthSession SignSessionHandle,
    Tpm2bNonce SignNonceCaller,
    TpmaSession SignSessionAttributes,
    Tpm2bAuth SuppliedSignHmac,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    TpmlPcrSelection PcrSelection,
    TpmParameterArea RawParameterArea,
    bool HasCompanionSlot,
    TpmiShAuthSession CompanionSessionHandle,
    Tpm2bNonce CompanionNonceCaller,
    TpmaSession CompanionSessionAttributes,
    Tpm2bAuth SuppliedCompanionHmac,
    bool HasSecondCompanionSlot,
    TpmiShAuthSession SecondCompanionSessionHandle,
    Tpm2bNonce SecondCompanionNonceCaller,
    TpmaSession SecondCompanionSessionAttributes,
    Tpm2bAuth SuppliedSecondCompanionHmac,
    Tpm2bAuth? ResolvedSignAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — the sign slot's supplied HMAC and caller nonce, each companion
    /// slot's supplied HMAC and caller nonce, the qualifying data, and the PCR selection — on a refusing path.
    /// The consuming continuation instead releases every supplied HMAC itself as their terminal owner, transfers
    /// each slot's nonce into that slot's response-session entry, and transfers the qualifying data and the PCR
    /// selection into the quote action, so it never calls this. <see cref="ResolvedSignAuthValue"/> is a borrowed
    /// reference the durable state owns and is never released here.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignHmac.Dispose();
        SignNonceCaller.Dispose();
        SuppliedCompanionHmac.Dispose();
        CompanionNonceCaller.Dispose();
        SuppliedSecondCompanionHmac.Dispose();
        SecondCompanionNonceCaller.Dispose();
        QualifyingData.Dispose();
        PcrSelection.Dispose();
        RawParameterArea.Dispose();
    }
}

/// <summary>
/// A session-authorized <c>TPM2_CertifyCreation()</c> command (TPM 2.0 Library Part 3, clause 18.3): the
/// attest-family counterpart of <see cref="TpmCertifyCreationRequested"/> for an area whose single
/// <c>@signHandle</c> slot names a real HMAC session. <see cref="ObjectHandle"/> still carries no authorization,
/// so its Name is threaded into cpHash but no session authorizes it. The parser forks to this record only when
/// the sign slot is real, so it always owes at least one genuine response entry.
/// </summary>
/// <param name="SignHandle">The loaded signing key that attests, whose retained private key signs the marshaled attestation and whose Name is cpHash's <c>Name1</c> term.</param>
/// <param name="SignSessionHandle">The session authorizing <paramref name="SignHandle"/> — a real HMAC session handle (never <c>TPM_RS_PW</c>).</param>
/// <param name="SignNonceCaller">
/// The sign slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignSessionAttributes">The sign slot's command session-attributes octet.</param>
/// <param name="SuppliedSignHmac">The sign slot's supplied command <c>hmac</c> — an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, refusing arms release it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="ObjectHandle">The loaded object whose creation is certified — cpHash's <c>Name2</c> term; it carries no session.</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming
/// continuation transfers it into the certify-creation action, whose effect is its terminal owner; every refusing
/// arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="CreationHash">
/// The creation hash the caller supplies (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92),
/// folded into the recomputed creation ticket and attested in <c>TPMS_CREATION_INFO.creationHash</c> — an owned
/// pooled carrier rented as the parse's last act, transferred by the consuming continuation into the action whose
/// effect is its terminal owner, and released by this record's <see cref="IDisposable.Dispose"/> on a refusal.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="TicketDigest">
/// The digest carried by the caller-supplied <c>TPMT_TK_CREATION</c> (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2,
/// clause 10.7.3, Table 105), compared constant-time against the recomputed ticket — an owned pooled carrier
/// rented as the parse's last act, transferred into the action whose effect is its terminal owner, and released
/// by this record's <see cref="IDisposable.Dispose"/> on a refusal.
/// </param>
/// <param name="RawParameterArea">The <c>qualifyingData ‖ creationHash ‖ inScheme ‖ creationTicket</c> wire bytes captured verbatim at parse time — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="HasCompanionSlot">
/// Whether the authorization area actually carried the slot at the index after the last authorizing one. The
/// parser decides this structurally, from the octets left inside <c>authorizationSize</c> once the required
/// slots have been read, and nothing downstream re-derives it from a handle value: a block naming any handle at
/// all is a block the caller sent, and it must be resolved, validated, and answered with a response entry
/// whatever it names (TPM 2.0 Library Part 3, clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="CompanionSessionHandle">
/// The slot at the index after the last authorizing one (here index 1): a session that authorizes NO entity and
/// is carried only for parameter decryption, parameter encryption, or audit (TPM 2.0 Library Part 1, clause
/// 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption, decryption, or
/// audit").
/// Meaningful only when <paramref name="HasCompanionSlot"/> is set: presence is a structural fact of the
/// wire and is never inferred from this value. Every value the slot can hold names a block the caller really did
/// send, which owes its own validation and its own response entry — including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot index, and <c>TPM_RS_PW</c>, a password slot arriving in the companion
/// position to be refused for the attributes it cannot carry.
/// </param>
/// <param name="CompanionNonceCaller">
/// The companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned pooled
/// carrier rented as part of the parse's last act; transferred into the companion's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no companion arrived.
/// </param>
/// <param name="CompanionSessionAttributes">The companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedCompanionHmac">
/// The companion slot's supplied <c>hmac</c> field. A companion presents a REAL command HMAC like every other
/// session in the area — clause 5.6 of Part 3 applies to the whole area — and only its authValue term is empty,
/// since it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="HasSecondCompanionSlot">
/// Whether the authorization area actually carried a third slot. Decided structurally by the parser from the
/// remaining <c>authorizationSize</c> octets, exactly as <paramref name="HasCompanionSlot"/> is, and
/// presupposing it because the area is read positionally.
/// </param>
/// <param name="SecondCompanionSessionHandle">
/// The slot at index 2 — the third and last block an authorization area may hold, since an area carries "at least
/// one but no more than three" of them (TPM 2.0 Library Part 1, clause 16.6.1) and Table 9 marks positions 2 and 3
/// alike as an encryption, decryption, or audit session. This command authorizes one handle, so both companion
/// positions are open to it. The area is read positionally, so this slot presupposes
/// <paramref name="HasCompanionSlot"/>. Meaningful only when <paramref name="HasSecondCompanionSlot"/> is set:
/// presence is a structural fact of the wire and is never inferred from this value. Every value the slot can
/// hold names a block the caller really did send — including zero, which <c>TPMI_SH_AUTH_SESSION</c> does not
/// admit at all (Part 2, clause 9.8, Table 55) and which is refused with <c>TPM_RC_HANDLE</c> at this slot
/// index, and <c>TPM_RS_PW</c>, a password slot arriving in that position to be refused for the attributes it
/// cannot carry.
/// </param>
/// <param name="SecondCompanionNonceCaller">
/// The second companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned
/// pooled carrier rented as part of the parse's last act; transferred into that slot's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no second companion arrived.
/// </param>
/// <param name="SecondCompanionSessionAttributes">The second companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedSecondCompanionHmac">
/// The second companion slot's supplied <c>hmac</c> field — a real command HMAC like every other session in the
/// area (clause 5.6 of Part 3 applies to the whole area), keyed on its session key with an empty authValue term
/// because it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ResolvedSignAuthValue">The bind-omission-resolved authValue term the sign slot's command HMAC used — a borrowed reference the response framing reuses (Part 1, clause 17.6.5, with the bind omission of clause 17.6.10 carried over unchanged). <see langword="null"/> until resolved.</param>
public sealed record TpmCertifyCreationOverSessionRequested(
    TpmiDhObject SignHandle,
    TpmiShAuthSession SignSessionHandle,
    Tpm2bNonce SignNonceCaller,
    TpmaSession SignSessionAttributes,
    Tpm2bAuth SuppliedSignHmac,
    TpmiDhObject ObjectHandle,
    Tpm2bData QualifyingData,
    Tpm2bDigest CreationHash,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    Tpm2bDigest TicketDigest,
    TpmParameterArea RawParameterArea,
    bool HasCompanionSlot,
    TpmiShAuthSession CompanionSessionHandle,
    Tpm2bNonce CompanionNonceCaller,
    TpmaSession CompanionSessionAttributes,
    Tpm2bAuth SuppliedCompanionHmac,
    bool HasSecondCompanionSlot,
    TpmiShAuthSession SecondCompanionSessionHandle,
    Tpm2bNonce SecondCompanionNonceCaller,
    TpmaSession SecondCompanionSessionAttributes,
    Tpm2bAuth SuppliedSecondCompanionHmac,
    Tpm2bAuth? ResolvedSignAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — the sign slot's supplied HMAC and caller nonce, each companion
    /// slot's supplied HMAC and caller nonce, the qualifying data, the creation hash, and the ticket digest — on
    /// a refusing path. The consuming continuation instead releases every supplied HMAC itself as their terminal
    /// owner, transfers each slot's nonce into that slot's response-session entry, and transfers the other three
    /// into the certify-creation action, so it never calls this. <see cref="ResolvedSignAuthValue"/> is a
    /// borrowed reference and is never released here.
    /// </summary>
    public void Dispose()
    {
        SuppliedSignHmac.Dispose();
        SignNonceCaller.Dispose();
        SuppliedCompanionHmac.Dispose();
        CompanionNonceCaller.Dispose();
        SuppliedSecondCompanionHmac.Dispose();
        SecondCompanionNonceCaller.Dispose();
        QualifyingData.Dispose();
        CreationHash.Dispose();
        TicketDigest.Dispose();
        RawParameterArea.Dispose();
    }
}

/// <summary>
/// A session-authorized <c>TPM2_Certify()</c> command (TPM 2.0 Library Part 3, clause 18.2): the attest-family
/// counterpart of <see cref="TpmCertifyRequested"/> for an area at least one of whose two slots names a real HMAC
/// session — <c>@objectHandle</c> (Auth Index 1, ADMIN role) then <c>@signHandle</c> (Auth Index 2, USER role).
/// Each slot independently takes <c>TPM_RS_PW</c> or an HMAC session; the parser forks here whenever the area is
/// not all-password, so at least one slot owes a genuine response entry.
/// </summary>
/// <param name="ObjectHandle">The loaded object whose Name is certified — cpHash's <c>Name1</c> term; authorized in the ADMIN role by the object slot.</param>
/// <param name="ObjectSessionHandle">The session authorizing <paramref name="ObjectHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise a real HMAC session handle.</param>
/// <param name="ObjectNonceCaller">
/// The object slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ObjectSessionAttributes">The object slot's command session-attributes octet.</param>
/// <param name="SuppliedObjectHmac">The object slot's supplied <c>hmac</c> — the plaintext authValue for a password slot, the command HMAC for a real session — held in an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, refusing arms release it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="SignHandle">The loaded signing key that attests — cpHash's <c>Name2</c> term; authorized in the USER role by the sign slot.</param>
/// <param name="SignSessionHandle">The session authorizing <paramref name="SignHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise a real HMAC session handle.</param>
/// <param name="SignNonceCaller">
/// The sign slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignSessionAttributes">The sign slot's command session-attributes octet.</param>
/// <param name="SuppliedSignHmac">The sign slot's supplied <c>hmac</c> — the plaintext authValue for a password slot, the command HMAC for a real session — an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, refusing arms release it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming
/// continuation transfers it into the certify action, whose effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="RawParameterArea">The <c>qualifyingData ‖ inScheme</c> wire bytes captured verbatim at parse time — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="HasCompanionSlot">
/// Whether the authorization area actually carried the slot at the index after the last authorizing one. The
/// parser decides this structurally, from the octets left inside <c>authorizationSize</c> once the required
/// slots have been read, and nothing downstream re-derives it from a handle value: a block naming any handle at
/// all is a block the caller sent, and it must be resolved, validated, and answered with a response entry
/// whatever it names (TPM 2.0 Library Part 3, clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="CompanionSessionHandle">
/// The slot at the index after the last authorizing one (here index 2): a session that authorizes NO entity and
/// is carried only for parameter decryption, parameter encryption, or audit (TPM 2.0 Library Part 1, clause
/// 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption, decryption, or
/// audit", and an area holds at most three slots).
/// Meaningful only when <paramref name="HasCompanionSlot"/> is set: presence is a structural fact of the
/// wire and is never inferred from this value. Every value the slot can hold names a block the caller really did
/// send, which owes its own validation and its own response entry — including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot index, and <c>TPM_RS_PW</c>, a password slot arriving in the companion
/// position to be refused for the attributes it cannot carry.
/// </param>
/// <param name="CompanionNonceCaller">
/// The companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned pooled
/// carrier rented as part of the parse's last act; transferred into the companion's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no companion arrived.
/// </param>
/// <param name="CompanionSessionAttributes">The companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedCompanionHmac">
/// The companion slot's supplied <c>hmac</c> field. A companion presents a REAL command HMAC like every other
/// session in the area — clause 5.6 of Part 3 applies to the whole area — and only its authValue term is empty,
/// since it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ResolvedObjectAuthValue">The bind-omission-resolved authValue term the object slot's command HMAC used (the certified object's own authValue, or empty when bound to it) — a borrowed reference the response framing reuses; <see langword="null"/> until resolved and for a password object slot, read as empty.</param>
/// <param name="ResolvedSignAuthValue">The bind-omission-resolved authValue term the sign slot's command HMAC used — a borrowed reference the response framing reuses; <see langword="null"/> until resolved and for a password sign slot, read as empty.</param>
public sealed record TpmCertifyOverSessionRequested(
    TpmiDhObject ObjectHandle,
    TpmiShAuthSession ObjectSessionHandle,
    Tpm2bNonce ObjectNonceCaller,
    TpmaSession ObjectSessionAttributes,
    Tpm2bAuth SuppliedObjectHmac,
    TpmiDhObject SignHandle,
    TpmiShAuthSession SignSessionHandle,
    Tpm2bNonce SignNonceCaller,
    TpmaSession SignSessionAttributes,
    Tpm2bAuth SuppliedSignHmac,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    TpmParameterArea RawParameterArea,
    bool HasCompanionSlot,
    TpmiShAuthSession CompanionSessionHandle,
    Tpm2bNonce CompanionNonceCaller,
    TpmaSession CompanionSessionAttributes,
    Tpm2bAuth SuppliedCompanionHmac,
    Tpm2bAuth? ResolvedObjectAuthValue = null,
    Tpm2bAuth? ResolvedSignAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — all three slots' supplied HMACs and caller nonces, and the
    /// qualifying data — on a refusing path. The consuming continuation instead releases the supplied HMACs
    /// itself as their terminal owner and transfers each slot's nonce into that slot's response-session entry and
    /// the qualifying data into the certify action, so it never calls this. The resolved-authValue references are
    /// borrowed and never released here.
    /// </summary>
    public void Dispose()
    {
        SuppliedObjectHmac.Dispose();
        ObjectNonceCaller.Dispose();
        SuppliedSignHmac.Dispose();
        SignNonceCaller.Dispose();
        SuppliedCompanionHmac.Dispose();
        CompanionNonceCaller.Dispose();
        QualifyingData.Dispose();
        RawParameterArea.Dispose();
    }
}

/// <summary>
/// A session-authorized <c>TPM2_GetTime()</c> command (TPM 2.0 Library Part 3, clause 18.7): the attest-family
/// counterpart of <see cref="TpmGetTimeRequested"/> for an area at least one of whose two slots names a real HMAC
/// session — <c>@privacyAdminHandle</c> (Auth Index 1, USER role; fixed to <c>TPM_RH_ENDORSEMENT</c>) then
/// <c>@signHandle</c> (Auth Index 2, USER role). The privacy-administrator slot authorizes a HIERARCHY, so its
/// bind Name is the 4-octet handle value; the parser forks here whenever the area is not all-password.
/// </summary>
/// <param name="PrivacyAdminHandle">The privacy administrator handle (<c>TPMI_RH_ENDORSEMENT</c>); only <c>TPM_RH_ENDORSEMENT</c> is legal. Its 4-octet handle value is cpHash's <c>Name1</c> term (Part 1, clause 14, Table 6).</param>
/// <param name="PrivacyAdminSessionHandle">The session authorizing <paramref name="PrivacyAdminHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise a real HMAC session handle.</param>
/// <param name="PrivacyAdminNonceCaller">
/// The privacy-administrator slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2,
/// clause 10.4.4, Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into
/// the response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing
/// arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PrivacyAdminSessionAttributes">The privacy-administrator slot's command session-attributes octet.</param>
/// <param name="SuppliedPrivacyAdminHmac">The privacy-administrator slot's supplied <c>hmac</c> — the plaintext authValue for a password slot, the command HMAC for a real session — an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, refusing arms release it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="SignHandle">The loaded signing key that attests — cpHash's <c>Name2</c> term; authorized in the USER role by the sign slot.</param>
/// <param name="SignSessionHandle">The session authorizing <paramref name="SignHandle"/>: <c>TPM_RS_PW</c> for a password slot, otherwise a real HMAC session handle.</param>
/// <param name="SignNonceCaller">
/// The sign slot's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4,
/// Table 94), in an owned pooled carrier rented as part of the parse's last act; transferred into the
/// response-session entry the continuation builds, whose attest effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignSessionAttributes">The sign slot's command session-attributes octet.</param>
/// <param name="SuppliedSignHmac">The sign slot's supplied <c>hmac</c> — the plaintext authValue for a password slot, the command HMAC for a real session — an owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming continuation is its terminal owner, refusing arms release it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="QualifyingData">
/// The caller nonce echoed into the attestation's <c>extraData</c> (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2,
/// clause 10.4.3, Table 93), in an owned pooled carrier rented as the parse's last act. The consuming
/// continuation transfers it into the time-attestation action, whose effect is its terminal owner; every refusing
/// arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="SignatureScheme">The signing scheme algorithm (dispatched on the signing key's type).</param>
/// <param name="SchemeHashAlg">The signing scheme's hash algorithm.</param>
/// <param name="RawParameterArea">The <c>qualifyingData ‖ inScheme</c> wire bytes captured verbatim at parse time — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="HasCompanionSlot">
/// Whether the authorization area actually carried the slot at the index after the last authorizing one. The
/// parser decides this structurally, from the octets left inside <c>authorizationSize</c> once the required
/// slots have been read, and nothing downstream re-derives it from a handle value: a block naming any handle at
/// all is a block the caller sent, and it must be resolved, validated, and answered with a response entry
/// whatever it names (TPM 2.0 Library Part 3, clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="CompanionSessionHandle">
/// The slot at the index after the last authorizing one (here index 2): a session that authorizes NO entity and
/// is carried only for parameter decryption, parameter encryption, or audit (TPM 2.0 Library Part 1, clause
/// 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption, decryption, or
/// audit", and an area holds at most three slots).
/// Meaningful only when <paramref name="HasCompanionSlot"/> is set: presence is a structural fact of the
/// wire and is never inferred from this value. Every value the slot can hold names a block the caller really did
/// send, which owes its own validation and its own response entry — including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot index, and <c>TPM_RS_PW</c>, a password slot arriving in the companion
/// position to be refused for the attributes it cannot carry.
/// </param>
/// <param name="CompanionNonceCaller">
/// The companion slot's caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in an owned pooled
/// carrier rented as part of the parse's last act; transferred into the companion's own response-session entry,
/// whose attest effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel when no companion arrived.
/// </param>
/// <param name="CompanionSessionAttributes">The companion slot's command session-attributes octet, whose decrypt/encrypt/audit bits are the whole reason such a slot is admitted at all (Part 1, clause 16.6.4).</param>
/// <param name="SuppliedCompanionHmac">
/// The companion slot's supplied <c>hmac</c> field. A companion presents a REAL command HMAC like every other
/// session in the area — clause 5.6 of Part 3 applies to the whole area — and only its authValue term is empty,
/// since it authorizes no entity. An owned pooled carrier rented at parse; the consuming continuation is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="ResolvedPrivacyAdminAuthValue">The bind-omission-resolved authValue term the privacy-administrator slot's command HMAC used (the endorsement hierarchy's authValue, or empty when bound to it) — a borrowed reference the response framing reuses; <see langword="null"/> until resolved and for a password slot, read as empty.</param>
/// <param name="ResolvedSignAuthValue">The bind-omission-resolved authValue term the sign slot's command HMAC used — a borrowed reference the response framing reuses; <see langword="null"/> until resolved and for a password sign slot, read as empty.</param>
public sealed record TpmGetTimeOverSessionRequested(
    TpmiRhEndorsement PrivacyAdminHandle,
    TpmiShAuthSession PrivacyAdminSessionHandle,
    Tpm2bNonce PrivacyAdminNonceCaller,
    TpmaSession PrivacyAdminSessionAttributes,
    Tpm2bAuth SuppliedPrivacyAdminHmac,
    TpmiDhObject SignHandle,
    TpmiShAuthSession SignSessionHandle,
    Tpm2bNonce SignNonceCaller,
    TpmaSession SignSessionAttributes,
    Tpm2bAuth SuppliedSignHmac,
    Tpm2bData QualifyingData,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    TpmParameterArea RawParameterArea,
    bool HasCompanionSlot,
    TpmiShAuthSession CompanionSessionHandle,
    Tpm2bNonce CompanionNonceCaller,
    TpmaSession CompanionSessionAttributes,
    Tpm2bAuth SuppliedCompanionHmac,
    Tpm2bAuth? ResolvedPrivacyAdminAuthValue = null,
    Tpm2bAuth? ResolvedSignAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the request's owned carriers — all three slots' supplied HMACs and caller nonces, and the
    /// qualifying data — on a refusing path. The consuming continuation instead releases the supplied HMACs
    /// itself as their terminal owner and transfers each slot's nonce into that slot's response-session entry and
    /// the qualifying data into the time-attestation action, so it never calls this. The resolved-authValue
    /// references are borrowed and never released here.
    /// </summary>
    public void Dispose()
    {
        SuppliedPrivacyAdminHmac.Dispose();
        PrivacyAdminNonceCaller.Dispose();
        SuppliedSignHmac.Dispose();
        SignNonceCaller.Dispose();
        SuppliedCompanionHmac.Dispose();
        CompanionNonceCaller.Dispose();
        QualifyingData.Dispose();
        RawParameterArea.Dispose();
    }
}

/// <summary>
/// One session's material for framing its response entry on an attest command — <c>TPM2_Certify()</c>,
/// <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c> (TPM 2.0
/// Library Part 1, clause 16.6.1) — the attest-family counterpart of <see cref="TpmCreateResponseSession"/>,
/// with <see cref="IsPasswordPlaceholder"/> decided per entry because an attest command's authorization slots are
/// independent of one another: a <c>TPM_RS_PW</c> slot can sit at any index, so which entries are placeholders
/// cannot be expressed by a single leading flag.
/// </summary>
/// <param name="IsPasswordPlaceholder">Whether this entry is a <c>TPM_RS_PW</c> slot's placeholder — an empty nonceTPM, the echoed attributes, and an empty HMAC (Part 1, clause 17.6.4.1: a password authorization carries no session key to compute one with). The key material and the session hash algorithm are meaningless when set; <paramref name="NonceCaller"/> still carries, and owns, whatever the slot presented on the wire.</param>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns (or the shared <see cref="TpmSimulatorState.EmptySessionKey"/> for a placeholder entry); the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <paramref name="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value (and the same bind-omission decision) the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it. The shared empty carrier when the slot's command HMAC folded nothing (a session bound to the entity it authorizes, so its authValue rode the bind).</param>
/// <param name="NonceCaller">
/// This slot's command caller nonce (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) — the
/// response HMAC's nonceOlder — OWNED by this entry, transferred out of the request record by the continuation
/// that built the entry, and released by the attest effect's <c>finally</c> once framing has read it. A
/// <c>TPM_RS_PW</c> slot's placeholder entry owns its slot's nonce exactly as a real entry does, so a mixed
/// authorization area leaves nothing behind.
/// </param>
/// <param name="EntityAuthValue">
/// The authValue folded into the CIPHER key alongside <paramref name="SessionKey"/> when this entry is the one
/// carrying <c>encrypt</c> — the authorized entity's LIVE value, UNRESOLVED by the session's bind, because for
/// parameter encryption "the binding of the session is ignored" (TPM 2.0 Library Part 1, clause 19.1) while the
/// response HMAC key in <paramref name="AuthValue"/> keeps equation 22's omission (clause 17.6.10). The shared
/// empty carrier for a companion, which authorizes no entity and whose <c>sessionValue</c> is its session key
/// alone, and for a placeholder entry. A borrowed reference to the carrier the durable state owns; the framing
/// effect reads its trailing-zero-stripped view at the keystream primitive and never disposes it.
/// </param>
/// <param name="SessionAttributes">This session's command session attributes (<c>TPMA_SESSION</c>, TPM 2.0 Library Part 2, clause 8.4, Table 40), echoed into its response entry.</param>
/// <param name="Encrypts">Whether this session carries the <c>encrypt</c> attribute and so protects the response's first parameter, the <c>TPM2B_ATTEST</c> (TPM 2.0 Library Part 1, clause 19.1; at most one session in a command may set it).</param>
/// <param name="Symmetric">The session's negotiated symmetric definition, meaningful only when <see cref="Encrypts"/> is set; <see cref="TpmtSymDef.Null"/> for a placeholder entry, which negotiated none.</param>
public sealed record TpmAttestResponseSession(
    bool IsPasswordPlaceholder,
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    bool Encrypts,
    TpmtSymDef Symmetric);

/// <summary>
/// One framed attest-command response session entry (<c>TPMS_AUTH_RESPONSE</c>, TPM 2.0 Library Part 2, clause
/// 10.10.2) produced from a <see cref="TpmAttestResponseSession"/> — the rolled nonceTPM and computed response
/// HMAC for a real session, or the empty-nonce, empty-HMAC placeholder for a <c>TPM_RS_PW</c> slot.
/// </summary>
/// <param name="IsPasswordPlaceholder">Whether this entry is a password slot's placeholder; <paramref name="Hmac"/> is then <see langword="null"/> and both nonce carriers are the dispose-immune shared empty.</param>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>; meaningless for a placeholder.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed as this entry's nonceNewer; the serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; the rolling transition transfers it onto the durable session record, and disposes it itself when that session has already left its table.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154), owned and disposed after framing; <see langword="null"/> for a placeholder, which owns nothing.</param>
public sealed record TpmAttestFramedSessionEntry(
    bool IsPasswordPlaceholder,
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth? Hmac);

/// <summary>
/// The result of executing an attest action — <see cref="TpmCertifyAction"/>, <see cref="TpmCertifyCreationAction"/>,
/// <see cref="TpmQuoteAction"/>, <see cref="TpmGetTimeAction"/>, <see cref="TpmNvCertifyAction"/>, or an RSA
/// counterpart — whose <c>ResponseSessions</c> was non-empty: the framed <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c>
/// response parameter area and every session's framed response entry, fed back so the transition can roll each
/// real session's stored nonce and frame the response. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <remarks>
/// The marshaled attest and the signature are consumed while framing <see cref="ParameterArea"/> and released
/// there, so — unlike the plain-arm results (<see cref="TpmObjectCertified"/> and its siblings), which carry both
/// onward — nothing but the parameter area and each real entry's <c>Hmac</c> survives to the framing step, which
/// is their terminal owner.
/// </remarks>
/// <param name="CommandCode">The attest command the response answers — the transition label's subject and, on the effect side, the <c>commandCode</c> term of every entry's rpHash (TPM 2.0 Library Part 1, clause 16.8 equation 16).</param>
/// <param name="ParameterArea">The framed <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c> response parameter area — the exact octets rpHash covered; disposed after framing.</param>
/// <param name="Entries">Every session's framed response entry, in command-session order.</param>
public sealed record TpmAttestedOverSessions(
    TpmCcConstants CommandCode,
    TpmParameterArea ParameterArea,
    ImmutableArray<TpmAttestFramedSessionEntry> Entries): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_VerifySignature()</c> command (TPM 2.0 Library Part 3, clause 20.1): validate that <see cref="Signature"/>
/// is a valid signature over <see cref="Digest"/> made with the key referenced by <see cref="KeyHandle"/>. This is a
/// public-key operation — <see cref="KeyHandle"/> requires no authorization at all, so the parser consumes no
/// session.
/// </summary>
/// <param name="KeyHandle">The loaded key whose public part verifies the signature.</param>
/// <param name="Digest">The digest the signature is claimed to be over (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), in an owned pooled carrier rented as the parse's last act; the consuming transition transfers it into the verification action, whose effect is its terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="SignatureScheme">The signing algorithm (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>), the <c>TPMU_SIGNATURE</c> selector.</param>
/// <param name="SchemeHashAlg">The hash algorithm carried inside the signature.</param>
/// <param name="Signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
public sealed record TpmVerifySignatureRequested(
    TpmiDhObject KeyHandle,
    Tpm2bDigest Digest,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    ReadOnlyMemory<byte> Signature): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="Digest"/> carrier on a refusing path; the consuming transition transfers
    /// its ownership into the verification action instead and never calls this.
    /// </summary>
    public void Dispose()
    {
        Digest.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmVerifySignatureAction"/> or <see cref="TpmRsaVerifySignatureAction"/>:
/// whether the signature verified and, on success, the octets of the ticket digest the effectful loop computed. A
/// failed verification (TPM 2.0 Library Part 3, clause 20.1: "Otherwise, the TPM shall return TPM_RC_SIGNATURE")
/// carries <c>TPM_RC_SIGNATURE</c> with no ticket, mirroring <see cref="TpmObjectCreationCertified"/>'s
/// success/rejection split. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the signature verified; otherwise <c>TPM_RC_SIGNATURE</c>.</param>
/// <param name="Validation">The minted <c>TPMT_TK_VERIFIED</c> — the whole single response parameter of <c>TPM2_VerifySignature()</c> (TPM 2.0 Library Part 3, clause 20.1.2, Table 108), tag, hierarchy, and ticket HMAC digest together (Part 2, clause 10.7.4, Table 110); an owned carrier whose ownership flows to the <c>TpmVerifySignatureResponse</c> and is released by <see cref="TpmSimulator"/> once framed. <see langword="null"/> when the signature did not verify, where no ticket is framed at all.</param>
public sealed record TpmSignatureVerified(
    TpmRcConstants ResponseCode,
    TpmtTkVerified? Validation): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmVerifyPolicySignedAction"/> or
/// <see cref="TpmRsaVerifyPolicySignedAction"/>: whether the recomputed <c>aHash</c> verified against
/// <c>authObject</c>'s signature (TPM 2.0 Library Part 3, Section 23.3), and, on success, the real
/// <c>TPMT_TK_AUTH</c> ticket the effect minted when a ticket was requested. A failed verification carries
/// <c>TPM_RC_SIGNATURE</c> and no ticket; the continuation folds the policyDigest only on success. Internal to
/// the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the signature verified; otherwise <c>TPM_RC_SIGNATURE</c>.</param>
/// <param name="PolicySession">The policy session to extend on a successful verification.</param>
/// <param name="FoldedDigest">The policyDigest the effect folded from the authorizing key's Name and the policy qualifier (<c>PolicyUpdate</c>, Part 3, Section 23.3) in an owned pooled carrier rented at the session's own digest width; the continuation installs it on the session, which becomes its owner. The dispose-immune empty sentinel on a failed verification, where nothing is folded.</param>
/// <param name="CpHashA">The cpHashA the request supplied in an owned pooled carrier, or the dispose-immune empty sentinel if unbound. On success, and only when non-empty and the session is unlatched, the continuation TRANSFERS it onto the session's first-writer-wins cpHash (Part 3, Section 23.2.4); on every other arm — an already-latched session and a failed verification alike — the continuation releases it, so a rejected assertion leaves the session exactly as it found it.</param>
/// <param name="Timeout">The deadline magnitude alone, recorded on the session under Part 3, Section 23.2.4's min-with-existing rule. It is carried apart from <see cref="FramedTimeout"/> because a no-ticket assertion still ranks a real deadline while framing a NULL one (Section 23.2.5).</param>
/// <param name="FramedTimeout">The deadline as the <c>TPM2B_TIMEOUT</c> the response frames, bit 63 carrying the expires-on-reset flag (TPM 2.0 Library Part 2, clause 10.4.10, Table 100); owned, and the shared empty carrier whenever <see cref="TicketDigest"/> is <see langword="null"/>, where the wire form is a NULL timeout (Part 3, Section 23.2.5).</param>
/// <param name="Hierarchy">The authorizing key's hierarchy, framed in the ticket's own <c>hierarchy</c> field; meaningless when <see cref="TicketDigest"/> is <see langword="null"/>.</param>
/// <param name="TicketDigest">The minted ticket's HMAC digest as the <c>TPM2B_DIGEST</c> <c>TPMT_TK_AUTH.digest</c> names (TPM 2.0 Library Part 2, clause 10.7.5, Table 111); owned, ownership flowing to the <c>TpmPolicySignedResponse</c> and released by <see cref="TpmSimulator"/> once framed. <see langword="null"/> when no ticket was requested (a non-negative expiration) — the response then frames a NULL ticket.</param>
public sealed record TpmPolicySignedVerified(
    TpmRcConstants ResponseCode,
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest,
    Tpm2bDigest CpHashA,
    ulong Timeout,
    Tpm2bTimeout FramedTimeout,
    TpmiRhHierarchy Hierarchy,
    Tpm2bDigest? TicketDigest): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_StartAuthSession()</c> command (TPM 2.0 Library Part 3, clause 11.1) that starts a POLICY or TRIAL
/// session. The bind/salt/nonceCaller/symmetric ladder is identical to <see cref="TpmStartHmacSessionRequested"/>'s
/// (Section 11.1.1: "For all session types, this command will cause initialization of the sessionKey") — only the
/// resulting session's own additional context differs (recorded on <see cref="PolicySessionState"/>, never on
/// <see cref="HmacSessionState"/>).
/// </summary>
/// <param name="SessionType">The session type (<c>TPM_SE_POLICY</c> or <c>TPM_SE_TRIAL</c>); a trial session accumulates the policyDigest but authorizes nothing.</param>
/// <param name="AuthHash">The session's policy hash algorithm (<c>authHash</c>), whose digest width the policyDigest carries and which sizes the returned nonceTPM.</param>
/// <param name="Bind">The entity the session binds to, whose authorization value seeds the session key (<c>TPM_RH_NULL</c> for an unbound session) — folded into the KDFa key only; a POLICY/TRIAL session never applies the HMAC-session bind-omission optimization (Part 1, clause 17.6.10's "the session is not bound").</param>
/// <param name="NonceCaller">
/// The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page
/// 134); the second context field of the session-key KDFa (Part 1, clause 17.6.10). An owned pooled carrier
/// rented at parse; the accepted transition transfers it into the session-start action, whose effect is its
/// terminal owner, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="Symmetric">The symmetric definition negotiated at start; consumed for wire-shape parity with an HMAC session but not recorded on a POLICY/TRIAL session (parameter encryption over such a session is out of this model's scope).</param>
/// <param name="TpmKey">The handle of the key salt is encrypted to (<c>TPM_RH_NULL</c> for an unsalted session).</param>
/// <param name="EncryptedSalt">
/// The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 210, page 180):
/// an RSA OAEP ciphertext or a marshaled <c>TPMS_ECC_POINT</c>, depending on <see cref="TpmKey"/>'s algorithm;
/// the dispose-immune empty sentinel when unsalted. An owned pooled carrier rented at parse, transferred into
/// the salted session-start action the same way <see cref="NonceCaller"/> is.
/// </param>
public sealed record TpmStartAuthSessionRequested(
    TpmSeConstants SessionType,
    TpmiAlgHash AuthHash,
    TpmiDhEntity Bind,
    Tpm2bNonce NonceCaller,
    TpmtSymDef Symmetric,
    TpmiDhObject TpmKey,
    Tpm2bEncryptedSecret EncryptedSalt): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NonceCaller"/> and <see cref="EncryptedSalt"/> carriers on a refusing path;
    /// the accepted arm instead transfers both into the session-start action and never calls this.
    /// </summary>
    public void Dispose()
    {
        NonceCaller.Dispose();
        EncryptedSalt.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_StartAuthSession()</c> command (TPM 2.0 Library Part 3, clause 11.1) that starts a bound and/or
/// salted HMAC session with parameter encryption. It is the parameter-encryption counterpart of
/// <see cref="TpmStartAuthSessionRequested"/>: the session key is derived from the bind entity's authorization
/// value and/or the recovered salt plus the two start nonces (Part 1, clause 17.6.10 equations 20/23/25), and
/// the negotiated symmetric definition keys the encryption of the first response parameter.
/// </summary>
/// <param name="Bind">The entity the session binds to, whose authorization value seeds the session key (<c>TPM_RH_NULL</c> for an unbound session).</param>
/// <param name="NonceCaller">
/// The caller nonce sent at start (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page
/// 134); it is the second context field of the session-key KDFa (Part 1, clause 17.6.10). An owned pooled
/// carrier rented at parse; the accepted transition transfers it into the session-start action, whose effect is
/// its terminal owner, and every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="Symmetric">The symmetric definition negotiated for parameter encryption (XOR obfuscation, AES-CFB, or <c>TPM_ALG_NULL</c>).</param>
/// <param name="AuthHash">The session hash algorithm (<c>authHash</c>), which drives the KDFa derivations and sizes the returned nonceTPM.</param>
/// <param name="TpmKey">The handle of the key salt is encrypted to (<c>TPM_RH_NULL</c> for an unsalted session).</param>
/// <param name="EncryptedSalt">
/// The wire <c>encryptedSalt</c> (<c>TPM2B_ENCRYPTED_SECRET</c>, Part 2, clause 11.4.3, Table 210, page 180):
/// an RSA OAEP ciphertext or a marshaled <c>TPMS_ECC_POINT</c>, depending on <see cref="TpmKey"/>'s algorithm;
/// the dispose-immune empty sentinel when unsalted. An owned pooled carrier rented at parse, transferred into
/// the salted session-start action the same way <see cref="NonceCaller"/> is.
/// </param>
public sealed record TpmStartHmacSessionRequested(
    TpmiDhEntity Bind,
    Tpm2bNonce NonceCaller,
    TpmtSymDef Symmetric,
    TpmiAlgHash AuthHash,
    TpmiDhObject TpmKey,
    Tpm2bEncryptedSecret EncryptedSalt): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NonceCaller"/> and <see cref="EncryptedSalt"/> carriers on a refusing path;
    /// the accepted arm instead transfers both into the session-start action and never calls this.
    /// </summary>
    public void Dispose()
    {
        NonceCaller.Dispose();
        EncryptedSalt.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that started (or failed to start) a bound and/or salted
/// HMAC session: the freshly generated nonceTPM and the derived session key, fed back so the transition can
/// record the session and frame the <c>TPM2_StartAuthSession()</c> response — or, when salt recovery failed,
/// the failure code to reject with. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// The session key and bound-entity value arrive as owned pooled sensitive carriers
/// (<see cref="SymmetricKeyMemory"/>, <see cref="SessionBoundEntity"/>), rented by the effect and handed to the
/// transition, which installs them on the durable <see cref="HmacSessionState"/>/<see cref="PolicySessionState"/>
/// — the session record becomes their single owner for the lifetime of the session. The nonce arrives in a PAIR
/// of owned <c>TPM2B_NONCE</c> carriers (TPM 2.0 Library Part 2, clause 10.4.4, Table 94) holding the same
/// octets, because the response framing and the session record release theirs at unrelated moments.
/// </remarks>
/// <param name="ResponseCode">
/// <c>TPM_RC_SUCCESS</c> when the session key was derived; <c>TPM_RC_VALUE</c> when a salted arm's secret
/// recovery failed internally (bad OAEP padding, an oversize recovered salt, or a malformed/off-curve ECC
/// point — TPM 2.0 Library Part 3, clause 11.1), reported immediately rather than poisoned-and-deferred. Every
/// other field is a meaningless empty placeholder when this is not <c>TPM_RC_SUCCESS</c>.
/// </param>
/// <param name="SessionHandle">The session handle the transition allocated for the new session.</param>
/// <param name="SessionAlg">The session hash algorithm to record on the session.</param>
/// <param name="Symmetric">The negotiated symmetric definition to record on the session.</param>
/// <param name="NonceTpm">The initial nonceTPM in an owned pooled carrier: generated from the injected RNG and framed in the response, whose serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; ownership transfers to the recorded session, which holds it as its current nonceTPM until the first roll, and the transition disposes it itself on every arm that records no session.</param>
/// <param name="SessionKey">The <c>KDFa</c>-derived session key to record on the session (the HMAC and parameter-encryption key), or the shared <see cref="TpmSimulatorState.EmptySessionKey"/> for a session that is neither bound nor salted; ownership passes to the session record.</param>
/// <param name="BoundEntity">The bound-entity value the effect computed from <see cref="Automata.TpmStartHmacSessionAction"/>'s Name and authValue (Part 4, <c>SessionComputeBoundEntity()</c>), to record on the session; ownership passes to the session record. Always <see cref="SessionBoundEntity.Unbound"/> when <see cref="PolicyContext"/> is set (a POLICY/TRIAL session never applies the bind-omission optimization).</param>
/// <param name="PolicyContext">Non-<see langword="null"/> when the action that produced this key was starting a POLICY or TRIAL session rather than an HMAC session; <c>OnHmacSessionStarted</c> then records a <see cref="PolicySessionState"/> instead of an <see cref="HmacSessionState"/>.</param>
/// <param name="IsBoundEntityDaProtected">
/// The bind entity's dictionary-attack protection state, threaded through unchanged from the action the
/// transition dispatched, to be recorded on the session — TPM 2.0 Library Part 1, clause 17.6.10: "The noDA
/// attribute of the bind entity is recorded in the session context." Unlike <see cref="BoundEntity"/> this
/// is meaningful for a POLICY/TRIAL session too, since clause 17.8.7's failure accounting is stated for a bound
/// session without qualification by session type.
/// </param>
/// <param name="IsBoundToLockout">Whether the bind entity was <c>TPM_RH_LOCKOUT</c>, recorded on the session so a later failed use takes the one-strike lockoutAuth discipline (TPM 2.0 Library Part 1, clauses 17.8.1 and 17.8.5).</param>
public sealed record TpmHmacSessionStarted(
    TpmRcConstants ResponseCode,
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    Tpm2bNonce NonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    SymmetricKeyMemory SessionKey,
    SessionBoundEntity BoundEntity,
    TpmPolicySessionKeyContext? PolicyContext = null,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1) carried over a bound HMAC session with
/// the <c>encrypt</c> attribute set. Unlike <see cref="TpmGetRandomRequested"/> (the unauthorized, no-session
/// form) this carries the command's authorization-area fields the command-HMAC verification and the response path
/// need: the rolled caller nonce, the session attributes, the supplied <c>hmac</c>, and the raw parameter-area
/// bytes cpHash is computed over (Part 1, clauses 16.7 and 19). <c>GetRandom</c> authorizes no entity, so the
/// verification's HMAC key is the session key alone and no dictionary-attack gate applies.
/// </summary>
/// <param name="SessionHandle">The HMAC session the command runs over.</param>
/// <param name="NonceCaller">The caller nonce rolled for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the cpHash-verification nonceNewer and the nonceOlder of the response-direction encryption and the response HMAC (Part 1, clause 19.2). Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-encryption step, whose effect releases it once both keystream and response HMAC have keyed their nonceOlder term on it.</param>
/// <param name="SessionAttributes">The command session-attributes octet, echoed into the response session area, folded into the command-HMAC verification, and folded into the response HMAC.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act, verified against the session's independently-derived key before the random draw proceeds. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>bytesRequested</c> wire bytes (the 2-octet <c>UINT16</c>, captured before decode), the cpHash parameter term (Part 1, clause 16.7 equation 15). Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="BytesRequested">The number of random octets the caller requested (clamped as in the no-session form).</param>
public sealed record TpmGetRandomOverSessionRequested(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    ushort BytesRequested): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/>
    /// carriers on every path that does not frame the command's response.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response encryption.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmAction"/> that produced an encrypt-attributed <c>TPM2_GetRandom()</c>
/// response over an HMAC session: the framed (encrypted) response parameter area, the freshly rolled nonceTPM,
/// and the response HMAC, fed back so the transition can roll the session nonce and frame the response. Internal
/// to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> and <see cref="Hmac"/> are pooled carriers the framing step disposes as the terminal
/// owner. The rolled nonceTPM arrives in a PAIR of owned carriers, one for the framing step and one for the
/// durable session record, because those two owners release theirs at unrelated moments.
/// </remarks>
/// <param name="SessionHandle">The HMAC session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed in the response session area (nonceNewer); ownership travels into the response intent, whose serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; the rolling transition transfers it onto the durable session record, and disposes it itself when the session has already left its table.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="ParameterArea">The framed <c>TPM2B_DIGEST</c> response parameter with its data portion encrypted; disposed after framing.</param>
/// <param name="Hmac">The response session HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154); owned, disposed after framing.</param>
public sealed record TpmEncryptedRandomProduced(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    TpmParameterArea ParameterArea,
    Tpm2bAuth Hmac): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyCommandCode()</c> command (TPM 2.0 Library Part 3, clause 23.4): restricts a policy session to
/// a single command, extending its policyDigest by <c>H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ code)</c>. The
/// policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the restriction is applied to.</param>
/// <param name="Code">The command code the policy is restricted to.</param>
public sealed record TpmPolicyCommandCodeRequested(TpmiShPolicy PolicySession, TpmCcConstants Code): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyAuthValue()</c> command (TPM 2.0 Library Part 3, clause 23.18): binds a policy to the
/// authorized object's authorization value, extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyAuthValue)</c>. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
public sealed record TpmPolicyAuthValueRequested(TpmiShPolicy PolicySession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyGetDigest()</c> command (TPM 2.0 Library Part 3, clause 23.6): returns the current policyDigest
/// of a policy or trial session. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle whose digest is read.</param>
public sealed record TpmPolicyGetDigestRequested(TpmiShPolicy PolicySession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyPCR()</c> command (TPM 2.0 Library Part 3, clause 23.7): binds a policy to a set of PCRs,
/// extending its policyDigest by <c>H(policyDigest ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ pcrDigest)</c>. On a trial session
/// the caller's pcrDigest is used verbatim. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="PcrDigest">
/// The expected digest of the selected PCR values (used verbatim on a trial session), a <c>TPM2B_DIGEST</c>
/// (TPM 2.0 Library Part 2, clause 10.4.2, Table 92) in an owned pooled carrier rented as the parse's last act.
/// The accepting arm TRANSFERS it into the <see cref="Automata.TpmFoldPolicyDigestAction"/>, whose effect is its
/// terminal owner on both outcomes — the folded one and the <c>TPM_RC_VALUE</c> mismatch against the live
/// composite (Part 3, clause 23.7); the refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PcrSelectionBytes">The marshaled <c>TPML_PCR_SELECTION</c> wire bytes, captured verbatim and folded into the policyDigest exactly as sent.</param>
public sealed record TpmPolicyPcrRequested(
    TpmiShPolicy PolicySession,
    Tpm2bDigest PcrDigest,
    ReadOnlyMemory<byte> PcrSelectionBytes): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="PcrDigest"/> carrier on a refusing path; the accepting arm transfers it
    /// into the fold action instead, and never calls this.
    /// </summary>
    public void Dispose()
    {
        PcrDigest.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_PolicyOR()</c> command (TPM 2.0 Library Part 3, clause 23.6): authorizes a policy session when its
/// current policyDigest matches one of the branches, then collapses it to
/// <c>H(0…0 ‖ TPM_CC_PolicyOR ‖ branches)</c>. On a trial session the match check is skipped. The policy session
/// is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="Branches">
/// The allowed branch policy digests (the OR alternatives), in the order sent, as the <c>TPML_DIGEST</c> the
/// command's <c>pHashList</c> parameter names (TPM 2.0 Library Part 2, clause 10.9.5, Table 123) in an owned
/// pooled carrier rented as the parse's last act. The consuming transition transfers it into the fold, whose
/// effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmPolicyOrRequested(
    TpmiShPolicy PolicySession,
    TpmlDigest Branches): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="Branches"/> list and every branch carrier in it on a refusing path; the
    /// accepting arm transfers the list into the fold action instead, and never calls this.
    /// </summary>
    public void Dispose()
    {
        Branches.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_PolicySecret()</c> command, immediate or non-immediate (TPM 2.0 Library Part 3, clause 23.4):
/// binds a policy to the authorization of the entity at <see cref="AuthHandle"/>, extending its policyDigest
/// by <c>H(policyDigest ‖ TPM_CC_PolicySecret ‖ authName)</c> followed by the <see cref="PolicyRef"/> hash. The
/// authorized entity requires authorization — a genuinely verified authValue (constant-time compared against
/// the entity's own, non-dictionary-attack-gated, mirroring the existing owner-auth posture), checked even for
/// a trial session (Part 3, Section 23.4.1: "The authorization is checked even for a trial policy session")
/// — carried by <see cref="AuthValueSupplied"/>. A non-trial session additionally runs
/// <see cref="NonceTpm"/>/<see cref="Expiration"/>/<see cref="CpHashA"/> checks (Section 23.2.2) and, on
/// <see cref="Expiration"/> negative, mints a <c>TPM_ST_AUTH_SECRET</c> ticket.
/// </summary>
/// <param name="AuthHandle">The entity whose authorization the policy requires (for a permanent hierarchy its Name is its 4-byte handle value).</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="AuthValueSupplied">The password session's supplied authValue for <see cref="AuthHandle"/>, verified before anything else — the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (Part 2, clause 10.13.2, Table 153) — in a pooled carrier this record OWNS, rented as the parse's last act. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NonceTpm">The caller-supplied nonceTPM (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act: it must equal the session's retained nonce when non-empty, or be empty for a session-unbound authorization (non-trial only). The transition that runs that comparison releases it immediately afterwards and carries only its emptiness onward, so the shared post-authorization ladder never holds it; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="CpHashA">
/// The command-parameter digest being authorized (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2,
/// Table 92) in an owned pooled carrier rented as the parse's last act, or the dispose-immune empty sentinel
/// when unbound (non-trial only). An unlatched session's latch TRANSFERS this carrier onto the session
/// (Section 23.2.4); every other arm — an already-latched session, a trial session, and every refusal —
/// releases it, the refusals through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PolicyRef">
/// The opaque policy qualifier, folded into the policyDigest unconditionally (Part 3, Section 23.2.3), as the
/// <c>TPM2B_NONCE</c> its own command table names (Part 2, clause 10.4.4, Table 94) in an owned pooled carrier
/// rented as the parse's last act. The accepting arm transfers it into the fold or the ticket-mint action,
/// whose effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="Expiration">The requested expiration (seconds); 0 = no expiry, negative = ticket requested (non-trial only; ignored on a trial session).</param>
public sealed record TpmPolicySecretRequested(
    TpmiDhEntity AuthHandle,
    TpmiShPolicy PolicySession,
    Tpm2bAuth AuthValueSupplied,
    Tpm2bNonce NonceTpm,
    Tpm2bDigest CpHashA,
    Tpm2bNonce PolicyRef,
    int Expiration): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthValueSupplied"/>, <see cref="NonceTpm"/>, <see cref="CpHashA"/> and
    /// <see cref="PolicyRef"/> carriers on a refusing path; the accepting arms transfer or release them
    /// explicitly instead, and never call this.
    /// </summary>
    public void Dispose()
    {
        AuthValueSupplied.Dispose();
        NonceTpm.Dispose();
        CpHashA.Dispose();
        PolicyRef.Dispose();
    }
}

/// <summary>
/// The resolved session material for whichever HMAC or POLICY session proved knowledge of
/// <c>TPM2_PolicySecret()</c>'s <c>authHandle</c> — the widened form <see cref="TpmPolicySecretRequested"/>'s
/// direct <see cref="TpmPolicySecretRequested.AuthValueSupplied"/> compare takes when authorization instead
/// rides a real session (TPM 2.0 Library Part 3, Section 23.4.1). Carried from
/// <c>OnPolicySecretOverSession</c>/<c>ContinuePolicySecretOverSession</c> through <c>FoldPolicySecret</c> and,
/// when a ticket is minted, through <see cref="Automata.TpmMintPolicySecretTicketAction"/> and
/// <see cref="TpmPolicySecretTicketMinted"/>, so the eventual response-framing effect can roll this session's
/// nonceTPM and compute a real response HMAC keyed on the SAME <c>sessionKey ‖ authValue</c> the command-HMAC
/// verification used (Part 1, clause 17.6.5).
/// </summary>
/// <param name="SessionHandle">The authorizing session's handle.</param>
/// <param name="IsPolicySession">Whether <see cref="SessionHandle"/> names a POLICY session (eq. 26/27, Part 1 clause 17.6.12, TPM_RC_MODE-gated) rather than an HMAC session (ordinary bind-omission, equation 22, Part 1 clause 17.6.10).</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session's KDFa-derived session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue term folded into the HMAC key alongside <see cref="SessionKey"/> — the shared empty carrier when the HMAC-session bind-omission (equation 22) or the POLICY-session eq. 27 (isAuthValueNeeded CLEAR) applies, a borrowed reference to the hierarchy's live authValue carrier otherwise (equation 26; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it).</param>
/// <param name="NonceCaller">
/// This command's caller nonce for the session (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94) — the
/// response HMAC's nonceOlder. OWNED by this entry, transferred out of the request record by the continuation
/// that built it, carried unchanged across the fold and ticket-mint hops into
/// <see cref="Automata.TpmFramePolicySecretSessionResponseAction"/>, and released by that framing effect's
/// <see langword="finally"/>. The one shared ladder both arms run through releases it at the arm instead
/// wherever it refuses after this entry was built.
/// </param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
public sealed record PolicySecretAuthorizingSession(
    TpmiShAuthSession SessionHandle,
    bool IsPolicySession,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes);

/// <summary>
/// A <c>TPM2_PolicySecret()</c> command whose <c>authHandle</c> is authorized by an HMAC or POLICY session
/// rather than a password (TPM 2.0 Library Part 3, Section 23.4.1: "A password session, an HMAC session, or a
/// policy session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this requirement").
/// The wire shape is identical to the password arm's (<see cref="TpmPolicySecretRequested"/>) except the
/// authorization area carries a real <c>TPMS_AUTH_COMMAND</c> (sessionHandle/nonceCaller/sessionAttributes/hmac)
/// instead of a <c>TPM_RS_PW</c> password body; <c>TryReadCommandSessionSpans</c> parses both shapes uniformly,
/// so which record this becomes is decided purely by whether the parsed <c>sessionHandle</c> equals
/// <c>TPM_RS_PW</c>.
/// </summary>
/// <param name="AuthHandle">The entity whose authorization the policy requires (for a permanent hierarchy its Name is its 4-byte handle value — also the cpHash's Name1 term).</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to — also the cpHash's Name2 term (TPM 2.0 Library Part 1, Table 6: a session's Name is its own raw handle), which is <b>this</b> handle, never <see cref="AuthorizingSessionHandle"/>, even when the two happen to differ.</param>
/// <param name="AuthorizingSessionHandle">The session (HMAC or POLICY table) that authorizes <see cref="AuthHandle"/>.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the continuation TRANSFERS it into <see cref="PolicySecretAuthorizingSession"/>, from where the response-framing effect releases it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act, verified against the session's independently-derived key before anything else proceeds. Everything downstream BORROWS it, so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>nonceTPM ‖ cpHashA ‖ policyRef ‖ expiration</c> wire bytes exactly as received (Part 1, clause 16.7 equation 15's <c>parameters</c> term) — PolicySecret's entire parameter set, captured before any field is decoded. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="NonceTpm">The caller-supplied nonceTPM (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act: it must equal the session's retained nonce when non-empty, or be empty for a session-unbound authorization (non-trial only). The continuation that runs that comparison releases it immediately afterwards and carries only its emptiness onward; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="CpHashA">
/// The command-parameter digest being authorized (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2,
/// Table 92) in an owned pooled carrier rented as the parse's last act, or the dispose-immune empty sentinel
/// when unbound (non-trial only). An unlatched session's latch TRANSFERS this carrier onto the session
/// (Section 23.2.4); every other arm — an already-latched session, a trial session, and every refusal —
/// releases it, the refusals through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PolicyRef">
/// The opaque policy qualifier, folded into the policyDigest unconditionally (Part 3, Section 23.2.3), as the
/// <c>TPM2B_NONCE</c> its own command table names (Part 2, clause 10.4.4, Table 94) in an owned pooled carrier
/// rented as the parse's last act. The accepting arm transfers it into the fold or the ticket-mint action,
/// whose effect is its terminal owner; every refusing arm releases it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="Expiration">The requested expiration (seconds); 0 = no expiry, negative = ticket requested (non-trial only; ignored on a trial session).</param>
public sealed record TpmPolicySecretOverSessionRequested(
    TpmiDhEntity AuthHandle,
    TpmiShPolicy PolicySession,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bNonce NonceTpm,
    Tpm2bDigest CpHashA,
    Tpm2bNonce PolicyRef,
    int Expiration): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="CpHashA"/>, <see cref="PolicyRef"/>, <see cref="RawParameterArea"/>,
    /// <see cref="NonceTpm"/> and session-slot carriers on a refusing path — including the command-HMAC
    /// mismatch and cancellation arms this record is enrolled in; the accepting arms transfer or release them
    /// explicitly instead, and never call this.
    /// </summary>
    public void Dispose()
    {
        CpHashA.Dispose();
        PolicyRef.Dispose();
        RawParameterArea.Dispose();
        NonceTpm.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmFramePolicySecretSessionResponseAction"/>: the rolled
/// nonceTPM, framed <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> parameter bytes, and response HMAC for a
/// session-authorized <c>TPM2_PolicySecret()</c> call, fed back so the transition can roll the authorizing
/// session's stored nonceTPM and frame the response (TPM 2.0 Library Part 1, clause 16.6.1). Internal to
/// the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="SessionHandle">The authorizing session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>.</param>
/// <param name="IsPolicySession">Whether <see cref="SessionHandle"/> names a POLICY session (rolled in <c>PolicySessions</c>) rather than an HMAC session (<c>HmacSessions</c>).</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed as this entry's nonceNewer; ownership travels into the response intent, whose serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier the framing effect rents alongside <paramref name="NewNonceTpm"/>; the rolling transition transfers it onto the durable session record, and disposes it itself when the session has already left its table. Two carriers because the two owners' lifetimes are disjoint — the framed one dies with the response, the session's lives until the next roll or the session's flush.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="ParameterArea">The framed <c>TPM2B_TIMEOUT ‖ TPMT_TK_AUTH</c> response parameter bytes; disposed after framing.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154); owned, disposed after framing.</param>
public sealed record TpmPolicySecretSessionResponseFramed(
    TpmiShAuthSession SessionHandle,
    bool IsPolicySession,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    TpmParameterArea ParameterArea,
    Tpm2bAuth Hmac): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicySigned()</c> command (TPM 2.0 Library Part 3, Section 23.3): binds a policy session to a
/// signature over <c>aHash = H_authAlg(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef)</c> made by the key at
/// <see cref="AuthObject"/>. Neither <see cref="AuthObject"/> nor <see cref="PolicySession"/> requires
/// authorization, so the parser admits only <c>TPM_ST_NO_SESSIONS</c>, exactly as
/// <see cref="TpmVerifySignatureRequested"/> does.
/// </summary>
/// <param name="AuthObject">The handle of the key that validates the signature (any loaded public key — no <c>sign</c>-attribute gate, unlike <c>TPM2_VerifySignature()</c>'s <c>keyHandle</c>).</param>
/// <param name="PolicySession">The policy session handle being extended.</param>
/// <param name="NonceTpm">The caller-supplied nonceTPM (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act: it must equal the session's retained nonce when non-empty, or be empty for a session-unbound authorization. The accepting arm TRANSFERS it into the signature-verification action, whose effect is its terminal owner once the aHash has bound to it; a trial session, which compares no nonce at all, releases it at its own arm, and every refusing path releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="CpHashA">
/// The command-parameter digest being authorized (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2,
/// Table 92) in an owned pooled carrier rented as the parse's last act, or the dispose-immune empty sentinel
/// when unbound. The accepting arm transfers it into the verification action, whose effect hands it on to the
/// continuation that either latches it onto the session or releases it; a trial session and every refusing arm
/// release it, the refusals through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PolicyRef">
/// The opaque policy qualifier, folded into the policyDigest unconditionally (Part 3, Section 23.2.3), as the
/// <c>TPM2B_NONCE</c> its own command table names (Part 2, clause 10.4.4, Table 94) in an owned pooled carrier
/// rented as the parse's last act. The accepting arm transfers it into the verification action, whose effect is
/// its terminal owner; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="Expiration">The signed expiration (seconds); 0 = no expiry, negative = ticket requested (a non-trial session mints a real <c>TPM_ST_AUTH_SIGNED</c> ticket on success).</param>
/// <param name="SignatureScheme">The signing scheme (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).</param>
/// <param name="SchemeHashAlg">H_authAlg: the hash algorithm carried inside the signature — independent of the session's own policy hash algorithm.</param>
/// <param name="Signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
public sealed record TpmPolicySignedRequested(
    TpmiDhObject AuthObject,
    TpmiShPolicy PolicySession,
    Tpm2bNonce NonceTpm,
    Tpm2bDigest CpHashA,
    Tpm2bNonce PolicyRef,
    int Expiration,
    TpmiAlgSigScheme SignatureScheme,
    TpmiAlgHash SchemeHashAlg,
    ReadOnlyMemory<byte> Signature): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NonceTpm"/>, <see cref="CpHashA"/> and <see cref="PolicyRef"/> carriers on a
    /// refusing path; the accepting arms transfer or release them explicitly instead, and never call this.
    /// </summary>
    public void Dispose()
    {
        NonceTpm.Dispose();
        CpHashA.Dispose();
        PolicyRef.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_PolicyAuthorize()</c> command (TPM 2.0 Library Part 3, Section 23.16): authorizes a policy session
/// when its current policyDigest equals <see cref="ApprovedPolicy"/> and the ticket described by
/// <see cref="CheckTicketHierarchy"/>/<see cref="CheckTicketDigest"/> proves <see cref="KeySign"/> signed
/// <c>H(approvedPolicy || policyRef)</c>, then REPLACES the policyDigest with <c>H(H(0...0 ||
/// TPM_CC_PolicyAuthorize || keySign) || policyRef)</c> — letting an object's fixed authPolicy accept a policy
/// the authority can revise at will. The policy session is a command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle being extended.</param>
/// <param name="ApprovedPolicy">
/// The policy digest being approved (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92) in an
/// owned pooled carrier rented as the parse's last act; must equal the session's current policyDigest (non-trial
/// only). The accepting non-trial arm transfers it into the ticket re-verification action, whose effect is its
/// terminal owner; the trial arm and every refusing arm release it through this record's
/// <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PolicyRef">
/// The opaque policy qualifier, folded into the replacement policyDigest unconditionally, as the
/// <c>TPM2B_NONCE</c> its own command table names (Part 2, clause 10.4.4, Table 94) in an owned pooled carrier
/// rented as the parse's last act. The trial arm transfers it into the fold action and the non-trial arm into
/// the re-verification action, whose effects are its terminal owners; every refusing arm releases it through
/// this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="KeySign">
/// The Name of the key that signed the approval as a <c>TPM2B_NAME</c> (TPM 2.0 Library Part 2, clause 10.5.3,
/// Table 104), in an owned pooled carrier rented as the parse's last act; its first two octets select aHash's
/// hash algorithm. The trial arm's fold and the non-trial ticket re-verification each become its terminal
/// owner in turn; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="CheckTicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from (non-trial only).</param>
/// <param name="CheckTicketDigest">
/// The caller-supplied ticket digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92) in
/// an owned pooled carrier rented as the parse's last act, compared against the recomputed one (non-trial only).
/// The accepting non-trial arm transfers it into the re-verification action, whose effect is its terminal owner;
/// the trial arm and every refusing arm release it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmPolicyAuthorizeRequested(
    TpmiShPolicy PolicySession,
    Tpm2bDigest ApprovedPolicy,
    Tpm2bNonce PolicyRef,
    Tpm2bName KeySign,
    TpmiRhHierarchy CheckTicketHierarchy,
    Tpm2bDigest CheckTicketDigest): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="ApprovedPolicy"/>, <see cref="PolicyRef"/>, <see cref="KeySign"/>, and
    /// <see cref="CheckTicketDigest"/> carriers on a refusing path; the accepting arms transfer or release each
    /// of them explicitly instead, and never call this.
    /// </summary>
    public void Dispose()
    {
        ApprovedPolicy.Dispose();
        PolicyRef.Dispose();
        KeySign.Dispose();
        CheckTicketDigest.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmVerifyPolicyAuthorizeTicketAction"/>: whether the recomputed ticket
/// matched the caller-supplied checkTicket (TPM 2.0 Library Part 3, Section 23.16). A mismatch carries
/// <c>TPM_RC_VALUE</c> — never <c>TPM_RC_TICKET</c>, never <c>TPM_RC_POLICY</c> (the reference implementation
/// folds both the approvedPolicy mismatch and the ticket mismatch into the same code). The continuation
/// resets-and-folds the policyDigest only on success. Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the ticket matched; otherwise <c>TPM_RC_VALUE</c>.</param>
/// <param name="PolicySession">The policy session to reset-and-fold on a successful re-verification.</param>
/// <param name="FoldedDigest">The replacement policyDigest the effect computed from the approving key's Name and the policy qualifier alone (<c>ExtendForAuthorize</c>, Part 3, Section 23.16) in an owned pooled carrier rented at the session's own digest width; the continuation installs it on the session, which becomes its owner. The dispose-immune empty sentinel on a failed re-verification, where nothing is folded.</param>
public sealed record TpmPolicyAuthorizeVerified(
    TpmRcConstants ResponseCode,
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="Automata.TpmMintPolicySecretTicketAction"/>: the real
/// <c>TPM_ST_AUTH_SECRET</c> ticket the effect minted per equation 12 (Part 2, Table 111) for a non-trial
/// <c>TPM2_PolicySecret()</c> call whose caller requested one (a negative expiration, TPM 2.0 Library Part 3,
/// clause 23.4). Unlike the verification continuations above, minting an HMAC has no failure mode of its own,
/// so this always proceeds to fold — there is no rejection branch. Internal to the effect loop; never arrives
/// from the command transport.
/// </summary>
/// <param name="PolicySession">The policy session to fold on completion.</param>
/// <param name="FoldedDigest">The policyDigest the effect folded from the authorizing entity's Name and the policy qualifier (<c>PolicyUpdate</c>, Part 3, Section 23.4) in an owned pooled carrier rented at the session's own digest width; the continuation installs it on the session, which becomes its owner.</param>
/// <param name="Timeout">The already-computed deadline as a <c>TPM2B_TIMEOUT</c> carrier, bit 63 carrying the expires-on-reset flag (TPM 2.0 Library Part 2, clause 10.4.10, Table 100); owned, and framed as the response <c>TPM2B_TIMEOUT</c> when a real ticket accompanies it.</param>
/// <param name="Hierarchy">The authorizing entity's hierarchy (its own permanent handle), framed in the ticket's own <c>hierarchy</c> field.</param>
/// <param name="TicketDigest">The minted ticket's HMAC digest as the <c>TPM2B_DIGEST</c> <c>TPMT_TK_AUTH.digest</c> names (TPM 2.0 Library Part 2, clause 10.7.5, Table 111); owned, ownership flowing to the response intent (or, for a session-authorized call, to the framed response parameter bytes) and released once framed.</param>
/// <param name="AuthorizingSession">Threaded from <see cref="Automata.TpmMintPolicySecretTicketAction.AuthorizingSession"/> unchanged, for <c>FoldPolicySecret</c> to consume.</param>
public sealed record TpmPolicySecretTicketMinted(
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest,
    Tpm2bTimeout Timeout,
    TpmiRhHierarchy Hierarchy,
    Tpm2bDigest TicketDigest,
    PolicySecretAuthorizingSession? AuthorizingSession = null): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyTicket()</c> command (TPM 2.0 Library Part 3, Section 23.5): authorizes a policy session by
/// replaying a ticket a prior <c>TPM2_PolicySigned()</c> or <c>TPM2_PolicySecret()</c> produced, instead of
/// presenting the original authorization again. <see cref="PolicySession"/> is a command handle with no
/// authorization of its own (Auth Index: None) — unlike PolicySigned/PolicySecret, this command carries no
/// <c>nonceTPM</c> at all; the session-binding-vs-absolute distinction was baked into <see cref="Timeout"/> at
/// ticket-mint time and is not re-evaluated here.
/// </summary>
/// <param name="PolicySession">The policy session handle being extended.</param>
/// <param name="Timeout">
/// The caller-supplied <c>TPM2B_TIMEOUT</c> (TPM 2.0 Library Part 2, clause 10.4.10, Table 100) in an owned
/// pooled carrier rented as the parse's last act. Table 100's generic <c>sizeof(UINT64)</c> bound is answered at
/// the wire read; the command-specific "exactly 8" rule is a tighter, separate check the transition applies
/// after the trial-session rejection, the order Part 4's <c>TPM2_PolicyTicket()</c> gives it on printed page
/// 654. The accepting arm consumes the value and releases the
/// carrier; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="CpHashA">
/// The command-parameter digest the ticket is limited to (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause
/// 10.4.2, Table 92) in an owned pooled carrier rented as the parse's last act, or the dispose-immune empty
/// sentinel if unlimited. The accepting arm transfers it into the re-verification action, whose effect hands it
/// on to the continuation that either latches it onto the session or releases it; every refusing arm releases it
/// through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="PolicyRef">
/// The opaque policy qualifier, folded into the recomputed ticket HMAC and, on success, folded again as the
/// fold's second <c>PolicyUpdate</c> hash, as the <c>TPM2B_NONCE</c> its own command table names (Part 2, clause
/// 10.4.4, Table 94) in an owned pooled carrier rented as the parse's last act. The accepting arm transfers it
/// into the re-verification action, whose effect is its terminal owner; every refusing arm releases it through
/// this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="AuthName">
/// The Name of the object that provided the original authorization as a <c>TPM2B_NAME</c> (TPM 2.0 Library
/// Part 2, clause 10.5.3, Table 104), in an owned pooled carrier rented as the parse's last act. The consuming
/// transition transfers it into the re-verification action, whose effect transfers it onward to the
/// continuation; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
/// <param name="TicketTag">The ticket's structure tag (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c> — already legality-checked at parse, Part 2, Table 111's <c>TPM_RC_TAG</c> rule).</param>
/// <param name="TicketHierarchy">The caller-supplied hierarchy the expected ticket's proof is derived from (used AS-IS, never independently re-derived).</param>
/// <param name="TicketDigest">
/// The caller-supplied ticket digest to compare the recomputed one against (<c>TPM2B_DIGEST</c>, TPM 2.0
/// Library Part 2, clause 10.4.2, Table 92) in an owned pooled carrier rented as the parse's last act. The
/// accepting arm transfers it into the re-verification action, whose effect is its terminal owner; every
/// refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmPolicyTicketRequested(
    TpmiShPolicy PolicySession,
    Tpm2bTimeout Timeout,
    Tpm2bDigest CpHashA,
    Tpm2bNonce PolicyRef,
    Tpm2bName AuthName,
    ushort TicketTag,
    TpmiRhHierarchy TicketHierarchy,
    Tpm2bDigest TicketDigest): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="Timeout"/>, <see cref="CpHashA"/>, <see cref="PolicyRef"/>,
    /// <see cref="AuthName"/>, and <see cref="TicketDigest"/> carriers on a refusing path; the accepting arm
    /// consumes the timeout and transfers the other four into the re-verification action instead.
    /// </summary>
    public void Dispose()
    {
        Timeout.Dispose();
        CpHashA.Dispose();
        PolicyRef.Dispose();
        AuthName.Dispose();
        TicketDigest.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmVerifyPolicyTicketAction"/>: whether the recomputed ticket
/// matched the caller-supplied one (TPM 2.0 Library Part 3, Section 23.5). A mismatch carries
/// <c>TPM_RC_TICKET</c>; the continuation folds the policyDigest only on success, via <c>ExtendForSigned</c>
/// or <c>ExtendForSecret</c> selected by <see cref="Tag"/> — the ORIGINAL command's own fold, never a
/// <c>TPM_CC_PolicyTicket</c>-keyed one (Part 3, Section 23.5.1). Internal to the effect loop; never arrives
/// from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the ticket matched; otherwise <c>TPM_RC_TICKET</c>.</param>
/// <param name="PolicySession">The policy session to fold on a successful re-verification.</param>
/// <param name="FoldedDigest">The policyDigest the effect folded through the ORIGINAL command's own <c>PolicyUpdate</c> — selected by the ticket's structure tag, never a <c>TPM_CC_PolicyTicket</c>-keyed one — in an owned pooled carrier rented at the session's own digest width; the continuation installs it on the session, which becomes its owner. The dispose-immune empty sentinel on a failed re-verification, where nothing is folded.</param>
/// <param name="CpHashA">The cpHashA the request supplied in an owned pooled carrier, or the dispose-immune empty sentinel if unbound. On success, and only when non-empty and the session is unlatched, the continuation TRANSFERS it onto the session's first-writer-wins cpHash (Part 3, Section 23.2.4); on every other arm — an already-latched session and a failed re-verification alike — the continuation releases it, so a rejected <c>TPM2_PolicyTicket()</c> leaves the session exactly as it found it.</param>
/// <param name="Timeout">The de-flagged <c>authTimeout</c> magnitude the caller's wire timeout carried, recorded on the session on success per Section 23.2.4's min-with-existing rule.</param>
public sealed record TpmPolicyTicketVerified(
    TpmRcConstants ResponseCode,
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest,
    Tpm2bDigest CpHashA,
    ulong Timeout): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_PolicyNV()</c> command (TPM 2.0 Library Part 3, clause 23.9): binds a policy to a comparison against
/// an NV Index's contents, extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyNV ‖ H(operandB ‖ offset ‖ operation) ‖ nvIndex.Name)</c>. On a REAL (non-trial)
/// session the retained Index data at <see cref="Offset"/> is compared to <see cref="OperandB"/> per
/// <see cref="Operation"/> before the fold, rejecting with <c>TPM_RC_POLICY</c> on a false comparison; a TRIAL
/// session skips the comparison and only the Index Name and the arguments drive the digest. The authorization
/// entity for reading the Index requires authorization, so its password session is consumed by the parser and
/// the supplied value is retained for the transition's authorization arm (the Index's own authValue or the
/// owner hierarchy's, selected by <see cref="AuthHandle"/>).
/// </summary>
/// <param name="AuthHandle">The authorization handle for reading the Index (the Index itself, or a hierarchy).</param>
/// <param name="SuppliedAuthPassword">
/// The plaintext authorization value the caller supplied for the read-authorization slot (the password
/// session's <c>hmac</c> field), compared against the entity <see cref="AuthHandle"/> names — the Index's own
/// retained <see cref="NvIndexState.AuthValue"/> or the owner hierarchy's retained authorization value — both
/// sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An owned
/// pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal owner,
/// releasing it once the authorization arm has consumed it. The dispose-immune empty sentinel for an empty
/// password.
/// </param>
/// <param name="NvIndex">The NV Index whose Name is folded into the policyDigest.</param>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="OperandB">
/// The comparison operand (<c>TPM2B_OPERAND</c>, TPM 2.0 Library Part 2, clause 10.4.6, Table 96) in an owned
/// pooled carrier rented at parse; the accepted arm transfers it into <see cref="Automata.TpmComputeNvNameAction"/>,
/// whose effect is its terminal owner, and a refusing arm releases it through this record's own
/// <see cref="Dispose"/>. The dispose-immune empty sentinel for an empty operand.
/// </param>
/// <param name="Offset">The octet offset into the NV Index data.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation value.</param>
public sealed record TpmPolicyNvRequested(
    TpmiRhNvAuth AuthHandle,
    Tpm2bAuth SuppliedAuthPassword,
    TpmiRhNvIndex NvIndex,
    TpmiShPolicy PolicySession,
    Tpm2bOperand OperandB,
    ushort Offset,
    ushort Operation): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedAuthPassword"/> and <see cref="OperandB"/> carriers on a refusing
    /// path; the consuming transition instead releases the password itself once the authorization arm has
    /// consumed it and transfers the operand into the Name-computing action, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedAuthPassword.Dispose();
        OperandB.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_PolicyCounterTimer()</c> command (TPM 2.0 Library Part 3, Section 23.10): binds a policy to a
/// comparison against the TPM's live <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount, restartCount, Safe),
/// extending its policyDigest by
/// <c>H(policyDigest ‖ TPM_CC_PolicyCounterTimer ‖ H(operandB ‖ offset ‖ operation))</c>. The offset/size range
/// checks (<c>TPM_RC_VALUE</c>/<c>TPM_RC_RANGE</c>) run for trial and real sessions alike; only the comparison
/// itself (<c>TPM_RC_POLICY</c> on a false result) is skipped for a trial session. The policy session is a
/// command handle with no authorization.
/// </summary>
/// <param name="PolicySession">The policy session handle the assertion is applied to.</param>
/// <param name="OperandB">
/// The comparison operand (<c>TPM2B_OPERAND</c>, TPM 2.0 Library Part 2, clause 10.4.6, Table 96) in an owned
/// pooled carrier rented at parse; the accepted arm transfers it into the shared
/// <see cref="Automata.TpmFoldPolicyDigestAction"/>, whose effect is its terminal owner, and a refusing arm
/// releases it through this record's own <see cref="Dispose"/>. The dispose-immune empty sentinel for an empty
/// operand.
/// </param>
/// <param name="Offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
/// <param name="Operation">The <c>TPM_EO</c> comparison operation value.</param>
public sealed record TpmPolicyCounterTimerRequested(
    TpmiShPolicy PolicySession,
    Tpm2bOperand OperandB,
    ushort Offset,
    ushort Operation): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="OperandB"/> carrier on a refusing path; the consuming transition instead
    /// transfers it into the shared fold action, and never calls this.
    /// </summary>
    public void Dispose()
    {
        OperandB.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmComputeNvNameAction"/>: the policyDigest already extended with the
/// NV Index's computed Name and the pending assertion's arguments, fed back so the transition can install it on
/// the policy session and frame the <c>TPM2_PolicyNV()</c> response. Internal to the effect loop; never arrives
/// from the command transport.
/// </summary>
/// <param name="PolicySession">The policy session whose policyDigest the assertion extends.</param>
/// <param name="FoldedDigest">The policyDigest the effect folded from the Index's Name and the assertion's arguments (<c>ExtendForNv</c>, TPM 2.0 Library Part 3, clause 23.9) in an owned pooled carrier rented at the session's own digest width; the continuation installs it on the session, which becomes its owner.</param>
public sealed record TpmNvNameComputedForPolicy(
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="Automata.TpmFoldPolicyDigestAction"/>: the advanced policyDigest, fed
/// back so the transition can install it on the policy session and frame the assertion's own response. One
/// record serves every assertion the shared fold covers, keyed by <see cref="Fold"/>. Internal to the effect
/// loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the fold ran; <c>TPM_RC_VALUE</c> when a real <c>TPM2_PolicyPCR()</c>'s caller-supplied digest did not match the live composite (TPM 2.0 Library Part 3, clause 23.7), the one failure any of these folds has.</param>
/// <param name="Fold">The formula that was applied, selecting which response the resuming transition frames.</param>
/// <param name="PolicySession">The policy session the advanced digest is installed on.</param>
/// <param name="FoldedDigest">The advanced policyDigest in an owned pooled carrier rented at the session's own digest width; the resuming transition installs it, and the session becomes its owner. The dispose-immune empty sentinel when <see cref="ResponseCode"/> is not <c>TPM_RC_SUCCESS</c>.</param>
/// <param name="Label">
/// The assertion's own transition label, threaded through unchanged so the resuming transition emits it
/// verbatim. It is read by every fold whose resume frames a plain header-only success. The <c>Secret</c> and
/// <c>Signed</c> arms resume through the shared completion functions that the ticket-mint and
/// signature-verification continuations also reach, and those name the label themselves because those other
/// callers carry none — the label is the same value on either route.
/// </param>
/// <param name="TimeoutMagnitude">The deadline magnitude the session's own tracked timeout ranks under Part 3, Section 23.2.4's min-with-existing rule, threaded through unchanged.</param>
/// <param name="AuthorizingSession">The session that authorized <c>TPM2_PolicySecret()</c>, threaded through unchanged, or <see langword="null"/> for its password arm.</param>
public sealed record TpmPolicyDigestFolded(
    TpmRcConstants ResponseCode,
    TpmPolicyDigestFold Fold,
    TpmiShPolicy PolicySession,
    Tpm2bDigest FoldedDigest,
    string Label,
    ulong TimeoutMagnitude,
    PolicySecretAuthorizingSession? AuthorizingSession): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_FlushContext()</c> command (TPM 2.0 Library Part 3, clause 28.4): removes a loaded policy session or
/// transient object from TPM memory. The handle to flush is carried in the parameter area (not the handle area)
/// and the command takes no authorization.
/// </summary>
/// <param name="FlushHandle">The session or transient-object handle to remove.</param>
public sealed record TpmFlushContextRequested(TpmiDhContext FlushHandle): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_MakeCredential()</c> command (TPM 2.0 Library Part 3, clause 12.6): wraps a credential secret so
/// that only a TPM holding the private key of the credential key (the endorsement key) and loaded with the
/// object whose Name is <paramref name="ObjectName"/> (the attestation key) can recover it. The command uses only
/// the credential key's public area, so it takes no authorization; its single handle is the credential key.
/// </summary>
/// <param name="KeyHandle">The credential key (the endorsement key) whose public area protects the seed.</param>
/// <param name="Credential">The secret to wrap (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), in an owned pooled carrier rented as the parse's last act. The consuming transition transfers it into the wrap action, whose effect is its terminal owner; every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="ObjectName">
/// The Name the credential is bound to (the attestation key's Name) as a <c>TPM2B_NAME</c> (TPM 2.0 Library
/// Part 2, clause 10.5.3, Table 104), in an owned pooled carrier rented as the parse's last act. The consuming
/// transition transfers it into the wrap action, whose effect is its terminal owner; every refusing arm
/// releases it through this record's <see cref="IDisposable.Dispose"/>.
/// </param>
public sealed record TpmMakeCredentialRequested(
    TpmiDhObject KeyHandle,
    Tpm2bDigest Credential,
    Tpm2bName ObjectName): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="Credential"/> and <see cref="ObjectName"/> carriers on a refusing path;
    /// the accepting arm transfers both into the wrap action instead, and never calls this.
    /// </summary>
    public void Dispose()
    {
        Credential.Dispose();
        ObjectName.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmMakeCredentialAction"/>: the integrity-protected, encrypted credential
/// blob and the asymmetrically-protected seed, fed back so the transition can frame the
/// <c>TPM2_MakeCredential()</c> response. Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="CredentialBlob">The <c>TPMS_ID_OBJECT</c> in an owned <c>TPM2B_ID_OBJECT</c> carrier (TPM 2.0 Library Part 2, clause 12.4.3, Table 229) (the outer HMAC then the encrypted credential); disposed after framing.</param>
/// <param name="Secret">The seed transport (for an ECC credential key a marshaled <c>TPMS_ECC_POINT</c>, the ephemeral public point; for an RSA one the OAEP ciphertext verbatim) in an owned <c>TPM2B_ENCRYPTED_SECRET</c> carrier (TPM 2.0 Library Part 2, clause 11.4.3, Table 210); disposed after framing.</param>
public sealed record TpmCredentialMade(
    Tpm2bIdObject CredentialBlob,
    Tpm2bEncryptedSecret Secret): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_ActivateCredential()</c> command (TPM 2.0 Library Part 3, clause 12.5): recovers a credential wrapped
/// by <c>TPM2_MakeCredential()</c>, proving that the activate object (the attestation key) and the credential key
/// (the endorsement key) are loaded in the same TPM. Both handles require authorization; this is the form where
/// <c>keyHandle</c>'s session resolves to <c>TPM_RS_PW</c> — the activate object's session is always password-only
/// in this slice (Part 3, clause 5.6). A policy session on <c>keyHandle</c> instead parses as
/// <see cref="TpmActivateCredentialOverSessionRequested"/>.
/// </summary>
/// <param name="ActivateHandle">The object the credential is bound to (the attestation key); its Name re-keys the credential's integrity.</param>
/// <param name="SuppliedActivatePassword">
/// The plaintext authorization value the caller supplied for the activate-object slot (session 0's
/// <c>hmac</c> field, ADMIN role), compared against the object's retained
/// <see cref="TransientKeyState.AuthValue"/> — both sides trailing-zero-stripped (TPM 2.0 Library Part 1,
/// clause 17.6.4.3) — rather than discarded. An owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse;
/// the consuming transition is its terminal owner, releasing it once the activate-slot compare has consumed
/// it. The dispose-immune empty sentinel for an empty password.
/// </param>
/// <param name="KeyHandle">The credential key that decrypts the seed (the endorsement key); its private scalar recovers the shared value.</param>
/// <param name="SuppliedKeyPassword">
/// The plaintext authorization value the caller supplied for the credential-key slot (session 1's <c>hmac</c>
/// field, USER role), compared against the key's retained <see cref="TransientKeyState.AuthValue"/> — both
/// sides trailing-zero-stripped — rather than discarded. An owned pooled <see cref="Tpm2bAuth"/> carrier
/// rented at parse; the consuming transition is its terminal owner. The dispose-immune empty sentinel for an
/// empty password.
/// </param>
/// <param name="CredentialBlob">The credential blob from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ID_OBJECT</c> value), copied into durable model memory.</param>
/// <param name="Secret">The encrypted seed from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ENCRYPTED_SECRET</c> value), copied into durable model memory.</param>
public sealed record TpmActivateCredentialRequested(
    TpmiDhObject ActivateHandle,
    Tpm2bAuth SuppliedActivatePassword,
    TpmiDhObject KeyHandle,
    Tpm2bAuth SuppliedKeyPassword,
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedActivatePassword"/> and <see cref="SuppliedKeyPassword"/> carriers
    /// on a refusing path; the consuming transition instead releases both itself once the per-slot compares
    /// have consumed them, and never calls this.
    /// </summary>
    public void Dispose()
    {
        SuppliedActivatePassword.Dispose();
        SuppliedKeyPassword.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_ActivateCredential()</c> command (TPM 2.0 Library Part 3, clause 12.5) whose <c>keyHandle</c> (the
/// credential key, USER role) is authorized by a policy session rather than a password — the form a standard
/// endorsement key (<see cref="Verifiable.Tpm.Infrastructure.Commands.CreatePrimaryInput.ForEndorsementKey"/>,
/// whose <c>authPolicy</c> is "PolicyA" and whose <c>userWithAuth</c> attribute is CLEAR) requires (Part 3, clause
/// 5.6). <c>activateHandle</c> stays password-authorized in this slice, exactly as in
/// <see cref="TpmActivateCredentialRequested"/>.
/// </summary>
/// <param name="ActivateHandle">The object the credential is bound to (the attestation key), password-authorized (ADMIN role).</param>
/// <param name="SuppliedActivatePassword">
/// The plaintext authorization value the caller supplied for the activate-object slot (session 0's
/// <c>hmac</c> field), compared against the object's retained <see cref="TransientKeyState.AuthValue"/> —
/// both sides trailing-zero-stripped (TPM 2.0 Library Part 1, clause 17.6.4.3) — rather than discarded. An
/// owned pooled <see cref="Tpm2bAuth"/> carrier rented at parse; the consuming transition is its terminal
/// owner, releasing it once the activate-slot compare has consumed it. The dispose-immune empty sentinel for
/// an empty password.
/// </param>
/// <param name="KeyHandle">The credential key (the endorsement key) whose <c>authPolicy</c> the policy session must satisfy (USER role).</param>
/// <param name="CredentialBlob">The credential blob from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ID_OBJECT</c> value), copied into durable model memory.</param>
/// <param name="Secret">The encrypted seed from <c>TPM2_MakeCredential()</c> (a <c>TPM2B_ENCRYPTED_SECRET</c> value), copied into durable model memory.</param>
/// <param name="KeyPolicySession">
/// The session handle authorizing <paramref name="KeyHandle"/>, carried in session slot 1 of the command's
/// authorization area. The wire types that slot <c>TPMI_SH_AUTH_SESSION</c> — <c>TPMS_AUTH_COMMAND.sessionHandle</c>
/// (TPM 2.0 Library Part 2, clause 10.13.2, Table 153), one such structure per authorization the command's
/// <c>TPM_ST_SESSIONS</c> tag brings, and <c>TPM2_ActivateCredential()</c>'s <c>@keyHandle</c> is Auth Index 2
/// (Part 3, clause 12.5.2, Table 26) — so an HMAC session handle is as well-formed here as a policy one. That
/// only a policy session is modelled is this simulator's carve-out, not a wire constraint: the transition
/// narrows the handle to <c>TPMI_SH_POLICY</c> when it looks the session up, and a handle naming no policy
/// session is refused there with <c>TPM_RC_HANDLE</c>.
/// </param>
/// <param name="KeyPolicyAttributes">
/// The policy session's command session-attributes octet. Unused by the response: <c>TPM2_ActivateCredential()</c>'s
/// response is framed <c>TPM_ST_NO_SESSIONS</c> regardless (see <see cref="TpmActivateCredentialResponse"/>), so
/// there is no response session entry to echo it into — the same simplification
/// <see cref="TpmUnsealOverSessionsRequested"/>'s no-encrypt-session branch relies on.
/// </param>
public sealed record TpmActivateCredentialOverSessionRequested(
    TpmiDhObject ActivateHandle,
    Tpm2bAuth SuppliedActivatePassword,
    TpmiDhObject KeyHandle,
    ReadOnlyMemory<byte> CredentialBlob,
    ReadOnlyMemory<byte> Secret,
    TpmiShAuthSession KeyPolicySession,
    TpmaSession KeyPolicyAttributes): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="SuppliedActivatePassword"/> carrier on a refusing path; the consuming
    /// transition instead releases it itself once the activate-slot compare has consumed it, and never calls
    /// this.
    /// </summary>
    public void Dispose()
    {
        SuppliedActivatePassword.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="TpmActivateCredentialAction"/>: either the recovered credential secret
/// (on success) or a failure code (when the credential's integrity does not verify against the activate object's
/// Name), fed back so the transition can frame the <c>TPM2_ActivateCredential()</c> response. Internal to the
/// effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// On success <paramref name="CertInfo"/> holds the recovered secret and <paramref name="ResponseCode"/> is
/// <c>TPM_RC_SUCCESS</c>; on an integrity mismatch <paramref name="CertInfo"/> is <see langword="null"/> and
/// <paramref name="ResponseCode"/> carries the rejection (<c>TPM_RC_INTEGRITY</c>, TPM 2.0 Library Part 3, clause
/// 12.5). The buffer holds a confidential value, so <see cref="TpmSimulator"/>, as the terminal owner, releases
/// its pinned segment to the pool, which zeroes every segment it takes back.
/// </remarks>
/// <param name="ResponseCode">The command response code: success, or the integrity-failure rejection.</param>
/// <param name="CertInfo">The recovered credential secret in an owned <c>TPM2B_DIGEST</c> carrier, the type Table 27 gives <c>certInfo</c> (TPM 2.0 Library Part 2, clause 10.4.2, Table 92); <see langword="null"/> on rejection; disposed after framing.</param>
public sealed record TpmCredentialActivated(
    TpmRcConstants ResponseCode,
    Tpm2bDigest? CertInfo): TpmSimulatorInput;

/// <summary>
/// A command whose code the lifecycle skeleton does not yet model. It is gated by the current phase
/// like any other command (rejected with the phase-appropriate response code).
/// </summary>
/// <param name="CommandCode">The unsupported command code as parsed from the request header.</param>
public sealed record TpmUnsupportedCommandReceived(TpmCcConstants CommandCode): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Create()</c> command (TPM 2.0 Library Part 3, clause 12.1) whose parent authorization is either a
/// bound HMAC session or a <c>TPM_RS_PW</c> password session, optionally paired with a SEPARATE bound HMAC
/// session carrying the <c>decrypt</c> attribute that protects <c>inSensitive</c> (Part 1, clauses 19 and 21).
/// Unlike <see cref="TpmCreateSealedObjectRequested"/> (the plain single-password form, left untouched), NONE of
/// <c>inSensitive</c>/<c>inPublic</c>/<c>outsideInfo</c>/<c>creationPCR</c> is decoded at parse time: every
/// command handle's command-HMAC must verify (Part 3, clause 5.6) strictly BEFORE any parameter is interpreted
/// (clause 5.8), and <c>inPublic</c>'s own start offset within the parameter area depends on <c>inSensitive</c>'s
/// declared size — a value that is itself validated only after decryption (clause 5.7), so trusting it to locate
/// <c>inPublic</c> any earlier would interpret unauthenticated, possibly-still-encrypted content. Only the raw
/// parameter-area bytes are captured; <see cref="Automata.TpmDecryptCreateSensitiveAction"/> decodes everything
/// once every session's command HMAC has verified and (if present) the decrypt session has run.
/// </summary>
/// <param name="ParentHandle">The loaded storage parent under which the object is created.</param>
/// <param name="FirstSession">The parent-authorizing session's handle (<c>TPM_RH_PW</c> or a bound HMAC session).</param>
/// <param name="FirstNonceCaller">The first session's caller nonce rolled for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the dispose-immune empty sentinel for a <c>TPM_RS_PW</c> slot, whose nonce the width rule already forces empty. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the resume that builds this slot's response-session entry TRANSFERS it there, and the branch that builds no entry for the slot releases it at the arm.</param>
/// <param name="FirstAttributes">The first session's command session-attributes octet.</param>
/// <param name="FirstHmac">The first session's supplied <c>hmac</c> field (<c>TPM2B_AUTH</c>, Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act: the real command HMAC for an HMAC session, whose verification folds the parent's retained <see cref="TransientKeyState.AuthValue"/> with bind omission (equation 22, TPM 2.0 Library Part 1, clause 17.6.10); or, for <c>TPM_RH_PW</c>, the plaintext parent password the consuming transition compares against that same retained authValue — both sides trailing-zero-stripped (clause 17.6.4.3). Everything downstream BORROWS it, so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HasDecryptSlot">
/// Whether the authorization area actually carried a second slot. The parser decides this structurally, from the
/// octets left inside <c>authorizationSize</c> once the parent-authorizing slot has been read, and nothing
/// downstream re-derives it from a handle value: a block naming any handle at all is a block the caller sent, and
/// it must be resolved, validated, and answered with a response entry whatever it names (TPM 2.0 Library Part 3,
/// clause 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="DecryptSession">
/// The second slot's session handle — the bound HMAC session whose <c>decrypt</c> attribute protects
/// <c>inSensitive</c>. Meaningful only when <paramref name="HasDecryptSlot"/> is set: presence is a structural
/// fact of the wire and is never inferred from this value, including zero, which <c>TPMI_SH_AUTH_SESSION</c>
/// does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with <c>TPM_RC_HANDLE</c> at this
/// slot's index rather than read as an absent slot.
/// </param>
/// <param name="DecryptNonceCaller">The decrypt session's caller nonce rolled for this command (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the nonceNewer of the command-direction decryption and that session's own command-HMAC verification. The empty sentinel when there is no decrypt session. Released and transferred exactly as <paramref name="FirstNonceCaller"/> is.</param>
/// <param name="DecryptAttributes">The decrypt session's command session-attributes octet. Zero when there is no decrypt session.</param>
/// <param name="DecryptHmac">The decrypt session's supplied <c>hmac</c> field (<c>TPM2B_AUTH</c>, Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act; the empty sentinel when there is no decrypt session. Borrowed downstream, terminal at the accepting continuation, exactly as <paramref name="FirstHmac"/> is.</param>
/// <param name="RawParameterArea">The raw <c>inSensitive ‖ inPublic ‖ outsideInfo ‖ creationPCR</c> wire bytes exactly as received (still encrypted, if a decrypt session is present) — cpHash's parameter term (Part 1, clause 16.7 equation 15) and the buffer every field is later decoded from. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
public sealed record TpmCreateSealedObjectOverSessionsRequested(
    TpmiDhObject ParentHandle,
    TpmiShAuthSession FirstSession,
    Tpm2bNonce FirstNonceCaller,
    TpmaSession FirstAttributes,
    Tpm2bAuth FirstHmac,
    bool HasDecryptSlot,
    TpmiShAuthSession DecryptSession,
    Tpm2bNonce DecryptNonceCaller,
    TpmaSession DecryptAttributes,
    Tpm2bAuth DecryptHmac,
    TpmParameterArea RawParameterArea): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/> carrier and both slots' credential and caller-nonce
    /// carriers on every path that does not frame the command's response.
    /// </summary>
    /// <remarks>
    /// The four session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes both hmacs per carrier once the verification queue is
    /// done with them, and transfers each slot's caller nonce into that slot's response-session entry — or
    /// releases the nonce at the arm where no entry is built for the slot.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        FirstNonceCaller.Dispose();
        FirstHmac.Dispose();
        DecryptNonceCaller.Dispose();
        DecryptHmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptCreateSensitiveAction"/>: <c>inSensitive</c> is
/// decrypted first (if a decrypt session was present, Part 1, clause 21), then <c>inSensitive ‖ inPublic ‖
/// outsideInfo ‖ creationPCR</c> are ALL decoded here — strictly after the command HMAC(s) verified (Part 3,
/// clause 5.6 precedes clause 5.8) — with bounds-checked reads so a wrong decryption key's garbage bytes report
/// a failure code rather than crash the simulator. <see cref="SizeFailureBlamesDecryptSession"/> distinguishes a
/// truncated/oversized <c>inSensitive</c> declared size (session-index-encoded to the decrypt session, since the
/// size problem surfaces only while attempting to decrypt) from every other malformation (reported bare, exactly
/// as the plain password form's parser already does). Internal to the effect loop; never arrives from the
/// command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when every field decoded; otherwise the rejection.</param>
/// <param name="SizeFailureBlamesDecryptSession">
/// Whether <paramref name="ResponseCode"/> is <c>TPM_RC_SIZE</c> caused by <c>inSensitive</c>'s own declared size
/// while a decrypt session was present — the ONE failure session-index-encoded to that session; every
/// other rejection (a generic parameter malformation, or the SAME size problem with no decrypt session to blame)
/// is reported bare.
/// </param>
/// <param name="Request">The original parsed command request, threaded through so the completing transition can resolve the sessions needing a real response entry.</param>
/// <param name="NameAlg">The Name algorithm carried in <c>inPublic</c>. Empty/default on failure.</param>
/// <param name="AuthPolicy">The authorization policy digest carried in <c>inPublic</c> (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92; empty when the seal is authorized by its authValue alone), in an owned pooled carrier the decrypt effect rents as its last act. The completing transition transfers it into the sealing action, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel on failure.</param>
/// <param name="NoDa">Whether <c>inPublic</c> sets <c>TPMA_OBJECT.noDA</c>. Meaningless on failure.</param>
/// <param name="UserWithAuth">Whether <c>inPublic</c> sets <c>TPMA_OBJECT.userWithAuth</c>, deciding whether a USER-role action against the created object may ever be authorized by a password or an HMAC session (TPM 2.0 Library Part 3, clause 5.6, check 7.1). Meaningless on failure.</param>
/// <param name="SecretData">The decoded (plaintext) data to seal (<c>TPMS_SENSITIVE_CREATE.data</c>, a <c>TPM2B_SENSITIVE_DATA</c> — TPM 2.0 Library Part 2, clause 11.1.14, Table 167), in an owned pooled carrier the decrypt effect rents as its last act. The completing transition transfers it into the sealing action, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>. The dispose-immune empty sentinel on failure.</param>
/// <param name="UserAuth">The decoded (plaintext) authorization value for the new object's <c>userAuth</c> (a <c>TPM2B_AUTH</c>), in an owned pooled carrier the decrypt effect rents as its last act, on the same transfer-or-release contract as <paramref name="SecretData"/>. The dispose-immune empty sentinel on failure.</param>
public sealed record TpmCreateSensitiveDecrypted(
    TpmRcConstants ResponseCode,
    bool SizeFailureBlamesDecryptSession,
    TpmCreateSealedObjectOverSessionsRequested Request,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy,
    bool NoDa,
    bool UserWithAuth,
    Tpm2bSensitiveData SecretData,
    Tpm2bAuth UserAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthPolicy"/>, <see cref="SecretData"/> and <see cref="UserAuth"/> carriers
    /// and cascades to the threaded <see cref="Request"/>'s own carriers on a refusing path; the completing path
    /// transfers all three into the sealing action and itself releases the request's parameter area and both
    /// slots' supplied credentials, and never calls this.
    /// </summary>
    public void Dispose()
    {
        AuthPolicy.Dispose();
        SecretData.Dispose();
        UserAuth.Dispose();
        Request.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptNvDefineAuthAction"/>: <c>TPM2_NV_DefineSpace()</c>'s
/// <c>auth</c> first parameter has been decrypted (TPM 2.0 Library Part 3, Section 31.3; Part 1, Section 21) and
/// its plaintext value read back, so the completing transition can install it as the new Index's authValue.
/// Reached strictly after the authorizing session's command HMAC verified (Part 3, Section 5.6 precedes Section
/// 5.8). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the encrypted <c>auth</c> parameter's own size field was consistent; otherwise the rejection (a wrong decryption key cannot itself be detected here — a corrupted authValue merely fails a later authorization).</param>
/// <param name="Request">The original parsed session-authorized request, threaded through so the completing transition can define the Index and frame the response.</param>
/// <param name="DecryptedAuth">The decrypted (plaintext) authorization value in an owned <see cref="Tpm2bAuth"/> carrier rented by the decrypt effect, its trailing zeros NOT yet removed — consumers take trailing-zero-stripped views (Part 1, Section 17.6.4.3); ownership transfers to the Index at install, and every refusing arm disposes it instead. The shared empty carrier on failure.</param>
public sealed record TpmNvDefineAuthDecrypted(
    TpmRcConstants ResponseCode,
    TpmNvDefineSpaceOverSessionRequested Request,
    Tpm2bAuth DecryptedAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="DecryptedAuth"/> carrier and the threaded <see cref="Request"/>'s own
    /// carriers on a refusing path; the installing path transfers <see cref="DecryptedAuth"/> to the
    /// defined Index and releases the request's superseded ciphertext carrier itself.
    /// </summary>
    public void Dispose()
    {
        DecryptedAuth.Dispose();
        Request.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptAttestQualifyingDataAction"/>: an attest command's
/// <c>qualifyingData</c> first parameter has been recovered in plaintext — decrypted over the one slot carrying
/// the <c>decrypt</c> attribute, or read straight through when no slot carried it (TPM 2.0 Library Part 3,
/// clause 5.7; Part 1, clause 19.1). Reached strictly after every session in the authorization area has had its
/// command HMAC verified, since cpHash covers the CIPHERTEXT (clause 5.6 precedes clause 5.7). Internal to the
/// effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode">
/// <c>TPM_RC_SUCCESS</c> when the parameter's own framing and the recovered value's width were both consistent;
/// otherwise <c>TPM_RC_INSUFFICIENT</c> (the parameter area cannot hold the 2-octet size field) or
/// <c>TPM_RC_SIZE</c> (the declared size overruns the parameter area, or the recovered value exceeds
/// <c>TPM2B_DATA</c>'s bound). A wrong decryption key is not itself detectable — the attestation is simply
/// signed over the garbage that decryption produced (clause 19.1's malleability note).
/// </param>
/// <param name="CommandCode">The attest command being resumed, so one feedback shape serves all five and the rejection names the right command.</param>
/// <param name="DecryptSessionIndex">
/// The zero-based slot index of the session carrying <c>decrypt</c>, which a failure is session-index-encoded to
/// because the failure surfaces only while attempting to decrypt (Part 2, clause 6.6.2; the reference blames the
/// decrypt session's own index), or <c>-1</c> when no slot claimed the attribute and a failure is reported bare.
/// </param>
/// <param name="Request">The original parsed session-authorized request, threaded through so the resuming transition can run the command's remaining ladder.</param>
/// <param name="QualifyingData">
/// The recovered plaintext <c>qualifyingData</c> in an owned <see cref="Tpm2bData"/> carrier rented by the
/// decrypt effect as its last act; ownership transfers into the attest action the resuming transition builds,
/// whose effect releases it, and every refusing arm releases it through this record's own
/// <see cref="IDisposable.Dispose"/>. The shared empty carrier on failure.
/// </param>
public sealed record TpmAttestQualifyingDataDecrypted(
    TpmRcConstants ResponseCode,
    TpmCcConstants CommandCode,
    int DecryptSessionIndex,
    TpmSimulatorInput Request,
    Tpm2bData QualifyingData): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="QualifyingData"/> carrier and cascades to the threaded
    /// <see cref="Request"/>'s own carriers on a refusing path. The resuming path instead adopts the recovered
    /// carrier into the request it rebuilds and never calls this, so the request's carriers travel on rather than
    /// being released twice.
    /// </summary>
    public void Dispose()
    {
        QualifyingData.Dispose();
        (Request as IDisposable)?.Dispose();
    }
}

/// <summary>
/// One session's material for framing a real per-session <c>TPM2_Create()</c> response entry over sessions
/// (the request-decrypt counterpart of <see cref="TpmUnsealResponseSession"/>): the effect rolls a fresh
/// nonceTPM and computes a real response HMAC for it, keyed on THE SAME <c>sessionKey ‖ authValue</c> its
/// command-HMAC verification used (Part 1, clause 17.6.8). Response-direction parameter encryption is out of
/// scope for <c>TPM2_Create()</c>, so every entry's own <c>outPrivate</c>/<c>outPublic</c>/creation
/// by-products are always returned in the clear.
/// </summary>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value (and the same bind-omission decision) the command-HMAC verification used; the effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="NonceCaller">
/// This session's command caller nonce (<c>TPM2B_NONCE</c>, Part 2, clause 10.4.4, Table 94) — the response
/// HMAC's nonceOlder. OWNED by this entry, transferred out of the request record by the resume that built the
/// entry, and released by the seal effect's <see langword="finally"/>.
/// </param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
public sealed record TpmCreateResponseSession(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes);

/// <summary>
/// One already-verified session's framed real <c>TPM2_Create()</c> response entry — the rolled nonceTPM and
/// computed response HMAC produced from a <see cref="TpmCreateResponseSession"/> (the request-decrypt
/// counterpart of <see cref="TpmUnsealFramedSessionEntry"/>).
/// </summary>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94) in an owned pooled carrier, framed as this entry's nonceNewer; the serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; the rolling transition transfers it onto the durable session record, and disposes it itself when that session has already left its table.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.3, Table 154); owned, disposed after framing.</param>
public sealed record TpmCreateFramedSessionEntry(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac);

/// <summary>
/// The result of executing a <see cref="Automata.TpmSealDataOverSessionsAction"/>: the framed (unencrypted)
/// response parameter area and every real session's framed response entry, fed back so the transition can roll
/// each session's stored nonce and frame the response (the request-decrypt counterpart of
/// <see cref="TpmUnsealedOverSessions"/>). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// <see cref="ParameterArea"/> is a pooled carrier the framing step disposes as the terminal owner; each
/// <see cref="TpmCreateFramedSessionEntry"/> in <see cref="Entries"/> owns its own <c>Hmac</c> buffer the same way.
/// </remarks>
/// <param name="ParameterArea">The framed <c>outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket</c> response parameter area; disposed after framing.</param>
/// <param name="HasPasswordPlaceholder">Whether session index 0 is a <c>TPM_RS_PW</c> session needing the empty-nonce, empty-HMAC password placeholder entry (Part 1, clause 17.6.4).</param>
/// <param name="PasswordPlaceholderAttributes">The password session's command session-attributes octet, framed into its placeholder entry (continueSession is unconditionally SET for a password session, Part 1, clause 17.6.4). Meaningful only when <see cref="HasPasswordPlaceholder"/> is set.</param>
/// <param name="Entries">Every real session's framed response entry, in command-session order (after the password placeholder, when present).</param>
public sealed record TpmObjectSealedOverSessions(
    TpmParameterArea ParameterArea,
    bool HasPasswordPlaceholder,
    TpmaSession PasswordPlaceholderAttributes,
    ImmutableArray<TpmCreateFramedSessionEntry> Entries): TpmSimulatorInput;

/// <summary>
/// A password-authorized <c>TPM2_Clear()</c> command (TPM 2.0 Library Part 3, clause 24.6): the removal of all
/// TPM context associated with a specific Owner. It carries a single handle and no parameters at all, so the
/// authorization handle is the whole of what a caller supplies beyond the authorization area.
/// </summary>
/// <remarks>
/// Only <c>TPM_RH_LOCKOUT</c> and <c>TPM_RH_PLATFORM</c> are admissible (<c>TPMI_RH_CLEAR</c>, clause 24.6.2,
/// Table 184). The two are not interchangeable in consequence: a lockoutAuth-authorized clear is
/// dictionary-attack gated and leaves the new, Empty lockoutAuth keying the response, whereas platform
/// authorization is categorically dictionary-attack exempt (clause 25.1).
/// </remarks>
/// <param name="AuthHandle">The authorizing hierarchy handle, <c>TPM_RH_LOCKOUT</c> or <c>TPM_RH_PLATFORM</c>.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It authorizes the lockout entity or the platform hierarchy. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
public sealed record TpmClearRequested(
    TpmiRhClear AuthHandle,
    Tpm2bAuth AuthSupplied): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_Clear()</c> command authorized over an HMAC session (TPM 2.0 Library Part 3, clause 24.6) — the
/// same command as <see cref="TpmClearRequested"/>, proven by a session HMAC rather than a cleartext value.
/// </summary>
/// <remarks>
/// The response HMAC is what makes this more than a transport variation: "If this command is authorized using
/// lockoutAuth, the HMAC in the response shall use the new lockoutAuth value (that is, the Empty Buffer)"
/// (clause 24.6.1). The clear commits before the response is framed, so the authValue term of the response key
/// is resolved from the POST-clear state, never from <paramref name="ResolvedAuthValue"/>.
/// </remarks>
/// <param name="AuthHandle">The authorizing hierarchy handle, <c>TPM_RH_LOCKOUT</c> or <c>TPM_RH_PLATFORM</c>.</param>
/// <param name="AuthorizingSessionHandle">The HMAC session presented to authorize <paramref name="AuthHandle"/>.</param>
/// <param name="NonceCaller">The session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw parameter-area bytes exactly as received — always empty, since the command has no parameters, and captured only so cpHash is built the same way for every command. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="ResolvedAuthValue">The authValue term folded into the COMMAND HMAC key — a borrowed reference to the pre-clear value's carrier (the HMAC primitive takes its trailing-zero-stripped view), or the shared empty carrier when the session is bound to the authorizing hierarchy; resolved at the entry transition and threaded onward, <see langword="null"/> until then and read as empty.</param>
/// <param name="BindOmitsAuthValue">The command-time bind-omission decision, recorded at the entry transition and mirrored by the response framing (TPM 2.0 Library Part 1, clause 17.6.10's "The TPM will record the fact that the authValue was not used ... and not include it in the HMAC computation on the response") — the clear rotates lockoutAuth away mid-command, so the response must not re-derive this against post-effect state.</param>
public sealed record TpmClearOverSessionRequested(
    TpmiRhClear AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bAuth? ResolvedAuthValue = null,
    bool BindOmitsAuthValue = false): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/>
    /// carriers on every path that does not frame the command's response.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A password-authorized <c>TPM2_ClearControl()</c> command (TPM 2.0 Library Part 3, clause 24.7): the control
/// that disables and re-enables execution of <c>TPM2_Clear()</c>.
/// </summary>
/// <param name="AuthHandle">The authorizing hierarchy handle, <c>TPM_RH_LOCKOUT</c> or <c>TPM_RH_PLATFORM</c> (<c>TPMI_RH_CLEAR</c>).</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It authorizes the lockout entity or the platform hierarchy. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="Disable">
/// YES to SET <c>TPMA_PERMANENT.disableClear</c>, NO to CLEAR it. The wire field's own description still names
/// the legacy <c>disableOwnerClear</c> flag (clause 24.7.2, Table 186) while the attribute it writes is
/// <c>disableClear</c> (clause 24.7.1); both names are the specification's.
/// </param>
public sealed record TpmClearControlRequested(
    TpmiRhClear AuthHandle,
    Tpm2bAuth AuthSupplied,
    TpmiYesNo Disable): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_ClearControl()</c> command authorized over an HMAC session (TPM 2.0 Library Part 3, clause 24.7).
/// </summary>
/// <param name="AuthHandle">The authorizing hierarchy handle, <c>TPM_RH_LOCKOUT</c> or <c>TPM_RH_PLATFORM</c>.</param>
/// <param name="AuthorizingSessionHandle">The HMAC session presented to authorize <paramref name="AuthHandle"/>.</param>
/// <param name="NonceCaller">The session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>disable</c> wire byte exactly as received — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="Disable">YES to SET <c>TPMA_PERMANENT.disableClear</c>, NO to CLEAR it.</param>
/// <param name="ResolvedAuthValue">The authValue term folded into the command HMAC key, resolved at the entry transition and reused for the response key (the command changes no authValue, so both directions agree).</param>
public sealed record TpmClearControlOverSessionRequested(
    TpmiRhClear AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    TpmiYesNo Disable,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/>
    /// carriers on every path that does not frame the command's response.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A password-authorized <c>TPM2_HierarchyControl()</c> command (TPM 2.0 Library Part 3, clause 24.2): the
/// enabling and disabling of a hierarchy and its associated NV storage.
/// </summary>
/// <param name="AuthHandle">The authorizing hierarchy handle — <c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, or <c>TPM_RH_PLATFORM</c> (<c>TPMI_RH_BASE_HIERARCHY</c>, clause 24.2.2), never <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It authorizes the hierarchy the authorization handle names. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="Enable">The enable being modified (<c>TPMI_RH_ENABLES</c>): <c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c>, or <c>TPM_RH_PLATFORM_NV</c> — a hierarchy handle naming a bit, not an authorization.</param>
/// <param name="State">YES if the enable is to be SET, NO if it is to be CLEAR.</param>
public sealed record TpmHierarchyControlRequested(
    TpmiRhBaseHierarchy AuthHandle,
    Tpm2bAuth AuthSupplied,
    TpmiRhEnables Enable,
    TpmiYesNo State): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthSupplied"/> carrier on a refusing path; the authorizing transition disposes
    /// it per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_HierarchyControl()</c> command authorized over an HMAC session (TPM 2.0 Library Part 3, clause 24.2).
/// </summary>
/// <param name="AuthHandle">The authorizing hierarchy handle (<c>TPMI_RH_BASE_HIERARCHY</c>).</param>
/// <param name="AuthorizingSessionHandle">The HMAC session presented to authorize <paramref name="AuthHandle"/>.</param>
/// <param name="NonceCaller">The session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>enable ‖ state</c> wire bytes exactly as received — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="Enable">The enable being modified (<c>TPMI_RH_ENABLES</c>).</param>
/// <param name="State">YES if the enable is to be SET, NO if it is to be CLEAR.</param>
/// <param name="ResolvedAuthValue">The authValue term folded into the command HMAC key, resolved at the entry transition and reused for the response key.</param>
public sealed record TpmHierarchyControlOverSessionRequested(
    TpmiRhBaseHierarchy AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    TpmiRhEnables Enable,
    TpmiYesNo State,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="RawParameterArea"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/>
    /// carriers on every path that does not frame the command's response.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A password-authorized <c>TPM2_SetPrimaryPolicy()</c> command (TPM 2.0 Library Part 3, clause 24.3): the
/// installation of the authorization policy for the lockout entity or one of the three hierarchies.
/// </summary>
/// <remarks>
/// <c>TPMI_RH_HIERARCHY_POLICY</c> (clause 24.3.2) additionally admits the Authenticated Countdown Timer range,
/// which this simulator does not model; the handle set accepted here is the four permanent entities that carry a
/// policy slot.
/// </remarks>
/// <param name="AuthHandle">The entity whose policy is being set — <c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c>, or <c>TPM_RH_LOCKOUT</c>.</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It authorizes the entity whose policy is being set. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="AuthPolicy">The policy digest to install (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), or the Empty Buffer to disable policy authorization of that entity, in an owned pooled carrier rented as the parse's last act. Ownership transfers to the hierarchy's policy slot at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HashAlg">The hash algorithm <paramref name="AuthPolicy"/> is expressed under, <c>TPM_ALG_NULL</c> exactly when it is empty.</param>
public sealed record TpmSetPrimaryPolicyRequested(
    TpmiRhHierarchyPolicy AuthHandle,
    Tpm2bAuth AuthSupplied,
    Tpm2bDigest AuthPolicy,
    TpmiAlgHash HashAlg): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthPolicy"/> carrier on a refusing path; the installing path transfers
    /// its ownership to the hierarchy's policy slot instead and never calls this.
    /// <see cref="AuthSupplied"/> is released on every refusing path; the authorizing transition disposes it
    /// per carrier once the compare that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        AuthPolicy.Dispose();
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_SetPrimaryPolicy()</c> command authorized over an HMAC session (TPM 2.0 Library Part 3, clause 24.3).
/// </summary>
/// <param name="AuthHandle">The entity whose policy is being set (<c>TPMI_RH_HIERARCHY_POLICY</c>).</param>
/// <param name="AuthorizingSessionHandle">The HMAC session presented to authorize <paramref name="AuthHandle"/>.</param>
/// <param name="NonceCaller">The session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>authPolicy ‖ hashAlg</c> wire bytes exactly as received — cpHash's <c>parameters</c> term. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="AuthPolicy">The policy digest to install (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), or the Empty Buffer to disable policy authorization of that entity, in an owned pooled carrier rented as the parse's last act. Ownership transfers to the hierarchy's policy slot at install, and every refusing arm releases it through this record's <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HashAlg">The hash algorithm <paramref name="AuthPolicy"/> is expressed under.</param>
/// <param name="ResolvedAuthValue">The authValue term folded into the command HMAC key, resolved at the entry transition and reused for the response key (the command changes no authValue).</param>
public sealed record TpmSetPrimaryPolicyOverSessionRequested(
    TpmiRhHierarchyPolicy AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    TpmParameterArea RawParameterArea,
    Tpm2bDigest AuthPolicy,
    TpmiAlgHash HashAlg,
    Tpm2bAuth? ResolvedAuthValue = null): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="AuthPolicy"/> carrier on a refusing path; the installing path transfers
    /// its ownership to the hierarchy's policy slot instead and never calls this. The owned
    /// <see cref="RawParameterArea"/>, <see cref="NonceCaller"/> and <see cref="Hmac"/> carriers are released
    /// here on every non-framing path. <see cref="ResolvedAuthValue"/> is a borrow and is never touched here.
    /// </summary>
    /// <remarks>
    /// The two session-slot credentials are owned outright from the parse until a terminal arm takes them, and
    /// only the accepting path takes them: it disposes the hmac per carrier once the verification queue is done
    /// with it, and transfers the caller nonce into the response framing.
    /// </remarks>
    public void Dispose()
    {
        AuthPolicy.Dispose();
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
    }
}

/// <summary>
/// A password-authorized <c>TPM2_HierarchyChangeAuth()</c> command (TPM 2.0 Library Part 3, clause 24.8): the
/// replacement of a hierarchy's (or the lockout entity's) authorization value, authorized by the value being
/// replaced.
/// </summary>
/// <param name="AuthHandle">The entity whose authValue is being replaced — <c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c>, or <c>TPM_RH_LOCKOUT</c> (<c>TPMI_RH_HIERARCHY_AUTH</c>).</param>
/// <param name="AuthSupplied">The authorization value the caller supplied — the password session's plaintext authValue, which is the same <c>TPM2B_AUTH</c> wire field a real session carries an HMAC in (TPM 2.0 Library Part 2, clause 10.13.2, Table 153: "either an HMAC, a password, or an EmptyAuth") — in a pooled carrier this record OWNS, rented as the parse's last act. It is the CURRENT value, the one this command replaces. The authorizing transition is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="NewAuth">The replacement authorization value in an owned <see cref="Tpm2bAuth"/> carrier rented at parse time holding the wire-exact octets, trailing zeros not yet removed; ownership transfers to the hierarchy slot at install, and every refusing arm disposes it instead.</param>
public sealed record TpmHierarchyChangeAuthRequested(
    TpmiRhHierarchyAuth AuthHandle,
    Tpm2bAuth AuthSupplied,
    Tpm2bAuth NewAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NewAuth"/> carrier on a refusing path; the installing path transfers
    /// its ownership to the hierarchy slot instead and never calls this. <see cref="AuthSupplied"/> is
    /// released on every refusing path; the authorizing transition disposes it per carrier once the compare
    /// that is its only use has run.
    /// </summary>
    public void Dispose()
    {
        NewAuth.Dispose();
        AuthSupplied.Dispose();
    }
}

/// <summary>
/// A <c>TPM2_HierarchyChangeAuth()</c> command whose authorization area is more than a lone password slot (TPM
/// 2.0 Library Part 3, clause 24.8): an HMAC session authorizing the hierarchy, or a <c>TPM_RS_PW</c> slot
/// accompanied by a separate <c>decrypt</c> session protecting <paramref name="NewAuth"/> in flight.
/// </summary>
/// <remarks>
/// <para>
/// A LONE password area parses to <see cref="TpmHierarchyChangeAuthRequested"/> instead, so the one shape that
/// brings a <c>TPM_RS_PW</c> slot here is the two-block area: the companion must be resolved, validated,
/// HMAC-verified, and answered with its own response entry (Part 3, clause 5.5, step 4 and clause 5.6; Part 1,
/// clause 16.6.1), which the plain record has nowhere to carry.
/// </para>
/// <para>
/// The response-HMAC rule is this command's defining subtlety: "The HMAC in the response shall use the new
/// authorization value when computing the response HMAC" (clause 24.8.1). The rotation therefore commits before
/// the response is framed and the response key is NOT <paramref name="ResolvedAuthValue"/>, which is the
/// pre-rotation term the command HMAC used.
/// </para>
/// <para>
/// <paramref name="DecryptSessionHandle"/> is nonzero when a SECOND session carrying the <c>decrypt</c>
/// attribute accompanied the command: <c>newAuth</c> is the sole, and therefore first, sized command parameter,
/// which is exactly what makes it encryptable (Part 1, clause 19.1). The authorizing session itself may not
/// carry <c>decrypt</c> or <c>encrypt</c> — an unbound, unsalted session of that shape would derive its
/// keystream from the very authValue being rotated away from.
/// </para>
/// </remarks>
/// <param name="AuthHandle">The entity whose authValue is being replaced (<c>TPMI_RH_HIERARCHY_AUTH</c>).</param>
/// <param name="AuthorizingSessionHandle">The session presented to authorize <paramref name="AuthHandle"/> — an HMAC session, or <c>TPM_RS_PW</c> when a companion accompanies it.</param>
/// <param name="NonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting continuation TRANSFERS it into the response-framing step, whose effect releases it once the response HMAC has keyed its nonceOlder term on it.</param>
/// <param name="SessionAttributes">The authorizing session's command session-attributes octet.</param>
/// <param name="Hmac">The supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), in a pooled carrier this record OWNS, rented as the parse's last act. Everything downstream BORROWS it — the verification queue reads it at the HMAC primitive and disposes nothing — so the accepting continuation is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="HasDecryptSlot">
/// Whether the authorization area actually carried a second slot. The parser decides this structurally, from the
/// octets left inside <c>authorizationSize</c> once the authorizing slot has been read, and nothing downstream
/// re-derives it from a handle value: a block naming any handle at all is a block the caller sent, and it must
/// be resolved, validated, and answered with a response entry whatever it names (TPM 2.0 Library Part 3, clause
/// 5.5, step 4 walks every unmarshaled session in turn).
/// </param>
/// <param name="DecryptSessionHandle">
/// The separate decrypt session's handle. Meaningful only when <paramref name="HasDecryptSlot"/> is set:
/// presence is a structural fact of the wire and is never inferred from this value, including zero, which
/// <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (Part 2, clause 9.8, Table 55) and which is refused with
/// <c>TPM_RC_HANDLE</c> at this slot's index rather than read as an absent slot.
/// </param>
/// <param name="DecryptNonceCaller">The decrypt session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), in a pooled carrier this record OWNS, rented as the parse's last act; the shared empty carrier when <paramref name="HasDecryptSlot"/> is clear. The decrypt effect only BORROWS it. Every refusing path releases it through <see cref="IDisposable.Dispose"/>; the accepting tail TRANSFERS it into that slot's response entry, whose framing effect releases it.</param>
/// <param name="DecryptSessionAttributes">The decrypt session's command session-attributes octet. Meaningful only when <paramref name="HasDecryptSlot"/> is set.</param>
/// <param name="DecryptHmac">The decrypt session's supplied command <c>hmac</c> field (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), verified like every other session in the area (Part 3, clause 5.6), in a pooled carrier this record OWNS, rented as the parse's last act; the shared empty carrier when <paramref name="HasDecryptSlot"/> is clear. The accepting tail is its terminal owner; every refusing path releases it through <see cref="IDisposable.Dispose"/>.</param>
/// <param name="RawParameterArea">The raw <c>newAuth</c> wire bytes exactly as received — cpHash's <c>parameters</c> term, still carrying ciphertext when a decrypt session is present. Held in a pooled carrier this record OWNS, rented as the parse's last act; released through <see cref="IDisposable.Dispose"/> on every refusing path and by the accepting continuation once the command has been framed.</param>
/// <param name="NewAuth">The parsed <c>newAuth</c> value in an owned <see cref="Tpm2bAuth"/> carrier rented at parse time holding the wire-exact octets — the plaintext replacement only when no decrypt session accompanied the command (ciphertext otherwise, in which case the decrypt effect's output supersedes it). Ownership transfers to the hierarchy slot at install on the plaintext path; every other terminal arm disposes it.</param>
/// <param name="ResolvedAuthValue">The authValue term folded into the command HMAC key — a borrowed reference to the CURRENT (pre-rotation) value's carrier (the HMAC primitive takes its trailing-zero-stripped view), or the shared empty carrier when the session is bound to the entity now authorizing; <see langword="null"/> until resolved, read as empty.</param>
/// <param name="BindOmitsAuthValue">The command-time bind-omission decision, recorded at the entry transition and mirrored by the response framing (TPM 2.0 Library Part 1, clause 17.6.10's "The TPM will record the fact that the authValue was not used ... and not include it in the HMAC computation on the response") — this command rotates the very authValue the binding folded, so the response must not re-derive this against post-effect state.</param>
public sealed record TpmHierarchyChangeAuthOverSessionRequested(
    TpmiRhHierarchyAuth AuthHandle,
    TpmiShAuthSession AuthorizingSessionHandle,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    bool HasDecryptSlot,
    TpmiShAuthSession DecryptSessionHandle,
    Tpm2bNonce DecryptNonceCaller,
    TpmaSession DecryptSessionAttributes,
    Tpm2bAuth DecryptHmac,
    TpmParameterArea RawParameterArea,
    Tpm2bAuth NewAuth,
    Tpm2bAuth? ResolvedAuthValue = null,
    bool BindOmitsAuthValue = false): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="NewAuth"/> carrier on a refusing path (or, on the decrypted path,
    /// once the decrypt effect's own output supersedes the ciphertext it holds); the plaintext installing
    /// path transfers its ownership to the hierarchy slot instead. <see cref="RawParameterArea"/> and both
    /// slots' credential carriers are owned outright and released here. <see cref="ResolvedAuthValue"/> is a
    /// borrow and is never touched here.
    /// </summary>
    /// <remarks>
    /// Each slot's two credentials are owned outright from the parse until a terminal arm takes them, and only
    /// the accepting tail takes them: it disposes both hmacs per carrier once the verification queue is done
    /// with them, and transfers each slot's caller nonce into that slot's response entry.
    /// </remarks>
    public void Dispose()
    {
        NewAuth.Dispose();
        RawParameterArea.Dispose();
        NonceCaller.Dispose();
        Hmac.Dispose();
        DecryptNonceCaller.Dispose();
        DecryptHmac.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmDecryptHierarchyChangeAuthAction"/>:
/// <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> first command parameter has been decrypted (TPM 2.0
/// Library Part 3, clause 24.8; Part 1, clause 19.1) and its plaintext read back, so the completing transition
/// can size-check and install it. Reached strictly after every session in the authorization area has verified
/// (Part 3, clause 5.6 precedes clause 5.8). Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="ResponseCode"><c>TPM_RC_SUCCESS</c> when the encrypted <c>newAuth</c> parameter's own size field was consistent; otherwise the rejection (a wrong decryption key cannot itself be detected here — a corrupted authValue merely fails a later authorization).</param>
/// <param name="Request">The original parsed request, threaded through so the completing transition can rotate the authValue and frame the response.</param>
/// <param name="DecryptedNewAuth">The decrypted replacement authorization value in an owned <see cref="Tpm2bAuth"/> carrier rented by the decrypt effect, its trailing zeros NOT yet removed — the completing transition takes the stripped view for the size check (Part 1, clause 17.6.4.3), then transfers ownership to the hierarchy slot at install; every refusing arm disposes it instead. The shared empty carrier on failure.</param>
public sealed record TpmHierarchyChangeAuthDecrypted(
    TpmRcConstants ResponseCode,
    TpmHierarchyChangeAuthOverSessionRequested Request,
    Tpm2bAuth DecryptedNewAuth): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="DecryptedNewAuth"/> carrier and the threaded <see cref="Request"/>'s
    /// own carriers on a refusing path; the installing path transfers <see cref="DecryptedNewAuth"/> to
    /// the hierarchy slot and releases the request's superseded ciphertext carrier itself.
    /// </summary>
    public void Dispose()
    {
        DecryptedNewAuth.Dispose();
        Request.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmPersistObjectAction"/>: the deep-copied persistent
/// instance <c>TPM2_EvictControl()</c>'s persist arm installs (TPM 2.0 Library Part 3, clause 28.5).
/// Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="PersistentCopy">The persistent instance, owning its own deep-copied private-key carrier; ownership transfers to <c>PersistentObjects</c> at install, and a refusing path releases it through <see cref="Dispose"/>.</param>
public sealed record TpmObjectPersisted(
    TransientKeyState PersistentCopy): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the persistent copy's owned private-key carrier on a refusing path; the installing
    /// transition transfers it into <c>PersistentObjects</c> instead and never calls this.
    /// </summary>
    public void Dispose()
    {
        PersistentCopy.Dispose();
    }
}

/// <summary>
/// The result of executing a <see cref="Automata.TpmGenerateStorageProofSeedAction"/>: the fresh storage primary
/// seed <c>TPM2_Clear()</c> installs, drawn from the TPM's random number generator (TPM 2.0 Library Part 3,
/// clause 24.6.1: "change the storage primary seed (SPS) to a new value from the TPM's random number generator").
/// Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <remarks>
/// The seed arrives in an owned <see cref="Automata.StorageProofSeed"/> carrier the effect rents: it becomes
/// <see cref="TpmSimulatorState.StorageProofSeed"/> and outlives the command, so the installing transition
/// adopts the carrier (disposing the one it replaces) rather than copying the octets.
/// </remarks>
/// <param name="StorageProofSeed">The freshly drawn seed the storage and endorsement hierarchy proofs derive from once it is installed; ownership transfers to the installing transition.</param>
/// <param name="Resume">The parsed <c>TPM2_Clear()</c> request to resume, deciding whether the response is header-only or session-framed.</param>
public sealed record TpmStorageProofSeedGenerated(
    StorageProofSeed StorageProofSeed,
    TpmSimulatorInput Resume): TpmSimulatorInput, IDisposable
{
    /// <summary>
    /// Releases the owned <see cref="StorageProofSeed"/> carrier (and whatever the resumed request itself
    /// owns) on a refusing path; the installing path transfers the seed to
    /// <see cref="TpmSimulatorState.StorageProofSeed"/> instead.
    /// </summary>
    public void Dispose()
    {
        StorageProofSeed.Dispose();
        (Resume as IDisposable)?.Dispose();
    }
}
