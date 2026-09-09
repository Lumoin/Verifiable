using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Session-audit attestation information (TPMS_SESSION_AUDIT_INFO), the <c>sessionAudit</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// "This Table 148 structure is the attested data for TPM2_GetSessionAuditDigest()." (TPM 2.0 Library Part 2,
/// clause 10.11.6, Table 148). Produced by <c>TPM2_GetSessionAuditDigest()</c>: attests the current value of an
/// audit session's digest and whether that session has been the TPM's exclusive audit session for its entire
/// sequence.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_YES_NO exclusiveSession;            // Whether the session is currently exclusive.
///     TPM2B_DIGEST sessionDigest;               // The current value of the session audit digest.
/// } TPMS_SESSION_AUDIT_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.11.6, Table 148.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsSessionAuditInfo: ITpmWireType, IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="SessionDigest"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Gets whether all of the commands recorded in <see cref="SessionDigest"/> were executed without any
    /// intervening TPM command that did not use this audit session ("YES if all of the commands recorded in the
    /// sessionDigest were executed without any intervening TPM command that did not use this audit session",
    /// TPM 2.0 Library Part 2, clause 10.11.6, Table 148).
    /// </summary>
    public TpmiYesNo ExclusiveSession { get; }

    /// <summary>
    /// Gets the current value of the session audit digest ("the current value of the session audit digest",
    /// TPM 2.0 Library Part 2, clause 10.11.6, Table 148).
    /// </summary>
    public Tpm2bDigest SessionDigest { get; }

    /// <summary>
    /// Initializes a new session-audit-info structure.
    /// </summary>
    /// <param name="exclusiveSession">The exclusive-session flag.</param>
    /// <param name="sessionDigest">The session audit digest. Ownership is transferred.</param>
    private TpmsSessionAuditInfo(TpmiYesNo exclusiveSession, Tpm2bDigest sessionDigest)
    {
        ExclusiveSession = exclusiveSession;
        SessionDigest = sessionDigest;
    }

    /// <summary>
    /// Creates a session-audit-info structure from an exclusive-session flag and a session digest.
    /// </summary>
    /// <param name="exclusiveSession">The exclusive-session flag.</param>
    /// <param name="sessionDigest">The session audit digest. Ownership is transferred.</param>
    /// <returns>The created session audit info.</returns>
    public static TpmsSessionAuditInfo Create(TpmiYesNo exclusiveSession, Tpm2bDigest sessionDigest)
    {
        ArgumentNullException.ThrowIfNull(sessionDigest);

        return new TpmsSessionAuditInfo(exclusiveSession, sessionDigest);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return 1 + SessionDigest.SerializedSize;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        ExclusiveSession.WriteTo(ref writer);
        SessionDigest.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a session-audit-info structure from a TPM reader.
    /// </summary>
    /// <remarks>
    /// <paramref name="reader"/>'s first field, <see cref="ExclusiveSession"/>, is a one-octet value type that
    /// owns no pooled memory, so a malformed <see cref="SessionDigest"/> throws before anything is rented — there
    /// is nothing to dispose on that path, unlike a sibling whose first field is itself an owned carrier.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed session audit info.</returns>
    public static TpmsSessionAuditInfo Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmiYesNo exclusiveSession = TpmiYesNo.Parse(ref reader);
        Tpm2bDigest sessionDigest = Tpm2bDigest.Parse(ref reader, pool);

        return new TpmsSessionAuditInfo(exclusiveSession, sessionDigest);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            SessionDigest.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the exclusive-session flag and the digest's octet count only, never the
    /// digest octets themselves.
    /// </summary>
    private string DebuggerDisplay => $"TPMS_SESSION_AUDIT_INFO(exclusiveSession={ExclusiveSession}, sessionDigest={SessionDigest.Size} bytes)";
}
