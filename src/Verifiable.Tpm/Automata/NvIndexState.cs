using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a single defined NV Index: the persistent identity, authorization value,
/// attributes, size, and (once written) data area established by <c>TPM2_NV_DefineSpace()</c> and
/// <c>TPM2_NV_Write()</c>. This is the smallest NV-Index model the dictionary-attack/PIN flow and the
/// EK-certificate provisioning flow need — an NV Index is the lightest entity whose authValue can be made
/// dictionary-attack protected (TPM 2.0 Library Part 1, clause 16.8.1), which hierarchy authValues cannot,
/// and the persistent slot a manufacturer writes an EK certificate into (Part 3, clause 31.7).
/// </summary>
/// <remarks>
/// <para>
/// The authorization value lives in a pinned, zero-on-dispose <see cref="Tpm2bAuth"/> carrier the record
/// owns: it is rented where a pool is in scope (the command parser or a decrypt effect), its ownership
/// transfers into this record at the installing transition, and it is disposed when the specific field is
/// replaced (<see cref="WithAuthValue"/>) or the Index is evicted. The carrier holds the exact octets the
/// installing path stored — the wire-exact value on the plaintext <c>TPM2_NV_DefineSpace()</c> arms, the
/// trailing-zero-stripped value on the decrypted-auth and <c>TPM2_NV_ChangeAuth()</c> paths — and every
/// consumer takes its comparison or stripped view at the point of use. The data area is a pooled
/// <see cref="TpmNvIndexData"/> the record likewise owns, reserved at the declared <see cref="DataSize"/> by the
/// defining command's parser and stored into in place by every later write: an Index's space is reserved at
/// definition and a write merges into it (TPM 2.0 Library Part 3, clause 31.7.1), which is also what lets the
/// pure transitions that perform those stores hold no memory pool.
/// </para>
/// <para>
/// Written-ness is modelled as the <c>TPMA_NV_WRITTEN</c> bit within <see cref="Attributes"/>, set by the
/// first <c>TPM2_NV_Write()</c> (TPM 2.0 Library Part 2, clause 13.4). A freshly defined Index has the bit
/// clear and an empty <see cref="Data"/>, so a read of it answers <c>TPM_RC_NV_UNINITIALIZED</c>; a written
/// Index carries its stored octets in <see cref="Data"/> and answers a read from that buffer.
/// </para>
/// <para>
/// The two lock indicators are likewise bits within <see cref="Attributes"/>: <c>TPMA_NV_WRITELOCKED</c>, SET by
/// <c>TPM2_NV_WriteLock()</c>, and <c>TPMA_NV_READLOCKED</c>, SET by <c>TPM2_NV_ReadLock()</c> (Part 2, clause
/// 13.4: "The TPM is expected to maintain indicators to indicate that the Index is temporarily locked. The state
/// of these indicators is reported in the TPMA_NV_READLOCKED and TPMA_NV_WRITELOCKED attributes"). Both are
/// CLEAR at definition, both change the Index's Name when SET (Part 1, clause 13), and both are revisited by the
/// startup pass <see cref="AtStartup"/> applies on a TPM Reset or TPM Restart.
/// </para>
/// </remarks>
/// <param name="NvIndex">The NV Index handle (its most-significant octet is <c>TPM_HT_NV_INDEX</c>).</param>
/// <param name="AuthValue">The Index authorization value supplied at definition, in an owned <see cref="Tpm2bAuth"/> carrier; compared against a caller's authorization on access.</param>
/// <param name="Attributes">The Index attributes (<c>TPMA_NV</c>) set at definition, with <c>TPMA_NV_WRITTEN</c> folded in once the Index has been written.</param>
/// <param name="DataSize">The size in octets of the Index data area declared at definition.</param>
/// <param name="Data">
/// The Index's data area in an owned pooled carrier reserved at <paramref name="DataSize"/> octets by the
/// defining command's parser, whose ownership transfers into this record at the installing transition and which
/// is released when the Index is evicted. Its <see cref="TpmNvIndexData.Length"/> is the written extent — the
/// octets a store has actually reached — and is zero until the first write.
/// </param>
/// <param name="NameAlg">
/// The hash algorithm used to compute this Index's Name (<c>Name ≔ nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> - the
/// marshaled public area whose own first field is the Index handle, so the handle is hashed exactly once,
/// TPM 2.0 Library Part 1, clause 13 and Table 9) and to process <see cref="AuthPolicy"/>, supplied at
/// <c>TPM2_NV_DefineSpace()</c> and retained unchanged for the Index's lifetime.
/// </param>
/// <param name="AuthPolicy">
/// This Index's access policy digest (<c>TPMS_NV_PUBLIC.authPolicy</c>, a <c>TPM2B_DIGEST</c> — TPM 2.0 Library
/// Part 2, clause 10.3.2, Table 90), in an owned pooled carrier: supplied at <c>TPM2_NV_DefineSpace()</c>,
/// adopted from the defining request at install, and folded into the marshaled public area every Name
/// computation hashes. The dispose-immune <see cref="Tpm2bDigest.Empty"/> when the Index was defined with no
/// policy; released when the Index leaves the dictionary.
/// </param>
public sealed record NvIndexState(
    TpmiRhNvIndex NvIndex,
    Tpm2bAuth AuthValue,
    TpmaNv Attributes,
    ushort DataSize,
    TpmNvIndexData Data,
    TpmiAlgHash NameAlg,
    Tpm2bDigest AuthPolicy): IDisposable
{
    /// <summary>
    /// The size in octets of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (pinCount + pinLimit, each a
    /// <c>UINT32</c>; TPM 2.0 Library Part 2, clause 13.3).
    /// </summary>
    private const int PinCounterParametersSize = 2 * sizeof(uint);

    /// <summary>
    /// The size in octets of a Counter Index's value (TPM 2.0 Library Part 2, clause 13.2: "Counter -
    /// contains an 8-octet value...").
    /// </summary>
    private const int CounterValueSize = sizeof(ulong);

    /// <summary>
    /// The size in octets of a Bit Field Index's value (TPM 2.0 Library Part 2, clause 13.2, Table 247: "Bit
    /// Field - contains an 8-octet value to be used as a bit field").
    /// </summary>
    private const int BitFieldValueSize = sizeof(ulong);

    /// <summary>
    /// Gets a value indicating whether this Index is dictionary-attack protected: an authorization
    /// failure against it feeds the lockout counter and is blocked in lockout, unless
    /// <see cref="TpmaNv.TPMA_NV_NO_DA"/> is set (TPM 2.0 Library Part 2, clause 13.4; Part 1, clause 16.8).
    /// </summary>
    public bool IsDaProtected => (Attributes & TpmaNv.TPMA_NV_NO_DA) == 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be read using its authorization value: only when
    /// <see cref="TpmaNv.TPMA_NV_AUTHREAD"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear the Index authValue cannot authorize a read, even when the supplied value matches.
    /// </summary>
    public bool IsAuthReadAllowed => (Attributes & TpmaNv.TPMA_NV_AUTHREAD) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be written using its authorization value: only when
    /// <see cref="TpmaNv.TPMA_NV_AUTHWRITE"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear the Index authValue cannot authorize a write, even when the supplied value matches.
    /// </summary>
    public bool IsAuthWriteAllowed => (Attributes & TpmaNv.TPMA_NV_AUTHWRITE) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be written under Owner Authorization: only when
    /// <see cref="TpmaNv.TPMA_NV_OWNERWRITE"/> is set (TPM 2.0 Library Part 2, clause 13.4). With the bit
    /// clear owner authorization cannot write the Index, even when the owner authValue matches. This is the
    /// sole write path for a PIN Index, whose own authValue forbids <see cref="TpmaNv.TPMA_NV_AUTHWRITE"/>
    /// (Part 1, clause 34.2.6.1).
    /// </summary>
    public bool IsOwnerWriteAllowed => (Attributes & TpmaNv.TPMA_NV_OWNERWRITE) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be read under Owner Authorization: only when
    /// <see cref="TpmaNv.TPMA_NV_OWNERREAD"/> is set (TPM 2.0 Library Part 3, clause 31.13: "Proper
    /// authorizations are required for this command as determined by TPMA_NV_PPREAD, TPMA_NV_OWNERREAD,
    /// TPMA_NV_AUTHREAD, and the authPolicy of the NV Index"). With the bit clear owner authorization cannot
    /// read the Index, even when the owner authValue matches - checked before the owner-auth compare, the
    /// same non-leaking order <see cref="IsOwnerWriteAllowed"/>'s gate uses at the owner-write arm.
    /// </summary>
    public bool IsOwnerReadAllowed => (Attributes & TpmaNv.TPMA_NV_OWNERREAD) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index has been written (<c>TPMA_NV_WRITTEN</c> SET). An unwritten
    /// Index answers a read with <c>TPM_RC_NV_UNINITIALIZED</c> (TPM 2.0 Library Part 3, clause 31.13).
    /// </summary>
    public bool IsWritten => (Attributes & TpmaNv.TPMA_NV_WRITTEN) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index is locked for writing (<c>TPMA_NV_WRITELOCKED</c> SET): every
    /// command that modifies the data area — <c>TPM2_NV_Write()</c>, <c>TPM2_NV_Increment()</c>,
    /// <c>TPM2_NV_SetBits()</c>, <c>TPM2_NV_Extend()</c> — answers <c>TPM_RC_NV_LOCKED</c> (TPM 2.0 Library Part 1,
    /// clause 34.2.6.1; Part 3, clauses 31.7.1, 31.8.1 and 31.9.1). SET by <c>TPM2_NV_WriteLock()</c>; CLEAR by the
    /// next TPM Reset or TPM Restart unless <c>TPMA_NV_WRITEDEFINE</c> is SET and the Index is still written after
    /// that startup's own pass (<see cref="AtStartup"/>), in which case the lock "may not be CLEAR except by deleting
    /// and redefining the Index" (Part 2, clause 13.4).
    /// </summary>
    public bool IsWriteLocked => (Attributes & TpmaNv.TPMA_NV_WRITELOCKED) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index is locked for reading (<c>TPMA_NV_READLOCKED</c> SET): every
    /// command that reads the data area — <c>TPM2_NV_Read()</c>, <c>TPM2_NV_Certify()</c>, <c>TPM2_PolicyNV()</c>,
    /// <c>TPM2_PolicyAuthorizeNV()</c> — answers <c>TPM_RC_NV_LOCKED</c> (TPM 2.0 Library Part 1, clause 34.2.5;
    /// Part 3, clause 31.13.1). SET by <c>TPM2_NV_ReadLock()</c>; CLEAR by the next TPM Reset or TPM Restart.
    /// </summary>
    public bool IsReadLocked => (Attributes & TpmaNv.TPMA_NV_READLOCKED) != 0;

    /// <summary>
    /// Gets a value indicating whether <c>TPM2_NV_WriteLock()</c> may lock this Index: <c>TPMA_NV_WRITEDEFINE</c>
    /// or <c>TPMA_NV_WRITE_STCLEAR</c> SET (TPM 2.0 Library Part 3, clause 31.11.1: "If neither TPMA_NV_WRITEDEFINE
    /// nor TPMA_NV_WRITE_STCLEAR of the NV Index is SET, then the TPM shall return TPM_RC_ATTRIBUTES").
    /// <c>TPMA_NV_GLOBALLOCK</c> is <c>TPM2_NV_GlobalWriteLock()</c>'s attribute and does not open this command.
    /// </summary>
    public bool IsWriteLockable => (Attributes & (TpmaNv.TPMA_NV_WRITEDEFINE | TpmaNv.TPMA_NV_WRITE_STCLEAR)) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index elects <c>TPM2_NV_GlobalWriteLock()</c>'s effect:
    /// <c>TPMA_NV_GLOBALLOCK</c> SET (TPM 2.0 Library Part 2, clause 13.4, Table 249, bit 15: "SET (1): If
    /// TPM2_NV_GlobalWriteLock() is successful, TPMA_NV_WRITELOCKED is set"). This is a separate election from
    /// <see cref="IsWriteLockable"/>, which <c>TPMA_NV_GLOBALLOCK</c> does not open — the two attributes gate two
    /// different commands.
    /// </summary>
    public bool IsGlobalLockElected => (Attributes & TpmaNv.TPMA_NV_GLOBALLOCK) != 0;

    /// <summary>
    /// Gets a value indicating whether <c>TPM2_NV_ReadLock()</c> may lock this Index: <c>TPMA_NV_READ_STCLEAR</c>
    /// SET (TPM 2.0 Library Part 3, clause 31.14.1: "If TPMA_NV_READ_STCLEAR of the NV Index is CLEAR, then the
    /// TPM shall return TPM_RC_ATTRIBUTES").
    /// </summary>
    public bool IsReadLockable => (Attributes & TpmaNv.TPMA_NV_READ_STCLEAR) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index was defined under Platform Authorization
    /// (<see cref="TpmaNv.TPMA_NV_PLATFORMCREATE"/>, <c>TPMA_NV</c> bit 30; TPM 2.0 Library Part 2, clause 13.4).
    /// It fixes which authority owns the Index for the rest of its life: a platform-created Index may be
    /// undefined only with Platform Authorization, and it is gated by <c>phEnableNV</c> rather than
    /// <c>shEnable</c> (Part 3, clause 24.2.1).
    /// </summary>
    /// <remarks>
    /// This is the discriminator <c>TPM2_Clear()</c> turns on: its effect list deletes exactly the Indexes with
    /// this attribute CLEAR — "delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR" (Part 3, clause
    /// 24.6.1) — so a platform-created Index survives an owner change. It reads the bit out of
    /// <see cref="Attributes"/> rather than shadowing it in a field of its own, the way every other attribute
    /// lens on this record does: the bit is fixed at definition and no later state change touches it
    /// (<see cref="WriteData"/> only folds in <c>TPMA_NV_WRITTEN</c>), so a derived reading cannot drift from
    /// the attributes the Name is computed over.
    /// </remarks>
    public bool IsPlatformCreated => (Attributes & TpmaNv.TPMA_NV_PLATFORMCREATE) != 0;

    /// <summary>
    /// Gets a value indicating whether this Index may be deleted only through
    /// <c>TPM2_NV_UndefineSpaceSpecial()</c>'s policy-satisfying ADMIN authorization
    /// (<see cref="TpmaNv.TPMA_NV_POLICY_DELETE"/>, <c>TPMA_NV</c> bit 10; TPM 2.0 Library Part 2, clause
    /// 13.4): "Index may not be deleted unless the authPolicy is satisfied using
    /// TPM2_NV_UndefineSpaceSpecial()". <c>TPM2_NV_UndefineSpace()</c> refuses such an Index outright, and
    /// definition admits the bit only under Platform Authorization (Part 3, clause 31.3.1).
    /// </summary>
    /// <remarks>
    /// This reads the bit out of <see cref="Attributes"/> rather than shadowing it in a field of its own, the
    /// same shape <see cref="IsPlatformCreated"/> uses: the bit is fixed at definition and no later state
    /// change touches it, so a derived reading cannot drift from the attributes the Name is computed over.
    /// </remarks>
    public bool IsPolicyDeleteRequired => (Attributes & TpmaNv.TPMA_NV_POLICY_DELETE) != 0;

    /// <summary>
    /// Gets the Index's type (the <c>TPM_NT</c> field within <see cref="Attributes"/>, bits 7:4; TPM 2.0
    /// Library Part 2, clause 13.2).
    /// </summary>
    public TpmNt IndexType => TpmaNvFields.GetTpmNt(Attributes);

    /// <summary>
    /// Gets a value indicating whether this Index is a PIN Fail Index (<see cref="TpmNt.TPM_NT_PIN_FAIL"/>):
    /// its own <see cref="PinCount"/> resets to zero on a successful authorization and increments on a failed
    /// one (TPM 2.0 Library Part 1, clause 34.2.6.6).
    /// </summary>
    public bool IsPinFail => IndexType == TpmNt.TPM_NT_PIN_FAIL;

    /// <summary>
    /// Gets a value indicating whether this Index is a PIN Pass Index (<see cref="TpmNt.TPM_NT_PIN_PASS"/>):
    /// its own <see cref="PinCount"/> increments on a successful authorization and is left unchanged on a
    /// failed one (TPM 2.0 Library Part 1, clause 34.2.6.6).
    /// </summary>
    public bool IsPinPass => IndexType == TpmNt.TPM_NT_PIN_PASS;

    /// <summary>
    /// Gets a value indicating whether this Index carries the localized PIN dictionary-attack defense
    /// (<see cref="IsPinFail"/> or <see cref="IsPinPass"/>; TPM 2.0 Library Part 1, clause 34.2.8.2), distinct
    /// from — and, for a PIN Pass Index without <see cref="TpmaNv.TPMA_NV_NO_DA"/>, additional to — the
    /// TPM-wide mechanism <see cref="IsDaProtected"/> gates.
    /// </summary>
    public bool IsPinIndex => IsPinFail || IsPinPass;

    /// <summary>
    /// Gets the current attempt count from the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data (the
    /// first four octets of <see cref="Data"/>; TPM 2.0 Library Part 2, clause 13.3). Zero for an unwritten
    /// Index, since no counter data has been stored yet — computed directly over <see cref="Data"/>, with no
    /// parallel counter state.
    /// </summary>
    public uint PinCount => Data.Length >= PinCounterParametersSize
        ? BinaryPrimitives.ReadUInt32BigEndian(Data.Span[..sizeof(uint)])
        : 0u;

    /// <summary>
    /// Returns a copy of this Index with <paramref name="data"/> stored at <paramref name="offset"/> and
    /// <c>TPMA_NV_WRITTEN</c> set, merging into the reserved data area (TPM 2.0 Library Part 3, clause 31.7).
    /// The caller has already range-checked the write against <see cref="DataSize"/>.
    /// </summary>
    /// <remarks>
    /// The store happens in place, in the carrier the Index already owns: an Index's space is reserved at
    /// definition and a write merges <c>data.size</c> octets into it starting at <c>offset</c> (clause 31.7.1),
    /// so the returned copy shares the very carrier this one holds and only the attribute word differs. That is
    /// what lets the pure transitions that perform every store hold no memory pool.
    /// </remarks>
    /// <param name="offset">The octet offset into the data area at which to write.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WriteData(int offset, ReadOnlySpan<byte> data)
    {
        Data.Write(offset, data);

        return this with { Attributes = Attributes | TpmaNv.TPMA_NV_WRITTEN };
    }

    /// <summary>
    /// Gets the attempt threshold from the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data (the second
    /// four octets of <see cref="Data"/>; TPM 2.0 Library Part 2, clause 13.3). Zero for an unwritten Index.
    /// </summary>
    public uint PinLimit => Data.Length >= PinCounterParametersSize
        ? BinaryPrimitives.ReadUInt32BigEndian(Data.Span.Slice(sizeof(uint), sizeof(uint)))
        : 0u;

    /// <summary>
    /// Gets a value indicating whether this PIN Index's authValue is currently usable for authorization: the
    /// Index must already be written and <see cref="PinCount"/> must be strictly less than
    /// <see cref="PinLimit"/> (TPM 2.0 Library Part 1, clause 34.2.6.6). Meaningful only when
    /// <see cref="IsPinIndex"/> is <see langword="true"/>.
    /// </summary>
    public bool IsPinAuthAvailable => IsWritten && PinCount < PinLimit;

    /// <summary>
    /// Gets the current 8-octet counter value (TPM 2.0 Library Part 2, clause 13.2), stored big-endian across
    /// the whole <see cref="Data"/> area. Zero for an unwritten Index, since no counter data has been stored
    /// yet — meaningful only when <see cref="IndexType"/> is <see cref="TpmNt.TPM_NT_COUNTER"/>.
    /// </summary>
    public ulong CounterValue => Data.Length >= CounterValueSize
        ? BinaryPrimitives.ReadUInt64BigEndian(Data.Span[..CounterValueSize])
        : 0ul;

    /// <summary>
    /// Returns a copy of this PIN Index with <paramref name="pinCount"/> stored as the first four octets of
    /// the retained <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> data, leaving <see cref="PinLimit"/> (and any
    /// further stored octets) untouched (TPM 2.0 Library Part 2, clause 13.3). Composes over
    /// <see cref="WriteData"/>, so it also (harmlessly, for an already-written PIN Index) confirms
    /// <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="pinCount">The new pinCount value.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithPinCount(uint pinCount)
    {
        //Tiny, non-secret counter value (4 bytes) - never the authValue or key material this Index protects.
        Span<byte> pinCountBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(pinCountBytes, pinCount);

        return WriteData(0, pinCountBytes);
    }

    /// <summary>
    /// Returns a copy of this Index carrying <paramref name="strippedAuthValue"/> as its authorization value —
    /// the sole effect of <c>TPM2_NV_ChangeAuth()</c> (TPM 2.0 Library Part 3, clause 31.15), which replaces the
    /// authValue and nothing else.
    /// </summary>
    /// <remarks>
    /// The data area is untouched, so a PIN Index's retained pinCount/pinLimit and its <c>TPMA_NV_WRITTEN</c> bit
    /// survive a rotation, and the Index's Name is stable by construction: <see cref="AuthValue"/> is not a field
    /// of <c>TPMS_NV_PUBLIC</c>, which is the only structure the Name recipe hashes (Part 1, clause 13 and
    /// Table 9). A Name or attestation obtained before a rotation therefore stays valid after it. The carrier
    /// holds the exact octets the rotating command supplied; every consumer takes its trailing-zero-stripped
    /// view where the value is used as an authValue (Part 1, clause 16.6.4.3: "Trailing octets of zero are to be
    /// removed from any string before it is used as an authValue"), so the stored form and the compared form
    /// cannot drift.
    /// </remarks>
    /// <param name="newAuth">The new authorization value in an owned carrier; ownership transfers to the returned Index.</param>
    /// <returns>The updated Index.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of newAuth transfers to the returned NvIndexState's AuthValue, which the record's Dispose or the next rotation releases; the outgoing carrier is disposed here before the with-copy replaces it.")]
    public NvIndexState WithAuthValue(Tpm2bAuth newAuth)
    {
        AuthValue.Dispose();

        return this with { AuthValue = newAuth };
    }

    /// <summary>
    /// Releases the Index's owned authorization-value, access-policy-digest, and data-area carriers. Called when
    /// the Index leaves the automaton's dictionary for good (<c>TPM2_NV_UndefineSpace()</c>, <c>TPM2_Clear()</c>,
    /// simulator teardown); the shared empty carriers are dispose-immune, so the walk is safe for a no-auth,
    /// no-policy, zero-size Index.
    /// </summary>
    public void Dispose()
    {
        AuthValue.Dispose();
        AuthPolicy.Dispose();
        Data.Dispose();
    }

    /// <summary>
    /// Returns a copy of this Counter Index with <paramref name="counterValue"/> stored as the 8 big-endian
    /// octets spanning the whole retained data area (TPM 2.0 Library Part 2, clause 13.2). Composes over
    /// <see cref="WriteData"/> the way <see cref="WithPinCount"/> does, so it also sets
    /// <c>TPMA_NV_WRITTEN</c> (TPM 2.0 Library Part 1, clause 34.2.6.3: "the TPMA_NV_WRITTEN attribute will be
    /// SET" on the first increment).
    /// </summary>
    /// <param name="counterValue">The new counter value.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithCounterValue(ulong counterValue)
    {
        //Tiny, non-secret counter value (8 bytes) - never the authValue or key material this Index protects.
        Span<byte> counterValueBytes = stackalloc byte[CounterValueSize];
        BinaryPrimitives.WriteUInt64BigEndian(counterValueBytes, counterValue);

        return WriteData(0, counterValueBytes);
    }

    /// <summary>
    /// Gets the current 64-bit bit-field value (TPM 2.0 Library Part 2, clause 13.2, Table 247: "an 8-octet
    /// value to be used as a bit field"), stored big-endian across the whole <see cref="Data"/> area. Zero for an
    /// unwritten Index — the value <c>TPM2_NV_SetBits()</c> ORs its first <c>bits</c> into (Part 3, clause 31.10.1:
    /// "If TPMA_NV_WRITTEN is not SET, then, for the purposes of this command, the NV Index is considered to
    /// contain all zero bits") — meaningful only when <see cref="IndexType"/> is <see cref="TpmNt.TPM_NT_BITS"/>.
    /// </summary>
    public ulong BitsValue => Data.Length >= BitFieldValueSize
        ? BinaryPrimitives.ReadUInt64BigEndian(Data.Span[..BitFieldValueSize])
        : 0ul;

    /// <summary>
    /// Returns a copy of this Bit Field Index with <paramref name="bitsValue"/> stored as the 8 big-endian octets
    /// spanning the whole retained data area (TPM 2.0 Library Part 2, clause 13.2). Composes over
    /// <see cref="WriteData"/> the way <see cref="WithCounterValue"/> does, so it also sets
    /// <c>TPMA_NV_WRITTEN</c> — "TPMA_NV_WRITTEN will be SET even if no bits were SET" (Part 3, clause 31.10.1).
    /// </summary>
    /// <param name="bitsValue">The new bit-field value — the previous value ORed with the command's <c>bits</c>.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithBitsValue(ulong bitsValue)
    {
        //Tiny, non-secret bit-field value (8 bytes) - never the authValue or key material this Index protects.
        Span<byte> bitsValueBytes = stackalloc byte[BitFieldValueSize];
        BinaryPrimitives.WriteUInt64BigEndian(bitsValueBytes, bitsValue);

        return WriteData(0, bitsValueBytes);
    }

    /// <summary>
    /// Returns a copy of this Index with <c>TPMA_NV_WRITELOCKED</c> SET — the effect of <c>TPM2_NV_WriteLock()</c>
    /// (TPM 2.0 Library Part 3, clause 31.11.1: "the TPM shall SET TPMA_NV_WRITELOCKED for the NV Index"). The data
    /// area and <c>TPMA_NV_WRITTEN</c> are untouched; the attribute word changes, so the Index's Name changes with
    /// it (Part 1, clause 13: "When an NV Index becomes locked ... the Name of the NV Index changes").
    /// </summary>
    /// <remarks>
    /// This is a with-copy: the replaced record's <see cref="AuthValue"/>, <see cref="AuthPolicy"/> and
    /// <see cref="Data"/> carriers move to the clone wholesale, so the displaced <see cref="NvIndexState"/> is
    /// never disposed on this path.
    /// </remarks>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithWriteLocked() => this with { Attributes = Attributes | TpmaNv.TPMA_NV_WRITELOCKED };

    /// <summary>
    /// Returns a copy of this Index with <c>TPMA_NV_READLOCKED</c> SET — the effect of <c>TPM2_NV_ReadLock()</c>
    /// (TPM 2.0 Library Part 3, clause 31.14.1: "the TPM shall SET TPMA_NV_READLOCKED for the NV Index"). The data
    /// area and <c>TPMA_NV_WRITTEN</c> are untouched — "An Index that had not been written may be locked for
    /// reading" — and the Name changes with the attribute word (Part 1, clause 13).
    /// </summary>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithReadLocked() => this with { Attributes = Attributes | TpmaNv.TPMA_NV_READLOCKED };

    /// <summary>
    /// Returns this Index as a completed TPM Reset or TPM Restart leaves it (TPM 2.0 Library Part 3, clause 9.3's
    /// Reset and Restart bullets; Part 4 <c>NvSetStartupAttributes</c>): <c>TPMA_NV_READLOCKED</c> CLEAR
    /// unconditionally (Part 1, clause 34.2.5: "TPMA_NV_READLOCKED will be CLEAR on the next TPM Reset or TPM
    /// Restart"); for a non-counter Index, <c>TPMA_NV_WRITTEN</c> CLEAR when <c>TPMA_NV_CLEAR_STCLEAR</c> is SET, or
    /// when <c>TPMA_NV_ORDERLY</c> is SET and the startup is a Reset (Part 2, clause 13.4; Part 1, clauses 34.2.6.4
    /// and 34.2.6.5); then <c>TPMA_NV_WRITELOCKED</c> CLEAR unless the lock is permanent (Part 3, clause 9.3: "For
    /// each NV Index with TPMA_NV_WRITEDEFINE CLEAR or TPMA_NV_WRITTEN CLEAR, TPMA_NV_WRITELOCKED shall be CLEAR").
    /// </summary>
    /// <remarks>
    /// The unlock is judged over the WRITTEN bit as this pass leaves it, the reference's order: a WRITEDEFINE Index
    /// whose value the same startup just discarded is unlocked with it, which is what Part 1, clause 34.2.6.1's Note
    /// asks for — "If TPMA_NV_WRITELOCKED is SET, but TPMA_NV_WRITTEN is CLEAR, then TPMA_NV_WRITELOCKED is CLEAR by
    /// TPM Reset or TPM Restart. This is true even if the TPMA_NV_WRITEDEFINE attribute is set. It prevents an NV
    /// Index from being defined that can never be written". Counters are exempt from the WRITTEN arm alone: a
    /// counter is restored or advanced across a startup, never cleared (Part 1, clause 34.2.6.3), and
    /// <c>TPMA_NV_CLEAR_STCLEAR</c> cannot reach one (Part 3, clause 31.3.1). A TPM Resume runs no pass at all. The
    /// carriers move to the returned record wholesale, so nothing is disposed here; the very same record comes back
    /// when no bit changes.
    /// </remarks>
    /// <param name="isReset">Whether the startup is a TPM Reset, which extends the WRITTEN arm to <c>TPMA_NV_ORDERLY</c> Indexes; otherwise a TPM Restart.</param>
    /// <returns>The Index as the startup leaves it.</returns>
    public NvIndexState AtStartup(bool isReset)
    {
        TpmaNv attributes = Attributes & ~TpmaNv.TPMA_NV_READLOCKED;

        bool isClearElected = (attributes & TpmaNv.TPMA_NV_CLEAR_STCLEAR) != 0
            || (isReset && (attributes & TpmaNv.TPMA_NV_ORDERLY) != 0);
        if(IndexType != TpmNt.TPM_NT_COUNTER && isClearElected)
        {
            attributes &= ~TpmaNv.TPMA_NV_WRITTEN;
        }

        bool isWriteLockPermanent = (attributes & TpmaNv.TPMA_NV_WRITTEN) != 0 && (attributes & TpmaNv.TPMA_NV_WRITEDEFINE) != 0;
        if(!isWriteLockPermanent)
        {
            attributes &= ~TpmaNv.TPMA_NV_WRITELOCKED;
        }

        return attributes == Attributes ? this : this with { Attributes = attributes };
    }

    /// <summary>
    /// Returns a copy of this Extend Index with <paramref name="digest"/> stored as its whole value — the result
    /// of <c>TPM2_NV_Extend()</c>'s <c>H_nameAlg(old ‖ data)</c> fold (TPM 2.0 Library Part 1, clause 34.2.6.5,
    /// equation 56; Part 3, clause 31.9.1) — exactly the Index's declared size, which
    /// <c>TPM2_NV_DefineSpace()</c> fixed at the nameAlg's digest width (Part 3, clause 31.3.1). Composes over
    /// <see cref="WriteData"/> the way <see cref="WithCounterValue"/> does, so it also sets
    /// <c>TPMA_NV_WRITTEN</c> ("After successful completion of this command, TPMA_NV_WRITTEN for the NV Index
    /// will be SET", clause 31.9.1).
    /// </summary>
    /// <param name="digest">The new value, <see cref="DataSize"/> octets wide.</param>
    /// <returns>The updated Index.</returns>
    public NvIndexState WithExtendedValue(ReadOnlySpan<byte> digest) => WriteData(0, digest);

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two Indexes are equal only when they
    /// share the same <see cref="AuthValue"/>, <see cref="AuthPolicy"/> and <see cref="Data"/> instances. A
    /// rotated authValue is a different resource even under equal octets, and
    /// <see cref="SensitiveMemory"/>'s own equality reads
    /// buffer content — which a
    /// rotation has already disposed when <c>ImmutableDictionary.SetItem</c> compares the replacement
    /// against the superseded entry. Reference comparison preserves the object-identity semantics the
    /// field had as plain memory and never reads bytes, so a superseded snapshot cannot throw here.
    /// </summary>
    /// <param name="other">The Index to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(NvIndexState? other) =>
        other is not null
        && NvIndex == other.NvIndex
        && ReferenceEquals(AuthValue, other.AuthValue)
        && Attributes == other.Attributes
        && DataSize == other.DataSize
        && ReferenceEquals(Data, other.Data)
        && NameAlg == other.NameAlg
        && ReferenceEquals(AuthPolicy, other.AuthPolicy);

    /// <summary>
    /// Hashes the Index's immutable identity fields, consistent with <see cref="Equals(NvIndexState)"/>
    /// without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(NvIndex, Attributes, DataSize, NameAlg);
}
