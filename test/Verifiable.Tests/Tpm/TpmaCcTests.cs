using System;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// <c>TPMA_CC</c> as the <see cref="TpmaCc"/> factories encode it and as
/// <see cref="TpmCcConstantsExtensions.GetCommandAttributes"/> reports it per command
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 2: Structures, clause 8.9): each attribute bit is traced to the Part 3 header
/// modifier or response shape that sets it (Part 3: Commands, clauses 4.2.6, 4.2.7, 4.2.8; Part 2, clause 8.9.3.6).
/// </summary>
[TestClass]
internal sealed class TpmaCcTests
{
    /// <summary>The <c>nv</c> attribute's bit position (Part 2, clause 8.9.3.2).</summary>
    private const int NvBit = 22;

    /// <summary>The <c>extensive</c> attribute's bit position (Part 2, clause 8.9.3.3).</summary>
    private const int ExtensiveBit = 23;

    /// <summary>The <c>flushed</c> attribute's bit position (Part 2, clause 8.9.3.4).</summary>
    private const int FlushedBit = 24;

    /// <summary>The <c>rHandle</c> attribute's bit position (Part 2, clause 8.9.3.6).</summary>
    private const int RHandleBit = 28;

    /// <summary>
    /// A factory call naming no attribute leaves every attribute bit CLEAR: only <c>commandIndex</c> and
    /// <c>cHandles</c> are populated (Part 2, clause 8.9, Table 43).
    /// </summary>
    [TestMethod]
    public void FromCommandIndexWithoutFlagsLeavesEveryAttributeBitClear()
    {
        TpmaCc attributes = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Sign, cHandles: 1);

        Assert.AreEqual((ushort)TpmCcConstants.TPM_CC_Sign, attributes.COMMAND_INDEX);
        Assert.AreEqual((byte)1, attributes.C_HANDLES);
        Assert.IsFalse(attributes.NV, "nv must be CLEAR when not requested.");
        Assert.IsFalse(attributes.EXTENSIVE, "extensive must be CLEAR when not requested.");
        Assert.IsFalse(attributes.FLUSHED, "flushed must be CLEAR when not requested.");
        Assert.IsFalse(attributes.R_HANDLE, "rHandle must be CLEAR when not requested.");
        Assert.IsFalse(attributes.V, "V is never set by the factory: every mapped command is defined by the Library specification.");
    }

    /// <summary>
    /// Each requested attribute lands in exactly its specified bit — <c>nv</c> bit 22, <c>extensive</c> bit 23,
    /// <c>flushed</c> bit 24, <c>rHandle</c> bit 28 — and nowhere else (Part 2, clause 8.9, Table 43).
    /// </summary>
    [TestMethod]
    public void FromCommandIndexEncodesEachAttributeInItsOwnBit()
    {
        uint baseline = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_NV_Write, cHandles: 2).Value;

        TpmaCc nv = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_NV_Write, cHandles: 2, isNv: true);
        Assert.AreEqual(baseline | (1u << NvBit), nv.Value, "nv is bit 22.");
        Assert.IsTrue(nv.NV);

        TpmaCc extensive = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Clear, cHandles: 1, isExtensive: true);
        Assert.AreEqual(TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Clear, cHandles: 1).Value | (1u << ExtensiveBit), extensive.Value, "extensive is bit 23.");
        Assert.IsTrue(extensive.EXTENSIVE);

        TpmaCc flushed = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_SignSequenceComplete, cHandles: 2, isFlushed: true);
        Assert.AreEqual(TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_SignSequenceComplete, cHandles: 2).Value | (1u << FlushedBit), flushed.Value, "flushed is bit 24.");
        Assert.IsTrue(flushed.FLUSHED);

        TpmaCc rHandle = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Load, cHandles: 1, hasResponseHandle: true);
        Assert.AreEqual(TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_Load, cHandles: 1).Value | (1u << RHandleBit), rHandle.Value, "rHandle is bit 28.");
        Assert.IsTrue(rHandle.R_HANDLE);
    }

    /// <summary>
    /// <c>{F}</c> "may be combined with the {NV} modifier but not with the {E} modifier" (Part 3, clause 4.2.7),
    /// so the factory refuses <c>flushed</c> together with <c>extensive</c> while admitting it with <c>nv</c>.
    /// </summary>
    [TestMethod]
    public void FromCommandIndexRefusesFlushedTogetherWithExtensive()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(() => TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_EventSequenceComplete, cHandles: 2, isExtensive: true, isFlushed: true));

        TpmaCc nvAndFlushed = TpmaCc.FromCommandIndex((ushort)TpmCcConstants.TPM_CC_EventSequenceComplete, cHandles: 2, isNv: true, isFlushed: true);
        Assert.IsTrue(nvAndFlushed.NV && nvAndFlushed.FLUSHED, "{NV F} is a permitted combination (TPM2_EventSequenceComplete()'s own header).");
    }

    /// <summary>
    /// <see cref="TpmaCc.FromCommandCode"/> keeps only the low sixteen bits of a command code as
    /// <c>commandIndex</c> and carries the flags through unchanged (Part 2, clause 8.9.3.1).
    /// </summary>
    [TestMethod]
    public void FromCommandCodeKeepsTheLowSixteenBitsAndTheFlags()
    {
        TpmaCc attributes = TpmaCc.FromCommandCode((uint)TpmCcConstants.TPM_CC_SignSequenceStart | 0xFFFF_0000u, cHandles: 1, hasResponseHandle: true);

        Assert.AreEqual((ushort)TpmCcConstants.TPM_CC_SignSequenceStart, attributes.COMMAND_INDEX, "Only bits 15:0 of the command code form commandIndex.");
        Assert.IsTrue(attributes.R_HANDLE, "The flags ride through the command-code overload.");
        Assert.IsFalse(attributes.V, "The high bits of the command code never leak into the attribute word.");
    }

    /// <summary>
    /// Every command whose response carries a handle area reports <c>rHandle</c> SET — the bit "necessary to
    /// allow the TRM to locate the parameterSize field in the response" (Part 2, clause 8.9.3.6): the session,
    /// primary, loaded-object, and both sequence-start handles; a command answering no handle reports it CLEAR.
    /// </summary>
    [TestMethod]
    public void HandleReturningCommandsReportRHandle()
    {
        Assert.IsTrue(TpmCcConstants.TPM_CC_StartAuthSession.GetCommandAttributes().R_HANDLE, "TPM2_StartAuthSession() returns sessionHandle.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_CreatePrimary.GetCommandAttributes().R_HANDLE, "TPM2_CreatePrimary() returns objectHandle.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_Load.GetCommandAttributes().R_HANDLE, "TPM2_Load() returns objectHandle.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_SignSequenceStart.GetCommandAttributes().R_HANDLE, "TPM2_SignSequenceStart() returns sequenceHandle.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_VerifySequenceStart.GetCommandAttributes().R_HANDLE, "TPM2_VerifySequenceStart() returns sequenceHandle.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_Sign.GetCommandAttributes().R_HANDLE, "TPM2_Sign() answers no handle.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_Create.GetCommandAttributes().R_HANDLE, "TPM2_Create() answers no handle: the object is not loaded.");
    }

    /// <summary>
    /// The two sequence-completing commands carry the <c>{F}</c> modifier, "any transient handle context used by
    /// the command will be flushed from the TPM when the command completes" (Part 3, clause 4.2.7; clauses 20.3
    /// and 20.6), so they report <c>flushed</c> SET — while <c>TPM2_SequenceUpdate()</c> (clause 17.7) does not.
    /// </summary>
    [TestMethod]
    public void SequenceCompletingCommandsReportFlushed()
    {
        Assert.IsTrue(TpmCcConstants.TPM_CC_SignSequenceComplete.GetCommandAttributes().FLUSHED, "TPM2_SignSequenceComplete() is {F}.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_VerifySequenceComplete.GetCommandAttributes().FLUSHED, "TPM2_VerifySequenceComplete() is {F}.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_SequenceUpdate.GetCommandAttributes().FLUSHED, "TPM2_SequenceUpdate() keeps the sequence open.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_SignSequenceStart.GetCommandAttributes().FLUSHED, "TPM2_SignSequenceStart() opens, never flushes.");
    }

    /// <summary>
    /// A command carrying the <c>{NV}</c> modifier "may result in an update of NV memory" and reports <c>nv</c>
    /// SET; one without it does not write NV as part of its actions (Part 3, clause 4.2.6).
    /// </summary>
    [TestMethod]
    public void NvWritingCommandsReportNv()
    {
        Assert.IsTrue(TpmCcConstants.TPM_CC_NV_Write.GetCommandAttributes().NV, "TPM2_NV_Write() is {NV}.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_EvictControl.GetCommandAttributes().NV, "TPM2_EvictControl() is {NV}.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_ClockSet.GetCommandAttributes().NV, "TPM2_ClockSet() is {NV}.");
        Assert.IsTrue(TpmCcConstants.TPM_CC_DictionaryAttackLockReset.GetCommandAttributes().NV, "TPM2_DictionaryAttackLockReset() is {NV}.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_NV_Read.GetCommandAttributes().NV, "TPM2_NV_Read() carries no {NV} modifier.");
        Assert.IsFalse(TpmCcConstants.TPM_CC_GetRandom.GetCommandAttributes().NV, "TPM2_GetRandom() carries no {NV} modifier.");
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> and <c>TPM2_HierarchyControl()</c> carry <c>{NV E}</c> — the command "may flush many
    /// objects and re-enumeration of the loaded context likely will be required" (Part 3, clause 4.2.8; clauses
    /// 24.6 and 24.2) — so they report <c>extensive</c> alongside <c>nv</c>, while <c>TPM2_ClearControl()</c>
    /// (<c>{NV}</c> only, clause 24.7) reports <c>nv</c> alone.
    /// </summary>
    [TestMethod]
    public void ExtensiveCommandsReportExtensiveAlongsideNv()
    {
        TpmaCc clear = TpmCcConstants.TPM_CC_Clear.GetCommandAttributes();
        Assert.IsTrue(clear.EXTENSIVE && clear.NV, "TPM2_Clear() is {NV E}.");

        TpmaCc hierarchyControl = TpmCcConstants.TPM_CC_HierarchyControl.GetCommandAttributes();
        Assert.IsTrue(hierarchyControl.EXTENSIVE && hierarchyControl.NV, "TPM2_HierarchyControl() is {NV E}.");

        TpmaCc clearControl = TpmCcConstants.TPM_CC_ClearControl.GetCommandAttributes();
        Assert.IsTrue(clearControl.NV && !clearControl.EXTENSIVE, "TPM2_ClearControl() is {NV} only.");
    }

    /// <summary>
    /// The attribute bits ride alongside, never in place of, <c>cHandles</c> — the field the executor splits the
    /// command layout on (Part 2, clause 8.9.3.5): three for <c>TPM2_NV_Certify()</c>, two for
    /// <c>TPM2_StartAuthSession()</c>, none for <c>TPM2_GetRandom()</c>.
    /// </summary>
    [TestMethod]
    public void HandleCountsStayIntactBesideTheAttributeBits()
    {
        Assert.AreEqual((byte)3, TpmCcConstants.TPM_CC_NV_Certify.GetCommandAttributes().C_HANDLES);
        Assert.AreEqual((byte)2, TpmCcConstants.TPM_CC_StartAuthSession.GetCommandAttributes().C_HANDLES);
        Assert.AreEqual((byte)0, TpmCcConstants.TPM_CC_GetRandom.GetCommandAttributes().C_HANDLES);
        Assert.AreEqual((byte)1, TpmCcConstants.TPM_CC_Clear.GetCommandAttributes().C_HANDLES, "TPM2_Clear() keeps its single @authHandle beside {NV E}.");
    }
}
