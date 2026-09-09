using System.Collections.Frozen;
using System.Collections.Generic;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Whether a no-authorization command's first command parameter accepts a <c>decrypt</c> companion and whether
/// its first response parameter accepts an <c>encrypt</c> companion (TPM 2.0 Library Part 1, clause 18: "If
/// sessionAttributes.decrypt is SET in a session in a command, and the first parameter of the command is a
/// sized buffer, then that parameter is encrypted... If sessionAttributes.encrypt is SET in a session of a
/// command, and the first parameter of the response is a sized buffer, then the TPM will encrypt that
/// parameter") — the two flags <see cref="TpmLifecycleTransitions.ValidateSessionArea"/> needs for every slot in
/// a no-authorization command's authorization area, declared ONCE per command in <see cref="Table"/> rather than
/// duplicated at every command's own transition.
/// </summary>
/// <param name="FirstCommandParameterIsEncryptable">Whether the command's first parameter is a sized buffer a <c>decrypt</c> slot may protect.</param>
/// <param name="FirstResponseParameterIsEncryptable">Whether the response's first parameter is a sized buffer an <c>encrypt</c> slot may protect.</param>
/// <remarks>
/// Whether the response carries a handle (<see cref="TpmPendingSessionFrame.ResponseCarriesHandle"/>) is
/// deliberately NOT a field here: it is read from the shipped <c>TPMA_CC</c> row's <c>R_HANDLE</c> bit
/// (<see cref="Verifiable.Tpm.Spec.Attributes.TpmaCc.R_HANDLE"/>, TPM 2.0 Library Part 2, clause 8.9, Table 43),
/// so the two facts about a command's response cannot drift apart by being declared twice.
/// </remarks>
public readonly record struct TpmNoAuthSessionShape(bool FirstCommandParameterIsEncryptable, bool FirstResponseParameterIsEncryptable)
{
    /// <summary>
    /// The frozen per-command shape table for the no-authorization commands admitted through the generic
    /// wrapper (<see cref="TpmNoAuthOverSessionsRequested"/>) — one row per routed command, so no two callers
    /// can declare a different shape for the same command.
    /// </summary>
    private static FrozenDictionary<TpmCcConstants, TpmNoAuthSessionShape> Table { get; } = new Dictionary<TpmCcConstants, TpmNoAuthSessionShape>
    {
        //TPM2_GetRandom() (TPM 2.0 Library Part 3, clause 16.1, Table 75's tag cell: "TPM_ST_SESSIONS if an
        //audit or encrypt session is present"): the command's own parameter is bytesRequested (UINT16), not a
        //sized buffer a decrypt slot could protect; the response's randomBytes IS a TPM2B_DIGEST an encrypt
        //slot may protect (Part 4 CommandAttributeData.h, read by CommandCapGetCCAttribute(): "CC_GetRandom * (IS_IMPLEMENTED+ENCRYPT_2)").
        [TpmCcConstants.TPM_CC_GetRandom] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: true),

        //TPM2_StirRandom() (TPM 2.0 Library Part 3, clause 16.2, Table 77's tag cell: "TPM_ST_SESSIONS if an
        //audit or decrypt session is present"): the command's own inData IS a TPM2B_SENSITIVE_DATA a decrypt
        //slot may protect; the response carries no parameter for an encrypt slot to protect at all (Part 4
        //CommandAttributeData.h, read by CommandCapGetCCAttribute(): "CC_StirRandom * (IS_IMPLEMENTED+DECRYPT_2)", no ENCRYPT bit).
        [TpmCcConstants.TPM_CC_StirRandom] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_TestParms() (TPM 2.0 Library Part 3, clause 30.3, Table 240's tag cell: "TPM_ST_SESSIONS if an
        //audit session is present"): parameters is a TPMT_PUBLIC_PARMS structure, not a sized buffer, and the
        //response carries none either — neither direction admits anything but audit (Part 4
        //CommandAttributeData.h, read by CommandCapGetCCAttribute(): "CC_TestParms * (IS_IMPLEMENTED)" alone).
        [TpmCcConstants.TPM_CC_TestParms] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_ReadClock() (TPM 2.0 Library Part 3, clause 29.1, Table 232's tag cell: "TPM_ST_SESSIONS if an
        //audit session is present"): no command parameter and no sized response buffer — audit only.
        [TpmCcConstants.TPM_CC_ReadClock] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_Shutdown() (TPM 2.0 Library Part 3, Table 6's tag cell: "TPM_ST_SESSIONS if an audit session is
        //present"): shutdownType is a bare TPM_SU value, not a sized buffer, and the response carries no
        //parameters — audit only.
        [TpmCcConstants.TPM_CC_Shutdown] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_SelfTest() (TPM 2.0 Library Part 3, Table 8's tag cell: "TPM_ST_SESSIONS if an audit session is
        //present"): fullTest is a bare TPMI_YES_NO value, not a sized buffer, and the response carries no
        //parameters — audit only.
        [TpmCcConstants.TPM_CC_SelfTest] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_GetTestResult() (TPM 2.0 Library Part 3, Table 12's tag cell: "TPM_ST_SESSIONS if an audit or
        //encrypt session is present"): no command parameter; the response's outData IS a TPM2B_MAX_BUFFER an
        //encrypt slot may protect.
        [TpmCcConstants.TPM_CC_GetTestResult] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: true),

        //TPM2_GetCapability() (TPM 2.0 Library Part 3, Table 238's tag cell: "TPM_ST_SESSIONS if an audit
        //session is present"): capability/property/propertyCount are bare values, not a sized buffer, and the
        //response's capabilityData is a TPMS_CAPABILITY_DATA union, not a TPM2B — audit only.
        [TpmCcConstants.TPM_CC_GetCapability] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_PCR_Read() (TPM 2.0 Library Part 3, clause 22.4, Table 134's tag cell: "TPM_ST_SESSIONS if an
        //audit session is present"): pcrSelectionIn is a TPML_PCR_SELECTION, not a sized buffer, and the
        //response's pcrValues is a TPML_DIGEST, not a TPM2B — audit only.
        [TpmCcConstants.TPM_CC_PCR_Read] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: false),

        //TPM2_ReadPublic() (TPM 2.0 Library Part 3, clause 12.4, Table 24's tag cell: "TPM_ST_SESSIONS if an
        //audit or encrypt session is present"): no command parameter (the whole request is the handle area);
        //the response's outPublic IS a TPM2B_PUBLIC an encrypt slot may protect.
        [TpmCcConstants.TPM_CC_ReadPublic] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: true),

        //TPM2_NV_ReadPublic() (TPM 2.0 Library Part 3, clause 31.6, Table 251's tag cell: "TPM_ST_SESSIONS if
        //an audit or encrypt session is present"): no command parameter (the whole request is the handle
        //area); the response's nvPublic IS a TPM2B_NV_PUBLIC an encrypt slot may protect.
        [TpmCcConstants.TPM_CC_NV_ReadPublic] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: true),

        //TPM2_Hash() (TPM 2.0 Library Part 3, clause 15.4, Table 69's tag cell: "TPM_ST_SESSIONS if an audit,
        //encrypt, or decrypt session is present"): no handle; the command's own data IS a TPM2B_MAX_BUFFER a
        //decrypt slot may protect, and the response's outHash IS a TPM2B_DIGEST an encrypt slot may protect —
        //the one row admitting all three companion kinds at once.
        [TpmCcConstants.TPM_CC_Hash] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: true),

        //TPM2_HashSequenceStart() (TPM 2.0 Library Part 3, clause 17.4, Table 85's tag cell: "TPM_ST_SESSIONS
        //if an audit or decrypt session is present"): no handle; the command's own auth IS a TPM2B_AUTH a
        //decrypt slot may protect; the response carries the new sequenceHandle alone, no sized buffer an
        //encrypt slot could protect (Table 86).
        [TpmCcConstants.TPM_CC_HashSequenceStart] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_SignSequenceStart() (TPM 2.0 Library Part 3, clause 17.5, Table 87's tag cell: "TPM_ST_SESSIONS
        //if an audit or decrypt session is present"): keyHandle carries no '@' (Auth Index None); the
        //command's own auth IS a TPM2B_AUTH a decrypt slot may protect; the response carries the new
        //sequenceHandle alone (Table 88).
        [TpmCcConstants.TPM_CC_SignSequenceStart] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_VerifySequenceStart() (TPM 2.0 Library Part 3, clause 17.6, Table 89's tag cell: "TPM_ST_SESSIONS
        //if an audit or decrypt session is present"): keyHandle carries no '@'; the command's own auth IS a
        //TPM2B_AUTH a decrypt slot may protect; the response carries the new sequenceHandle alone (Table 90).
        [TpmCcConstants.TPM_CC_VerifySequenceStart] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_VerifySignature() (TPM 2.0 Library Part 3, clause 20.2, Table 116's tag cell: "TPM_ST_SESSIONS
        //if an audit or decrypt session is present"; deprecated in this revision, still mandatory): keyHandle
        //carries no '@'; the command's own digest IS a TPM2B_DIGEST a decrypt slot may protect; the response's
        //validation is a TPMT_TK_VERIFIED, not a TPM2B, so no encrypt slot can protect it.
        [TpmCcConstants.TPM_CC_VerifySignature] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_VerifyDigestSignature() (TPM 2.0 Library Part 3, clause 20.4, Table 120's tag cell:
        //"TPM_ST_SESSIONS if an audit or decrypt session is present"): keyHandle carries no '@'; the command's
        //FIRST parameter is context (TPM2B_SIGNATURE_CTX, not digest) and IS a decrypt-eligible sized buffer;
        //the response's validation is a TPMT_TK_VERIFIED, not a TPM2B.
        [TpmCcConstants.TPM_CC_VerifyDigestSignature] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: false),

        //TPM2_Encapsulate() (TPM 2.0 Library Part 3, clause 14.10, Table 60's tag cell: "TPM_ST_SESSIONS if an
        //audit or encrypt session is present"): keyHandle carries no '@'; Table 60 declares no command
        //parameter at all, so no decrypt slot has anything to protect; the response's sharedSecret IS a
        //TPM2B_SHARED_SECRET (Table 61's FIRST field) an encrypt slot may protect.
        [TpmCcConstants.TPM_CC_Encapsulate] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: false, FirstResponseParameterIsEncryptable: true),

        //TPM2_MakeCredential() (TPM 2.0 Library Part 3, clause 12.6, Table 28's tag cell: "TPM_ST_SESSIONS if
        //an audit, encrypt, or decrypt session is present"): handle carries no '@'; the command's own
        //credential IS a TPM2B_DIGEST a decrypt slot may protect; the response's credentialBlob IS a
        //TPM2B_ID_OBJECT an encrypt slot may protect (Part 4 CommandAttributeData.h's ENCRYPT_2 bit, read by CommandCapGetCCAttribute()).
        [TpmCcConstants.TPM_CC_MakeCredential] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: true),

        //TPM2_LoadExternal() (TPM 2.0 Library Part 3, clause 12.3, Table 22's tag cell: "TPM_ST_SESSIONS if an
        //audit, encrypt, or decrypt session is present"): no handle; the command's own inPrivate IS a
        //TPM2B_SENSITIVE a decrypt slot may protect; the response's name (Table 23) IS a TPM2B_NAME an encrypt
        //slot may protect, following objectHandle in the response handle area (Part 2, Table 43's R_HANDLE bit).
        [TpmCcConstants.TPM_CC_LoadExternal] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: true),

        //TPM2_RSA_Encrypt() (TPM 2.0 Library Part 3, clause 14.2, Table 44's tag cell: "TPM_ST_SESSIONS if an
        //audit, encrypt, or decrypt session is present"): keyHandle carries no '@'; the command's own message
        //IS a TPM2B_PUBLIC_KEY_RSA a decrypt slot may protect; the response's outData (Table 45) is the same
        //buffer type an encrypt slot may protect (Part 4 CommandAttributeData.h, read by CommandCapGetCCAttribute(): "CC_RSA_Encrypt *
        //(IS_IMPLEMENTED+DECRYPT_2+ENCRYPT_2)").
        [TpmCcConstants.TPM_CC_RSA_Encrypt] = new TpmNoAuthSessionShape(FirstCommandParameterIsEncryptable: true, FirstResponseParameterIsEncryptable: true),
    }.ToFrozenDictionary();

    /// <summary>
    /// Looks up a routed command's shape row.
    /// </summary>
    /// <param name="commandCode">The command.</param>
    /// <param name="shape">The command's shape.</param>
    /// <returns><see langword="true"/> when the command has a row.</returns>
    public static bool TryGet(TpmCcConstants commandCode, out TpmNoAuthSessionShape shape) => Table.TryGetValue(commandCode, out shape);

    /// <summary>
    /// Every routed command's shape row, keyed by command code — the enumerable surface a cross-check test
    /// walks to confirm every row agrees with the host's <see cref="Infrastructure.ITpmCommandInput.FirstCommandParameterIsEncryptable"/>
    /// and the codec's <see cref="Infrastructure.TpmResponseCodec.ResponseFirstParameterIsEncryptable"/>, so the
    /// two layers cannot silently drift apart.
    /// </summary>
    public static IReadOnlyDictionary<TpmCcConstants, TpmNoAuthSessionShape> Entries => Table;
}
