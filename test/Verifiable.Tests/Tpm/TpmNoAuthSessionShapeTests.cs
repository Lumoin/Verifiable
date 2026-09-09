using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Cross-checks every row of <see cref="TpmNoAuthSessionShape"/> against the host surface's own declarations —
/// the command input's <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/>, the registered
/// response codec's <see cref="TpmResponseCodec.ResponseFirstParameterIsEncryptable"/>, and the shipped
/// <c>TPMA_CC</c> row's <see cref="TpmaCc.C_HANDLES"/>/<see cref="TpmaCc.R_HANDLE"/> — so the simulator's shape
/// table and the host's own declarations cannot silently drift apart (TPM 2.0 Library Part 1, clause 18's
/// first-parameter encryption rule; Part 2, clause 8.9, Table 43).
/// </summary>
[TestClass]
internal sealed class TpmNoAuthSessionShapeTests
{
    /// <summary>
    /// For every routed command: the shape row's <see cref="TpmNoAuthSessionShape.FirstCommandParameterIsEncryptable"/>
    /// equals the host input's own declaration; where a response codec is registered for the command, the shape
    /// row's <see cref="TpmNoAuthSessionShape.FirstResponseParameterIsEncryptable"/> equals the codec's own
    /// declaration — a command with no registered codec (a header-only response, TPM 2.0 Library Part 3, Tables
    /// 6 and 8) instead has its shape row checked directly against that fact; and the <c>TPMA_CC</c> row's
    /// <c>C_HANDLES</c> matches the handle count the command's own Part 3 table declares, with <c>R_HANDLE</c>
    /// set for exactly the commands whose response carries a handle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18; Part 2, clause 8.9, Table 43; Part 3, Tables 6 and 8</see>.
    /// </summary>
    [TestMethod]
    public void EveryShapeRowAgreesWithTheHostInputTheCodecAndTpmaCc()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        foreach(KeyValuePair<TpmCcConstants, TpmNoAuthSessionShape> entry in TpmNoAuthSessionShape.Entries)
        {
            TpmCcConstants commandCode = entry.Key;
            TpmNoAuthSessionShape shape = entry.Value;

            (bool hostFirstCommandParameterIsEncryptable, TpmResponseCodec? codec, byte expectedHandleCount, bool hostIsFirstHandleAuthorized) = BuildProbe(commandCode, pool);

            Assert.AreEqual(
                shape.FirstCommandParameterIsEncryptable, hostFirstCommandParameterIsEncryptable,
                $"'{commandCode}': the shape row's FirstCommandParameterIsEncryptable must equal the host input's own declaration.");

            if(expectedHandleCount == 1)
            {
                Assert.IsFalse(
                    hostIsFirstHandleAuthorized,
                    $"'{commandCode}': a no-authorization command never authorizes its one handle (Auth Index None on its own Part 3 table), so ITpmCommandInput.IsFirstHandleAuthorized must be false.");
            }

            if(codec is null)
            {
                Assert.IsFalse(
                    shape.FirstResponseParameterIsEncryptable,
                    $"'{commandCode}': a command with no registered response codec carries no response parameter to protect, so its shape row must declare FirstResponseParameterIsEncryptable false.");
            }
            else
            {
                Assert.AreEqual(
                    shape.FirstResponseParameterIsEncryptable, codec.ResponseFirstParameterIsEncryptable,
                    $"'{commandCode}': the shape row's FirstResponseParameterIsEncryptable must equal the response codec's own declaration.");
            }

            TpmaCc attributes = commandCode.GetCommandAttributes();
            Assert.AreEqual(
                expectedHandleCount, attributes.C_HANDLES,
                $"'{commandCode}': the TPMA_CC row's C_HANDLES must match the handle count the command's Part 3 table declares.");

            bool expectedResponseCarriesHandle = commandCode is
                TpmCcConstants.TPM_CC_HashSequenceStart or TpmCcConstants.TPM_CC_SignSequenceStart or TpmCcConstants.TPM_CC_VerifySequenceStart
                or TpmCcConstants.TPM_CC_LoadExternal;
            Assert.AreEqual(
                expectedResponseCarriesHandle, attributes.R_HANDLE,
                $"'{commandCode}': R_HANDLE must be SET for exactly the three sequence-start commands (Table 86/88/90) and TPM2_LoadExternal() (Table 23), and CLEAR for every other row.");
        }
    }

    /// <summary>
    /// "An authorization session is present for each of the handles with the '@' decoration" (TPM 2.0 Library
    /// Part 3, clause 5.5, step 5): a command whose FIRST handle carries an Auth Index in its own table keeps
    /// <see cref="ITpmCommandInput.IsFirstHandleAuthorized"/> at the interface's default <see langword="true"/>,
    /// the opposite declaration from every no-authorization command's row above — spot-checked across five
    /// otherwise-unrelated authorized commands so the default is not merely unset by omission.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 5</see>.
    /// </summary>
    [TestMethod]
    public void FiveAuthorizedCommandsKeepTheDefaultFirstHandleAuthorizedDeclaration()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CreateInput createInput = CreateInput.ForEccSigningChild(
            0x8000_0000, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
        Assert.IsTrue(((ITpmCommandInput)createInput).IsFirstHandleAuthorized, "TPM2_Create()'s parentHandle carries an Auth Index (Table 18).");

        using SignInput signInput = SignInput.ForEcdsa(TpmiDhObject.FromValue(0x8000_0000), [0x01], TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        Assert.IsTrue(((ITpmCommandInput)signInput).IsFirstHandleAuthorized, "TPM2_Sign()'s keyHandle carries an Auth Index (Table 122).");

        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(0x8000_0000), TpmiDhObject.FromValue(0x8000_0001), [], TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        Assert.IsTrue(((ITpmCommandInput)certifyInput).IsFirstHandleAuthorized, "TPM2_Certify()'s objectHandle (the FIRST handle) carries an Auth Index (Table 97).");

        using Tpm2bMaxNvBuffer nvWriteData = Tpm2bMaxNvBuffer.Create([], pool);
        var nvWriteInput = new NvWriteInput(0x8100_0000, 0x0100_0000, nvWriteData, 0);
        Assert.IsTrue(((ITpmCommandInput)nvWriteInput).IsFirstHandleAuthorized, "TPM2_NV_Write()'s authHandle (the FIRST handle) carries an Auth Index (Table 253).");

        using ActivateCredentialInput activateCredentialInput = ActivateCredentialInput.Create(
            TpmiDhObject.FromValue(0x8000_0000), TpmiDhObject.FromValue(0x8000_0001), [], [], pool);
        Assert.IsTrue(((ITpmCommandInput)activateCredentialInput).IsFirstHandleAuthorized, "TPM2_ActivateCredential()'s activateHandle (the FIRST handle) carries an Auth Index (Table 26).");
    }

    /// <summary>
    /// Builds a minimal host input for <paramref name="commandCode"/>, disposed by the caller through the
    /// <see langword="using"/> declarations inside this switch — content is irrelevant to the check, since
    /// <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> is a fixed per-command declaration, not
    /// derived from any instance state — together with the command's registered response codec (or
    /// <see langword="null"/> when none is registered) and the handle count the command's own Part 3 table
    /// declares for it.
    /// </summary>
    /// <param name="commandCode">The command under test.</param>
    /// <param name="pool">The memory pool a pooled input's owned carriers are rented from.</param>
    /// <returns>The host input's own flag, the registered codec (or <see langword="null"/>), the expected handle count, and (for a one-handle command) whether the host declares its handle authorized.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="commandCode"/> has no arm here — a programming error, since every row in <see cref="TpmNoAuthSessionShape.Entries"/> needs one.</exception>
    private static (bool FirstCommandParameterIsEncryptable, TpmResponseCodec? Codec, byte HandleCount, bool IsFirstHandleAuthorized) BuildProbe(TpmCcConstants commandCode, BaseMemoryPool pool)
    {
        switch(commandCode)
        {
            case TpmCcConstants.TPM_CC_GetRandom:
            {
                return (((ITpmCommandInput)new GetRandomInput(8)).FirstCommandParameterIsEncryptable, TpmResponseCodec.GetRandom, 0, true);
            }

            case TpmCcConstants.TPM_CC_StirRandom:
            {
                return (new StirRandomInput(Tpm2bSensitiveData.Empty).FirstCommandParameterIsEncryptable, TpmResponseCodec.StirRandom, 0, true);
            }

            case TpmCcConstants.TPM_CC_TestParms:
            {
                TpmtPublicParms parms = TpmtPublicParms.Create(
                    TpmAlgIdConstants.TPM_ALG_ECC,
                    TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))));

                return (new TestParmsInput(parms).FirstCommandParameterIsEncryptable, TpmResponseCodec.TestParms, 0, true);
            }

            case TpmCcConstants.TPM_CC_ReadClock:
            {
                return (((ITpmCommandInput)new ReadClockInput()).FirstCommandParameterIsEncryptable, TpmResponseCodec.ReadClock, 0, true);
            }

            case TpmCcConstants.TPM_CC_Shutdown:
            {
                return (((ITpmCommandInput)new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR)).FirstCommandParameterIsEncryptable, null, 0, true);
            }

            case TpmCcConstants.TPM_CC_SelfTest:
            {
                return (((ITpmCommandInput)new SelfTestInput(true)).FirstCommandParameterIsEncryptable, null, 0, true);
            }

            case TpmCcConstants.TPM_CC_GetTestResult:
            {
                return (((ITpmCommandInput)new GetTestResultInput()).FirstCommandParameterIsEncryptable, TpmResponseCodec.GetTestResult, 0, true);
            }

            case TpmCcConstants.TPM_CC_GetCapability:
            {
                return (((ITpmCommandInput)GetCapabilityInput.ForFixedProperties()).FirstCommandParameterIsEncryptable, TpmResponseCodec.GetCapability, 0, true);
            }

            case TpmCcConstants.TPM_CC_PCR_Read:
            {
                using PcrReadInput input = PcrReadInput.ForBootPcrs(TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                return (((ITpmCommandInput)input).FirstCommandParameterIsEncryptable, TpmResponseCodec.PcrRead, 0, true);
            }

            case TpmCcConstants.TPM_CC_ReadPublic:
            {
                ITpmCommandInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(0x80000000));

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.ReadPublic, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_NV_ReadPublic:
            {
                ITpmCommandInput input = new NvReadPublicInput(0x01000000);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.NvReadPublic, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_Hash:
            {
                using HashInput input = HashInput.Create([0x01], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Owner, pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.Hash, 0, true);
            }

            case TpmCcConstants.TPM_CC_HashSequenceStart:
            {
                using HashSequenceStartInput input = HashSequenceStartInput.CreateFromPassword(string.Empty, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.HashSequenceStart, 0, true);
            }

            case TpmCcConstants.TPM_CC_SignSequenceStart:
            {
                using SignSequenceStartInput input = SignSequenceStartInput.CreateFromPassword(TpmiDhObject.FromValue(0x80000000), string.Empty, pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.SignSequenceStart, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_VerifySequenceStart:
            {
                using VerifySequenceStartInput input = VerifySequenceStartInput.CreateFromPassword(TpmiDhObject.FromValue(0x80000000), string.Empty, pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.VerifySequenceStart, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_VerifySignature:
            {
                using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(TpmiDhObject.FromValue(0x80000000), [0x01], [0x01], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.VerifySignature, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_VerifyDigestSignature:
            {
                using VerifyDigestSignatureInput input = VerifyDigestSignatureInput.ForEcdsa(TpmiDhObject.FromValue(0x80000000), [0x01], [0x01], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.VerifyDigestSignature, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_Encapsulate:
            {
                ITpmCommandInput input = EncapsulateInput.ForHandle(TpmiDhObject.FromValue(0x80000000));

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.Encapsulate, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_MakeCredential:
            {
                using MakeCredentialInput input = MakeCredentialInput.Create(TpmiDhObject.FromValue(0x80000000), [0x01], [0x01], pool);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.MakeCredential, 1, input.IsFirstHandleAuthorized);
            }

            case TpmCcConstants.TPM_CC_LoadExternal:
            {
                using Tpm2bPublic inPublic = BuildLoadExternalProbePublic(pool);
                using LoadExternalInput input = LoadExternalInput.PublicOnly(inPublic, TpmiRhHierarchy.Owner);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.LoadExternal, 0, true);
            }

            case TpmCcConstants.TPM_CC_RSA_Encrypt:
            {
                ITpmCommandInput input = new RsaEncryptInput(TpmiDhObject.FromValue(0x80000000), Tpm2bPublicKeyRsa.Empty, default, Tpm2bData.Empty);

                return (input.FirstCommandParameterIsEncryptable, TpmResponseCodec.RsaEncrypt, 1, input.IsFirstHandleAuthorized);
            }

            default:
            {
                throw new ArgumentOutOfRangeException(nameof(commandCode), commandCode, "No probe is defined for this command.");
            }
        }
    }

    /// <summary>Builds a minimal ECC P-256 ECDSA-SHA-256 signing public area for the <see cref="TpmCcConstants.TPM_CC_LoadExternal"/> probe.</summary>
    /// <param name="pool">The memory pool the point carrier is rented from.</param>
    /// <returns>The public area; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point carrier transfers to the returned public area, which its caller disposes.")]
    private static Tpm2bPublic BuildLoadExternalProbePublic(BaseMemoryPool pool) =>
        Tpm2bPublic.CreateEccSigningKey(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA,
            TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            TpmsEccPoint.Create([0x01], [0x01], pool), pool);
}
