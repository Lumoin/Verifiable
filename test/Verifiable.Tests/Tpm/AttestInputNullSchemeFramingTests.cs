using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the <c>TPMT_SIG_SCHEME inScheme</c> parameter for a <c>TPM_ALG_NULL</c> scheme, across
/// the five attestation inputs whose scheme parameter is framed by selector width, the hashAlg pair present
/// only for a non-NULL selector: <see cref="GetTimeInput"/>, <see cref="QuoteInput"/>, <see cref="CertifyInput"/>,
/// <see cref="CertifyCreationInput"/> and <see cref="NvCertifyInput"/>. Table 182's "null" row carries an empty
/// Type column against selector TPM_ALG_NULL, so Table 183's <c>[scheme]details</c> is absent entirely and the
/// whole <c>TPMT_SIG_SCHEME</c> is the bare two-octet selector — the same rule <see cref="SignInput"/> already
/// framed correctly and <see cref="GetSessionAuditDigestInputFramingTests"/> pins for the sixth sibling.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
/// clause 11.2.1.4, Table 182; clause 11.2.1.5, Table 183</see>.
/// </summary>
[TestClass]
internal sealed class AttestInputNullSchemeFramingTests
{
    /// <summary>
    /// <see cref="GetTimeInput.Create"/> with a NULL scheme frames <c>qualifyingData</c>'s empty TPM2B_DATA
    /// followed by the bare two-octet <c>inScheme</c> selector, with no trailing hashAlg octets — Table 107's
    /// parameter shape (TPM 2.0 Library Part 3, clause 18.7, Table 107) narrowed to the NULL scheme's width.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 18.7, Table 107</see>.
    /// </summary>
    [TestMethod]
    public void GetTimeInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using GetTimeInput input = GetTimeInput.Create(
            TpmRh.TPM_RH_ENDORSEMENT, TpmiDhObject.FromValue(0x8000_0001u), ReadOnlySpan<byte>.Empty,
            TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

        byte[] expectedHandles = [0x40, 0x00, 0x00, 0x0B, 0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x00, //qualifyingData: TPM2B_DATA, size 0.
            0x00, 0x10  //inScheme.scheme = TPM_ALG_NULL, no details follow.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="QuoteInput.Create"/> with a NULL scheme frames the bare two-octet <c>inScheme</c> selector
    /// between <c>qualifyingData</c> and <c>PCRselect</c> — Table 101's parameter shape (TPM 2.0 Library Part 3,
    /// clause 18.4, Table 101) narrowed to the NULL scheme's width.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 18.4, Table 101</see>.
    /// </summary>
    [TestMethod]
    public void QuoteInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using QuoteInput input = QuoteInput.Create(
            TpmiDhObject.FromValue(0x8000_0002u), ReadOnlySpan<byte>.Empty,
            TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, TpmlPcrSelection.Empty, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x02];
        byte[] expectedParameters =
        [
            0x00, 0x00,             //qualifyingData: TPM2B_DATA, size 0.
            0x00, 0x10,             //inScheme.scheme = TPM_ALG_NULL, no details follow.
            0x00, 0x00, 0x00, 0x00  //PCRselect: TPML_PCR_SELECTION, count 0.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="CertifyInput.Create"/> with a NULL scheme frames the bare two-octet <c>inScheme</c> selector as
    /// the parameter area's final entry — Table 97's parameter shape (TPM 2.0 Library Part 3, clause 18.2, Table
    /// 97) narrowed to the NULL scheme's width.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 18.2, Table 97</see>.
    /// </summary>
    [TestMethod]
    public void CertifyInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using CertifyInput input = CertifyInput.Create(
            TpmiDhObject.FromValue(0x8000_0003u), TpmiDhObject.FromValue(0x8000_0004u), ReadOnlySpan<byte>.Empty,
            TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x03, 0x80, 0x00, 0x00, 0x04];
        byte[] expectedParameters =
        [
            0x00, 0x00, //qualifyingData: TPM2B_DATA, size 0.
            0x00, 0x10  //inScheme.scheme = TPM_ALG_NULL, no details follow.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="CertifyCreationInput.Create"/> with a NULL scheme frames the bare two-octet <c>inScheme</c>
    /// selector between <c>creationHash</c> and <c>creationTicket</c> — Table 99's parameter shape (TPM 2.0
    /// Library Part 3, clause 18.3, Table 99) narrowed to the NULL scheme's width.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 18.3, Table 99</see>.
    /// </summary>
    [TestMethod]
    public void CertifyCreationInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] creationHash = [0xAA];
        using CertifyCreationInput input = CertifyCreationInput.Create(
            TpmiDhObject.FromValue(0x8000_0005u), TpmiDhObject.FromValue(0x8000_0006u), ReadOnlySpan<byte>.Empty,
            creationHash, TpmtTkCreation.Null, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x05, 0x80, 0x00, 0x00, 0x06];
        byte[] expectedParameters =
        [
            0x00, 0x00,             //qualifyingData: TPM2B_DATA, size 0.
            0x00, 0x01, 0xAA,       //creationHash: TPM2B_DIGEST, size 1.
            0x00, 0x10,             //inScheme.scheme = TPM_ALG_NULL, no details follow.
            0x80, 0x21,             //creationTicket.tag = TPM_ST_CREATION.
            0x40, 0x00, 0x00, 0x07, //creationTicket.hierarchy = TPM_RH_NULL (the NULL Creation Ticket).
            0x00, 0x00              //creationTicket.digest: empty.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="NvCertifyInput.Create"/> with a NULL scheme frames the bare two-octet <c>inScheme</c> selector
    /// between <c>qualifyingData</c> and <c>size</c>/<c>offset</c> — Table 271's parameter shape (TPM 2.0 Library
    /// Part 3, clause 31.16, Table 271) narrowed to the NULL scheme's width.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2,
    /// clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 31.16, Table 271</see>.
    /// </summary>
    [TestMethod]
    public void NvCertifyInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using NvCertifyInput input = NvCertifyInput.Create(
            TpmiDhObject.FromValue(0x8000_0007u), 0x0150_0001u, 0x0150_0001u, ReadOnlySpan<byte>.Empty,
            TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, size: 4, offset: 0, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x07, 0x01, 0x50, 0x00, 0x01, 0x01, 0x50, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x00, //qualifyingData: TPM2B_DATA, size 0.
            0x00, 0x10, //inScheme.scheme = TPM_ALG_NULL, no details follow.
            0x00, 0x04, //size = 4.
            0x00, 0x00  //offset = 0.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Asserts an input's framed handle and parameter areas against the expected octets, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly both.
    /// </summary>
    /// <param name="input">The input under test.</param>
    /// <param name="expectedHandles">The expected handle-area octets.</param>
    /// <param name="expectedParameters">The expected parameter-area octets.</param>
    private static void AssertFraming(ITpmCommandInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles);

        byte[] parameters = new byte[expectedParameters.Length];
        var paramWriter = new TpmWriter(parameters);
        input.WriteParameters(ref paramWriter);
        Assert.AreEqual(parameters.Length, paramWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters);
    }
}
