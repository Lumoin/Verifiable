using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_ObjectChangeAuth()</c>'s input against its published table (TPM 2.0 Library
/// Part 3, clause 12.8, Table 32) — two handles in the handle area and one <c>TPM2B_AUTH</c> parameter — plus
/// its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, and its response's parse (Table 33: one
/// <c>TPM2B_PRIVATE</c>).
/// </summary>
[TestClass]
internal sealed class ObjectChangeAuthInputFramingTests
{
    /// <summary>The <c>objectHandle</c> the frames carry.</summary>
    private static TpmiDhObject ObjectHandle { get; } = TpmiDhObject.FromValue(0x8000_0001);

    /// <summary>The <c>parentHandle</c> the frames carry.</summary>
    private static TpmiDhObject ParentHandle { get; } = TpmiDhObject.FromValue(0x8000_0002);

    /// <summary>
    /// Table 32's handle area is <c>@objectHandle</c> then <c>parentHandle</c>, each a four-octet
    /// <c>TPMI_DH_OBJECT</c>, and its parameter area is <c>newAuth</c> alone — a <c>TPM2B_AUTH</c>: a two-octet
    /// size then the value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32; Part 2, clause 10.3.5, Table 93</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthInputFramesTwoHandlesAndTheNewAuthByteExactlyPerTable32()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bAuth newAuth = Tpm2bAuth.Create([0x0A, 0x0B, 0x0C], pool);
        var input = new ObjectChangeAuthInput(ObjectHandle, ParentHandle, newAuth);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x02], [0x00, 0x03, 0x0A, 0x0B, 0x0C]);
    }

    /// <summary>
    /// An empty <c>newAuth</c> — admitted, since a <c>TPM2B_AUTH</c> "may be a zero-length string" — frames as the
    /// two-octet size alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32; Part 2, clause 10.3.5, Table 93</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthInputFramesAnEmptyNewAuthAsItsSizeAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bAuth newAuth = Tpm2bAuth.CreateEmpty(pool);
        var input = new ObjectChangeAuthInput(ObjectHandle, ParentHandle, newAuth);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x02], [0x00, 0x00]);
    }

    /// <summary>
    /// Table 32's <c>commandCode</c> row is <c>TPM_CC_ObjectChangeAuth</c>, whose assigned value in Part 2's
    /// listing of command codes is 0x00000150; the row carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthCommandCodeEqualsTheRawValueListedInTable12()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bAuth newAuth = Tpm2bAuth.CreateEmpty(pool);
        var input = new ObjectChangeAuthInput(ObjectHandle, ParentHandle, newAuth);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ObjectChangeAuth, input.CommandCode);
        Assert.AreEqual(0x00000150u, (uint)input.CommandCode, "TPM_CC_ObjectChangeAuth must equal Table 12's raw value 0x00000150.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>newAuth</c> is a <c>TPM2B_AUTH</c>, so the command's first parameter is encryptable; neither handle
    /// names a sequence object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthInputMarksItsFirstParameterEncryptableAndHasNoSequenceHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bAuth newAuth = Tpm2bAuth.CreateEmpty(pool);
        ITpmCommandInput input = new ObjectChangeAuthInput(ObjectHandle, ParentHandle, newAuth);

        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "newAuth is a TPM2B_AUTH, a sized first parameter a decrypt session may protect.");
        Assert.IsFalse(input.HandleIsSequence(0), "objectHandle names an object with a real Name.");
        Assert.IsFalse(input.HandleIsSequence(1), "parentHandle names an object with a real Name.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_ObjectChangeAuth</c> takes the two handles
    /// of Table 32, is not <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the
    /// low 16 bits of 0x00000150.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 12.8, Tables 32 and 33</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthCommandAttributesCarryTwoHandlesAndNoResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_ObjectChangeAuth.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES, "Table 32 lists objectHandle and parentHandle.");
        Assert.IsFalse(attributes.R_HANDLE, "Table 33 returns no handle.");
        Assert.IsFalse(attributes.NV, "TPM2_ObjectChangeAuth carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0150, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 33's shape: no output handle, a parameter area (<c>outPrivate</c>),
    /// and — since <c>outPrivate</c> is a sized buffer — a response an encrypt session may protect (Part 1,
    /// clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 33; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthCodecDeclaresNoHandleAndAnEncryptableOutPrivate()
    {
        TpmResponseCodec codec = TpmResponseCodec.ObjectChangeAuth;

        Assert.AreEqual(0, codec.OutHandleCount, "Table 33 returns no handle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 33 returns outPrivate.");
        Assert.IsTrue(codec.ResponseFirstParameterIsEncryptable, "outPrivate is a TPM2B_PRIVATE, a sized first response parameter an encrypt session may protect.");
    }

    /// <summary>
    /// Table 33's response parses to the <c>TPM2B_PRIVATE</c> the wire carried, octet for octet.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 33; Part 2, clause 12.3.7, Table 243</see>.
    /// </summary>
    [TestMethod]
    public void ObjectChangeAuthResponseParsesTheOutPrivate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] parameters = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        var reader = new TpmReader(parameters);

        using ObjectChangeAuthResponse response = ObjectChangeAuthResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the TPM2B_PRIVATE.");
        Assert.AreEqual(4, response.OutPrivate.Length, "outPrivate carries the four wire octets.");
        ReadOnlySpan<byte> expectedOctets = [0xDE, 0xAD, 0xBE, 0xEF];
        Assert.IsTrue(response.OutPrivate.Span.SequenceEqual(expectedOctets), "outPrivate's octets are the wire's.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle area and parameter area into freshly-sized buffers and asserts
    /// each reproduces its hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for both together.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ObjectChangeAuthInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must account for the handle area and the parameter area together.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles, "The handle area must reproduce the hand-computed octets exactly.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
