using System.Buffers.Binary;
using Verifiable.Fido2;
using Verifiable.JCose;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="AuthenticatorDataReader"/> and <see cref="AuthenticatorDataFlags"/>: the fail-closed
/// binary parse of the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section 6.1</see> authenticator data
/// layout, spanning the minimum-length layout, the attested-credential-data and extensions structures, and every
/// malformed-input rejection path.
/// </summary>
[TestClass]
internal sealed class AuthenticatorDataReaderTests
{
    /// <summary>The credential-ID length bound per section 7.1 step 25 (the largest permitted value).</summary>
    private const int MaximumCredentialIdLength = 1023;

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The 37-byte minimum layout (no attested credential data, no extensions) parses: the RP ID hash, flags, and
    /// big-endian sign count are recovered exactly, and both optional trailing structures are absent.
    /// </summary>
    [TestMethod]
    public void MinimumThirtySevenByteLayoutParsesWithoutAttestedCredentialDataOrExtensions()
    {
        byte[] rpIdHash = CreateRpIdHash();
        byte[] authenticatorData = BuildAuthenticatorData(rpIdHash, flags: AuthenticatorDataFlags.None, signCount: 0x01020304);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsTrue(parsed.RpIdHash.AsReadOnlySpan().SequenceEqual(rpIdHash));
        Assert.AreEqual((byte)0x00, parsed.Flags.Value);
        Assert.AreEqual(16909060u, parsed.SignCount);
        Assert.IsNull(parsed.AttestedCredentialData);
        Assert.AreEqual(0, parsed.Extensions.Length);
    }


    /// <summary>
    /// A layout with the attested-credential-data flag set parses the AAGUID, credential ID, and credential
    /// public key, with no extensions present.
    /// </summary>
    [TestMethod]
    public void AttestedCredentialDataFlagParsesAaguidCredentialIdAndPublicKey()
    {
        byte[] aaguidBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        Guid expectedAaguid = new(aaguidBytes, bigEndian: true);
        byte[] credentialId = [0x10, 0x20, 0x30, 0x40];
        byte[] attestedCredentialData = BuildAttestedCredentialData(expectedAaguid, credentialId, EncodeP256CoseKey());
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 1,
            attestedCredentialData: attestedCredentialData);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.AreEqual(expectedAaguid, parsed.AttestedCredentialData.Aaguid);
        Assert.IsTrue(parsed.AttestedCredentialData.CredentialId.AsReadOnlySpan().SequenceEqual(credentialId));
        Assert.AreEqual(CoseKeyTypes.Ec2, parsed.AttestedCredentialData.CredentialPublicKey.Kty);
        Assert.AreEqual(CoseKeyCurves.P256, parsed.AttestedCredentialData.CredentialPublicKey.Curve);
        Assert.AreEqual(0, parsed.Extensions.Length);
    }


    /// <summary>
    /// A layout with both the attested-credential-data and extension-data flags set parses the attested
    /// credential data and recovers the trailing extensions bytes verbatim.
    /// </summary>
    [TestMethod]
    public void AttestedCredentialDataAndExtensionsBothParse()
    {
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), [0xAA, 0xBB], EncodeP256CoseKey());
        byte[] extensions = [0xA0]; //An empty CBOR map.
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: (byte)(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit | AuthenticatorDataFlags.ExtensionDataIncludedBit),
            signCount: 1,
            attestedCredentialData: attestedCredentialData,
            extensions: extensions);

        using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

        Assert.IsNotNull(parsed.AttestedCredentialData);
        Assert.IsTrue(parsed.Extensions.Span.SequenceEqual(extensions));
    }


    /// <summary>
    /// Each flags-table bit (section 6.1) reflects independently in <see cref="AuthenticatorDataFlags"/>: setting
    /// exactly one bit yields exactly one <see langword="true"/> boolean, and the zero byte yields every
    /// boolean <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public void EachFlagsBitIsIndependentlyReflected()
    {
        var none = new AuthenticatorDataFlags(AuthenticatorDataFlags.None);
        Assert.IsFalse(none.UserPresent);
        Assert.IsFalse(none.UserVerified);
        Assert.IsFalse(none.BackupEligible);
        Assert.IsFalse(none.BackupState);
        Assert.IsFalse(none.AttestedCredentialDataIncluded);
        Assert.IsFalse(none.ExtensionDataIncluded);

        var userPresent = new AuthenticatorDataFlags(AuthenticatorDataFlags.UserPresentBit);
        Assert.IsTrue(userPresent.UserPresent);
        Assert.IsFalse(userPresent.UserVerified);

        var userVerified = new AuthenticatorDataFlags(AuthenticatorDataFlags.UserVerifiedBit);
        Assert.IsTrue(userVerified.UserVerified);
        Assert.IsFalse(userVerified.UserPresent);

        var backupEligible = new AuthenticatorDataFlags(AuthenticatorDataFlags.BackupEligibleBit);
        Assert.IsTrue(backupEligible.BackupEligible);
        Assert.IsFalse(backupEligible.BackupState);

        var backupState = new AuthenticatorDataFlags(AuthenticatorDataFlags.BackupStateBit);
        Assert.IsTrue(backupState.BackupState);
        Assert.IsFalse(backupState.BackupEligible);

        var attestedCredentialDataIncluded = new AuthenticatorDataFlags(AuthenticatorDataFlags.AttestedCredentialDataIncludedBit);
        Assert.IsTrue(attestedCredentialDataIncluded.AttestedCredentialDataIncluded);
        Assert.IsFalse(attestedCredentialDataIncluded.ExtensionDataIncluded);

        var extensionDataIncluded = new AuthenticatorDataFlags(AuthenticatorDataFlags.ExtensionDataIncludedBit);
        Assert.IsTrue(extensionDataIncluded.ExtensionDataIncluded);
        Assert.IsFalse(extensionDataIncluded.AttestedCredentialDataIncluded);
    }


    /// <summary>A buffer of length 36 is one byte short of the section 6.1 minimum and is rejected.</summary>
    [TestMethod]
    public void LengthOneShortOfMinimumIsRejected()
    {
        byte[] authenticatorData = new byte[36];

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// The attested-credential-data flag is set but only 17 bytes follow the 37-byte prefix — one short of the
    /// 18 bytes (aaguid 16 + credentialIdLength 2) the layout requires before it can even begin.
    /// </summary>
    [TestMethod]
    public void AttestedCredentialDataFlagSetWithOnlySeventeenTrailingBytesIsRejected()
    {
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: new byte[17]);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A <c>credentialIdLength</c> of 1024 exceeds the section 7.1 step 25 bound of 1023 and is rejected, with the
    /// rejection message naming either the bound or the offending length.
    /// </summary>
    [TestMethod]
    public void CredentialIdLengthOneOverTheBoundIsRejected()
    {
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), new byte[MaximumCredentialIdLength + 1], EncodeP256CoseKey());
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: attestedCredentialData);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));

        Assert.IsTrue(
            exception.Message.Contains("1023", StringComparison.Ordinal) || exception.Message.Contains("1024", StringComparison.Ordinal),
            $"The message must name the bound or the offending length; was: {exception.Message}");
    }


    /// <summary>
    /// A <c>credentialIdLength</c> that claims more bytes than remain in the buffer is rejected as a
    /// bounds violation rather than an out-of-range slice.
    /// </summary>
    [TestMethod]
    public void CredentialIdLengthExceedingRemainingBytesIsRejected()
    {
        byte[] credentialIdLengthBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(credentialIdLengthBytes, 50);
        byte[] attestedCredentialData = Concat(new byte[16], credentialIdLengthBytes, new byte[10]);
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: attestedCredentialData);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A trailing byte after the 37-byte prefix with both the attested-credential-data and extension-data flags
    /// clear is rejected: fail-closed on any unconsumed byte.
    /// </summary>
    [TestMethod]
    public void TrailingByteWithAttestedCredentialDataAndExtensionFlagsClearIsRejected()
    {
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.None,
            signCount: 0,
            attestedCredentialData: [0xFF]);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// The extension-data flag is set but zero bytes remain for it: the extensions slice MUST be non-empty when
    /// the flag is set.
    /// </summary>
    [TestMethod]
    public void ExtensionFlagSetWithZeroRemainingBytesIsRejected()
    {
        byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.ExtensionDataIncludedBit, signCount: 0);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A supplied <see cref="ReadCredentialPublicKeyDelegate"/> that reports zero bytes consumed is rejected: the
    /// reader validates <c>0 &lt; BytesConsumed</c>.
    /// </summary>
    [TestMethod]
    public void DelegateReportingZeroBytesConsumedIsRejected()
    {
        byte[] attestedCredentialData = Concat(new byte[16], LengthBytes(2), new byte[] { 0x01, 0x02 }, new byte[5]);
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: attestedCredentialData);

        ReadCredentialPublicKeyDelegate stubReader = source => new CredentialPublicKeyReadResult(new CoseKey(CoseKeyTypes.Ec2), 0, []);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, stubReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A supplied <see cref="ReadCredentialPublicKeyDelegate"/> that reports more bytes consumed than were
    /// available is rejected: the reader validates <c>BytesConsumed &lt;= remaining</c>.
    /// </summary>
    [TestMethod]
    public void DelegateReportingMoreBytesConsumedThanRemainingIsRejected()
    {
        byte[] attestedCredentialData = Concat(new byte[16], LengthBytes(2), new byte[] { 0x01, 0x02 }, new byte[5]);
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: attestedCredentialData);

        ReadCredentialPublicKeyDelegate stubReader = source => new CredentialPublicKeyReadResult(new CoseKey(CoseKeyTypes.Ec2), source.Length + 1, []);

        Assert.ThrowsExactly<Fido2FormatException>(() => AuthenticatorDataReader.Read(authenticatorData, stubReader, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A <see langword="null"/> <see cref="ReadCredentialPublicKeyDelegate"/> is rejected with
    /// <see cref="ArgumentNullException"/> for a buffer whose attested-credential-data flag is set and which is
    /// otherwise a well-formed layout.
    /// </summary>
    [TestMethod]
    public void NullDelegateWithAttestedCredentialDataFlagSetThrowsArgumentNullException()
    {
        byte[] attestedCredentialData = BuildAttestedCredentialData(Guid.NewGuid(), [0x01, 0x02], EncodeP256CoseKey());
        byte[] authenticatorData = BuildAuthenticatorData(
            CreateRpIdHash(),
            flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit,
            signCount: 0,
            attestedCredentialData: attestedCredentialData);

        Assert.ThrowsExactly<ArgumentNullException>(() => AuthenticatorDataReader.Read(authenticatorData, null!, BaseMemoryPool.Shared));
    }


    /// <summary>Encodes <paramref name="value"/> as a two-byte big-endian <c>credentialIdLength</c> field.</summary>
    /// <param name="value">The credential ID length to encode.</param>
    /// <returns>The two-byte big-endian encoding.</returns>
    private static byte[] LengthBytes(ushort value)
    {
        byte[] bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);

        return bytes;
    }
}
