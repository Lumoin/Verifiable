using System.Buffers.Binary;
using CsCheck;
using Verifiable.Fido2;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="AuthenticatorDataReader"/>: the truncation and
/// out-of-range-length invariants that must hold for every buffer, not just the hand-picked vectors in
/// <see cref="AuthenticatorDataReaderTests"/>, plus the round-trip invariant for the fixed-size prefix fields.
/// </summary>
[TestClass]
internal sealed class AuthenticatorDataReaderPropertyTests
{
    /// <summary>The section 6.1 minimum total length of <c>authData</c>.</summary>
    private const int MinimumLength = 37;

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Masks off the attested-credential-data (bit 6) and extension-data (bit 7) flags, leaving only the bits a
    /// minimum-length layout can legally carry.
    /// </summary>
    private const byte NeitherAttestedNorExtensionMask = 0x3F;

    /// <summary>Generates a (flags, signCount) pair whose flags never set the AT or ED bit.</summary>
    private static Gen<(byte Flags, uint SignCount)> GenFlagsAndSignCount { get; } =
        from flags in Gen.Byte
        from signCountHigh in Gen.Int[0, ushort.MaxValue]
        from signCountLow in Gen.Int[0, ushort.MaxValue]
        select ((byte)(flags & NeitherAttestedNorExtensionMask), ((uint)signCountHigh << 16) | (uint)signCountLow);


    /// <summary>
    /// Any buffer shorter than the section 6.1 minimum of 37 bytes is rejected with
    /// <see cref="Fido2FormatException"/>, regardless of its content.
    /// </summary>
    [TestMethod]
    public void AnyBufferShorterThanTheMinimumLengthIsRejected()
    {
        Gen.Byte.Array[0, MinimumLength - 1].Sample(bytes =>
        {
            try
            {
                AuthenticatorDataReader.Read(bytes, TestCredentialPublicKeyReader, BaseMemoryPool.Shared).Dispose();

                return false; //A short buffer must never parse.
            }
            catch(Fido2FormatException)
            {
                return true;
            }
        });
    }


    /// <summary>
    /// A <c>credentialIdLength</c> anywhere in [1024, 65535] — above the section 7.1 step 25 bound of 1023 — is
    /// rejected with <see cref="Fido2FormatException"/>, even though the rest of the attested-credential-data
    /// header is otherwise well-formed.
    /// </summary>
    [TestMethod]
    public void AnyCredentialIdLengthAboveTheBoundIsRejected()
    {
        Gen.Int[1024, 65535].Sample(candidateLength =>
        {
            byte[] lengthBytes = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(lengthBytes, (ushort)candidateLength);
            byte[] attestedCredentialData = Concat(new byte[16], lengthBytes);
            byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), flags: AuthenticatorDataFlags.AttestedCredentialDataIncludedBit, signCount: 0, attestedCredentialData: attestedCredentialData);

            try
            {
                AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared).Dispose();

                return false; //An out-of-range length must never parse.
            }
            catch(Fido2FormatException)
            {
                return true;
            }
        });
    }


    /// <summary>
    /// For any flags byte with the attested-credential-data and extension-data bits clear and any 32-bit sign
    /// count, reading the assembled buffer reproduces both fields exactly.
    /// </summary>
    [TestMethod]
    public void FlagsAndSignCountRoundTripWhenNeitherAttestedNorExtensionBitIsSet()
    {
        GenFlagsAndSignCount.Sample(sample =>
        {
            byte[] authenticatorData = BuildAuthenticatorData(CreateRpIdHash(), sample.Flags, sample.SignCount);

            using AuthenticatorData parsed = AuthenticatorDataReader.Read(authenticatorData, TestCredentialPublicKeyReader, BaseMemoryPool.Shared);

            return parsed.Flags.Value == sample.Flags && parsed.SignCount == sample.SignCount;
        });
    }
}
