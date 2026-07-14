using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Covers the <c>encodedYCompressionSign:true</c> half of the <c>publicKey.yCompressionSign</c>
/// round trip that <see cref="Fido2CredentialRecordJsonTests"/>'s existing round-trip tests leave
/// untested: both <c>Ec2RecordRoundTripsEveryMember</c> and <c>RsaRecordRoundTripsEveryMember</c>
/// exercise only the <see langword="false"/>/absent branch of
/// <c>Fido2CredentialRecordJsonWriter.WriteOptionalBool</c> and
/// <c>Fido2CredentialRecordJsonReader.ReadRequiredBoolean</c>, so a mutation hard-coding either
/// method to always write/return <see langword="false"/> would still pass every existing assertion.
/// </summary>
[TestClass]
internal sealed class Fido2CredentialRecordJsonYCompressionSignTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A record whose EC2 public key encodes <c>y</c> in compressed (sign-bit) form —
    /// <c>encodedYCompressionSign: true</c>, no uncompressed <c>y</c> coordinate — round-trips the flag
    /// byte-for-byte, and the written document carries the member as the JSON literal <c>true</c>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the CredentialId created inline transfers to the Fido2CredentialRecord constructed on the same statement, which the 'using' declaration disposes.")]
    public void Ec2RecordWithCompressedYSignRoundTripsToTrue()
    {
        byte[] idBytes = [1, 2, 3, 4];
        byte[] xBytes = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        using Fido2CredentialRecord original = new(
            WellKnownPublicKeyCredentialTypes.PublicKey,
            CredentialId.Create(idBytes, BaseMemoryPool.Shared),
            new CoseKey(CoseKeyTypes.Ec2, alg: -7, curve: CoseKeyCurves.P256, x: xBytes, y: null, encodedYCompressionSign: true),
            SignCount: 7,
            UvInitialized: true,
            Transports: ["usb"],
            BackupEligible: true,
            BackupState: true);

        ArrayBufferWriter<byte> buffer = new();
        Fido2CredentialRecordJsonWriter.Write(original, buffer);
        string json = Encoding.UTF8.GetString(buffer.WrittenSpan);

        Assert.Contains("\"yCompressionSign\":true", json, StringComparison.Ordinal);

        using Fido2CredentialRecord roundTripped = Fido2CredentialRecordJsonReader.Read(buffer.WrittenMemory, BaseMemoryPool.Shared);

        Assert.AreEqual(original, roundTripped);
        Assert.IsTrue(roundTripped.PublicKey.EncodedYCompressionSign);
    }
}
