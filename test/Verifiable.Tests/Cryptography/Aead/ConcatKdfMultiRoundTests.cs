using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for the multi-round single-step Concat KDF of
/// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf">NIST SP 800-56A §5.8.1.1</see>
/// as implemented by <see cref="ConcatKdf.Derive(ReadOnlySpan{byte}, string, ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, ReadOnlySpan{byte}, Tag, MemoryPool{byte})"/>.
/// The reference oracle recomputes the round hashes with
/// <see cref="System.Security.Cryptography.SHA256"/> independently, so any perturbation of
/// the ≤256-bit single-round path or the multi-round concatenation is caught byte for byte.
/// The Appendix C case pins the derivation against the
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#appendix-C">RFC 7518 Appendix C</see> vector.
/// </summary>
[TestClass]
internal sealed class ConcatKdfMultiRoundTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //RFC 7518 Appendix C: the ECDH-ES key agreement output Z (32 octets), the AlgorithmID
    //"A128GCM", empty PartyUInfo/PartyVInfo equivalents replaced here by "Alice"/"Bob", and
    //the 128-bit derived key whose base64url encoding the appendix prints.
    private const string AppendixCZ =
        "9E56D91D817135D372834283BF84269CFB316EA3DA806A48F6DAA7798CFE90C4";

    private const string AppendixCAlgorithmId = "A128GCM";
    private const string AppendixCApu = "Alice";
    private const string AppendixCApv = "Bob";
    private const string AppendixCDerivedKeyBase64Url = "VqqN6vgjbSBcIijNcacQGg";


    [TestMethod]
    [DataRow(128)]
    [DataRow(256)]
    public void Derive_SingleRound_ByteIdenticalToReference(int keydataLenBits)
    {
        byte[] z = Convert.FromHexString(AppendixCZ);
        const string algorithmId = "A128GCM";

        using ContentEncryptionKey derived = ConcatKdf.Derive(
            z,
            algorithmId,
            partyUInfo: [],
            partyVInfo: [],
            keydataLenBits,
            committedTag: [],
            CryptoTags.AesGcmCek,
            Pool);

        byte[] expected = ReferenceConcatKdf(z, algorithmId, [], [], keydataLenBits, committedTag: []);

        using SymmetricKeyMemory derivedKey = derived.UseKey();
        Assert.HasCount(keydataLenBits / 8, derivedKey.AsReadOnlySpan(),
            "The single-round derivation must produce exactly keydataLenBits / 8 octets.");
        Assert.AreEqual(Convert.ToHexString(expected), Convert.ToHexString(derivedKey.AsReadOnlySpan()),
            "The ≤256-bit single-round path must remain byte identical to the reference SHA-256 oracle.");
    }


    [TestMethod]
    public void Derive_512Bit_RunsTwoRoundsAndConcatenates()
    {
        byte[] z = Convert.FromHexString(AppendixCZ);
        const string algorithmId = "A256CBC-HS512";

        using ContentEncryptionKey derived = ConcatKdf.Derive(
            z,
            algorithmId,
            partyUInfo: [],
            partyVInfo: [],
            keydataLenBits: 512,
            committedTag: [],
            CryptoTags.AesCbcHmacCek,
            Pool);

        byte[] expected = ReferenceConcatKdf(z, algorithmId, [], [], keydataLenBits: 512, committedTag: []);

        using SymmetricKeyMemory derivedKey = derived.UseKey();
        Assert.HasCount(64, derivedKey.AsReadOnlySpan(),
            "A 512-bit derivation must produce 64 octets.");
        Assert.AreEqual(Convert.ToHexString(expected), Convert.ToHexString(derivedKey.AsReadOnlySpan()),
            "The 512-bit derivation must equal SHA256(round 1) || SHA256(round 2) of the reference oracle.");
    }


    [TestMethod]
    public void Derive_Rfc7518AppendixC_EcdhEsDirectA128Gcm()
    {
        byte[] z = Convert.FromHexString(AppendixCZ);

        using ContentEncryptionKey derived = ConcatKdf.Derive(
            z,
            AppendixCAlgorithmId,
            Encoding.UTF8.GetBytes(AppendixCApu),
            Encoding.UTF8.GetBytes(AppendixCApv),
            keydataLenBits: 128,
            committedTag: [],
            CryptoTags.AesGcmCek,
            Pool);

        using SymmetricKeyMemory derivedKey = derived.UseKey();
        Assert.AreEqual(AppendixCDerivedKeyBase64Url, TestSetup.Base64UrlEncoder(derivedKey.AsReadOnlySpan()),
            "The Appendix C ECDH-ES Direct A128GCM derivation must reproduce the vector derived key.");
    }


    [TestMethod]
    [DataRow(0)]
    [DataRow(-8)]
    [DataRow(7)]
    public void Derive_RejectsNonPositiveOrNonByteMultiple(int keydataLenBits)
    {
        byte[] z = Convert.FromHexString(AppendixCZ);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            using ContentEncryptionKey _ = ConcatKdf.Derive(
                z,
                "A128GCM",
                partyUInfo: [],
                partyVInfo: [],
                keydataLenBits,
                committedTag: [],
                CryptoTags.AesGcmCek,
                Pool);
        });
    }


    //An independent NIST SP 800-56A §5.8.1.1 oracle: for reps = ceil(keydatalen / hashlen)
    //rounds, hash counter || Z || OtherInfo with the counter running 1..reps as a 32-bit
    //big-endian integer, concatenate the round outputs, and truncate to keydatalen. OtherInfo
    //is BE32(len(algId)) || algId || BE32(len(apu)) || apu || BE32(len(apv)) || apv ||
    //BE32(keydataLenBits), with a length-prefixed cctag appended when committedTag is non-empty.
    private static byte[] ReferenceConcatKdf(
        ReadOnlySpan<byte> sharedSecret,
        string algorithmId,
        ReadOnlySpan<byte> partyUInfo,
        ReadOnlySpan<byte> partyVInfo,
        int keydataLenBits,
        ReadOnlySpan<byte> committedTag)
    {
        byte[] algId = Encoding.ASCII.GetBytes(algorithmId);

        int otherInfoLength =
            4 + algId.Length
            + 4 + partyUInfo.Length
            + 4 + partyVInfo.Length
            + 4
            + (committedTag.IsEmpty ? 0 : 4 + committedTag.Length);

        byte[] otherInfo = new byte[otherInfoLength];
        Span<byte> oi = otherInfo;
        int offset = 0;

        BinaryPrimitives.WriteInt32BigEndian(oi[offset..], algId.Length);
        offset += 4;
        algId.CopyTo(oi[offset..]);
        offset += algId.Length;

        BinaryPrimitives.WriteInt32BigEndian(oi[offset..], partyUInfo.Length);
        offset += 4;
        partyUInfo.CopyTo(oi[offset..]);
        offset += partyUInfo.Length;

        BinaryPrimitives.WriteInt32BigEndian(oi[offset..], partyVInfo.Length);
        offset += 4;
        partyVInfo.CopyTo(oi[offset..]);
        offset += partyVInfo.Length;

        BinaryPrimitives.WriteInt32BigEndian(oi[offset..], keydataLenBits);
        offset += 4;

        if(!committedTag.IsEmpty)
        {
            BinaryPrimitives.WriteInt32BigEndian(oi[offset..], committedTag.Length);
            offset += 4;
            committedTag.CopyTo(oi[offset..]);
        }

        int outputByteLength = keydataLenBits / 8;
        int reps = (outputByteLength + SHA256.HashSizeInBytes - 1) / SHA256.HashSizeInBytes;

        byte[] roundInput = new byte[4 + sharedSecret.Length + otherInfo.Length];
        sharedSecret.CopyTo(roundInput.AsSpan(4));
        otherInfo.CopyTo(roundInput.AsSpan(4 + sharedSecret.Length));

        byte[] accumulated = new byte[reps * SHA256.HashSizeInBytes];
        for(int counter = 1; counter <= reps; ++counter)
        {
            BinaryPrimitives.WriteInt32BigEndian(roundInput.AsSpan(0, 4), counter);
            byte[] digest = SHA256.HashData(roundInput);
            digest.CopyTo(accumulated.AsSpan((counter - 1) * SHA256.HashSizeInBytes));
        }

        return accumulated[..outputByteLength];
    }
}
