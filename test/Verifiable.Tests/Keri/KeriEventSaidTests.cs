using System;
using System.Buffers;
using System.Formats.Cbor;
using System.Text;
using Lumoin.Base;
using Verifiable.BouncyCastle;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Keri;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriEventSaid"/> — recomputing and verifying a key event's Self-Addressing IDentifier
/// over its own serialization bytes, independent of the serialization. Each test mints an event by setting the
/// SAID field (and, for an inception, the equal self-addressing identifier) to the dummy placeholder, computing
/// the SAID over those bytes with an independent digest oracle, and substituting the SAID back; verification then
/// recomputes over the minted bytes and must agree. The JSON and CBOR cases prove the same primitive serves any
/// serialization, since the SAID is embedded as the same characters in each.
/// </summary>
[TestClass]
internal sealed class KeriEventSaidTests
{
    private static readonly string Code = CesrDigestCodes.Blake3Bits256;
    private const string SigningKey = "DBFiIgoCOpJ_zW_OO0GdffhHfEvJWb1HxpDx95bFvufu";
    private const string OtherAid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";


    /// <summary>
    /// An algorithm-agile digest oracle: a Blake3 request routes to the BouncyCastle backend, every other to the
    /// Microsoft backend. Constructed in the test, independent of the production registry.
    /// </summary>
    private static readonly ComputeDigestDelegate AgileDigest = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// An inception SAID, where the controller identifier equals the SAID, verifies over its JSON bytes.
    /// </summary>
    [TestMethod]
    public async Task VerifiesInceptionSaidOverJson()
    {
        using MintedEvent minted = await MintInceptionJson().ConfigureAwait(false);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(minted.Memory, minted.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The same inception, serialized as CBOR, verifies through the same primitive: the SAID derivation is
    /// independent of the serialization.
    /// </summary>
    [TestMethod]
    public async Task VerifiesInceptionSaidOverCbor()
    {
        using MintedEvent minted = await MintInceptionCbor().ConfigureAwait(false);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(minted.Memory, minted.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A non-inception event, whose controller identifier differs from the event SAID, verifies: only the SAID
    /// field is reset to the placeholder, leaving the identifier intact.
    /// </summary>
    [TestMethod]
    public async Task VerifiesInteractionSaidWhereIdentifierDiffers()
    {
        using MintedEvent minted = await MintInteractionJson().ConfigureAwait(false);

        Assert.IsTrue(await KeriEventSaid.VerifyAsync(minted.Memory, minted.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        Assert.AreNotEqual(OtherAid, minted.Said, "The interaction SAID must differ from the controller identifier for this test to be meaningful.");
    }


    /// <summary>
    /// A SAID does not verify against a serialization whose bytes were altered after the SAID was computed.
    /// </summary>
    [TestMethod]
    public async Task RejectsTamperedEvent()
    {
        using MintedEvent minted = await MintInceptionJson().ConfigureAwait(false);
        string tampered = Encoding.UTF8.GetString(minted.Serialization).Replace("\"s\":\"0\"", "\"s\":\"1\"", StringComparison.Ordinal);

        int length = Encoding.UTF8.GetByteCount(tampered);
        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(tampered, tamperedOwner.Memory.Span);

        Assert.IsFalse(await KeriEventSaid.VerifyAsync(tamperedOwner.Memory[..length], minted.Said, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A claimed SAID that differs from the recomputed value does not verify.
    /// </summary>
    [TestMethod]
    public async Task RejectsWrongSaid()
    {
        using MintedEvent minted = await MintInceptionJson().ConfigureAwait(false);
        string wrongSaid = minted.Said[..^1] + (minted.Said[^1] == 'A' ? 'B' : 'A');

        Assert.IsFalse(await KeriEventSaid.VerifyAsync(minted.Memory, wrongSaid, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    //Mints a JSON inception: the SAID field (d) and the equal self-addressing identifier (i) are the dummy
    //placeholder, the SAID is computed over those bytes, then substituted back into both.
    private static async Task<MintedEvent> MintInceptionJson()
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string template =
            $$"""{"v":"KERI10JSON0000ff_","t":"icp","d":"{{placeholder}}","i":"{{placeholder}}","s":"0","kt":"1","k":["{{SigningKey}}"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}""";

        string said = await SaidOf(template).ConfigureAwait(false);
        string final = template.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    //Mints a JSON interaction: only the SAID field (d) is the placeholder; the identifier (i) is a fixed,
    //different AID.
    private static async Task<MintedEvent> MintInteractionJson()
    {
        string placeholder = CesrSaid.Placeholder(Code);
        string template =
            $$"""{"v":"KERI10JSON0000ff_","t":"ixn","d":"{{placeholder}}","i":"{{OtherAid}}","s":"1","p":"{{OtherAid}}","a":[]}""";

        string said = await SaidOf(template).ConfigureAwait(false);
        string final = template.Replace(placeholder, said, StringComparison.Ordinal);

        return Rent(final, said);
    }


    //Mints a CBOR inception equivalent to the JSON one: d and i set to the placeholder, the SAID computed over
    //the CBOR bytes, then the body re-encoded with the SAID in both fields.
    private static async Task<MintedEvent> MintInceptionCbor()
    {
        string placeholder = CesrSaid.Placeholder(Code);

        string said;
        using(IMemoryOwner<byte> dummied = EncodeInceptionCbor(placeholder, out int dummiedLength))
        {
            said = await CesrSaid.ComputeAsync(dummied.Memory[..dummiedLength], Code, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None).ConfigureAwait(false);
        }

        IMemoryOwner<byte> owner = EncodeInceptionCbor(said, out int length);

        return new MintedEvent(owner, length, said);
    }


    //Encodes the inception as CBOR into a pooled buffer the caller owns, returning the owner and the byte length.
    private static IMemoryOwner<byte> EncodeInceptionCbor(string identifierAndSaid, out int length)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(13);
        WriteScalar(writer, "v", "KERICAACAACBOR0000ff.");
        WriteScalar(writer, "t", "icp");
        WriteScalar(writer, "d", identifierAndSaid);
        WriteScalar(writer, "i", identifierAndSaid);
        WriteScalar(writer, "s", "0");
        WriteScalar(writer, "kt", "1");
        WriteList(writer, "k", [SigningKey]);
        WriteScalar(writer, "nt", "0");
        WriteList(writer, "n", []);
        WriteScalar(writer, "bt", "0");
        WriteList(writer, "b", []);
        WriteList(writer, "c", []);
        WriteList(writer, "a", []);
        writer.WriteEndMap();

        length = writer.BytesWritten;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        writer.Encode(owner.Memory.Span);

        return owner;
    }


    //Computes a SAID over a serialization's bytes, renting a transient pooled buffer for the digest input.
    private static async Task<string> SaidOf(string serialization)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return await CesrSaid.ComputeAsync(owner.Memory[..length], Code, AgileDigest, BaseMemoryPool.Shared, CancellationToken.None).ConfigureAwait(false);
    }


    //Rents a pooled buffer for a serialization a verifier reads, owned by the returned carrier and disposed by the
    //caller rather than left as a naked array.
    private static MintedEvent Rent(string serialization, string said)
    {
        int length = Encoding.UTF8.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.UTF8.GetBytes(serialization, owner.Memory.Span);

        return new MintedEvent(owner, length, said);
    }


    //A minted event's serialization, carried in a pooled buffer the test owns and disposes, with its SAID.
    private sealed class MintedEvent: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int length;

        public MintedEvent(IMemoryOwner<byte> owner, int length, string said)
        {
            this.owner = owner;
            this.length = length;
            Said = said;
        }

        public string Said { get; }

        public ReadOnlySpan<byte> Serialization => owner.Memory.Span[..length];

        public ReadOnlyMemory<byte> Memory => owner.Memory[..length];

        public void Dispose() => owner.Dispose();
    }


    private static void WriteScalar(CborWriter writer, string label, string value)
    {
        writer.WriteTextString(label);
        writer.WriteTextString(value);
    }


    private static void WriteList(CborWriter writer, string label, string[] values)
    {
        writer.WriteTextString(label);
        writer.WriteStartArray(values.Length);
        foreach(string value in values)
        {
            writer.WriteTextString(value);
        }

        writer.WriteEndArray();
    }
}
