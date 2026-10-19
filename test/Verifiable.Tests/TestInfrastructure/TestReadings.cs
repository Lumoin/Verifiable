using Verifiable.Cbor;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json.Sd;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The readings a test expects to succeed or to refuse, answered as the value they read or the refusal they give: a reading
/// answering otherwise fails the test at the assertion, naming the reading it answered.
/// </summary>
internal static class TestReadings
{
    /// <summary>The token a compact SD-JWT the test expects to be well-formed states, read with the SHA-256 disclosure digest.</summary>
    /// <param name="sdJwt">The compact SD-JWT.</param>
    /// <param name="decoder">The base64url decoder.</param>
    /// <param name="encoder">The base64url encoder.</param>
    /// <param name="pool">The pool the disclosures' salts rent from.</param>
    /// <param name="saltTag">The tag stamped on each salt.</param>
    /// <returns>The token, which the caller disposes.</returns>
    internal static SdToken<string> SdJwtToken(string sdJwt, DecodeDelegate decoder, EncodeDelegate encoder, BaseMemoryPool pool, Tag saltTag) =>
        Assert.IsInstanceOfType<SdJwtRead>(SdJwtSerializer.ParseToken(sdJwt, decoder, encoder, pool, saltTag, WellKnownHashAlgorithms.Sha256Iana)).Token;


    /// <summary>The refusal of a compact SD-JWT the test expects to be refused, read with the SHA-256 disclosure digest.</summary>
    /// <param name="sdJwt">The compact SD-JWT.</param>
    /// <param name="decoder">The base64url decoder.</param>
    /// <param name="encoder">The base64url encoder.</param>
    /// <param name="pool">The pool the disclosures' salts rent from.</param>
    /// <param name="saltTag">The tag stamped on each salt.</param>
    /// <returns>The refusal.</returns>
    internal static SdJwtRefused SdJwtRefusal(string sdJwt, DecodeDelegate decoder, EncodeDelegate encoder, BaseMemoryPool pool, Tag saltTag) =>
        Assert.IsInstanceOfType<SdJwtRefused>(SdJwtSerializer.ParseToken(sdJwt, decoder, encoder, pool, saltTag, WellKnownHashAlgorithms.Sha256Iana));


    /// <summary>The disclosure a base64url disclosure the test expects to be well-formed states.</summary>
    /// <param name="encoded">The base64url disclosure.</param>
    /// <param name="decoder">The base64url decoder.</param>
    /// <param name="pool">The pool the salt rents from.</param>
    /// <param name="saltTag">The tag stamped on the salt.</param>
    /// <returns>The disclosure, which the caller disposes.</returns>
    internal static SdDisclosure Disclosure(string encoded, DecodeDelegate decoder, BaseMemoryPool pool, Tag saltTag) =>
        Assert.IsInstanceOfType<SdDisclosureRead>(SdJwtSerializer.ParseDisclosure(encoded, decoder, pool, saltTag)).Disclosure;


    /// <summary>The message a COSE_Sign1 the test expects to be well-formed states, read with its payload attached.</summary>
    /// <param name="coseSign1">The tagged COSE_Sign1.</param>
    /// <param name="pool">The pool the carriers rent from.</param>
    /// <returns>The message, which the caller disposes.</returns>
    internal static CoseSign1Message CoseSign1(ReadOnlyMemory<byte> coseSign1, BaseMemoryPool pool) =>
        Assert.IsInstanceOfType<CoseSign1Read>(CoseSerialization.ParseCoseSign1(coseSign1, pool)).Message;


    /// <summary>The message a COSE_Sign1 the test expects to be well-formed states, read with a detached payload admitted.</summary>
    /// <param name="coseSign1">The tagged COSE_Sign1.</param>
    /// <param name="pool">The pool the carriers rent from.</param>
    /// <returns>The message, which the caller disposes.</returns>
    internal static CoseSign1Message CoseSign1AllowingNilPayload(ReadOnlyMemory<byte> coseSign1, BaseMemoryPool pool) =>
        Assert.IsInstanceOfType<CoseSign1Read>(CoseSerialization.ParseCoseSign1AllowingNilPayload(coseSign1, pool)).Message;


    /// <summary>The key the library's JWK reconstruction rebuilds from a JWK the test expects to state one.</summary>
    /// <param name="jwk">The JWK's members.</param>
    /// <param name="pool">The pool the key material rents from.</param>
    /// <param name="decoder">The base64url decoder.</param>
    /// <returns>The reconstruction, whose material the caller owns.</returns>
    internal static JwkKeyReconstructed JwkKey(Dictionary<string, object> jwk, BaseMemoryPool pool, DecodeDelegate decoder) =>
        Assert.IsInstanceOfType<JwkKeyReconstructed>(CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, pool, decoder));


    /// <summary>The public key a JWK the test expects to state one rebuilds to.</summary>
    /// <param name="reconstruction">The reconstruction.</param>
    /// <returns>The key, which the caller disposes.</returns>
    internal static PublicKeyMemory PublicKeyOf(JwkKeyReconstruction reconstruction) =>
        Assert.IsInstanceOfType<JwkKeyReconstructed>(reconstruction).ToPublicKeyMemory();
}
