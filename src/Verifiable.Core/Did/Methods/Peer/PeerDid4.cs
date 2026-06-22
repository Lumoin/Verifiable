using System;
using System.Buffers;
using System.Text;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.Peer;

/// <summary>
/// Resolves <c>did:peer</c> numalgo 4 (peer DID method 4) long-form identifiers, per the
/// <see href="https://identity.foundation/peer-did-4/">did:peer:4 specification</see>. The full DID
/// document is embedded in the identifier, so resolution is deterministic: verify the hash over the
/// encoded document, decode it, then "contextualize" it with the DID.
/// </summary>
internal static class PeerDid4
{
    private const int Sha256DigestLength = 32;


    /// <summary>
    /// Resolves a numalgo 4 identifier. <paramref name="afterNumalgo"/> is everything after the
    /// <c>did:peer:4</c> prefix: <c>{hash}:{encoded document}</c> for the long form, or just
    /// <c>{hash}</c> for the short form (which cannot be resolved without the long form).
    /// </summary>
    public static DidResolutionResult Resolve(
        string longFormDid,
        string afterNumalgo,
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction)
        => ResolveCore(longFormDid, afterNumalgo, pool, didDocumentDeserializer, hashFunction, asShortForm: false);


    /// <summary>
    /// Resolves a <c>did:peer:4</c> short form given its long-form counterpart (which the caller must have
    /// stored — a short form has no embedded document of its own). The result is contextualized with the
    /// short-form DID, with the long form recorded in <c>alsoKnownAs</c>.
    /// </summary>
    public static DidResolutionResult ResolveShort(
        string longFormDid,
        string afterNumalgo,
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction)
        => ResolveCore(longFormDid, afterNumalgo, pool, didDocumentDeserializer, hashFunction, asShortForm: true);


    private static DidResolutionResult ResolveCore(
        string longFormDid,
        string afterNumalgo,
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction,
        bool asShortForm)
    {
        int separator = afterNumalgo.IndexOf(':', StringComparison.Ordinal);
        if(separator < 0)
        {
            //Short form: the document is not embedded, so it cannot be resolved without first having
            //seen and stored the long form.
            return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
        }

        string hashPortion = afterNumalgo[..separator];
        string encodedDocument = afterNumalgo[(separator + 1)..];
        if(hashPortion.Length == 0 || encodedDocument.Length == 0)
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        DecodeDelegate base58Decoder = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));

        //The hash binds the short form to the long form; a tampered encoded document must be rejected.
        if(!IsHashValid(hashPortion, encodedDocument, base58Decoder, hashFunction, pool))
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        DidDocument? document;
        try
        {
            using IMemoryOwner<byte> decoded = MultibaseSerializer.Decode(encodedDocument, codecHeaderLength: 0, base58Decoder, pool);
            ReadOnlySpan<byte> bytes = decoded.Memory.Span;
            ReadOnlySpan<byte> jsonMulticodec = MulticodecHeaders.Json;
            if(bytes.Length < jsonMulticodec.Length || !bytes[..jsonMulticodec.Length].SequenceEqual(jsonMulticodec))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            document = Deserialize(didDocumentDeserializer, bytes[jsonMulticodec.Length..]);
        }
        catch(Exception decodeException) when(decodeException is FormatException or ArgumentException or IndexOutOfRangeException)
        {
            //A non-ASCII base58 char makes the injected SimpleBase decoder throw IndexOutOfRangeException
            //(not FormatException); a malformed encoded document is the client's problem — InvalidDid.
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        if(document is null)
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDidDocument);
        }

        //Long-form resolution presents the long-form DID and records the short form in alsoKnownAs; the
        //short-form resolution is the inverse.
        string shortForm = $"{PeerDidMethod.Prefix}4{hashPortion}";
        if(asShortForm)
        {
            Contextualize(document, idToSet: shortForm, alsoKnownAsToAppend: longFormDid);
        }
        else
        {
            Contextualize(document, idToSet: longFormDid, alsoKnownAsToAppend: shortForm);
        }

        return DidResolutionResult.Success(document, DidDocumentMetadata.Empty, contentType: "application/did+json");
    }


    //A throwing deserializer is treated as a malformed embedded document so resolution fails closed as
    //InvalidDidDocument rather than letting the exception escape as an internal fault.
    private static DidDocument? Deserialize(PeerDidDocumentDeserializer deserializer, ReadOnlySpan<byte> json)
    {
        try
        {
            return deserializer(json);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }


    //Recreates the SHA2-256 multihash over the encoded-document string and compares it against the
    //hash embedded in the DID. Any decode failure of the hash portion is a non-conforming DID.
    private static bool IsHashValid(string hashPortion, string encodedDocument, DecodeDelegate base58Decoder, HashFunctionDelegate hashFunction, MemoryPool<byte> pool)
    {
        //did:peer:4 fixes the hash to SHA2-256, validated against the multihash code below.
        Span<byte> digest = stackalloc byte[Sha256DigestLength];
        int byteCount = Encoding.UTF8.GetByteCount(encodedDocument);
        using(IMemoryOwner<byte> encodedBytes = pool.Rent(byteCount))
        {
            Span<byte> encodedSpan = encodedBytes.Memory.Span[..byteCount];
            Encoding.UTF8.GetBytes(encodedDocument, encodedSpan);
            hashFunction(encodedSpan, digest);
        }

        try
        {
            using IMemoryOwner<byte> multihash = MultibaseSerializer.Decode(hashPortion, codecHeaderLength: 0, base58Decoder, pool);
            ReadOnlySpan<byte> bytes = multihash.Memory.Span;

            //A multihash is varint(hash code) || varint(digest length) || digest; the code comes from the
            //multiformats facility, the length must equal the SHA2-256 digest size.
            ReadOnlySpan<byte> sha256Code = MultihashHeaders.Sha2Bits256;
            if(bytes.Length != sha256Code.Length + 1 + Sha256DigestLength
                || !bytes[..sha256Code.Length].SequenceEqual(sha256Code)
                || bytes[sha256Code.Length] != Sha256DigestLength)
            {
                return false;
            }

            return bytes[(sha256Code.Length + 1)..].SequenceEqual(digest);
        }
        catch(Exception decodeException) when(decodeException is FormatException or ArgumentException or IndexOutOfRangeException)
        {
            //A non-ASCII base58 char makes the injected SimpleBase decoder throw IndexOutOfRangeException;
            //a malformed hash portion fails the hash check rather than escaping as an unhandled exception.
            return false;
        }
    }


    //Contextualizes the decoded (input) document per the specification: set the root id, add the other
    //form of the DID to alsoKnownAs, and default each verification method's controller to the id.
    private static void Contextualize(DidDocument document, string idToSet, string alsoKnownAsToAppend)
    {
        document.Id = new PeerDidMethod(idToSet);
        document.AlsoKnownAs = AppendDistinct(document.AlsoKnownAs, alsoKnownAsToAppend);

        if(document.VerificationMethod is not null)
        {
            foreach(VerificationMethod method in document.VerificationMethod)
            {
                if(method.Controller is null)
                {
                    method.Controller = idToSet;
                }
            }
        }

        //Verification methods may also be embedded directly within a relationship rather than referenced.
        DefaultEmbeddedControllers(document.Authentication, idToSet);
        DefaultEmbeddedControllers(document.AssertionMethod, idToSet);
        DefaultEmbeddedControllers(document.KeyAgreement, idToSet);
        DefaultEmbeddedControllers(document.CapabilityInvocation, idToSet);
        DefaultEmbeddedControllers(document.CapabilityDelegation, idToSet);
    }


    private static void DefaultEmbeddedControllers<T>(T[]? references, string did) where T : VerificationMethodReference
    {
        if(references is null)
        {
            return;
        }

        foreach(T reference in references)
        {
            if(reference.EmbeddedVerification is { Controller: null } embedded)
            {
                embedded.Controller = did;
            }
        }
    }


    private static string[] AppendDistinct(string[]? existing, string value)
    {
        if(existing is null)
        {
            return [value];
        }

        foreach(string item in existing)
        {
            if(string.Equals(item, value, StringComparison.Ordinal))
            {
                return existing;
            }
        }

        return [.. existing, value];
    }
}
