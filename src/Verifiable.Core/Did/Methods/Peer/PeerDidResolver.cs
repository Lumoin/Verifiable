using System;
using System.Buffers;
using System.Buffers.Text;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Did.Methods.Peer;

/// <summary>
/// Deserializes the UTF-8 JSON bytes of a <c>did:peer:4</c> embedded DID document into a
/// <see cref="DidDocument"/>. Supplied by the JSON layer (or application/test code) because
/// <see cref="Verifiable.Core"/> takes no JSON-serializer dependency — full DID-document
/// deserialization is the <c>Verifiable.Json</c> leaf's responsibility, reached through this seam.
/// </summary>
/// <param name="didDocumentJsonUtf8">The decoded (un-base58, multicodec-stripped) JSON bytes.</param>
/// <returns>
/// The parsed DID document, or <see langword="null"/> when the bytes are not a valid DID document.
/// The implementation must not throw on malformed input.
/// </returns>
public delegate DidDocument? PeerDidDocumentDeserializer(ReadOnlySpan<byte> didDocumentJsonUtf8);

/// <summary>
/// Resolves <c>did:peer</c> identifiers per the
/// <see href="https://identity.foundation/peer-did-method-spec/">Peer DID Method specification</see>
/// and the <see href="https://identity.foundation/peer-did-4/">did:peer:4 specification</see>.
/// Resolution is purely synthetic — the DID document material is encoded in the identifier itself —
/// so there are no network calls.
/// </summary>
/// <remarks>
/// <para>
/// <c>numalgo 2</c> (<c>did:peer:2</c>) is period-separated elements where each element is a key
/// (purpose code followed by a multibase key) or a service (<c>S</c> followed by a base64url-encoded
/// service object). <c>numalgo 4</c> (<c>did:peer:4</c>) embeds the whole DID document: the long form
/// is verified against its hash, decoded, and contextualized with the DID; the short form cannot be
/// resolved standalone and surfaces as <see cref="DidResolutionErrors.NotFound"/>. <c>numalgo 0</c> (a
/// single inception key) and <c>numalgo 1</c> (a genesis-document hash) are not resolved by this build
/// and surface as <see cref="DidResolutionErrors.MethodNotSupported"/>.
/// </para>
/// <para>
/// Like <see cref="KeyDidResolver"/>, the resolver needs a <see cref="MemoryPool{T}"/> for decoded key
/// and service material; numalgo 4 additionally needs a <see cref="PeerDidDocumentDeserializer"/> and a
/// <see cref="HashFunctionDelegate"/> for the embedded document. Build the delegate via <see cref="Build"/>
/// and register the returned instance:
/// </para>
/// <code>
/// DidMethodResolverDelegate peerResolver = PeerDidResolver.Build(pool, deserializeDidDocument, SHA256.HashData);
/// DidResolver resolver = new(DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, peerResolver)));
/// </code>
/// </remarks>
public static class PeerDidResolver
{
    //Purpose code → verification relationship per the peer DID method lookup table.
    private const char AuthenticationCode = 'V';
    private const char AssertionMethodCode = 'A';
    private const char KeyAgreementCode = 'E';
    private const char CapabilityInvocationCode = 'I';
    private const char CapabilityDelegationCode = 'D';
    private const char ServiceCode = 'S';

    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> for the <c>did:peer</c> method.
    /// </summary>
    /// <param name="pool">
    /// Memory pool for decoded key, service, and document material. The resolved <see cref="DidDocument"/>
    /// holds only string-encoded material, so the pooled buffers are released within the resolution call.
    /// </param>
    /// <param name="didDocumentDeserializer">
    /// Deserializer for the <c>did:peer:4</c> embedded DID document. Required because the resolver
    /// supports the whole <c>did:peer</c> method, of which numalgo 4 is part.
    /// </param>
    /// <param name="hashFunction">
    /// The hash function used to verify the <c>did:peer:4</c> embedded-document hash, which the
    /// specification fixes to SHA-256.
    /// </param>
    /// <returns>
    /// A <see cref="DidMethodResolverDelegate"/> suitable for registration with
    /// <see cref="DidMethodSelectors.FromResolvers"/>.
    /// </returns>
    public static DidMethodResolverDelegate Build(
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(didDocumentDeserializer);
        ArgumentNullException.ThrowIfNull(hashFunction);

        //did:peer is purely synthetic — no network dereference — so the threaded context is unused.
        return (did, _, _, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            return ValueTask.FromResult(Resolve(did, pool, didDocumentDeserializer, hashFunction));
        };
    }


    /// <summary>
    /// Resolves a <c>did:peer:4</c> short form, given the long-form counterpart the caller has stored. A
    /// short form has no embedded document, so it cannot be resolved on its own (the standard resolver
    /// returns <see cref="DidResolutionErrors.NotFound"/> for it); this entry takes the long form and
    /// contextualizes the result with the short-form DID.
    /// </summary>
    /// <param name="longFormDid">The stored long-form <c>did:peer:4</c> identifier.</param>
    /// <param name="pool">Memory pool for decoded material.</param>
    /// <param name="didDocumentDeserializer">Deserializer for the embedded DID document.</param>
    /// <param name="hashFunction">The hash function verifying the embedded multihash (SHA-256).</param>
    /// <returns>The resolution result, contextualized with the short-form DID.</returns>
    public static DidResolutionResult ResolveShortForm(
        string longFormDid,
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction)
    {
        ArgumentNullException.ThrowIfNull(longFormDid);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(didDocumentDeserializer);
        ArgumentNullException.ThrowIfNull(hashFunction);

        if(!longFormDid.StartsWith(PeerDidMethod.Prefix, StringComparison.Ordinal))
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        string numalgoAndElements = longFormDid[PeerDidMethod.Prefix.Length..];
        if(numalgoAndElements.Length == 0 || numalgoAndElements[0] != '4')
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        return PeerDid4.ResolveShort(longFormDid, numalgoAndElements[1..], pool, didDocumentDeserializer, hashFunction);
    }


    private static DidResolutionResult Resolve(
        string did,
        MemoryPool<byte> pool,
        PeerDidDocumentDeserializer didDocumentDeserializer,
        HashFunctionDelegate hashFunction)
    {
        if(!did.StartsWith(PeerDidMethod.Prefix, StringComparison.Ordinal))
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        //The character immediately after "did:peer:" selects the generation algorithm (numalgo).
        string numalgoAndElements = did[PeerDidMethod.Prefix.Length..];
        if(numalgoAndElements.Length == 0)
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        char numalgo = numalgoAndElements[0];

        //numalgo 4 embeds the whole DID document; everything after the numalgo is "{hash}:{encoded}".
        if(numalgo == '4')
        {
            return PeerDid4.Resolve(did, numalgoAndElements[1..], pool, didDocumentDeserializer, hashFunction);
        }

        //numalgo 0 (single inception key) and 1 (genesis-document hash) are not resolved by this build.
        if(numalgo != '2')
        {
            return numalgo is '0' or '1'
                ? DidResolutionResult.Failure(DidResolutionErrors.MethodNotSupported)
                : DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        DidDocument document = new()
        {
            Context = new Context { Contexts = [Context.DidCore10, Context.Multikey10] },
            Id = new PeerDidMethod(did)
        };

        //The numalgo-2 ABNF is "did:peer:2" 1*element, where element = "." followed by a non-empty
        //body. The text after the numalgo must therefore begin with '.', and splitting on '.' yields
        //a leading empty entry (the part before the first separator) then one body per element. Keys
        //are base58 and services are base64url, so neither body carries a '.'.
        string elementsPart = numalgoAndElements[1..];
        if(elementsPart.Length == 0 || elementsPart[0] != '.')
        {
            return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
        }

        string[] elements = elementsPart.Split('.');

        int keyIndex = 1;
        int idlessServiceCount = 0;

        //elements[0] is the empty string before the first '.' separator; the bodies start at index 1.
        for(int i = 1; i < elements.Length; i++)
        {
            string element = elements[i];

            //An empty body is a doubled or trailing '.', which the "1*element" ABNF does not permit.
            if(element.Length == 0)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            char purposeCode = element[0];
            string elementValue = element[1..];

            if(purposeCode == ServiceCode)
            {
                if(!TryAppendService(document, elementValue, pool, ref idlessServiceCount))
                {
                    return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
                }

                continue;
            }

            if(!IsKeyPurposeCode(purposeCode))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            if(!TryAppendKey(document, purposeCode, elementValue, did, keyIndex, pool))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            keyIndex++;
        }

        return DidResolutionResult.Success(document, DidDocumentMetadata.Empty, contentType: "application/did+json");
    }


    //Decodes a key element into a Multikey verification method with a relative "#key-N" id and the
    //full DID as controller, then references it from the relationship mapped by the purpose code.
    //The decoded key material is read into the multibase string by CreateKeyFormat and then released,
    //so the document retains no pooled buffer.
    private static bool TryAppendKey(
        DidDocument document,
        char purposeCode,
        string encodedKey,
        string did,
        int keyIndex,
        MemoryPool<byte> pool)
    {
        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) decoded;
        try
        {
            decoded = CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(
                encodedKey,
                pool,
                DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase)));
        }
        catch(Exception exception) when(exception is ArgumentException or FormatException or NotSupportedException or IndexOutOfRangeException)
        {
            //Malformed multibase/multicodec header, a non-ASCII base58 char (the injected SimpleBase decoder
            //throws IndexOutOfRangeException), or an unsupported curve (NotSupportedException) — the input is
            //the problem, so drop the key rather than let a malformed-input exception escape the resolver.
            return false;
        }

        Tag publicKeyTag = Tag.Create(decoded.algorithm).With(decoded.purpose).With(decoded.scheme);

        KeyFormat keyFormat;
        using(PublicKeyMemory publicKey = new(decoded.keyMaterial, publicKeyTag))
        {
            keyFormat = MultikeyVerificationMethodTypeInfo.Instance.CreateKeyFormat(publicKey);
        }

        string referenceId = $"#key-{keyIndex}";
        VerificationMethod verificationMethod = new()
        {
            Id = referenceId,
            Type = MultikeyVerificationMethodTypeInfo.Instance.TypeName,
            Controller = did,
            KeyFormat = keyFormat
        };

        _ = ApplyRelationship(document.WithVerificationMethod(verificationMethod), purposeCode, referenceId);

        return true;
    }


    //Decodes a base64url service element into a Service, expanding the peer DID abbreviations, and
    //assigns the positional default id ("#service" then "#service-1", ...) when the block has none.
    private static bool TryAppendService(
        DidDocument document,
        string encodedService,
        MemoryPool<byte> pool,
        ref int idlessServiceCount)
    {
        int maxDecodedLength = Base64Url.GetMaxDecodedLength(encodedService.Length);
        Service? service;
        using(IMemoryOwner<byte> owner = pool.Rent(maxDecodedLength))
        {
            if(Base64Url.DecodeFromChars(encodedService.AsSpan(), owner.Memory.Span, out _, out int bytesWritten) != OperationStatus.Done)
            {
                return false;
            }

            if(!PeerDidServiceReader.TryRead(owner.Memory.Span[..bytesWritten], out service))
            {
                return false;
            }
        }

        if(service!.Id is null)
        {
            string serviceId = idlessServiceCount == 0 ? "#service" : $"#service-{idlessServiceCount}";
            service.Id = DidUrl.ParseFragment(serviceId);
            idlessServiceCount++;
        }

        _ = document.WithService(service);

        return true;
    }


    private static DidDocument ApplyRelationship(DidDocument document, char purposeCode, string referenceId) => purposeCode switch
    {
        AuthenticationCode => document.WithAuthentication(referenceId),
        AssertionMethodCode => document.WithAssertionMethod(referenceId),
        KeyAgreementCode => document.WithKeyAgreement(referenceId),
        CapabilityInvocationCode => document.WithCapabilityInvocation(referenceId),
        CapabilityDelegationCode => document.WithCapabilityDelegation(referenceId),
        _ => document
    };


    private static bool IsKeyPurposeCode(char purposeCode) => purposeCode is
        AuthenticationCode or AssertionMethodCode or KeyAgreementCode or CapabilityInvocationCode or CapabilityDelegationCode;
}
