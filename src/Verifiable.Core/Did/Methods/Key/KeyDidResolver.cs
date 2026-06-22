using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Did.Methods.Key;

/// <summary>
/// Derives the X25519 (key agreement) public key birationally equivalent to an Ed25519 public key.
/// Supplied by the cryptographic backend so <see cref="Verifiable.Core"/> takes no BouncyCastle dependency.
/// </summary>
/// <param name="ed25519PublicKey">The Ed25519 public key — the 32-byte compressed Edwards point.</param>
/// <param name="pool">Memory pool for the derived 32-byte X25519 public key.</param>
/// <returns>The derived raw X25519 public key as 32 little-endian bytes. The caller owns the result.</returns>
public delegate IMemoryOwner<byte> Ed25519ToX25519PublicKeyDelegate(ReadOnlySpan<byte> ed25519PublicKey, MemoryPool<byte> pool);

/// <summary>
/// Resolves <c>did:key</c> identifiers per the
/// <see href="https://w3c-ccg.github.io/did-method-key/">DID Key method specification</see>.
/// Resolution is purely synthetic — the public key is decoded from the
/// multibase suffix and a single-verification-method <see cref="DidDocument"/>
/// is constructed via <see cref="KeyDidBuilder"/>. No network calls.
/// </summary>
/// <remarks>
/// <para>
/// Examples:
/// </para>
/// <list type="bullet">
///   <item><description><c>did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</c> (Ed25519)</description></item>
///   <item><description><c>did:key:zDnaeUKTWUXc1HDpGfKbEK31nKLN19yX5aTCzR3rqqSjQzkog</c> (P-256)</description></item>
/// </list>
/// <para>
/// Because the resolver needs a <see cref="MemoryPool{T}"/> for the decoded key
/// material and a base58 <see cref="DecodeDelegate"/> for the multibase suffix,
/// a static method group cannot be used directly with
/// <see cref="DidMethodSelectors.FromResolvers"/>. Build the delegate via
/// <see cref="Build(MemoryPool{byte})"/> and register the returned instance:
/// </para>
/// <code>
/// DidMethodResolverDelegate keyResolver = KeyDidResolver.Build(pool);
/// DidResolver resolver = new(DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, keyResolver)));
/// </code>
/// </remarks>
public static class KeyDidResolver
{
    //A resolved did:key document is a JSON-LD representation: it always carries @context. Both the DID v1
    //context and the verification-method suite context (Multikey) are required by the did:key Context
    //Creation Algorithm. The JSON-LD representation media type is the DID Core §6.2.1 value.
    private const string ContentTypeDidLdJson = "application/did+ld+json";


    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> for the <c>did:key</c>
    /// method. The returned delegate decodes the multibase suffix into a
    /// <see cref="PublicKeyMemory"/>, then synthesises a single-verification-method
    /// <see cref="DidDocument"/> using <see cref="MultikeyVerificationMethodTypeInfo.Instance"/>.
    /// </summary>
    /// <param name="pool">
    /// Memory pool for the decoded key material. The caller owns the eventual
    /// disposal of the resulting <see cref="DidDocument"/>'s embedded key
    /// material through the document lifecycle.
    /// </param>
    /// <returns>
    /// A <see cref="DidMethodResolverDelegate"/> suitable for registration with
    /// <see cref="DidMethodSelectors.FromResolvers"/>.
    /// </returns>
    public static DidMethodResolverDelegate Build(MemoryPool<byte> pool)
    {
        return Build(pool, ed25519ToX25519: null);
    }


    /// <summary>
    /// Builds a <see cref="DidMethodResolverDelegate"/> for the <c>did:key</c> method, optionally wiring the
    /// Ed25519 → X25519 derivation used when the caller requests
    /// <see cref="DidResolutionOptions.EnableEncryptionKeyDerivation"/>.
    /// </summary>
    /// <param name="pool">Memory pool for the decoded key material.</param>
    /// <param name="ed25519ToX25519">
    /// The Ed25519 → X25519 public key derivation supplied by the cryptographic backend, or
    /// <see langword="null"/> to leave the derivation unsupported. When <see langword="null"/> and the caller
    /// requests <see cref="DidResolutionOptions.EnableEncryptionKeyDerivation"/> for an Ed25519 <c>did:key</c>,
    /// resolution fails with <see cref="DidResolutionErrors.FeatureNotSupported"/>.
    /// </param>
    /// <returns>A <see cref="DidMethodResolverDelegate"/> suitable for registration.</returns>
    public static DidMethodResolverDelegate Build(MemoryPool<byte> pool, Ed25519ToX25519PublicKeyDelegate? ed25519ToX25519)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //did:key is purely synthetic — no network dereference — so the threaded
        //context is unused here (named _).
        return async (did, options, _, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            //Strip the "did:key:" scheme and method prefix, leaving the optional version segment and the
            //multibase (z-base58btc or u-base64url) public key encoding.
            string prefix = KeyDidMethod.Prefix;
            if(!did.StartsWith(prefix, StringComparison.Ordinal))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            string remainder = did[prefix.Length..];
            if(string.IsNullOrEmpty(remainder))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //did:key §Document Creation Algorithm: the identifier MAY carry an explicit version segment
            //(did:key:VERSION:MULTIBASE). When present the version MUST be convertible to a positive integer;
            //only version 1 is defined, so any other value is an invalidDid. When absent the version defaults to 1.
            string multibase = remainder;
            int versionDelimiter = remainder.IndexOf(':', StringComparison.Ordinal);
            if(versionDelimiter >= 0)
            {
                string version = remainder[..versionDelimiter];
                if(!int.TryParse(version, out int versionNumber) || versionNumber != 1)
                {
                    return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
                }

                multibase = remainder[(versionDelimiter + 1)..];
            }

            if(string.IsNullOrEmpty(multibase))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //did:key §Document Creation Algorithm: "The multibaseValue MUST be a string and begin with the
            //letter `z`. If any of these requirements fail, an `invalidDid` error MUST be raised." The base64url
            //`u` form appears in the identifier ABNF, but the resolution algorithm constrains the resolver to the
            //base58btc `z` form; a `u`-prefixed (or any non-`z`) value is an invalidDid here even though the
            //decoder retains the base64url capability for non-resolution callers.
            if(multibase[0] != MultibaseAlgorithms.Base58Btc)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) decoded;
            try
            {
                decoded = CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(
                    multibase,
                    pool,
                    DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase)));
            }
            catch(Exception exception) when(exception is FormatException or ArgumentException or NotSupportedException or IndexOutOfRangeException)
            {
                //Malformed multibase, wrong-length body (invalidPublicKeyLength), a non-ASCII base58 char
                //(the injected SimpleBase decoder throws IndexOutOfRangeException), or an unsupported curve
                //(NotSupportedException) — all surface as InvalidDid, not InternalError, since the input is
                //the problem. Every malformed-input exception the decoders/converter raise is mapped here.
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            //Tag the decoded bytes so downstream consumers route through the
            //correct verification primitives.
            Tag publicKeyTag = Tag.Create(
                (typeof(CryptoAlgorithm), decoded.algorithm),
                (typeof(Purpose), decoded.purpose),
                (typeof(EncodingScheme), decoded.scheme));
            PublicKeyMemory publicKey = new(decoded.keyMaterial, publicKeyTag);

            DidDocument document = await new KeyDidBuilder().BuildAsync(
                publicKey,
                MultikeyVerificationMethodTypeInfo.Instance,
                includeDefaultContext: false,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            //A resolved did:key document MUST carry @context (the JSON-LD representation): the DID v1 context
            //followed by the Multikey suite context, per the did:key Context Creation Algorithm.
            //
            //The did:key spec is internally inconsistent on the first context value. The normative Document
            //Creation Algorithm (spec L342) states the options.defaultContext is "an array where the first
            //element is the string value `https://www.w3.org/ns/did/v1`" — which DidCore10 satisfies. The spec's
            //own worked example (L301-302) instead emits a single-element array ["https://www.w3.org/ns/did/v1.1"],
            //contradicting that normative requirement. The value below follows the normative L342 text and the
            //Multikey-suite interop convention (DID v1 + multikey/v1), not the example's v1.1 outlier.
            document.Context = new Verifiable.Core.Model.Common.Context
            {
                Contexts = [Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10]
            };

            //did:key §Decode Public Key Algorithm: when enableEncryptionKeyDerivation is set, derive an
            //X25519 keyAgreement verification method from the Ed25519 signature key (multicodec 0xed).
            if(options.EnableEncryptionKeyDerivation == true && decoded.algorithm.Equals(CryptoAlgorithm.Ed25519))
            {
                if(ed25519ToX25519 is null)
                {
                    return DidResolutionResult.Failure(DidResolutionErrors.FeatureNotSupported);
                }

                IMemoryOwner<byte> x25519Material;
                try
                {
                    x25519Material = ed25519ToX25519(publicKey.AsReadOnlySpan(), pool);
                }
                catch(Exception exception) when(exception is FormatException or ArgumentException or ArithmeticException)
                {
                    //A crafted Ed25519 key whose Edwards y-coordinate is the identity point (y == 1) makes the
                    //birational map's (1 - y) denominator zero; the backend guards that as an ArgumentException,
                    //but ArithmeticException is caught here as belt-and-suspenders so a degenerate point maps to
                    //InvalidDid rather than faulting out of the resolver.
                    return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
                }

                Tag x25519Tag = Tag.Create(
                    (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
                    (typeof(Purpose), Purpose.Exchange),
                    (typeof(EncodingScheme), EncodingScheme.Raw));
                PublicKeyMemory x25519Key = new(x25519Material, x25519Tag);

                AppendDerivedKeyAgreement(document, x25519Key, did);
            }

            return DidResolutionResult.Success(
                document,
                DidDocumentMetadata.Empty,
                contentType: ContentTypeDidLdJson);
        };
    }


    //Appends the derived X25519 key as a separate keyAgreement verification method whose fragment is the
    //X25519 multibase (#z6LS...), per the did:key Ed25519-with-X25519 example.
    private static void AppendDerivedKeyAgreement(DidDocument document, PublicKeyMemory x25519Key, string did)
    {
        string encodedX25519 = CryptoFormatConversions.DefaultAlgorithmToBase58Converter(
            CryptoAlgorithm.X25519,
            Purpose.Exchange,
            x25519Key.AsReadOnlySpan(),
            DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase)));

        string verificationMethodId = $"{did}#{encodedX25519}";

        VerificationMethod keyAgreementMethod = new()
        {
            Id = verificationMethodId,
            Type = MultikeyVerificationMethodTypeInfo.Instance.TypeName,
            Controller = did,
            KeyFormat = MultikeyVerificationMethodTypeInfo.Instance.CreateKeyFormat(x25519Key)
        };

        VerificationMethod[] existing = document.VerificationMethod ?? [];
        document.VerificationMethod = [.. existing, keyAgreementMethod];

        document.WithKeyAgreement(verificationMethodId);
    }
}
