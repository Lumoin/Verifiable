using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Resolvers;

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
/// <see cref="Build"/> and register the returned instance:
/// </para>
/// <code>
/// DidMethodResolverDelegate keyResolver = KeyDidResolver.Build(pool);
/// DidResolver resolver = new(DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, keyResolver)));
/// </code>
/// </remarks>
public static class KeyDidResolver
{
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
        ArgumentNullException.ThrowIfNull(pool);

        //did:key is purely synthetic — no network dereference — so the threaded
        //context is unused here (named _).
        return async (did, options, _, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            //Strip the "did:key:" scheme and method prefix, leaving the multibase
            //(z-prefixed base58btc) public key encoding.
            string prefix = KeyDidMethod.Prefix;
            if(!did.StartsWith(prefix, StringComparison.Ordinal))
            {
                return DidResolutionResult.Failure(DidResolutionErrors.InvalidDid);
            }

            string multibase = did[prefix.Length..];
            if(string.IsNullOrEmpty(multibase))
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
            catch(ArgumentException)
            {
                //Malformed multicodec header or unsupported curve — surfaces as
                //InvalidDid, not InternalError, since the input is the problem.
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

            return DidResolutionResult.Success(
                document,
                DidDocumentMetadata.Empty,
                contentType: "application/did+json");
        };
    }
}
