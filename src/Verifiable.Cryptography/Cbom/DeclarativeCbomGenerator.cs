using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using Lumoin.Base;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// Builds the declarative ("capabilities") CBOM: every cryptographic asset the library
/// can describe, derived from <see cref="CryptoTags.AllTags"/>. This view is independent
/// of which backend provider is wired at runtime, so it always lists the full curated
/// algorithm surface (Ed25519, ECDSA P-256/384/521, secp256k1, RSA, X25519, the Brainpool
/// curves, and the post-quantum ML-DSA / ML-KEM families).
/// </summary>
/// <remarks>
/// <para>
/// The generator is reflection-free: it enumerates the explicit
/// <see cref="CryptoTags.AllTags"/> list and maps the type-keyed <see cref="Tag"/>
/// metadata onto CycloneDX cryptographic-asset components via <c>switch</c> expressions.
/// </para>
/// </remarks>
public static class DeclarativeCbomGenerator
{
    private const string CryptographicAssetType = "cryptographic-asset";

    /// <summary>The CycloneDX BOM format literal.</summary>
    public const string BomFormat = "CycloneDX";

    /// <summary>The targeted CycloneDX specification version.</summary>
    public const string SpecVersion = "1.6";


    /// <summary>
    /// Generates the declarative CBOM document describing the library's cryptographic
    /// capabilities.
    /// </summary>
    /// <param name="timestamp">The RFC 3339 generation timestamp.</param>
    /// <param name="toolVersion">The version string of the generating tool.</param>
    /// <returns>A populated <see cref="CbomDocument"/>.</returns>
    public static CbomDocument Generate(string timestamp, string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(toolVersion);

        var components = new List<CbomComponent>();
        var dependencies = new List<CbomDependency>();
        var seenRefs = new HashSet<string>(StringComparer.Ordinal);

        foreach(Tag tag in CryptoTags.AllTags)
        {
            CbomComponent? component = MapTag(tag);
            if(component is null)
            {
                continue;
            }

            if(!seenRefs.Add(component.BomRef))
            {
                continue;
            }

            components.Add(component);

            //Related-crypto-material assets depend on the algorithm that produces them
            //when that algorithm is identifiable from the tag (e.g. a P-256 nonce depends
            //on the P-256 algorithm asset). Algorithm assets have no outbound edges here.
            string? algorithmRef =
                component.CryptoProperties.RelatedCryptoMaterialProperties?.AlgorithmRef;
            if(algorithmRef is not null)
            {
                dependencies.Add(new CbomDependency(component.BomRef, [algorithmRef]));
            }
        }

        var metadata = new CbomMetadata(
            timestamp,
            [new CbomTool("Lumoin", "Verifiable", toolVersion)]);

        return new CbomDocument(
            BomFormat,
            SpecVersion,
            Version: 1,
            metadata,
            components,
            dependencies);
    }


    //Maps a single Tag to a cryptographic-asset component, or null when the tag does not
    //describe a CBOM-relevant asset on its own.
    private static CbomComponent? MapTag(Tag tag)
    {
        bool hasAlgorithm = tag.TryGet(out CryptoAlgorithm algorithm);
        bool hasHash = tag.TryGet(out HashAlgorithmName hashName);
        Purpose purpose = tag.TryGet(out Purpose p) ? p : Purpose.None;

        //Digest and HMAC tags carry a HashAlgorithmName rather than a CryptoAlgorithm.
        if(!hasAlgorithm && hasHash)
        {
            return MapHashTag(hashName, purpose);
        }

        if(!hasAlgorithm)
        {
            //Tags such as the COSE wire-form or mdoc salt tags carry only a Purpose and
            //encoding. They are wire-structure markers, not standalone declarative assets.
            return null;
        }

        return MapAlgorithmTag(algorithm, purpose);
    }


    private static CbomComponent? MapHashTag(HashAlgorithmName hashName, Purpose purpose)
    {
        string algorithmName = HashAlgorithmCbom.Name(hashName);

        //An HMAC tag describes a MAC algorithm; a digest tag describes a hash algorithm.
        if(purpose == Purpose.Hmac)
        {
            string macRef = $"crypto/algorithm/hmac-{CbomIdentifiers.AsciiLower(algorithmName)}";
            var macProperties = new CbomAlgorithmProperties(
                Primitive: "mac",
                ParameterSetIdentifier: algorithmName,
                Curve: null,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["keygen", "tag", "verify"],
                ClassicalSecurityLevel: HashAlgorithmCbom.ClassicalSecurityLevel(hashName),
                NistQuantumSecurityLevel: null);

            return new CbomComponent(
                CryptographicAssetType,
                macRef,
                $"HMAC-{algorithmName}",
                new CbomCryptoProperties("algorithm", macProperties, null));
        }

        string digestRef = $"crypto/algorithm/{CbomIdentifiers.AsciiLower(algorithmName)}";
        var hashProperties = new CbomAlgorithmProperties(
            Primitive: "hash",
            ParameterSetIdentifier: algorithmName,
            Curve: null,
            ExecutionEnvironment: "software-plain-ram",
            CryptoFunctions: ["digest"],
            ClassicalSecurityLevel: HashAlgorithmCbom.ClassicalSecurityLevel(hashName),
            NistQuantumSecurityLevel: null);

        return new CbomComponent(
            CryptographicAssetType,
            digestRef,
            algorithmName,
            new CbomCryptoProperties("algorithm", hashProperties, null));
    }


    private static CbomComponent MapAlgorithmTag(CryptoAlgorithm algorithm, Purpose purpose)
    {
        AlgorithmDescriptor descriptor = AlgorithmCatalog.Describe(algorithm);

        //Signature, verification, signing, encryption, and exchange key tags describe the
        //underlying algorithm asset. Material-shaped purposes (signature value, nonce, salt)
        //describe related-crypto-material whose algorithmRef points back at that algorithm.
        return purpose switch
        {
            var x when x == Purpose.Signature => MapRelatedMaterial(descriptor, "signature", purpose),
            var x when x == Purpose.Nonce => MapRelatedMaterial(descriptor, "nonce", purpose),
            var x when x == Purpose.Salt => MapRelatedMaterial(descriptor, "salt", purpose),
            var x when x == Purpose.Mac => MapRelatedMaterial(descriptor, "tag", purpose),
            var x when x == Purpose.Digest => MapRelatedMaterial(descriptor, "digest", purpose),
            _ => MapAlgorithmAsset(descriptor)
        };
    }


    private static CbomComponent MapAlgorithmAsset(AlgorithmDescriptor descriptor)
    {
        var algorithmProperties = new CbomAlgorithmProperties(
            descriptor.Primitive,
            descriptor.ParameterSetIdentifier,
            descriptor.Curve,
            ExecutionEnvironment: "software-plain-ram",
            descriptor.CryptoFunctions,
            descriptor.ClassicalSecurityLevel,
            descriptor.NistQuantumSecurityLevel);

        return new CbomComponent(
            CryptographicAssetType,
            descriptor.AlgorithmRef,
            descriptor.Name,
            new CbomCryptoProperties("algorithm", algorithmProperties, null));
    }


    private static CbomComponent MapRelatedMaterial(
        AlgorithmDescriptor descriptor,
        string materialType,
        Purpose purpose)
    {
        string materialRef = string.Create(
            CultureInfo.InvariantCulture,
            $"crypto/material/{descriptor.Slug}-{materialType}");

        var materialProperties = new CbomRelatedCryptoMaterialProperties(
            materialType,
            State: null,
            Size: null,
            AlgorithmRef: descriptor.AlgorithmRef);

        return new CbomComponent(
            CryptographicAssetType,
            materialRef,
            $"{descriptor.Name} {materialType}",
            new CbomCryptoProperties("related-crypto-material", null, materialProperties));
    }
}
