using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// Renders an observed ("runtime") CBOM from cryptographic telemetry spans captured by a
/// <see cref="CbomObserver"/>. The observed view reports what actually executed in a
/// workload: the digest / entropy / HMAC operations exercised, the entropy material
/// consumed, the producing crypto library, and the
/// entropy &#8594; DRBG &#8594; material &#8594; library dependency edges.
/// </summary>
public static class ObservedCbomRenderer
{
    private const string CryptographicAssetType = "cryptographic-asset";
    private const string DrbgRef = "crypto/algorithm/csprng-drbg";


    /// <summary>
    /// Renders the observed CBOM document from the supplied activities.
    /// </summary>
    /// <param name="activities">The captured cryptographic spans.</param>
    /// <param name="timestamp">The RFC 3339 generation timestamp.</param>
    /// <param name="toolVersion">The version string of the generating tool.</param>
    /// <returns>The observed <see cref="CbomDocument"/>.</returns>
    public static CbomDocument Render(
        IReadOnlyList<Activity> activities,
        string timestamp,
        string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(activities);
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(toolVersion);

        var components = new List<CbomComponent>();
        var dependencies = new List<CbomDependency>();
        var seenRefs = new HashSet<string>(StringComparer.Ordinal);
        var libraryRefs = new HashSet<string>(StringComparer.Ordinal);
        //A signature algorithm exercised for both sign and verify yields one merged asset:
        //its bom-ref maps to the component index so the union of cryptoFunctions can be applied.
        var signatureAlgorithmIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        bool hasEntropy = false;

        foreach(Activity activity in activities)
        {
            string operation = activity.OperationName;

            //The producing library is reported on every crypto span. Each distinct library
            //becomes a related-crypto-material asset so the dependency graph can point at it.
            string? libraryName = GetTag(activity, CryptoTelemetry.Library.Name);
            string? libraryVersion = GetTag(activity, CryptoTelemetry.Library.Version);
            string? libraryRef = AddLibrary(components, seenRefs, libraryRefs, libraryName, libraryVersion);

            switch(operation)
            {
                case CryptoTelemetry.ActivityNames.Digest:
                {
                    RenderDigest(activity, components, dependencies, seenRefs, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.Nonce:
                {
                    hasEntropy = true;
                    RenderEntropyMaterial(activity, "nonce", components, dependencies, seenRefs, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.Salt:
                {
                    hasEntropy = true;
                    RenderEntropyMaterial(activity, "salt", components, dependencies, seenRefs, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.HmacCompute:
                case CryptoTelemetry.ActivityNames.HmacVerify:
                {
                    RenderHmac(activity, components, dependencies, seenRefs, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.Sign:
                {
                    RenderSignature(activity, "sign", components, dependencies, seenRefs, signatureAlgorithmIndex, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.Verify:
                {
                    RenderSignature(activity, "verify", components, dependencies, seenRefs, signatureAlgorithmIndex, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.KeyGen:
                {
                    RenderKeyGen(activity, components, dependencies, seenRefs, libraryRef);
                    break;
                }

                case CryptoTelemetry.ActivityNames.KeyAgreement:
                {
                    RenderKeyAgreement(activity, components, dependencies, seenRefs, libraryRef);
                    break;
                }

                default:
                {
                    break;
                }
            }
        }

        //The DRBG asset materializes only when entropy was actually drawn; the entropy edge
        //(material -> DRBG) is added alongside each entropy material below.
        if(hasEntropy && seenRefs.Add(DrbgRef))
        {
            var drbgProperties = new CbomAlgorithmProperties(
                Primitive: WellKnownCryptographicPrimitives.Drbg,
                ParameterSetIdentifier: "CTR_DRBG",
                Curve: null,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["generate"],
                ClassicalSecurityLevel: null,
                NistQuantumSecurityLevel: null);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                DrbgRef,
                "CSPRNG (DRBG)",
                new CbomCryptoProperties("algorithm", drbgProperties, null)));
        }

        var metadata = new CbomMetadata(
            timestamp,
            [new CbomTool("Lumoin", "Verifiable", toolVersion)]);

        return new CbomDocument(
            DeclarativeCbomGenerator.BomFormat,
            DeclarativeCbomGenerator.SpecVersion,
            Version: 1,
            metadata,
            components,
            dependencies);
    }


    private static void RenderDigest(
        Activity activity,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        string? libraryRef)
    {
        string algorithm = GetTag(activity, CryptoTelemetry.Digest.Algorithm) ?? "unknown";
        string slug = CbomIdentifiers.AsciiLower(algorithm.Replace("-", string.Empty, StringComparison.Ordinal));
        string algorithmRef = $"crypto/algorithm/{slug}";

        if(seenRefs.Add(algorithmRef))
        {
            var hashProperties = new CbomAlgorithmProperties(
                Primitive: WellKnownCryptographicPrimitives.Hash,
                ParameterSetIdentifier: algorithm,
                Curve: null,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["digest"],
                ClassicalSecurityLevel: null,
                NistQuantumSecurityLevel: null);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                algorithmRef,
                algorithm,
                new CbomCryptoProperties("algorithm", hashProperties, null)));
        }

        string digestRef = $"crypto/material/{slug}-digest";
        if(seenRefs.Add(digestRef))
        {
            int? size = GetIntTag(activity, CryptoTelemetry.Digest.OutputLength) is int bytes
                ? bytes * 8
                : null;

            var digestMaterial = new CbomRelatedCryptoMaterialProperties(
                "digest",
                State: null,
                Size: size,
                AlgorithmRef: algorithmRef);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                digestRef,
                $"{algorithm} digest",
                new CbomCryptoProperties("related-crypto-material", null, digestMaterial)));

            AddDependency(dependencies, digestRef, algorithmRef, libraryRef);
        }
    }


    private static void RenderEntropyMaterial(
        Activity activity,
        string materialType,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        string? libraryRef)
    {
        string purpose = GetTag(activity, CryptoTelemetry.Purpose) ?? materialType;
        string materialRef = $"crypto/material/{materialType}-{components.Count.ToString(CultureInfo.InvariantCulture)}";

        int? size = GetIntTag(activity, CryptoTelemetry.ByteLength) is int bytes ? bytes * 8 : null;

        var materialProperties = new CbomRelatedCryptoMaterialProperties(
            materialType,
            State: "active",
            Size: size,
            AlgorithmRef: DrbgRef);

        components.Add(new CbomComponent(
            CryptographicAssetType,
            materialRef,
            $"{purpose} ({materialType})",
            new CbomCryptoProperties("related-crypto-material", null, materialProperties)));
        seenRefs.Add(materialRef);

        //Entropy edge: the consumed material depends on the DRBG and the producing library.
        AddDependency(dependencies, materialRef, DrbgRef, libraryRef);
    }


    private static void RenderHmac(
        Activity activity,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        string? libraryRef)
    {
        string algorithm = GetTag(activity, CryptoTelemetry.Hmac.Algorithm) ?? "unknown";
        string slug = CbomIdentifiers.AsciiLower(algorithm.Replace("-", string.Empty, StringComparison.Ordinal));
        string algorithmRef = $"crypto/algorithm/hmac-{slug}";

        if(seenRefs.Add(algorithmRef))
        {
            var macProperties = new CbomAlgorithmProperties(
                Primitive: WellKnownCryptographicPrimitives.Mac,
                ParameterSetIdentifier: algorithm,
                Curve: null,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["tag", "verify"],
                ClassicalSecurityLevel: null,
                NistQuantumSecurityLevel: null);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                algorithmRef,
                $"HMAC-{algorithm}",
                new CbomCryptoProperties("algorithm", macProperties, null)));

            if(libraryRef is not null)
            {
                AddDependency(dependencies, algorithmRef, libraryRef, additional: null);
            }
        }
    }


    //Builds (or augments) a signature algorithm asset for a sign or verify span. The asset
    //is keyed by algorithm + curve so a sign and a verify of the same algorithm collapse to one
    //asset whose cryptoFunctions union both functions. A dependency edge to the producing
    //library is added once per algorithm.
    private static void RenderSignature(
        Activity activity,
        string function,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        Dictionary<string, int> signatureAlgorithmIndex,
        string? libraryRef)
    {
        string algorithm = GetTag(activity, CryptoTelemetry.Signature.Algorithm) ?? "unknown";
        string? curve = GetTag(activity, CryptoTelemetry.Signature.Curve);
        string slug = BuildAlgorithmSlug(algorithm, curve);
        string algorithmRef = $"crypto/algorithm/signature-{slug}";

        if(signatureAlgorithmIndex.TryGetValue(algorithmRef, out int existingIndex))
        {
            //Same algorithm already rendered for the other function: union the cryptoFunctions.
            CbomComponent existing = components[existingIndex];
            CbomAlgorithmProperties existingProperties = existing.CryptoProperties.AlgorithmProperties!;
            if(!existingProperties.CryptoFunctions.Contains(function, StringComparer.Ordinal))
            {
                List<string> mergedFunctions = [.. existingProperties.CryptoFunctions, function];
                components[existingIndex] = existing with
                {
                    CryptoProperties = existing.CryptoProperties with
                    {
                        AlgorithmProperties = existingProperties with { CryptoFunctions = mergedFunctions }
                    }
                };
            }

            return;
        }

        var signatureProperties = new CbomAlgorithmProperties(
            Primitive: WellKnownCryptographicPrimitives.Signature,
            ParameterSetIdentifier: algorithm,
            Curve: curve,
            ExecutionEnvironment: "software-plain-ram",
            CryptoFunctions: [function],
            ClassicalSecurityLevel: null,
            NistQuantumSecurityLevel: null);

        string name = curve is not null ? $"{algorithm} ({curve})" : algorithm;
        components.Add(new CbomComponent(
            CryptographicAssetType,
            algorithmRef,
            name,
            new CbomCryptoProperties("algorithm", signatureProperties, null)));

        signatureAlgorithmIndex[algorithmRef] = components.Count - 1;
        seenRefs.Add(algorithmRef);

        if(libraryRef is not null)
        {
            AddDependency(dependencies, algorithmRef, libraryRef, additional: null);
        }
    }


    //Renders a key-generation span as the algorithm asset that was generated (cryptoFunctions:
    //keygen) plus the key-material entry that points back at it. The producer states only the
    //algorithm code; the renderer resolves it with CryptoAlgorithm.FromCode and derives the
    //primitive, name, curve, parameter set, and security levels through the same AlgorithmCatalog
    //the declarative view uses, so an observed key-generation asset matches its declarative
    //counterpart by construction.
    private static void RenderKeyGen(
        Activity activity,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        string? libraryRef)
    {
        string? codeText = GetTag(activity, CryptoTelemetry.Key.AlgorithmCode);
        CryptoAlgorithm algorithm = int.TryParse(codeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int code)
            ? CryptoAlgorithm.FromCode(code)
            : CryptoAlgorithm.Unknown;
        AlgorithmDescriptor descriptor = AlgorithmCatalog.Describe(algorithm);
        string algorithmRef = $"crypto/algorithm/keygen-{descriptor.Slug}";

        if(seenRefs.Add(algorithmRef))
        {
            var keygenProperties = new CbomAlgorithmProperties(
                Primitive: descriptor.Primitive,
                ParameterSetIdentifier: descriptor.ParameterSetIdentifier,
                Curve: descriptor.Curve,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["keygen"],
                ClassicalSecurityLevel: descriptor.ClassicalSecurityLevel,
                NistQuantumSecurityLevel: descriptor.NistQuantumSecurityLevel);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                algorithmRef,
                $"{descriptor.Name} keygen",
                new CbomCryptoProperties("algorithm", keygenProperties, null)));

            if(libraryRef is not null)
            {
                AddDependency(dependencies, algorithmRef, libraryRef, additional: null);
            }
        }

        //The span carries one key type per emission; render that material and edge.
        string keyType = GetTag(activity, CryptoTelemetry.Key.Type) ?? "private-key";
        string materialRef = $"crypto/material/{descriptor.Slug}-{keyType}";
        if(seenRefs.Add(materialRef))
        {
            var keyMaterial = new CbomRelatedCryptoMaterialProperties(
                keyType,
                State: "active",
                Size: null,
                AlgorithmRef: algorithmRef);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                materialRef,
                $"{descriptor.Name} {keyType}",
                new CbomCryptoProperties("related-crypto-material", null, keyMaterial)));

            AddDependency(dependencies, materialRef, algorithmRef, libraryRef);
        }
    }


    //Renders a key-agreement span as a key-agree algorithm asset (cryptoFunctions: keygen,
    //since an ephemeral key is generated) with a dependency edge to the producing library.
    private static void RenderKeyAgreement(
        Activity activity,
        List<CbomComponent> components,
        List<CbomDependency> dependencies,
        HashSet<string> seenRefs,
        string? libraryRef)
    {
        string algorithm = GetTag(activity, CryptoTelemetry.Key.Algorithm) ?? "unknown";
        string? curve = GetTag(activity, CryptoTelemetry.Key.Curve);
        string slug = BuildAlgorithmSlug(algorithm, curve);
        string algorithmRef = $"crypto/algorithm/keyagree-{slug}";

        if(seenRefs.Add(algorithmRef))
        {
            var agreeProperties = new CbomAlgorithmProperties(
                Primitive: WellKnownCryptographicPrimitives.KeyAgreement,
                ParameterSetIdentifier: algorithm,
                Curve: curve,
                ExecutionEnvironment: "software-plain-ram",
                CryptoFunctions: ["keygen", "key-derive"],
                ClassicalSecurityLevel: null,
                NistQuantumSecurityLevel: null);

            string name = curve is not null ? $"{algorithm} ({curve}) key agreement" : $"{algorithm} key agreement";
            components.Add(new CbomComponent(
                CryptographicAssetType,
                algorithmRef,
                name,
                new CbomCryptoProperties("algorithm", agreeProperties, null)));

            if(libraryRef is not null)
            {
                AddDependency(dependencies, algorithmRef, libraryRef, additional: null);
            }
        }
    }


    //Folds an algorithm and optional curve into a stable lowercase bom-ref slug. Both
    //components are stripped of '-' so "P-256" and "ML-DSA" yield "p256" / "mldsa".
    private static string BuildAlgorithmSlug(string algorithm, string? curve)
    {
        string algorithmSlug = CbomIdentifiers.AsciiLower(algorithm.Replace("-", string.Empty, StringComparison.Ordinal));
        if(string.IsNullOrEmpty(curve))
        {
            return algorithmSlug;
        }

        string curveSlug = CbomIdentifiers.AsciiLower(curve.Replace("-", string.Empty, StringComparison.Ordinal));

        return $"{algorithmSlug}-{curveSlug}";
    }


    //Registers a producing crypto library as a related-crypto-material asset once per
    //(name, version). Returns the bom-ref, or null when no library tag was present.
    private static string? AddLibrary(
        List<CbomComponent> components,
        HashSet<string> seenRefs,
        HashSet<string> libraryRefs,
        string? libraryName,
        string? libraryVersion)
    {
        if(string.IsNullOrEmpty(libraryName))
        {
            return null;
        }

        string slug = CbomIdentifiers.AsciiLower(libraryName.Replace(".", "-", StringComparison.Ordinal));
        string version = libraryVersion ?? "unknown";
        string libraryRef = $"crypto/library/{slug}";

        if(libraryRefs.Add(libraryRef) && seenRefs.Add(libraryRef))
        {
            var libraryMaterial = new CbomRelatedCryptoMaterialProperties(
                "additional-context",
                State: null,
                Size: null,
                AlgorithmRef: null);

            components.Add(new CbomComponent(
                CryptographicAssetType,
                libraryRef,
                $"{libraryName} {version}",
                new CbomCryptoProperties("related-crypto-material", null, libraryMaterial)));
        }

        return libraryRef;
    }


    private static void AddDependency(
        List<CbomDependency> dependencies,
        string dependentRef,
        string dependsOnRef,
        string? additional)
    {
        List<string> dependsOn = [dependsOnRef];
        if(additional is not null && !string.Equals(additional, dependsOnRef, StringComparison.Ordinal))
        {
            dependsOn.Add(additional);
        }

        dependencies.Add(new CbomDependency(dependentRef, dependsOn));
    }


    private static string? GetTag(Activity activity, string key)
    {
        foreach(KeyValuePair<string, string?> tag in activity.Tags)
        {
            if(string.Equals(tag.Key, key, StringComparison.Ordinal))
            {
                return tag.Value;
            }
        }

        return null;
    }


    private static int? GetIntTag(Activity activity, string key)
    {
        //Activity numeric tags surface through TagObjects as their boxed CLR type; the string
        //Tags view renders them via ToString. Read the typed object first, fall back to parse.
        foreach(KeyValuePair<string, object?> tag in activity.TagObjects)
        {
            if(string.Equals(tag.Key, key, StringComparison.Ordinal))
            {
                return tag.Value switch
                {
                    int i => i,
                    long l => (int)l,
                    string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) => parsed,
                    _ => null
                };
            }
        }

        return null;
    }
}
