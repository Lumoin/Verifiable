using System.Collections.Generic;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// A minimal, hand-rolled <see href="https://cyclonedx.org/docs/1.6/json/">CycloneDX 1.6</see>
/// Bill of Materials document specialized for cryptographic assets.
/// </summary>
/// <remarks>
/// <para>
/// These records are the neutral, serialization-agnostic CBOM model. They carry no
/// <c>System.Text.Json</c> attributes because <c>Verifiable.Core</c> forbids the
/// serializer namespace (the JSON firewall). The CLI host owns the
/// source-generated <c>JsonSerializerContext</c> that turns this model into wire JSON,
/// mirroring how <c>TpmInfo</c> (a library type) is serialized by the CLI's
/// <c>TpmJsonContext</c>.
/// </para>
/// <para>
/// The model deliberately mirrors only the CycloneDX fields needed to describe
/// cryptographic algorithms, related crypto material, and a dependency graph. It is
/// not a general CycloneDX implementation and takes no dependency on any CycloneDX
/// or BOM library.
/// </para>
/// </remarks>
/// <param name="BomFormat">The literal <c>CycloneDX</c>.</param>
/// <param name="SpecVersion">The CycloneDX specification version, e.g. <c>1.6</c>.</param>
/// <param name="Version">The monotonically increasing BOM version (always 1 here).</param>
/// <param name="Metadata">Document metadata describing the producer.</param>
/// <param name="Components">The cryptographic-asset components.</param>
/// <param name="Dependencies">The dependency graph linking components by bom-ref.</param>
public sealed record CbomDocument(
    string BomFormat,
    string SpecVersion,
    int Version,
    CbomMetadata Metadata,
    IReadOnlyList<CbomComponent> Components,
    IReadOnlyList<CbomDependency> Dependencies);


/// <summary>Document-level metadata for a <see cref="CbomDocument"/>.</summary>
/// <param name="Timestamp">RFC 3339 timestamp of generation.</param>
/// <param name="Tools">The tools that produced this BOM.</param>
public sealed record CbomMetadata(
    string Timestamp,
    IReadOnlyList<CbomTool> Tools);


/// <summary>A tool that produced a <see cref="CbomDocument"/>.</summary>
/// <param name="Vendor">The tool vendor.</param>
/// <param name="Name">The tool name.</param>
/// <param name="Version">The tool version.</param>
public sealed record CbomTool(
    string Vendor,
    string Name,
    string Version);


/// <summary>
/// A CycloneDX component of <c>type: "cryptographic-asset"</c>.
/// </summary>
/// <param name="Type">Always <c>cryptographic-asset</c>.</param>
/// <param name="BomRef">The stable bom-ref identifier referenced by the dependency graph.</param>
/// <param name="Name">A human-readable name, e.g. <c>Ed25519</c> or <c>nonce</c>.</param>
/// <param name="CryptoProperties">The cryptographic-asset properties.</param>
public sealed record CbomComponent(
    string Type,
    string BomRef,
    string Name,
    CbomCryptoProperties CryptoProperties);


/// <summary>
/// The <c>cryptoProperties</c> object of a cryptographic-asset component.
/// </summary>
/// <param name="AssetType">
/// One of <c>algorithm</c>, <c>certificate</c>, <c>protocol</c>,
/// <c>related-crypto-material</c>.
/// </param>
/// <param name="AlgorithmProperties">
/// Present when <see cref="AssetType"/> is <c>algorithm</c>.
/// </param>
/// <param name="RelatedCryptoMaterialProperties">
/// Present when <see cref="AssetType"/> is <c>related-crypto-material</c>.
/// </param>
public sealed record CbomCryptoProperties(
    string AssetType,
    CbomAlgorithmProperties? AlgorithmProperties,
    CbomRelatedCryptoMaterialProperties? RelatedCryptoMaterialProperties);


/// <summary>
/// The <c>algorithmProperties</c> of an <c>algorithm</c> cryptographic asset.
/// </summary>
/// <param name="Primitive">
/// The cryptographic primitive: <c>signature</c>, <c>hash</c>, <c>mac</c>,
/// <c>drbg</c>, <c>kem</c>, <c>kdf</c>, <c>keyagree</c>, <c>pke</c>, <c>other</c>.
/// </param>
/// <param name="ParameterSetIdentifier">
/// The parameter set, e.g. <c>ML-DSA-44</c> or <c>2048</c>.
/// </param>
/// <param name="Curve">The named curve, when applicable, e.g. <c>P-256</c>.</param>
/// <param name="ExecutionEnvironment">
/// The execution environment, e.g. <c>software-plain-ram</c>.
/// </param>
/// <param name="CryptoFunctions">
/// The supported functions: <c>keygen</c>, <c>sign</c>, <c>verify</c>,
/// <c>digest</c>, <c>generate</c>, <c>encapsulate</c>, <c>decapsulate</c>, ...
/// </param>
/// <param name="ClassicalSecurityLevel">The classical security level in bits.</param>
/// <param name="NistQuantumSecurityLevel">The NIST PQC category (1-5), when applicable.</param>
public sealed record CbomAlgorithmProperties(
    string Primitive,
    string? ParameterSetIdentifier,
    string? Curve,
    string? ExecutionEnvironment,
    IReadOnlyList<string> CryptoFunctions,
    int? ClassicalSecurityLevel,
    int? NistQuantumSecurityLevel);


/// <summary>
/// The <c>relatedCryptoMaterialProperties</c> of a <c>related-crypto-material</c> asset.
/// </summary>
/// <param name="Type">
/// The material type: <c>nonce</c>, <c>salt</c>, <c>seed</c>, <c>private-key</c>,
/// <c>public-key</c>, <c>signature</c>, <c>digest</c>, <c>secret-key</c>, ...
/// </param>
/// <param name="State">The material state, e.g. <c>active</c>.</param>
/// <param name="Size">The size of the material in bits, when known.</param>
/// <param name="AlgorithmRef">The bom-ref of the algorithm that produced this material.</param>
public sealed record CbomRelatedCryptoMaterialProperties(
    string Type,
    string? State,
    int? Size,
    string? AlgorithmRef);


/// <summary>
/// A dependency-graph entry linking a component (<see cref="Ref"/>) to the bom-refs
/// it depends on (<see cref="DependsOn"/>).
/// </summary>
/// <param name="Ref">The bom-ref of the depending component.</param>
/// <param name="DependsOn">The bom-refs this component depends on.</param>
public sealed record CbomDependency(
    string Ref,
    IReadOnlyList<string> DependsOn);
