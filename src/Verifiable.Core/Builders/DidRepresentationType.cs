namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Represents the target representation format for DID document production according to DID Core specification.
    /// This determines how the document should be structured, particularly regarding @context handling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Based on DID Core 1.0 §6.1 and DID Core 1.1 §6.1.1 Representation-Specific Entries:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// <strong>JSON-LD representation</strong> (<c>application/did+ld+json</c>):
    /// @context property <strong>MUST</strong> be included.
    /// See <see href="https://www.w3.org/TR/did-core/#json-ld">DID Core §6.3 JSON-LD</see>
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <strong>JSON representation</strong> (<c>application/did+json</c>):
    /// @context property <strong>MAY</strong> be omitted (but can be included).
    /// See <see href="https://www.w3.org/TR/did-core/#json">DID Core §6.2 JSON</see>
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// The key insight: "MAY be omitted" ≠ "MUST be omitted". JSON representations can include @context
    /// for dual compatibility, easier migration between processing models, or semantic preservation.
    /// </para>
    /// </remarks>
    public enum DidRepresentationType
    {
        /// <summary>
        /// No specific representation type selected.
        /// </summary>
        None = 0,

        /// <summary>
        /// Plain JSON representation without @context property following DID Core §6.2.
        /// Media type: <c>application/did+json</c>
        /// </summary>
        /// <remarks>
        /// This creates a minimal JSON structure with no semantic context information.
        /// Suitable for applications that only need plain JSON parsing without linked data semantics.
        /// </remarks>
        JsonWithoutContext = 1,

        /// <summary>
        /// JSON representation with @context property included following DID Core §6.2.
        /// Media type: <c>application/did+json</c>
        /// </summary>
        /// <remarks>
        /// <para>
        /// This creates a JSON structure that includes @context but is still processed as plain JSON.
        /// The @context provides semantic information while maintaining JSON-only processing.
        /// </para>
        /// <para>
        /// Useful for:
        /// </para>
        /// <list type="bullet">
        /// <item><description>Dual compatibility with JSON-LD tooling</description></item>
        /// <item><description>Preserving semantic information in JSON pipelines</description></item>
        /// <item><description>Easier migration between JSON and JSON-LD processing</description></item>
        /// <item><description>Testing scenarios requiring context preservation</description></item>
        /// </list>
        /// </remarks>
        JsonWithContext = 2,

        /// <summary>
        /// JSON-LD representation following DID Core §6.3.
        /// Media type: <c>application/did+ld+json</c>
        /// </summary>
        /// <remarks>
        /// <para>
        /// This creates a full JSON-LD document where @context is required and semantic processing applies.
        /// The document MUST include @context starting with <c>https://www.w3.org/ns/did/v1</c>.
        /// </para>
        /// <para>
        /// Required for applications that use JSON-LD processing, semantic web tooling,
        /// or need full linked data compatibility.
        /// </para>
        /// </remarks>
        JsonLd = 3
    }
}
