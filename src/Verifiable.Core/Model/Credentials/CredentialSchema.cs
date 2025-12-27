using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials
{
    /// <summary>
    /// Represents a data schema for validating the structure and content of a Verifiable
    /// Credential as defined in the W3C Verifiable Credentials Data Model v2.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Credential schemas allow verifiers to ensure that a credential conforms to an expected
    /// structure. This is useful for interoperability, automated processing, and ensuring
    /// that credentials contain the expected claims with appropriate data types.
    /// </para>
    /// <para>
    /// A credential can reference multiple schemas for different purposes, such as validating
    /// the credential structure, constraining claim values, or supporting semantic validation.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
    /// VC Data Model 2.0 §4.11 Data Schemas</see>.
    /// </para>
    /// </remarks>
    public class CredentialSchema
    {
        /// <summary>
        /// A URL identifying the schema.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The URL should be dereferenceable to obtain the actual schema definition.
        /// Verifiers use this to retrieve the schema for validation.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
        /// VC Data Model 2.0 §4.11 Data Schemas</see>.
        /// </para>
        /// </remarks>
        public required string Id { get; set; }

        /// <summary>
        /// The type of schema, indicating how to interpret and apply it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Common values include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>JsonSchema</c>: JSON Schema for structural validation.</description></item>
        /// <item><description><c>JsonSchemaCredential</c>: A Verifiable Credential containing a JSON Schema.</description></item>
        /// </list>
        /// <para>
        /// The type determines the validation algorithm and expected schema format.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">
        /// VC Data Model 2.0 §4.11 Data Schemas</see>.
        /// </para>
        /// </remarks>
        public required string Type { get; set; }

        /// <summary>
        /// Additional properties as defined by the schema type.
        /// </summary>
        /// <remarks>
        /// Different schema types may define additional properties for configuration
        /// or validation parameters.
        /// </remarks>
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}