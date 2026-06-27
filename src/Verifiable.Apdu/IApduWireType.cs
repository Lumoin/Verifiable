using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu;

/// <summary>
/// Marker interface for APDU wire-format types that can parse themselves from response data.
/// </summary>
/// <remarks>
/// <para>
/// Types implementing this interface represent parsed response data from specific
/// APDU commands. Each type provides a static <c>Parse</c> method that reads from
/// an <see cref="ApduReader"/> and returns a strongly-typed instance.
/// </para>
/// <para>
/// The convention follows the TPM wire type pattern:
/// </para>
/// <code>
/// public sealed class SelectResponse : IApduWireType
/// {
///     public static SelectResponse Parse(ref ApduReader reader, MemoryPool&lt;byte&gt; pool)
///     {
///         //Parse FCI template from response data.
///     }
/// }
/// </code>
/// <para>
/// The executor strips the status word before invoking the parser. Parsers receive
/// only the data portion of the response.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1040:Avoid empty interfaces", Justification = "Marker interface used to tag APDU wire types for discovery and generic constraints.")]
public interface IApduWireType
{
}
