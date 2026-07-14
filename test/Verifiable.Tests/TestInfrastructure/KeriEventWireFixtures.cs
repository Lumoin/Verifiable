using System.Formats.Cbor;
using MessagePack;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared hand-built KERI event field writers for the CBOR/MessagePack/SAID conformance test corpus.
/// </summary>
/// <remarks>
/// These are independent, hand-built wire encodings — the oracle KERI event readers/CESR conformance
/// tests parse and hash, never derived from a production KERI event writer — so every test in this
/// family keeps calling these rather than any production surface, per the iron oracle rule.
/// </remarks>
internal static class KeriEventWireFixtures
{
    /// <summary>Writes a <c>{label: value}</c> scalar field pair as canonical CBOR text strings.</summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="label">The field label.</param>
    /// <param name="value">The field value.</param>
    internal static void WriteScalar(CborWriter writer, string label, string value)
    {
        writer.WriteTextString(label);
        writer.WriteTextString(value);
    }


    /// <summary>Writes a <c>{label: [values...]}</c> list field as canonical CBOR.</summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="label">The field label.</param>
    /// <param name="values">The list's text-string values.</param>
    internal static void WriteList(CborWriter writer, string label, string[] values)
    {
        writer.WriteTextString(label);
        writer.WriteStartArray(values.Length);
        foreach(string value in values)
        {
            writer.WriteTextString(value);
        }

        writer.WriteEndArray();
    }


    /// <summary>Writes a <c>{label: value}</c> scalar field pair as MessagePack strings.</summary>
    /// <param name="writer">The MessagePack writer to append to.</param>
    /// <param name="label">The field label.</param>
    /// <param name="value">The field value.</param>
    internal static void WriteScalar(ref MessagePackWriter writer, string label, string value)
    {
        writer.Write(label);
        writer.Write(value);
    }


    /// <summary>Writes a <c>{label: [values...]}</c> list field as MessagePack.</summary>
    /// <param name="writer">The MessagePack writer to append to.</param>
    /// <param name="label">The field label.</param>
    /// <param name="values">The list's string values.</param>
    internal static void WriteList(ref MessagePackWriter writer, string label, string[] values)
    {
        writer.Write(label);
        writer.WriteArrayHeader(values.Length);
        foreach(string value in values)
        {
            writer.Write(value);
        }
    }
}
