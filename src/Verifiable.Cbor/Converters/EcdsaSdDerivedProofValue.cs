using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

namespace Verifiable.Cbor.Converters;

/// <summary>
/// Represents the CBOR-encoded derived proof value for ECDSA-SD-2023 cryptosuite.
/// </summary>
/// <remarks>
/// <para>
/// The derived proof is created by the Holder from a base proof when presenting
/// a credential with selective disclosure to a Verifier.
/// </para>
/// <para>
/// Structure per W3C VC Data Integrity ECDSA Cryptosuites specification:
/// </para>
/// <code>
/// [
///   baseSignature,       // byte string: signature over mandatory claims (from base proof)
///   publicKey,           // byte string: compressed ephemeral public key (from base proof)
///   signatures,          // array of byte strings: signatures for disclosed non-mandatory statements
///   labelMap,            // map: blank node label replacements
///   mandatoryIndexes,    // array of integers: indexes of mandatory statements
///   selectiveIndexes     // array of integers: indexes of selectively disclosed statements
/// ]
/// </code>
/// </remarks>
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class EcdsaSdDerivedProofValue: IEquatable<EcdsaSdDerivedProofValue>
{
    /// <summary>
    /// Gets the base signature over the mandatory claims hash.
    /// </summary>
    public required byte[] BaseSignature { get; init; }

    /// <summary>
    /// Gets the compressed ephemeral public key for verification.
    /// </summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Gets the signatures for the disclosed non-mandatory statements.
    /// </summary>
    public required IReadOnlyList<byte[]> Signatures { get; init; }

    /// <summary>
    /// Gets the label map for blank node replacement during verification.
    /// </summary>
    /// <remarks>
    /// Keys are the canonical blank node labels (e.g., "_:c14n0"), values are
    /// the HMAC-derived replacement labels.
    /// </remarks>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Gets the indexes of mandatory N-Quad statements in the canonical form.
    /// </summary>
    public required IReadOnlyList<int> MandatoryIndexes { get; init; }

    /// <summary>
    /// Gets the indexes of selectively disclosed N-Quad statements.
    /// </summary>
    public required IReadOnlyList<int> SelectiveIndexes { get; init; }


    /// <inheritdoc/>
    public bool Equals(EcdsaSdDerivedProofValue? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return BaseSignature.AsSpan().SequenceEqual(other.BaseSignature)
            && PublicKey.AsSpan().SequenceEqual(other.PublicKey)
            && SignaturesEqual(Signatures, other.Signatures)
            && LabelMapsEqual(LabelMap, other.LabelMap)
            && MandatoryIndexes.SequenceEqual(other.MandatoryIndexes)
            && SelectiveIndexes.SequenceEqual(other.SelectiveIndexes);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as EcdsaSdDerivedProofValue);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(BaseSignature);
        hash.AddBytes(PublicKey);
        hash.Add(Signatures.Count);
        hash.Add(LabelMap.Count);
        hash.Add(MandatoryIndexes.Count);
        hash.Add(SelectiveIndexes.Count);
        return hash.ToHashCode();
    }


    private static bool SignaturesEqual(IReadOnlyList<byte[]> a, IReadOnlyList<byte[]> b)
    {
        if(a.Count != b.Count)
        {
            return false;
        }

        for(int i = 0; i < a.Count; i++)
        {
            if(!a[i].AsSpan().SequenceEqual(b[i]))
            {
                return false;
            }
        }

        return true;
    }


    private static bool LabelMapsEqual(
        IReadOnlyDictionary<string, string> a,
        IReadOnlyDictionary<string, string> b)
    {
        if(a.Count != b.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, string> kvp in a)
        {
            if(!b.TryGetValue(kvp.Key, out string? value) || value != kvp.Value)
            {
                return false;
            }
        }

        return true;
    }
}


/// <summary>
/// CBOR converter for <see cref="EcdsaSdDerivedProofValue"/>.
/// </summary>
/// <remarks>
/// This converter handles the fixed 6-element CBOR array structure defined by
/// the ECDSA-SD-2023 cryptosuite specification for derived proofs.
/// </remarks>
public sealed class EcdsaSdDerivedProofValueConverter: CborConverter<EcdsaSdDerivedProofValue>
{
    private const int ExpectedArrayLength = 6;

    /// <inheritdoc/>
    public override EcdsaSdDerivedProofValue? Read(
        ref CborReader reader,
        Type typeToConvert,
        CborSerializerOptions options)
    {
        if(reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return null;
        }

        //Validate array structure.
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        if(length.Value != ExpectedArrayLength)
        {
            CborThrowHelper.ThrowInvalidArrayLength(ExpectedArrayLength, length.Value);
        }

        //Read each element in order.
        byte[] baseSignature = reader.ReadByteString();
        byte[] publicKey = reader.ReadByteString();
        List<byte[]> signatures = reader.ReadByteStringArray();
        Dictionary<string, string> labelMap = reader.ReadStringKeyedMap(r => r.ReadTextString());
        List<int> mandatoryIndexes = reader.ReadInt32Array();
        List<int> selectiveIndexes = reader.ReadInt32Array();

        reader.ReadEndArray();

        return new EcdsaSdDerivedProofValue
        {
            BaseSignature = baseSignature,
            PublicKey = publicKey,
            Signatures = signatures,
            LabelMap = labelMap,
            MandatoryIndexes = mandatoryIndexes,
            SelectiveIndexes = selectiveIndexes
        };
    }


    /// <inheritdoc/>
    public override void Write(
        CborWriter writer,
        EcdsaSdDerivedProofValue value,
        CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartArray(ExpectedArrayLength);

        writer.WriteByteString(value.BaseSignature);
        writer.WriteByteString(value.PublicKey);
        writer.WriteByteStringArray((IReadOnlyList<byte[]>)value.Signatures);
        writer.WriteStringKeyedMap(
            (IReadOnlyDictionary<string, string>)value.LabelMap,
            (w, v) => w.WriteTextString(v));
        writer.WriteInt32Array((IReadOnlyList<int>)value.MandatoryIndexes);
        writer.WriteInt32Array((IReadOnlyList<int>)value.SelectiveIndexes);

        writer.WriteEndArray();
    }
}