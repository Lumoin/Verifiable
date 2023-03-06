using System;
using System.Buffers.Binary;
using System.Diagnostics;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm
{
    /// <summary>
    /// Represents the TPMS_ALG_PROPERTY structure, which contains information about a TPM algorithm and its attributes.
    /// </summary>
    /// <remarks>
    /// For information see
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf"/>
    /// Trusted Platform Module Library Part 2: Structures Family "2.0" Level 00 Revision 01.38 20.2 TPMS_ALG_PROPERTY and
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TSS_Overview_Common_v1_r10_pub09232021.pdf">
    /// TCG TSS 2.0 Overview and Common Structures Specification Version 1.0 Revision 10 Table 30 - Definition of (UINT32) TPMA_ALGORITHM Bits.</see>
    /// </remarks>    
    [DebuggerDisplay("Alg = {Alg}, AlgorithmAttributes = {AlgorithmAttributes}")]
    public readonly struct TpmsAlgProperty: IEquatable<TpmsAlgProperty>
    {
        public Tpm2AlgId Alg { get; }

        public TpmaAlgorithm AlgorithmAttributes { get; }


        public TpmsAlgProperty(ReadOnlySpan<byte> algPropertyBuffer, bool isBufferBigEndian)
        {
            const int Tpm2AlgIdSize = sizeof(Tpm2AlgId);
            const int TpmaAlgorithmSize = sizeof(TpmaAlgorithm);
            bool isPlatformBigEndian = BitConverter.IsLittleEndian;
            if(isBufferBigEndian == isPlatformBigEndian)
            {
                Alg = (Tpm2AlgId)BinaryPrimitives.ReadUInt16BigEndian(algPropertyBuffer.Slice(0, Tpm2AlgIdSize));
                AlgorithmAttributes = (TpmaAlgorithm)BinaryPrimitives.ReadUInt32BigEndian(algPropertyBuffer.Slice(Tpm2AlgIdSize, TpmaAlgorithmSize));
            }
            else
            {
                Alg = (Tpm2AlgId)BinaryPrimitives.ReadUInt16LittleEndian(algPropertyBuffer.Slice(0, Tpm2AlgIdSize));
                AlgorithmAttributes = (TpmaAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(algPropertyBuffer.Slice(Tpm2AlgIdSize, TpmaAlgorithmSize));
            }
        }


        public TpmsAlgProperty(Tpm2AlgId alg, TpmaAlgorithm algorithmAttributes)
        {
            Alg = alg;
            AlgorithmAttributes = algorithmAttributes;
        }

        public bool Equals(TpmsAlgProperty other)
        {
            return Alg == other.Alg && AlgorithmAttributes == other.AlgorithmAttributes;
        }

        public override bool Equals(object? obj)
        {
            return obj is TpmsAlgProperty other && Equals(other);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Alg, AlgorithmAttributes);
        }

        public static bool operator ==(TpmsAlgProperty left, TpmsAlgProperty right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(TpmsAlgProperty left, TpmsAlgProperty right)
        {
            return !(left == right);
        }
    }
}
