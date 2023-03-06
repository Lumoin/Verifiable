using System;
using System.Diagnostics;

namespace Verifiable.Tpm
{    
    /// <summary>
    /// The TPMI_DH_OBJECT interface type is a handle that references a loaded object. The handles in this
    /// set are used to refer to either transient or persistent object. The range of these values would change
    /// according to the TPM implementation
    /// </summary>
    /// <remarks>
    /// These interface types should not be used by system software to qualify the keys produced by the TPM.
    /// The value returned by the TPM shall be used to reference the object
    /// 
    /// TPMI_DH_OBJECT is an alias for TPM2_HANDLE with specific usage. For more information, see the TPM 2.0 specification:
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">Part 2: Structures</see>,
    /// Section 9.3 TPMI_DH_OBJECT.
    /// </remarks>
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    //[DebuggerTypeProxy(typeof(DebuggerDisplay))]
    public readonly struct TpmiDhObject: IEquatable<TpmiDhObject>
    {
        public uint Value { get; init; }

        public TpmiDhObject(uint value)
        {
            Value = value;
        }

        public static implicit operator uint(TpmiDhObject obj) => obj.Value;
        public static implicit operator TpmiDhObject(uint value) => new TpmiDhObject(value);

        public bool Equals(TpmiDhObject other) => Value == other.Value;

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is TpmiDhObject other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => Value.GetHashCode();

        /// <inheritdoc/>
        public static bool operator ==(TpmiDhObject left, TpmiDhObject right) => left.Equals(right);

        /// <inheritdoc/>
        public static bool operator !=(TpmiDhObject left, TpmiDhObject right) => !left.Equals(right);


        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private string DebuggerDisplay => $"TPMI_DH_OBJECT: {Value}";
    }
}
