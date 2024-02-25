using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Cryptography.Context
{
    /// <summary>
    /// Defines the intended use of cryptographic materials, such as encryption,
    /// signing, or key exchange, to specify their role within cryptographic operations.
    /// Each purpose is represented by an integer constant.
    /// </summary>
    /// <remarks>
    /// This class is part of a structured tagging mechanism designed to clearly
    /// define cryptographic contexts without relying on OIDs, JWT values, or other
    /// identifiers that could be ambiguous over time or need extensive parsing. This works in
    /// conjunction with <see cref="EncodingScheme"/> and <see cref="CryptoAlgorithm"/>
    /// to provide a comprehensive framework for representing and manipulating 
    /// cryptographic material.
    /// </remarks>
    public readonly struct Purpose: IEquatable<Purpose>
    {
        private Purpose(int code)
        {
            Code = code;
        }

        public int Code { get; }


        public static Purpose Public { get; } = new Purpose(0);

        public static Purpose Private { get; } = new Purpose(1);

        public static Purpose Exchange { get; } = new Purpose(2);

        public static Purpose Wrapped { get; } = new Purpose(3);

        public static Purpose Signature { get; } = new Purpose(4);

        public static Purpose Encryption { get; } = new Purpose(5);


        private static List<Purpose> _purposeCodes = new([Public, Private, Exchange, Wrapped, Signature, Encryption]);

        public static IReadOnlyList<Purpose> PurposeCodes => _purposeCodes.AsReadOnly();

        public static Purpose Create(int purposeCode)
        {
            for(int i = 0; i < _purposeCodes.Count; ++i)
            {
                if(_purposeCodes[i].Code == purposeCode)
                {
                    throw new ArgumentException("Purpose code already exists.");
                }
            }

            var newPurpose = new Purpose(purposeCode);
            _purposeCodes.Add(newPurpose);

            return newPurpose;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(Purpose other)
        {
            return Code == other.Code;
        }

        
        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => o is Purpose Purpose && Equals(Purpose);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in Purpose Purpose1, in Purpose Purpose2) => Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in Purpose Purpose1, in Purpose Purpose2) => !Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object Purpose1, in Purpose Purpose2) => Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in Purpose Purpose1, in object Purpose2) => Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object Purpose1, in Purpose Purpose2) => !Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in Purpose Purpose1, in object Purpose2) => !Equals(Purpose1, Purpose2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return Code;
        }        
    }
}
