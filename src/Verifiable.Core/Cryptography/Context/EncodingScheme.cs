using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Cryptography.Context
{
    /// <summary>
    /// Represents the encoding scheme applied to cryptographic material.
    /// Each scheme is represented by an integer constant.
    /// </summary>
    /// <remarks>
    /// This class is part of a structured tagging mechanism designed to clearly
    /// define cryptographic contexts without relying on OIDs, JWT values, or other
    /// identifiers that could be ambiguous over time or need extensive parsing. This works in
    /// conjunction with <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/>
    /// to provide a comprehensive framework for representing and manipulating 
    /// cryptographic material.
    /// </remarks>
    public readonly struct EncodingScheme: IEquatable<EncodingScheme>
    {
        public int Scheme { get; }


        static EncodingScheme()
        {

        }


        private EncodingScheme(int scheme)
        {
            Scheme = scheme;
        }

        public static EncodingScheme Der { get; } = new EncodingScheme(0);

        public static EncodingScheme Pem { get; } = new EncodingScheme(1);

        public static EncodingScheme EcCompressed { get; } = new EncodingScheme(2);

        public static EncodingScheme EcUncompressed { get; } = new EncodingScheme(3);

        public static EncodingScheme Pkcs8 { get; } = new EncodingScheme(4);

        public static EncodingScheme Raw { get; } = new EncodingScheme(5);

        private static readonly List<EncodingScheme> schemes = new(collection: [Der, Pem, EcCompressed, EcUncompressed, Pkcs8, Raw]);
        public static IReadOnlyList<EncodingScheme> Schemes => schemes.AsReadOnly();

        public static EncodingScheme Create(int scheme)
        {
            for(int i = 0; i < schemes.Count; ++i)
            {
                if(schemes[i].Scheme == scheme)
                {
                    throw new ArgumentException("Scheme already exists.");
                }
            }

            var newScheme = new EncodingScheme(scheme);
            schemes.Add(newScheme);

            return newScheme;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(EncodingScheme other)
        {
            return Scheme == other.Scheme;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => o is EncodingScheme EncodingScheme && Equals(EncodingScheme);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in EncodingScheme EncodingScheme1, in EncodingScheme EncodingScheme2) => Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in EncodingScheme EncodingScheme1, in EncodingScheme EncodingScheme2) => !Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object EncodingScheme1, in EncodingScheme EncodingScheme2) => Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in EncodingScheme EncodingScheme1, in object EncodingScheme2) => Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object EncodingScheme1, in EncodingScheme EncodingScheme2) => !Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in EncodingScheme EncodingScheme1, in object EncodingScheme2) => !Equals(EncodingScheme1, EncodingScheme2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
