using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Core.Cryptography
{
    public sealed class EncodingScheme
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

        private static readonly List<EncodingScheme> schemes = new (collection: new[] { Der, Pem, EcCompressed, EcUncompressed, Pkcs8, Raw});
        public static IReadOnlyList<EncodingScheme> Schemes => schemes.AsReadOnly();

        public static EncodingScheme Create(int scheme)
        {
            if(schemes.Any(p => p.Scheme == scheme))
            {
                throw new ArgumentException("Scheme already exists.");
            }

            var newScheme = new EncodingScheme(scheme);
            schemes.Add(newScheme);

            return newScheme;
        }
    }
}
