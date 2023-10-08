using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Core.Cryptography
{
    public readonly struct Purpose
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


        private static List<Purpose> _purposeCodes = new List<Purpose>(new[] { Public, Private, Exchange, Wrapped, Signature, Encryption });

        public static IReadOnlyList<Purpose> PurposeCodes => _purposeCodes.AsReadOnly();

        public static Purpose Create(int code)
        {
            if(_purposeCodes.Any(p => p.Code == code))
            {
                throw new ArgumentException("Code already exists.");
            }

            var newPurpose = new Purpose(code);
            _purposeCodes.Add(newPurpose);

            return newPurpose;
        }
    }
}
