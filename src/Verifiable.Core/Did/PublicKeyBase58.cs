using System;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    [DebuggerDisplay("PublicKeyBase58({Key})")]
    public class PublicKeyBase58: KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyBase58(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));

            Key = key;
        }
    }
}
