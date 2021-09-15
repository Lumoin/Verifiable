using System;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    [DebuggerDisplay("PublicKeyHex({Key})")]
    public class PublicKeyHex: KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyHex(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));

            Key = key;
        }
    }
}
