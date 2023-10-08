using System;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// 
    /// </summary>
    [DebuggerDisplay("{Key}")]
    public class PublicKeyMultibase: KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyMultibase(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));

            Key = key;
        }
    }
}
