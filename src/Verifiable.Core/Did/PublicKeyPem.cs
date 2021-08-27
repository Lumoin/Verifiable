using System.Diagnostics;

namespace Verifiable.Core.Did
{
    [DebuggerDisplay("PublicKeyPem({Key})")]
    public class PublicKeyPem: KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyPem(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));

            Key = key;
        }
    }
}
