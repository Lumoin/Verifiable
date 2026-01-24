using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Commands
{
    public readonly ref struct Tpm2bRef<T>(T source) where T : SensitiveMemory
    {
        private readonly BufferRef buffer = new(source);

        // ...
    }
}
