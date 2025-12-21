using System.Buffers;

namespace Verifiable.Core.Cryptography
{
    public delegate PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory> PublicPrivateKeyCreationDelegate3<TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool)
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory;


    public delegate TPublicPrivateKeyMaterial PublicPrivateKeyCreationDelegateWithPool<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool)
        where TPublicPrivateKeyMaterial : PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory;




    public record class PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>(TPublicKeyMemory PublicKey, TPrivateKeyMemory PrivateKey)
        where TPublicKeyMemory : PublicKeyMemory
        where TPrivateKeyMemory : PrivateKeyMemory
    {
    }

    public class PublicKeyMemoryDerived: PublicKeyMemory
    {
        public PublicKeyMemoryDerived(IMemoryOwner<byte> sensitiveMemory, Tag tag) : base(sensitiveMemory, tag)
        {
        }
    }

    public class PrivateKeyMemoryDerived: PrivateKeyMemory
    {
        public PrivateKeyMemoryDerived(IMemoryOwner<byte> sensitiveMemory, Tag tag) : base(sensitiveMemory, tag)
        {
        }
    }

    public static class PublicPrivateKeyMaterialExtensions
    {
        public static PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory> Create<TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool, PublicPrivateKeyCreationDelegate3<TPublicKeyMemory, TPrivateKeyMemory> keyLoader)
             where TPublicKeyMemory : PublicKeyMemory
             where TPrivateKeyMemory : PrivateKeyMemory
        {
            return keyLoader(keyDataPool);
        }


        public static TPublicPrivateKeyMaterial Create<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory>(MemoryPool<byte> keyDataPool, PublicPrivateKeyCreationDelegateWithPool<TPublicPrivateKeyMaterial, TPublicKeyMemory, TPrivateKeyMemory> keyLoader)
            where TPublicPrivateKeyMaterial : PublicPrivateKeyMaterial<TPublicKeyMemory, TPrivateKeyMemory>
            where TPublicKeyMemory : PublicKeyMemory
            where TPrivateKeyMemory : PrivateKeyMemory
        {
            return keyLoader(keyDataPool);
        }
    }
}
