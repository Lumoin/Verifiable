using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;

namespace Verifiable.Tests.TestDataProviders
{
    public delegate bool KeyFormatValidatorDelegate(KeyFormat keyFormat, CryptoAlgorithm alg);


    public class KeyFormatValidator
    {
        private List<(Type Type, KeyFormatValidatorDelegate Validator)> Validators { get; } = [];


        public void AddValidator(Type type, KeyFormatValidatorDelegate validator)
        {
            Validators.Add((type, validator));
        }


        public bool Validate(KeyFormat keyFormat, CryptoAlgorithm alg)
        {
            foreach((Type type, KeyFormatValidatorDelegate validator) in Validators)
            {
                if(keyFormat.GetType() == type)
                {
                    return validator(keyFormat, alg);
                }
            }

            return false;
        }
    }
}
