using System.Text.RegularExpressions;
using Verifiable.Assessment;


namespace Verifiable.Core.Did
{
    /// <summary>
    /// Contains validation rules common for all DID documents.
    /// </summary>
    public static class DidDocumentValidationRules
    {
        public static IList<Claim> ValidatePrefix(DidDocument document)
        {
            Regex regex = DidUrlRegex.AbsoluteDidUrl();
            bool isSuccess = regex.IsMatch(document.Id?.Id ?? string.Empty);
            return
            [
                new(ClaimId.KeyDidIdFormat, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure)
            ];
        }
    }
}
