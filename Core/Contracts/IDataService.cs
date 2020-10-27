using System.Collections.Generic;
using System.Numerics;
using System.Threading.Tasks;

namespace ElectionGuard.Verifier.Core
{
    public interface IDataService
    {
        Task<Context> GetContext();
        Task<Constants> GetConstants();

        IAsyncEnumerable<Guardian> GetGuardians();
        IAsyncEnumerable<BigInteger> GetGuardianPublicKeys();
        IAsyncEnumerable<EncryptedBallot> GetEncryptedBallots();
        Task<Dictionary<string, int>> GetVoteLimits();
        Task<Description> GetDescription();
        Task<Tally> GetTally();
    }
}