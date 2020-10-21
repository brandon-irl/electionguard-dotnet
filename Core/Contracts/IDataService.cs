using System.Collections.Generic;
using System.Threading.Tasks;

namespace ElectionGuard.Verifier.Core
{
    public interface IDataService
    {
        Task<Context> GetContext();
        Task<Constants> GetConstants();

        IAsyncEnumerable<Guardian> GetGuardians();
        IAsyncEnumerable<EncryptedBallot> GetEncryptedBallots();
        Task<Dictionary<string, int>> GetVoteLimits();
    }
}