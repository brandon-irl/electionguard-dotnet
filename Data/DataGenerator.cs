using System;
using System.IO;
using System.Threading.Tasks;
using ElectionGuard.Verifier.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ElectionGuard.Verifier.Data
{
    public interface IDataGenerator
    {
        Task Initialization { get; }
        Constants constants { get; }
        Context context { get; }
        int NumOfGuardiansFiles();

    }

    public class DataGenerator : IDataGenerator
    {
        public Task Initialization { get; private set; }
        private readonly ILogger logger;
        private readonly IOptions<DataOptions> options;
        private readonly IDataService dataService;
        public Context context { get; private set; }
        public Constants constants { get; private set; }

        // public int Generator{get;}
        // public int LargePrime{get;}
        // public int SmallPrime{get;}
        // public int Cofactor{get;}
        // public int ExtendedHash{get;}
        // public int BaseHash{get;}
        // public int ElgamalKey{get;}
        // public object ContextVoteLimits{get;}
        // public object GetContextInfo();
        // public object GetConstants();
        // public object GetDescription();
        // public int GuardianPublicKey(int index);
        // public IEnumerable<int> AllGuardianPublicKeys();

        // public int QuorumAmount();
        // public int BallotsNum();
        // public int SpoiledBallotsNum();
        // public string DeviceId();
        // public string Location();

        public DataGenerator(ILogger logger, IOptions<DataOptions> options, IDataService dataService)
        {
            this.logger = logger;
            this.options = options;
            this.dataService = dataService;
            this.Initialization = Initialize();
        }      

        public int NumOfGuardiansFiles()
        {
            var dir = new DirectoryInfo($"{options.Value.BaseDir}/{options.Value.CoefficientsFolderPath}");
            return dir.GetFiles().Length;
        }

        private async Task Initialize()
        {
            var t1 = dataService.GetContext();
            var t2 = dataService.GetConstants();
            context = await t1;
            constants = await t2;
        }
    }
}