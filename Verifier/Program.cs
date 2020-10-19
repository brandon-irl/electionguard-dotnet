using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using ElectionGuard.Verifier.Data;

namespace ElectionGuard.Verifier.App
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await CreateHostBuilder(args).RunConsoleAsync();
        }

        private static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                .ConfigureServices((context, services) =>
                {
                    services.AddDataServices(context);
                    services.AddSingleton<Verifier>();
                    services.AddHostedService<VerifierService>();
                });
        }
    }
}
