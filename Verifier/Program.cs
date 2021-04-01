using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using ElectionGuard.Data;

namespace ElectionGuard.App
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
                    services.AddSingleton<Core.Verifier>();
                    services.AddHostedService<VerifierService>();
                });
        }
    }
}
