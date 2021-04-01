using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ElectionGuard.App
{
    internal sealed class VerifierService : IHostedService
    {
        private readonly ILogger<VerifierService> logger;
        private readonly IHostApplicationLifetime appLifetime;
        private readonly Core.Verifier verifier;
        private int? exitCode;

        public VerifierService(ILogger<VerifierService> logger, IHostApplicationLifetime appLifetime, Core.Verifier verifier)
        {
            this.logger = logger;
            this.appLifetime = appLifetime;
            this.verifier = verifier;
        }
        public Task StartAsync(CancellationToken cancellationToken)
        {
            appLifetime.ApplicationStarted.Register(() =>
            {
                Task.Run(async () =>
                {
                    try
                    {
                        await verifier.Initialization;

                        Console.WriteLine("Starting [box 1] baseline parameter check...");
                        var baseline = await verifier.VerifyAllParams();
                        Console.WriteLine($"Baseline Result: {(baseline ? "success" : "failure")} ");

                        Console.WriteLine("Starting [box 2] key generation check...");
                        var keyGen = await verifier.VerifyAllGuardians();
                        Console.WriteLine($"Key Gen Result: {(keyGen ? "success" : "failure")} ");

                        Console.WriteLine("Starting [box 3, 4, 5] ballot encyption check...");
                        var ballots = await verifier.VerifyAllBallots();
                        Console.WriteLine($"Ballots Result: {(ballots ? "success" : "failure")} ");

                        Console.WriteLine("Starting [box 6, 9] cast ballot check...");
                        var tally = await verifier.VerifyCastBallotTallies();
                        
                        Console.WriteLine("Starting [box 10] spoiled ballot check...");
                        await verifier.VerifyAllSpoiledBallots();

                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Unhandled exception!");
                        exitCode = 1;
                    }
                    finally
                    {
                        // Stop the application once the work is done
                        appLifetime.StopApplication();
                    }
                });
            });

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            logger.LogDebug($"Exiting with return code: {exitCode}");

            // Exit code may be null if the user cancelled via Ctrl+C/SIGTERM
            Environment.ExitCode = exitCode.GetValueOrDefault(-1);
            return Task.CompletedTask;
        }
    }
}