using System;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace ElectionGuard.Verifier.Core
{
    public class Verifier
    {
        Context context;
        Constants constants;
        private readonly IDataService dataService;
        public Task Initialization { get; private set; }

        public Verifier(IDataService dataService)
        {
            this.dataService = dataService;
            Initialization = Initialize();
        }

        private async Task Initialize()
        {
            var t1 = dataService.GetContext();
            var t2 = dataService.GetConstants();
            context = await t1;
            constants = await t2;
        }

        public async Task<bool> VerifyAllParams()
        {
            return await Task.Run(() =>
            {
                var expectedLarge = Numbers.LargePrime;
                var expectedSmall = Numbers.SmallPrime;
                var error = false;

                if (!expectedLarge.Equals(constants.large_prime) && !Numbers.IsProbablyPrime(constants.large_prime))
                    Console.WriteLine("Large prime value error.");

                if (!expectedSmall.Equals(constants.small_prime) && !Numbers.IsProbablyPrime(constants.small_prime))
                    Console.WriteLine("Small prime value error.");

                if (!BigInteger.Equals(constants.large_prime + BigInteger.MinusOne, BigInteger.Multiply(constants.small_prime, constants.cofactor)))
                    Console.WriteLine("p - 1 does not equals to r * q.");

                if (constants.small_prime % constants.cofactor == 0)
                    Console.WriteLine("q is a divisor of r.");

                if (BigInteger.Compare(0, constants.generator) == -1 && BigInteger.Compare(constants.generator, expectedLarge) == 1)
                    Console.WriteLine("g is not in the range of 1 to p.");

                if (BigInteger.ModPow(constants.generator, constants.small_prime, constants.large_prime) != 1)
                    Console.WriteLine("g^q mod p is not equal to 1.");

                return !error;
            });
        }

        public async Task<bool> VerifyAllGuardians()
        {
            var error = false;
            var count = 0;
            await foreach (var guardian in dataService.GetGuardians())
            {
                if (!await VerifyGuardian(guardian, count))
                {
                    Console.WriteLine($"guardian {count} key generation verification failure.");
                    error = true;
                }
                count++;
            }

            if (!error)
                Console.WriteLine("All guardians' key generation verification success. ");

            // Verify guardian number
            if (context.number_of_guardians != count)
                Console.WriteLine("Number of guardian error.");

            return !error;
        }

        private async Task<bool> VerifyGuardian(Guardian guardian, int guardianId)
        {

            if (guardian == null)
                throw new ArgumentNullException(nameof(Guardian));
            var error = false;
            var i = 0;
            foreach (var coeffProof in guardian.coefficient_proofs)
            {
                // computes challenge (c_ij) with hash, H(cij = H(base hash, public key, commitment) % q, each guardian has quorum number of these challenges
                var challengeComputed = Numbers.ModP(await Numbers.HashSha256(context.crypto_base_hash, coeffProof.public_key, coeffProof.commitment));
                // check if the computed challenge value matches the given
                if (!coeffProof.challenge.Equals(challengeComputed))
                {
                    Console.WriteLine($"guardian {guardianId}, quorum {i}, challenge number error.");
                    error = true;
                }

                // check the equation generator ^ response mod p = (commitment * public key ^ challenge) mod p
                var left = BigInteger.ModPow(constants.generator, coeffProof.response, constants.large_prime);
                var right = BigInteger.Multiply(coeffProof.commitment, BigInteger.ModPow(coeffProof.public_key, coeffProof.challenge, constants.large_prime)) % constants.large_prime;
                if (!left.Equals(right))
                {
                    Console.WriteLine($"guardian {guardian.owner_id}, quorum {coeffProof.name}, equation error. ");
                    error = true;
                }
                i++;
            }

            return !error;
        }

        public async Task<bool> VerifyAllBallots()
        {
            var error = false;
            var count = 0;
            var ballots = dataService.GetEncryptedBallots();
            // verify all ballots, box 3 & 4
            var bev = new BallotEncryptionVerifier(context, constants, await dataService.GetVoteLimits());
            await foreach (var ballot in ballots)
            {
                // Verify correctness
                var contestResult = await bev.VerifyAllContests(ballot);
                if (!contestResult)
                {
                    error = true;
                    count++;
                }

                // Aggregate tracking hashes, box 5
                if (!await bev.VerifyTrackingHash(ballot))
                {
                    error = true;
                    count++;
                }
            }
            Console.WriteLine($"[Box 3 & 4] Ballot verification {(error ? "failure, ({count}) ballots didn't pass check." : "success")} ");

            error = !await bev.VerifyTrackingHashChain(await ballots.ToListAsync());

            Console.WriteLine($"[Box 5] Tracking hashes verification {(error ? "failure" : "success")}. ");

            return !error;
        }


    }
}