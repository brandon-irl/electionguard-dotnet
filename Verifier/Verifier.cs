using System;
using System.Reflection;
using System.Collections.Generic;
using System.Numerics;
using System.Threading.Tasks;
using ElectionGuard.Verifier.Core;
using Microsoft.Extensions.Logging;
using System.Linq;

namespace ElectionGuard.Verifier.App
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
                if (!await VerifyGuardian(guardian))
                    Console.WriteLine($"guardian {guardian.owner_id} key generation verification failure.");
                count++;
            }

            // Verify guardian number
            if (context.number_of_guardians != count)
                Console.WriteLine("Number of guardian error.");

            return !error;
        }

        private async Task<bool> VerifyGuardian(Guardian guardian)
        {
            return await Task.Run(() =>
            {
                if (guardian == null)
                    throw new ArgumentNullException(nameof(Guardian));
                var error = false;
                foreach (var coeffProof in guardian.coefficient_proofs)
                {
                    // computes challenge (c_ij) with hash, H(cij = H(base hash, public key, commitment) % q, each guardian has quorum number of these challenges
                    var challengeComputed = Numbers.HashSha256(context.crypto_base_hash, coeffProof.public_key, coeffProof.commitment) % constants.large_prime;
                    // check if the computed challenge value matches the given
                    if (!coeffProof.challenge.Equals(challengeComputed))
                        Console.WriteLine($"guardian {guardian.owner_id}, quorum {coeffProof.name}, challenge number error.");

                    // check the equation generator ^ response mod p = (commitment * public key ^ challenge) mod p
                    var left = BigInteger.ModPow(constants.generator, coeffProof.response, constants.large_prime);
                    var right = BigInteger.Multiply(coeffProof.commitment, BigInteger.ModPow(coeffProof.public_key, coeffProof.challenge, constants.large_prime)) % constants.large_prime;
                    if (!left.Equals(right))
                        Console.WriteLine($"guardian {guardian.owner_id}, quorum {coeffProof.name}, equation error. ");
                }

                return !error;
            });
        }

        public async Task<bool> VerifyAllBallots()
        {
            var error = false;
            await foreach (var ballot in dataService.GetEncryptedBallots())
            {
                await Task.Delay(1000);
            }
            return !error;
        }

        public async Task<bool> VerifyAllContests(EncryptedBallot ballot)
        {
            var error = false;
            foreach (var contest in ballot.contests)
            {
                var result = await VerifyContest(contest);

            }
            return !error;
        }

        public async Task<bool> VerifyContest(EncryptedBallot.Contest contest)
        {
            var error = false;

            foreach (var selection in contest.ballot_selections)
            {

            }

            await Task.Delay(1000);
            return !error;
        }

        public async Task<bool> VerifyBallotSelection(EncryptedBallot.Contest.BallotSelection selection)
        {
            var error = false;

            var pad = selection.ciphertext.pad;
            var data = selection.ciphertext.data;
            var proof = selection.proof;

            // point 1: check alpha, beta, a0, b0, a1, b1 are all in set Zrp
            if (!(CheckParams(selection.ciphertext, typeof(ZRPParameterAttribute), _ => Numbers.IsWithinSetZrp(_))
            && CheckParams(proof, typeof(ZRPParameterAttribute), _ => Numbers.IsWithinSetZrp(_))))
                error = true;

            // point 3: check if the given values, c0, c1, v0, v1 are each in the set zq
            if (!CheckParams(proof, typeof(ZQParameterAttribute), _ => Numbers.IsWithinSetZq(_)))
                error = true;

            // point 2: conduct hash computation, c = H(Q-bar, (alpha, beta), (a0, b0), (a1, b1))
            var challenge = Numbers.HashSha256(
                context.crypto_extended_base_hash,
                pad,
                data,
                proof.proof_zero_pad,
                proof.proof_zero_data,
                proof.proof_one_pad,
                proof.proof_one_data
            );

            // point 4:  c = c0 + c1 mod q is satisfied
            if (!CheckHashComp(challenge, proof.proof_zero_challenge, proof.proof_one_challenge))
            { }

            // point 5: check 2 chaum-pedersen proofs, zero proof and one proof
            if (!(CheckCpProofZeroProof(pad, data, proof.proof_zero_pad, proof.proof_zero_data, proof.proof_zero_challenge, proof.proof_zero_response)
            && CheckCpProofOneProof(pad, data, proof.proof_one_pad, proof.proof_one_data, proof.proof_one_challenge, proof.proof_one_response)))
            { }

            return !error;
        }

        private bool CheckCpProofZeroProof(BigInteger pad, BigInteger data, BigInteger zeroPad, BigInteger zeroData, BigInteger zeroChallenge, BigInteger zeroRes)
        {
            var equ1L = BigInteger.ModPow(constants.generator, zeroRes, constants.large_prime);
            var equ1R = BigInteger.Multiply(Numbers.ModP(zeroPad), BigInteger.ModPow(pad, zeroChallenge, Numbers.LargePrime));

            var equ2L = BigInteger.ModPow(context.elgamal_public_key, zeroRes, constants.large_prime);
            var equ2R = BigInteger.Multiply(Numbers.ModP(zeroData), BigInteger.ModPow(data, zeroChallenge, Numbers.LargePrime));

            var res = BigInteger.Equals(equ1L, equ1R) && BigInteger.Equals(equ2L, equ2R);
            if (!res)
                Console.WriteLine("Chaum-pedersen proof zero proof failure.");

            return res;
        }

        private bool CheckCpProofOneProof(BigInteger pad, BigInteger data, BigInteger onePad, BigInteger oneData, BigInteger oneChallenge, BigInteger oneRes)
        {
            var equ1L = BigInteger.ModPow(constants.generator, oneRes, constants.large_prime);
            var equ1R = Numbers.ModP(BigInteger.Multiply(onePad, BigInteger.ModPow(pad, oneChallenge, constants.large_prime)));

            var equ2L = Numbers.ModP(BigInteger.Multiply(BigInteger.ModPow(constants.generator, oneChallenge, constants.large_prime), BigInteger.ModPow(context.elgamal_public_key, oneRes, constants.large_prime)));
            var equ2R = Numbers.ModP(BigInteger.Multiply(oneData, BigInteger.ModPow(data, oneChallenge, constants.large_prime)));

            var res = BigInteger.Equals(equ1L, equ1R) && BigInteger.Equals(equ2L, equ2R);
            if(!res)
                Console.WriteLine("Chaum-pedersen proof one proof failure.");

            return res;
        }

        private bool CheckHashComp(BigInteger challenge, BigInteger zeroChallenge, BigInteger oneChallenge)
        {
            var expected = BigInteger.Add(Numbers.ModQ(zeroChallenge), oneChallenge);
            var res = BigInteger.Equals(Numbers.ModQ(challenge), expected);
            if (!res)
                Console.WriteLine("challenge value error.");
            return res;
        }

        private bool CheckParams<T>(T obj, Type attribute, Func<BigInteger, bool> isWithin)
        {
            var error = false;
            var props = typeof(T).GetProperties().Where(_ => Attribute.IsDefined(_, attribute));

            foreach (var prop in props)
            {
                var val = (BigInteger)prop.GetValue(obj);
                if (!isWithin(val))
                {
                    Console.WriteLine($"parameter error, {prop.Name} is not in set Zrp.");
                    error = true;
                }
            }

            return !error;
        }
    }
}