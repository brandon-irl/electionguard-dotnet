using System;
using System.Collections.Generic;
using System.Numerics;
using System.Threading.Tasks;
using static ElectionGuard.Core.EncryptedBallot;

namespace ElectionGuard.Core
{
    public class BallotContestVerifier
    {
        private readonly Context context;
        private readonly Constants constants;
        private readonly Dictionary<string, int> voteLimits;

        public BallotContestVerifier(Context context, Constants constants, Dictionary<string, int> voteLimits)
        {
            this.context = context;
            this.constants = constants;
            this.voteLimits = voteLimits;
        }

        // verify a contest within a ballot, ballot correctness
        public async Task<(bool, bool)> VerifyContest(EncryptedBallot.Contest contest)
        {
            bool encryptionError = false, limitError = false;
            var voteLimit = voteLimits[contest.object_id];

            var placeHolderCount = 0;
            BigInteger alphaProd = 1, betaProd = 1;
            // verify encryption correctness on every selection  - selection check
            // create selection verifiers
            var sv = new BallotSelectionVerifier(context, constants);
            foreach (var selection in contest.ballot_selections)
            {
                // get alpha, beta products
                alphaProd = BigInteger.Multiply(alphaProd, selection.ciphertext.pad % constants.large_prime);
                betaProd = BigInteger.Multiply(betaProd, selection.ciphertext.pad % constants.large_prime);
                // check validity of a selection
                if (!await sv.VerifyBallotSelection(selection))
                    encryptionError = true;
                // check selection limit, whether each a and b are in zrp
                if (!sv.VerifySelectionLimit(selection))
                    limitError = true;
                // get placeholder counts
                if (selection.is_placeholder_selection)
                    placeHolderCount++;
            }
            // verify the placeholder numbers match the maximum votes allowed - contest check
            if (placeHolderCount != voteLimit)
            {
                Console.WriteLine("contest placeholder number error. ");
                limitError = true;
            }

            // check if given contest challenge matches the computation
            // calculate c = H(Q-bar, (A,B), (a,b)
            var challengeComputed = Numbers.HashSha256(context.crypto_extended_base_hash, alphaProd, betaProd, contest.proof.pad, contest.proof.data);
            if (!BigInteger.Equals(challengeComputed, contest.proof.challenge))
            {
                Console.Write("Contest challenge error. ");
                limitError = true;
            }

            var equ1Check = CheckCpProofAlpha(contest, alphaProd);
            var equ2Check = CheckCpProofBeta(contest, betaProd, voteLimit);

            if (!equ1Check || !equ2Check)
                limitError = true;

            if (limitError || encryptionError)
                Console.WriteLine($"{contest.object_id} verification failure: {(encryptionError ? "encryption error" : "")} {(limitError ? " selection limit error" : "")}");

            return (!encryptionError, !limitError);
        }

        private bool CheckCpProofAlpha(Contest contest, BigInteger alphaProduct)
        {
            /*
            check if equation g ^ v = a * A ^ c mod p is satisfied,
            This function checks the first part of aggregate encryption, A in (A, B), is used together with
            __check_cp_proof_beta() to form a pair-wise check on a complete encryption value pair (A,B)
            :param alpha_product: the accumulative product of all the alpha/pad values on all selections within a contest
            :return: True if the equation is satisfied, False if not
            */

            var left = BigInteger.ModPow(constants.generator, contest.proof.response, constants.large_prime);
            var right = Numbers.ModP(BigInteger.Multiply(Numbers.ModP(contest.proof.pad), BigInteger.ModPow(alphaProduct, contest.proof.challenge, constants.large_prime)));
            var res = BigInteger.Equals(left, right);
            if (!res)
                Console.WriteLine("Contest selection limit check equation 1 error. ");

            return res;
        }

        private bool CheckCpProofBeta(Contest contest, BigInteger betaProduct, int votesAllowed)
        {
            /*
           check if equation g ^ (L * c) * K ^ v = b * B ^ C mod p is satisfied
           This function checks the second part of aggregate encryption, B in (A, B), is used together with
            __check_cp_proof_alpha() to form a pair-wise check on a complete encryption value pair (A,B)
           :param beta_product: the accumalative product of pad/beta values of all the selections within a contest
           :param votes_allowed: the maximum votes allowed for this contest
           :return: True if the equation is satisfied, False if not
           */

            var left = Numbers.ModP(BigInteger.Multiply(BigInteger.ModPow(constants.generator, Numbers.ModQ(votesAllowed * contest.proof.challenge), constants.large_prime),
            BigInteger.ModPow(context.elgamal_public_key, contest.proof.response, constants.large_prime)));
            var right = Numbers.ModP(contest.proof.data * BigInteger.ModPow(context.elgamal_public_key, contest.proof.response, constants.large_prime));

            var res = BigInteger.Equals(left, right);
            if (res)
                Console.WriteLine("contest selection limit check equation 2 error. ");
            return res;
        }
    }
}