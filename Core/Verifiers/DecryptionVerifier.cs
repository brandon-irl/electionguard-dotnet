using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace ElectionGuard.Verifier.Core

{
    public class DecryptionVerifier
    {
        private readonly Description description;
        private readonly IEnumerable<EncryptedBallot> encryptedBallots;
        private readonly Tally tally;
        private readonly IEnumerable<BigInteger> publicKeys;
        private readonly Constants constants;
        private Dictionary<string, (Dictionary<string, string> pad, Dictionary<string, string> data)> contestPadDataMap;
        private Dictionary<string, (Dictionary<string, BigInteger> pad, Dictionary<string, BigInteger> data)> totalPadDataMap;

        public DecryptionVerifier(Description description, IEnumerable<EncryptedBallot> encryptedBallots, Tally tally, IEnumerable<BigInteger> publicKeys, Constants constants)
        {
            this.description = description;
            this.encryptedBallots = encryptedBallots;
            this.tally = tally;
            this.publicKeys = publicKeys;
            this.constants = constants;
            FillTotalPadData();
            FillInDics();
        }

        public bool MatchTotalAcrossBallots()
        {
            /*
            matching the given tallies with accumulative products calculated across all ballots
            :param aggregator: a SelectionInfoAggregator instance for accessing information of a selection
            :param contest_names: a list of unique contest names, listed as "object_id" under contests
            :return: true if all the tallies match, false if not
            */

            var error = false;

            foreach (var contest in tally.contests)
            {

                foreach (var selection in contest.Value.selections)
                {
                    // Pad
                    var tallyPad = totalPadDataMap.GetValueOrDefault(contest.Key).pad[selection.Key];
                    var accumPad = contestPadDataMap.GetValueOrDefault(contest.Key).pad[selection.Key];
                    // Data
                    var tallyData = totalPadDataMap.GetValueOrDefault(contest.Key).data[selection.Key];
                    var accumData = contestPadDataMap.GetValueOrDefault(contest.Key).data[selection.Key];

                    if (!BigInteger.Equals(accumPad, tallyPad) || !BigInteger.Equals(accumData, tallyData))
                        error = true;

                    if (error)
                        Console.WriteLine("Tally error.");

                    return !error;
                }
            }

            return !error;
        }

        public async Task<bool> MakeAllContestVerification(IEnumerable<Tally.Contest> contests)
        {
            /*
            helper function used in verify_cast_ballot_tallies() and verify_a_spoiled_ballot(str),
            verifying all contests in a ballot by calling the DecryptionContestVerifier
            :return: true if no error has been found in any contest verification in this cast ballot tallies or
            spoiled ballot check, false otherwise
            */
            var error = false;
            foreach (var contest in contests)
            {
                var errorr = false;
                foreach (var selection in contest.selections.Values)
                {
                    var errorrr = false;
                    var i = 0;
                    foreach (var share in selection.shares)
                    {
                        errorrr = await VerifyShare(share, selection, i);
                        if (!errorrr) Console.WriteLine($"Guardian {i} decryption error.");
                        i++;
                    }
                    if (errorrr)
                    {
                        Console.WriteLine($"{selection.object_id} tally verification error. ");
                        errorr = errorrr;
                    }
                }
                if (errorr)
                {
                    Console.WriteLine($"{contest.object_id} tally decryption failure. ");
                    error = errorr;
                }
            }

            Console.WriteLine($"{tally.object_id} [box 6 & 9] decryption verification {(error ? "failure" : "success")}");

            return !error;
        }

        private async Task<bool> VerifyShare(Tally.Contest.Selection.Share share, Tally.Contest.Selection selection, int i)
        {
            /*
            verify one share at a time, check box 6 requirements,
            (1) if the response vi is in the set Zq
            (2) if the given ai, bi are both in set Zrp
            */

            // check if the response vi is in the set Zq
            var responseCorrectness = Numbers.IsWithinSetZq(share.proof.response);
            if (!responseCorrectness)
                Console.WriteLine("response error.");

            // check if the given ai, bi are both in set Zrp
            var padDataCorrectness = Numbers.IsWithinSetZrp(share.proof.pad) && Numbers.IsWithinSetZrp(share.proof.data);
            if (!padDataCorrectness)
                Console.WriteLine("a/pad value error.");

            // check if challenge is correctly computed: challenge values Ci satisfies ci = H(Q-bar, (A,B), (ai, bi), Mi)
            var challengeCorrectness = BigInteger.Equals(
                share.proof.challenge,
                await Numbers.HashSha256(share.proof.pad, share.proof.data, share.share)
            );
            if (!challengeCorrectness)
                Console.WriteLine("challenge value error.");

            // check equations
            var equ1 = CheckEquation(constants.generator, share.proof.pad, share.proof.response, share.proof.challenge, publicKeys.ElementAt(i)); //check if equation g ^ vi = ai * (Ki ^ ci) mod p is satisfied.
            var equ2 = CheckEquation(selection.message.pad, share.proof.data, share.proof.response, share.proof.challenge, share.share); // check if equation A ^ vi = bi * (Mi^ ci) mod p is satisfied.

            var error = (responseCorrectness || padDataCorrectness || challengeCorrectness || equ1 || equ2);
            if (error)
                Console.WriteLine("partial decrytion failure.");
            return !error;
        }

        private void FillTotalPadData()
        {
            /*
            loop over the tally.json file and read alpha/pad and beta/data of each non dummy selections in all contests,
            store these alphas and betas in the corresponding contest dictionary
            :return: none
            */
            totalPadDataMap = tally.contests
                                .ToDictionary(
                                    _ => _.Key,
                                    _ => (_.Value.selections.ToDictionary(_ => _.Key, _ => _.Value.message.pad), _.Value.selections.ToDictionary(_ => _.Key, _ => _.Value.message.data))
                                );
        }

        private void FillInDics()
        {
            /*
            loop over the folder that stores all encrypted ballots once, go through every ballot to get the selection
            alpha/pad and beta/data
            :return: none
            */

            contestPadDataMap = new Dictionary<string, (Dictionary<string, string> pad, Dictionary<string, string> data)>();

            foreach (var ballot in encryptedBallots.Where(_ => _.state == "CAST")) // ignore spoiled ballots
            {
                foreach (var contest in ballot.contests)
                {
                    if (!contestPadDataMap.ContainsKey(contest.object_id))
                        contestPadDataMap.Add(contest.object_id, (new Dictionary<string, string>(), new Dictionary<string, string>()));
                    var (padDict, dataDict) = contestPadDataMap[contest.object_id];
                    foreach (var selection in contest.ballot_selections.Where(_ => !_.is_placeholder_selection))
                    {
                        padDict[selection.object_id] = GetAccumProduct(padDict.GetValueOrDefault(selection.object_id), selection.ciphertext.pad);
                        dataDict[selection.object_id] = GetAccumProduct(dataDict.GetValueOrDefault(selection.object_id), selection.ciphertext.data);
                    }
                }
            }
        }

        private string GetAccumProduct(string existing, BigInteger updated)
        {
            if (String.IsNullOrWhiteSpace(existing))
                return updated.ToString();

            if (BigInteger.TryParse(existing, out var temp))
            {
                var product = Numbers.ModP(BigInteger.Multiply(temp, updated));
                return product.ToString();
            }
            return "ERROR";
        }

        public bool CheckEquation(BigInteger A, BigInteger B, BigInteger response, BigInteger challenge, BigInteger guardianInfo)
        {
            var left = BigInteger.ModPow(A, response, constants.large_prime);
            var right = Numbers.ModP(BigInteger.Multiply(B, BigInteger.ModPow(guardianInfo, challenge, constants.large_prime)));

            var error = BigInteger.Equals(left, right);
            if (!error)
                Console.WriteLine($"equation error.");
            return error;
        }

    }
}