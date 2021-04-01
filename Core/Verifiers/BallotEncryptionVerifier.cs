using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace ElectionGuard.Core
{
    public class BallotEncryptionVerifier
    {
        private readonly Context context;
        private readonly Constants constants;
        private readonly Dictionary<string, int> voteLimits;

        public BallotEncryptionVerifier(Context context, Constants constants, Dictionary<string, int> voteLimits)
        {
            this.context = context;
            this.constants = constants;
            this.voteLimits = voteLimits;
        }

        public async Task<bool> VerifyAllContests(EncryptedBallot ballot)
        {
            /*
            verify all the contests within a ballot and check if there are any encryption or limit error
            :return: True if all contests checked out/no error, False if any error in any selection
            */
            var (encryptError, limitError) = (false, false);
            var conVerf = new BallotContestVerifier(context, constants, voteLimits);
            foreach (var contest in ballot.contests)
            {
                (encryptError, limitError) = await conVerf.VerifyContest(contest);
            }

            if (!encryptError && !limitError)
                Console.WriteLine(ballot.object_id + " [box 3 & 4] ballot correctness verification success.");
            else
            if (encryptError)
                Console.WriteLine(ballot.object_id + " [box 3] ballot encryption correctness verification failure.");
            if (limitError)
                Console.WriteLine(ballot.object_id + " [box 4] ballot limit check failure. ");

            return !(encryptError && limitError);
        }

        public async Task<bool> VerifyTrackingHash(EncryptedBallot ballot)
        {
            var currHashComputed = await Numbers.HashSha256(ballot.previous_tracking_hash, ballot.timestamp, ballot.crypto_hash);
            return BigInteger.Equals(ballot.tracking_hash, currHashComputed);
        }

        public async Task<bool> VerifyTrackingHashChain(IEnumerable<EncryptedBallot> ballots)
        {
            var error = false;
            var trackingHashes = ballots.ToDictionary(_ => _.tracking_hash, _ => _.previous_tracking_hash);

            // find the set that only contains first and last hash
            var first = trackingHashes.Keys.Where(_ => !trackingHashes.ContainsValue(_));
            var last = trackingHashes.Values.Where(_ => !trackingHashes.ContainsKey(_));
            var firstLastSet = first.Union(last);

            var firstHash = firstLastSet.FirstOrDefault(_ => trackingHashes.Values.Contains(_));
            var lastHash = firstLastSet.FirstOrDefault(_ => trackingHashes.Keys.Contains(_));

            // verify the first hash H0 = H(Q-bar)
            var zeroHash = await Numbers.HashSha256(context.crypto_extended_base_hash);

            if (!BigInteger.Equals(zeroHash, firstHash))
                error = true;

            // verify the closing hash, H-bar = H(Hl, 'CLOSE')
            //var  closingHashComputed = Numbers.HashSha256(lastHash, "CLOSE");

            return !error;
        }

    }
}