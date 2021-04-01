using System;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace ElectionGuard.Core
{
    public class BallotSelectionVerifier
    {
        private readonly Context context;
        private readonly Constants constants;

        public BallotSelectionVerifier(Context context, Constants constants)
        {
            this.context = context;
            this.constants = constants;
        }

        public async Task<bool> VerifyBallotSelection(EncryptedBallot.Contest.BallotSelection selection)
        {
            var error = false;

            var pad = selection.ciphertext.pad;
            var data = selection.ciphertext.data;
            var proof = selection.proof;

            // point 1: check alpha, beta, a0, b0, a1, b1 are all in set Zrp
            if (!(CheckParams(selection.ciphertext, typeof(ZRPParameterAttribute), _ => Numbers.IsWithinSetZrp(_)) && CheckParams(proof, typeof(ZRPParameterAttribute), _ => Numbers.IsWithinSetZrp(_))))
                error = true;

            // point 3: check if the given values, c0, c1, v0, v1 are each in the set zq
            if (!CheckParams(proof, typeof(ZQParameterAttribute), _ => Numbers.IsWithinSetZq(_)))
                error = true;

            // point 2: conduct hash computation, c = H(Q-bar, (alpha, beta), (a0, b0), (a1, b1))
            var challenge = await Numbers.HashSha256(
                context.crypto_extended_base_hash,
                pad,
                data,
                proof.proof_zero_pad,
                proof.proof_zero_data,
                proof.proof_one_pad,
                proof.proof_one_data
            );

            // point 4:  c = c0 + c1 mod q is satisfied
            // TODO: Verify that this works
            if (!CheckHashComp(challenge, proof.proof_zero_challenge, proof.proof_one_challenge))
                error = true;

            // point 5: check 2 chaum-pedersen proofs, zero proof and one proof
            if (!(CheckCpProofZeroProof(pad, data, proof.proof_zero_pad, proof.proof_zero_data, proof.proof_zero_challenge, proof.proof_zero_response)
            && CheckCpProofOneProof(pad, data, proof.proof_one_pad, proof.proof_one_data, proof.proof_one_challenge, proof.proof_one_response)))
                error = true;

            if (error)
                Console.WriteLine($"{selection.object_id} validity verification failure.");

            return !error;
        }

        public bool VerifySelectionLimit(EncryptedBallot.Contest.BallotSelection selection)
        {
            var a = Numbers.IsWithinSetZrp(selection.ciphertext.pad);
            var b = Numbers.IsWithinSetZrp(selection.ciphertext.data);
            if (!a)
                Console.WriteLine("selection pad/a value error.");
            if (!b)
                Console.WriteLine("selection data/b value error.");
            return a && b;
        }

        private bool CheckCpProofZeroProof(BigInteger pad, BigInteger data, BigInteger zeroPad, BigInteger zeroData, BigInteger zeroChallenge, BigInteger zeroRes)
        {
            /*
            check if Chaum-Pedersen proof zero proof(given challenge c0, response v0) is satisfied.

            To proof the zero proof, two equations g ^ v0 = a0 * alpha ^ c0 mod p, K ^ v0 = b0 * beta ^ c0 mod p
            have to be satisfied.
            In the verification process, the challenge c of a selection is allowed to be broken into two components
            in any way as long as c = (c0 + c1) mod p, c0 here is the first component broken from c.

            :param pad: alpha of a selection
            :param data: beta of a selection
            :param zero_pad: zero_pad of a selection
            :param zero_data: zero_data of a selection
            :param zero_chal: zero_challenge of a selection
            :param zero_res: zero_response of a selection
            :return: True if both equations of the zero proof are satisfied, False if either is not satisfied
            */
            var equ1L = BigInteger.ModPow(constants.generator, zeroRes, constants.large_prime);
            var equ1R = Numbers.ModP(BigInteger.Multiply(zeroPad, BigInteger.ModPow(pad, zeroChallenge, constants.large_prime)));

            var equ2L = BigInteger.ModPow(context.elgamal_public_key, zeroRes, constants.large_prime);
            var equ2R = Numbers.ModP(BigInteger.Multiply(zeroData, BigInteger.ModPow(data, zeroChallenge, Numbers.LargePrime)));

            var res = BigInteger.Equals(equ1L, equ1R) && BigInteger.Equals(equ2L, equ2R);
            if (!res)
                Console.WriteLine("Chaum-pedersen proof zero proof failure.");

            return res;
        }

        private bool CheckCpProofOneProof(BigInteger pad, BigInteger data, BigInteger onePad, BigInteger oneData, BigInteger oneChallenge, BigInteger oneRes)
        {
            /*
            check if Chaum-Pedersen proof one proof(given challenge c1, response v1) is satisfied.

            To proof the zero proof, two equations g ^ v1 = a1 * alpha ^ c1 mod p, g ^ c1 * K ^ v1 = b1 * beta ^ c1 mod p
            have to be satisfied.
            In the verification process, the challenge c of a selection is allowed to be broken into two components
            in any way as long as c = (c0 + c1) mod p, c1 here is the second component broken from c.

            :param pad: alpha of a selection
            :param data: beta of a selection
            :param one_pad: one_pad of a selection
            :param one_data: one_data of a selection
            :param one_chal: one_challenge of a selection
            :param one_res: one_response of a selection
            :return: True if both equations of the one proof are satisfied, False if either is not satisfied
            */
            var equ1L = BigInteger.ModPow(constants.generator, oneRes, constants.large_prime);
            var equ1R = Numbers.ModP(BigInteger.Multiply(onePad, BigInteger.ModPow(pad, oneChallenge, constants.large_prime)));

            var equ2L = Numbers.ModP(BigInteger.Multiply(BigInteger.ModPow(constants.generator, oneChallenge, constants.large_prime), BigInteger.ModPow(context.elgamal_public_key, oneRes, constants.large_prime)));
            var equ2R = Numbers.ModP(BigInteger.Multiply(oneData, BigInteger.ModPow(data, oneChallenge, constants.large_prime)));

            var res = BigInteger.Equals(equ1L, equ1R) && BigInteger.Equals(equ2L, equ2R);
            if (!res)
                Console.WriteLine("Chaum-pedersen proof one proof failure.");

            return res;
        }

        private bool CheckHashComp(BigInteger challenge, BigInteger zeroChallenge, BigInteger oneChallenge)
        {
            var expected = Numbers.ModQ(BigInteger.Add(zeroChallenge, oneChallenge));
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