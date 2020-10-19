using System.Numerics;

namespace ElectionGuard.Verifier.Core
{
    public class Context
    {
        public BigInteger crypto_base_hash { get; set; }
        public BigInteger crypto_extended_base_hash { get; set; }
        public BigInteger description_hash { get; set; }
        public BigInteger elgamal_public_key { get; set; }
        public int number_of_guardians { get; set; }
        public int quorum { get; set; }
    }

    public class Constants
    {
        public BigInteger cofactor { get; set; }
        public BigInteger generator { get; set; }
        public BigInteger large_prime { get; set; }
        public BigInteger small_prime { get; set; }
    }

    public class Guardian
    {
        public BigInteger[] coefficient_commitments { get; set; }
        public CoefficientProof[] coefficient_proofs { get; set; }
        public string owner_id { get; set; }

        public class CoefficientProof
        {
            public BigInteger challenge { get; set; }
            public BigInteger commitment { get; set; }
            public string name { get; set; }
            public BigInteger public_key { get; set; }
            public BigInteger response { get; set; }
            public string usage { get; set; }
        }
    }

    public class EncryptedBallot
    {
        public string ballot_style { get; set; }
        public Contest[] contests { get; set; }
        public BigInteger crypto_hash { get; set; }
        public string nonce { get; set; }
        public string object_id { get; set; }
        public BigInteger previous_tracking_hash { get; set; }
        public string state { get; set; }
        public long timestamp { get; set; }
        public BigInteger tracking_hash { get; set; }

        public class Contest
        {
            public BallotSelection[] ballot_selections { get; set; }
            public BigInteger crypto_hash { get; set; }
            public BigInteger description_hash { get; set; }
            public string object_id { get; set; }
            public Proof proof { get; set; }

            public class BallotSelection
            {
                public CipherText ciphertext { get; set; }
                public BigInteger crypto_hash { get; set; }
                public BigInteger description_hash { get; set; }
                public bool is_placeholder_selection { get; set; }
                public string object_id { get; set; }
                public Proof proof { get; set; }

                public class CipherText
                {
                    [ZRPParameter]
                    public BigInteger pad { get; set; }
                    [ZRPParameter]
                    public BigInteger data { get; set; }
                }

                public class Proof
                {
                    public string name { get; set; }
                    public string usage { get; set; }
                    [ZQParameter]
                    public BigInteger challenge { get; set; }
                    public BigInteger proof_one_challenge { get; set; }
                    [ZRPParameter]
                    public BigInteger proof_one_data { get; set; }
                    [ZRPParameter]
                    public BigInteger proof_one_pad { get; set; }
                    [ZQParameter]
                    public BigInteger proof_one_response { get; set; }
                    [ZQParameter]
                    public BigInteger proof_zero_challenge { get; set; }
                    [ZRPParameter]
                    public BigInteger proof_zero_data { get; set; }
                    [ZRPParameter]
                    public BigInteger proof_zero_pad { get; set; }
                    [ZQParameter]
                    public BigInteger proof_zero_response { get; set; }
                }
            }

            public class Proof
            {
                public BigInteger challenge { get; set; }
                public int constant { get; set; }
                public BigInteger data { get; set; }
                public string name { get; set; }
                public BigInteger pad { get; set; }
                public BigInteger response { get; set; }
                public string usage { get; set; }
            }
        }
    }
}