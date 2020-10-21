using System;
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

    public class Description
    {
        public BallotStyle[] ballot_styles { get; set; }
        public Candidate[] candidates { get; set; }
        public ContactInformation contact_information { get; set; }
        public Contest[] contests { get; set; }
        public string election_scope_id { get; set; }
        public DateTime end_date { get; set; }
        public GeopoliticalUnit[] geopolitical_units { get; set; }
        public Name name { get; set; }
        public Party[] parties { get; set; }
        public DateTime start_date { get; set; }
        public string type { get; set; }

        public class BallotStyle
        {
            public string[] geopolitical_unit_ids { get; set; }
            public string object_id { get; set; }
        }

        public class Text
        {
            public string language { get; set; }
            public string value { get; set; }
        }

        public class BallotName
        {
            public Text[] text { get; set; }
        }

        public class Candidate
        {
            public BallotName ballot_name { get; set; }
            public string object_id { get; set; }
            public string party_id { get; set; }
        }

        public class Email
        {
            public string annotation { get; set; }
            public string value { get; set; }
        }

        public class Phone
        {
            public string annotation { get; set; }
            public string value { get; set; }
        }

        public class ContactInformation
        {
            public string[] address_line { get; set; }
            public Email[] email { get; set; }
            public string name { get; set; }
            public Phone[] phone { get; set; }
        }

        public class BallotSelection
        {
            public string candidate_id { get; set; }
            public string object_id { get; set; }
            public int sequence_order { get; set; }
        }

        public class Text2
        {
            public string language { get; set; }
            public string value { get; set; }
        }

        public class BallotSubtitle
        {
            public Text2[] text { get; set; }
        }

        public class Text3
        {
            public string language { get; set; }
            public string value { get; set; }
        }

        public class BallotTitle
        {
            public Text3[] text { get; set; }
        }

        public class Text4
        {
            public string value { get; set; }
            public string language { get; set; }
        }

        public class BallotDescription
        {
            public Text4[] text { get; set; }
        }

        public class Contest
        {
            public string @Type { get; set; }
            public BallotSelection[] ballot_selections { get; set; }
            public BallotSubtitle ballot_subtitle { get; set; }
            public BallotTitle ballot_title { get; set; }
            public string electoral_district_id { get; set; }
            public string name { get; set; }
            public int number_elected { get; set; }
            public string object_id { get; set; }
            public int sequence_order { get; set; }
            public string vote_variation { get; set; }
            public int votes_allowed { get; set; }
            public BallotDescription ballotDescription { get; set; }
        }

        public class Email2
        {
            public string annotation { get; set; }
            public string value { get; set; }
        }

        public class Phone2
        {
            public string annotation { get; set; }
            public string value { get; set; }
        }

        public class ContactInformation2
        {
            public string[] address_line { get; set; }
            public Email2[] email { get; set; }
            public string name { get; set; }
            public Phone2[] phone { get; set; }
        }

        public class GeopoliticalUnit
        {
            public ContactInformation2 contact_information { get; set; }
            public string name { get; set; }
            public string object_id { get; set; }
            public string type { get; set; }
        }

        public class Text5
        {
            public string language { get; set; }
            public string value { get; set; }
        }

        public class Name
        {
            public Text5[] text { get; set; }
        }

        public class BallotName2
        {
            public object[] text { get; set; }
        }

        public class Text6
        {
            public string value { get; set; }
            public string language { get; set; }
        }

        public class Name2
        {
            public Text6[] text { get; set; }
        }

        public class Party
        {
            public string abbreviation { get; set; }
            public BallotName2 ballot_name { get; set; }
            public string color { get; set; }
            public string logo_uri { get; set; }
            public Name2 name { get; set; }
            public string object_id { get; set; }
        }
    }
}