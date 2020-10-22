using System;
using System.Collections;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ElectionGuard.Verifier.Core
{
    public class Numbers
    {
        // Random generator (thread safe)
        private static ThreadLocal<Random> s_Gen = new ThreadLocal<Random>(() => new Random());

        // Random generator (thread safe)
        private static Random Gen { get => s_Gen.Value; }

        public static BigInteger LargePrime { get; private set; }
        public static BigInteger SmallPrime { get; private set; }

        static Numbers()
        {
            var largePrimeString = @"104438888141315250669175271071662438257996424904738378038423348328
3953907971553643537729993126875883902173634017777416360502926082946377942955704498
5420976148418252467735806893983863204397479111608977315510749039672438834271329188
1374801626975452234350528589881677721176191239277291448552115552164104927344620757
8961939840619466145806859275053476560973295158703823395710210329314709715239251736
5523840808458360487786673189314183384224438910259118847234330847012077719019445932
8662497991739135056466263272370300796422984915475619689061525228653308964318490270
6926081744149289517418249153634178342075381874131646013444796894582106870531535803
6662545796026324531037414525697939055519015418561732513850474148403927535855819099
5015804625681054267836812127850996052095762473794291460031064660979266501285839738
1435755902851312071248102599442308951327039250818892493767423329663783709190716162
0235296692173009397831714158082331468230007669177892861540060422814237337064629052
4377485454312723950024587358201266366643058386277816736954760301634424272959224454
4608279405999759391099775667746401633668308698186721172238255007962658564443858927
6348504157753488390520266757856948263869301753031434500465754608438799417919463132
99322976993405829119";

            LargePrime = BigInteger.Parse(Regex.Replace(largePrimeString, @"\t|\n|\r", ""));
            SmallPrime = BigInteger.Pow(2, 256) - 189;
        }

        public static Boolean IsProbablyPrime(BigInteger value, int witnesses = 5)
        {
            if (value <= 1) return false;
            if (witnesses <= 0) witnesses = 5;
            var d = value - 1;
            var s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            var bytes = new byte[value.ToByteArray().LongLength];
            BigInteger a;
            for (var i = 0; i < witnesses; i++)
            {
                do
                {
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= value - 2);

                var x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1)
                    continue;

                for (var r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1)
                        return false;
                    if (x == value - 1)
                        break;
                }

                if (x != value - 1)
                    return false;
            }

            return true;
        }

        public static bool IsWithinRange(BigInteger num, BigInteger lower, BigInteger upper) =>
           BigInteger.Compare(num, lower) > 0 && BigInteger.Compare(num, upper) < 0;

        public static bool IsWithinSetZq(BigInteger num) =>
            IsWithinRange(num, -1, SmallPrime);

        public static bool IsWithinSetZstarp(BigInteger num) =>
            IsWithinRange(num, 0, LargePrime);

        public static bool IsWithinSetZrp(BigInteger num) =>
            IsWithinRange(num, 0, LargePrime) && BigInteger.Equals(1, BigInteger.ModPow(num, SmallPrime, LargePrime));

        public static BigInteger ModP(BigInteger dividend) => dividend % LargePrime;

        public static BigInteger ModQ(BigInteger dividend) => dividend % SmallPrime;

        // TODO: Figure out why this is broken
        public static Task<BigInteger> HashSha256<T>(params T[] elements)
        {
            return Task.Run(() =>
            {
                var pipeBytes = Encoding.UTF8.GetBytes("|");
                using (var sha = SHA256.Create())
                {
                    sha.TransformBlock(pipeBytes, 0, pipeBytes.Length, null, 0);
                    for (var i = 0; i < elements.Length; i++)
                    {
                        var ele = elements[i];
                        var hashMe = ele == null
                            ? "null"
                            : ele is string // Needs to be here because a string is an IEnumerable
                                ? ele.ToString()
                                : ele is IEnumerable
                                    ? HashSha256(ele).ToString()
                                    : ele.ToString();

                        var arr = Encoding.UTF8.GetBytes(hashMe + "|");
                        sha.TransformBlock(arr, 0, arr.Length, null, 0);

                        if (i == elements.Length - 1)
                            sha.TransformFinalBlock(arr, 0, 0);
                    }
                    
                    var bytes = sha.Hash.Reverse()   // BigInteger cotr expects input to be little endian, so we must reverse it
                        .Concat(new byte[] { 0 })    // Must apppend 00 byte to end of array to signal unsigned
                        .ToArray();

                    Console.WriteLine("your shit is " + BitConverter.ToString(sha.Hash).Replace("-", ""));
                    return new BigInteger(bytes) % BigInteger.Add(SmallPrime, BigInteger.MinusOne);
                }
            });
        }
    }
}