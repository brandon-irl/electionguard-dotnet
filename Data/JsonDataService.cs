using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using ElectionGuard.Verifier.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ElectionGuard.Verifier.Data
{
    public class JsonDataService : IDataService
    {
        const string fileExtension = "json";
        private readonly IOptions<DataOptions> dataOptions;
        private readonly ILogger<JsonDataService> logger;
        private readonly JsonSerializerOptions options = new JsonSerializerOptions();

        public JsonDataService(IOptions<DataOptions> dataOptions, ILogger<JsonDataService> logger, IConfiguration configuration)
        {
            this.dataOptions = dataOptions;
            this.logger = logger;

            options.Converters.Add(new JsonConverterBigInteger());
        }

        public async Task<Context> GetContext() => await GetFromFile<Context>(dataOptions.Value.ContextFileName);
        public async Task<Constants> GetConstants() => await GetFromFile<Constants>(dataOptions.Value.ConstantsFileName);

        public async IAsyncEnumerable<Guardian> GetGuardians()
        {
            await foreach(var file in GetFromFiles<Guardian>(Path.Combine(dataOptions.Value.BaseDir, dataOptions.Value.CoefficientsFolderPath)))
                yield return file;
        }

        public async IAsyncEnumerable<EncryptedBallot> GetEncryptedBallots()
        {
            await foreach(var file in GetFromFiles<EncryptedBallot>(Path.Combine(dataOptions.Value.BaseDir, dataOptions.Value.EncryptedBallotsFolderPath)))
                yield return file;
        }

        private async IAsyncEnumerable<T> GetFromFiles<T>(string path)
        {
            var files = new DirectoryInfo(path).GetFiles();
            foreach (var file in files)
                yield return await GetFromFile<T>(file.Name, path);
        }

        private async Task<T> GetFromFile<T>(string fileName, string path = "")
        {
            if (String.IsNullOrEmpty(path))
                path = dataOptions.Value.BaseDir;
            var result = default(T);
            using (var fs = File.OpenRead(Path.ChangeExtension(Path.Combine(path, fileName), fileExtension)))
                result = await JsonSerializer.DeserializeAsync<T>(fs, options);
            return result;
        }
    }

    public sealed class JsonConverterBigInteger : JsonConverter<BigInteger>
    {
        public override BigInteger Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => TryGetBigInteger(ref reader, out var bi) ? bi : throw new JsonException();

#if NETSTANDARD2_0
        public static bool TryGetBigInteger(ref Utf8JsonReader reader, out BigInteger bi)
        {
            var byteArray = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray();
            var str = Encoding.UTF8.GetString(byteArray);
            return BigInteger.TryParse(str, out bi);
        }
#else
        public static bool TryGetBigInteger(ref Utf8JsonReader reader, out BigInteger bi)
        {
            var byteSpan = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
            Span<char> chars = stackalloc char[byteSpan.Length];
            Encoding.UTF8.GetChars(reader.ValueSpan, chars);
            return BigInteger.TryParse(chars, out bi);
        }
#endif

        public override void Write(Utf8JsonWriter writer, BigInteger value, JsonSerializerOptions options)
        {
            // TODO: in fact, there will be a loss of accuracy;
            // TODO: there is no (yet) API on Utf8JsonReader that allows you to write JsonTokenType.Number tokens of arbitrary length

            // example:
            // BigInteger 636474637870330463636474637870330463636474637870330463 -> double 6.3647463787033043E+53

            // see Very_Very_Long_Number_Should_Return_As_Is_For_BigInteger and Very__Very_Long_Number_In_Input_Should_Work_For_BigInteger tests
            // tests succeed because the original (expected) string result first parsed to ExecutionResult and then converted back to string,
            // so finally we compare 6.3647463787033043E+53 with 6.3647463787033043E+53, not with original number value 636474637870330463636474637870330463636474637870330463
            writer.WriteNumberValue((double)value);
        }
    }
}