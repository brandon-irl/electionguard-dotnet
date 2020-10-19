using System.IO;

namespace ElectionGuard.Verifier.Core
{
    public class FilePathGenerator
    {
        private const string _fileExtension = "json";
        private readonly string _dataFolderPath;

        public string CoefficientsFolderPath { get => BuildFolderPath("coefficients"); }
        public string GuardianCoefficientFolderPath { get; }
        public string ContextFilePath { get => BuildFilePath("context"); }
        public string ConstantsFilePath { get => BuildFilePath("constants"); }
        public string TallyFilePath { get => BuildFilePath("tally"); }
        public string DescriptionFilePath { get => BuildFilePath("description"); }
        public string EncryptedBallotFolderPath { get => BuildFolderPath("encrypted_ballots"); }
        public string SpoiledBallotsFilePath { get => BuildFilePath("spoiled_ballots"); }
        public string DevicesFilePath { get => BuildFilePath("devices"); }

        public FilePathGenerator(string dataFolderPath = @"../data")
        {
            this._dataFolderPath = dataFolderPath;
        }
        private string BuildFolderPath(string folderName) => $"{_dataFolderPath}/{folderName}/";
        private string BuildFilePath(string fileName) => $"{_dataFolderPath}/{fileName}.{_fileExtension}";
    }
}
