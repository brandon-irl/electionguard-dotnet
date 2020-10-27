namespace ElectionGuard.Verifier.Data
{
    public class DataOptions
    {
        public const string Data = "Data";
        public string BaseDir { get; set; }
        public string ConstantsFileName { get; set; }
        public string ContextFileName { get; set; }
        public string DescriptionFileName { get; set; }
        public string CoefficientsFolderPath { get; set; }
        public string EncryptedBallotsFolderPath { get; set; }
        public string TallyFileName { get; set; }
    }
}