using System.IO.Enumeration;
using System.Reflection;


namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// An attribute to retrieve files with the given glob pattern.
    /// </summary>
    public sealed class FilesDataAttribute: Attribute, ITestDataSource
    {
        /// <summary>
        /// The directory to search for files.
        /// </summary>
        private string DirectoryPath { get; }

        /// <summary>
        /// The search pattern to apply for files.
        /// </summary>
        private string SearchPattern { get; }

        /// <summary>
        /// The option to search for files.
        /// </summary>
        private SearchOption SearchOption { get; }


        /// <summary>
        /// Loads the given file.
        /// </summary>
        /// <param name="file">The file to load.</param>
        public FilesDataAttribute(string file): this(Path.GetDirectoryName(file ?? Path.GetTempPath()) ?? Path.GetTempPath(), Path.GetFileName(file ?? Path.GetTempFileName()), SearchOption.TopDirectoryOnly) { }


        /// <summary>
        /// Loads files from a given directory with a given search pattern.
        /// </summary>
        /// <param name="directory">The absolute or relative path to the JSON file to load</param>
        public FilesDataAttribute(string directory, string searchPattern) : this(directory, searchPattern, SearchOption.AllDirectories) { }


        /// <summary>
        /// Loads files from a given directory with a given search pattern.
        /// </summary>
        /// <param name="directory">The directory to search for files.</param>
        /// <param name="searchPattern">The search pattern to apply for files.</param>
        /// <param name="searchOption">The option to search for files.</param>
        public FilesDataAttribute(string directory, string searchPattern, SearchOption searchOption)
        {
            //The path validity check here is not exhaustive.
            if(string.IsNullOrWhiteSpace(directory))
            {
                throw new ArgumentException(nameof(directory));
            }

            if(string.IsNullOrWhiteSpace(searchPattern))
            {
                throw new ArgumentException(nameof(searchPattern));
            }

            DirectoryPath = directory;
            SearchPattern = searchPattern;
            SearchOption = searchOption;
        }


        public string? GetDisplayName(MethodInfo methodInfo, object?[]? data)
        {
            if(data == null || data.Length == 0)
            {
                return null;
            }

            //Return a display name based on the file name.
            return $"{methodInfo.Name}({data[0]})";
        }


        /// <inheritDoc />
        public IEnumerable<object[]> GetData(MethodInfo testMethod)
        {
            ArgumentNullException.ThrowIfNull(testMethod);

            var enumeration = new FileSystemEnumerable<string>(
               directory: DirectoryPath,
               transform: (ref FileSystemEntry entry) => entry.ToFullPath(),
               options: new EnumerationOptions()
               {
                   RecurseSubdirectories = true
               })
            {
                ShouldIncludePredicate = (ref FileSystemEntry entry) =>
                {
                    if(entry.IsDirectory)
                    {
                        return false;
                    }

                    var entryPath = entry.ToFullPath();
                    return entryPath.EndsWith(SearchPattern);
                }
            };

            var files = enumeration.ToList();

            //Debug.Assert(false);
            //var files = Directory.GetFiles(Path.GetFullPath(DirectoryPath), SearchPattern, SearchOption);
            if(files.Count > 0)
            {
                return files.Select(file => new[] { Path.GetFileName(file), File.ReadAllText(file) });
            }
            else
            {
                throw new ArgumentException($"Could not find files using paramters directory \"{Path.GetFullPath(DirectoryPath)}\", \"{SearchPattern}\", \"{SearchOption}\"");
            }
        }
    }
}
