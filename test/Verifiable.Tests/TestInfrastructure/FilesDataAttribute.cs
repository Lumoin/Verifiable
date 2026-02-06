using System.IO.Enumeration;
using System.Reflection;


namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// An attribute to retrieve files with the given glob pattern.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class FilesDataAttribute: Attribute, ITestDataSource
    {
        /// <summary>
        /// The directory to search for files.
        /// </summary>
        public string DirectoryPath { get; }

        /// <summary>
        /// The search pattern to apply for files.
        /// </summary>
        public string SearchPattern { get; }

        /// <summary>
        /// The option to search for files.
        /// </summary>
        public SearchOption SearchOption { get; }


        /// <summary>
        /// Gets the full path of the directory where the application is located.
        /// </summary>
        public string Directory { get; }

       
        /// <summary>
        /// Loads files from a given directory with a given search pattern.
        /// </summary>
        /// <param name="directory">The absolute or relative path to the JSON file to load</param>
        public FilesDataAttribute(string directory, string searchPattern): this(directory, searchPattern, SearchOption.AllDirectories) { }


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
                throw new ArgumentException(null, nameof(directory));
            }

            if(string.IsNullOrWhiteSpace(searchPattern))
            {
                throw new ArgumentException(null, nameof(searchPattern));
            }

            DirectoryPath = directory;
            SearchPattern = searchPattern;
            SearchOption = searchOption;
            Directory = directory;            
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
                    return entryPath.EndsWith(SearchPattern, StringComparison.InvariantCulture);
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
                throw new ArgumentException($"Could not find files using paramters directory '{Path.GetFullPath(DirectoryPath)}', '{SearchPattern}', '{SearchOption}'.");
            }
        }        
    }
}
