using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Xunit.Sdk;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// An attribute to retrieve files with the given glob pattern.
    /// </summary>
    public sealed class FilesDataAttribute: DataAttribute
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
                throw new ArgumentException(nameof(directory));
            }

            if(string.IsNullOrWhiteSpace(searchPattern))
            {
                throw new ArgumentException(nameof(searchPattern));
            }

            DirectoryPath = directory ;
            SearchPattern = searchPattern;
            SearchOption = searchOption;
        }


        /// <inheritDoc />
        public override IEnumerable<object[]> GetData(MethodInfo testMethod)
        {
            if(testMethod == null)
            {
                throw new ArgumentNullException(nameof(testMethod));
            }

            var files = Directory.GetFiles(DirectoryPath, SearchPattern, SearchOption);
            if(files.Length > 0)
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
