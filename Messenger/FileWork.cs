using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Messenger
{
    static class FileWork
    {
        public static byte[] ReadFullFile(string filePathStr)
        {
            FileInfo infoFile = new FileInfo(filePathStr);
            byte[] userFile = new byte[infoFile.Length];

            using (BinaryReader strReader = new BinaryReader(File.Open(filePathStr, FileMode.Open), Encoding.UTF8))
            {
                strReader.Read(userFile, 0, userFile.Length);
            }

            return userFile;
        }

        public static void WriteInFile(byte[] text, string path)
        {
            using (BinaryWriter strWr = new BinaryWriter(File.Open(path, FileMode.Create), Encoding.UTF8))
            {
                strWr.Write(text, 0, text.Length);
                strWr.Flush();
            }
        }
    }
}
