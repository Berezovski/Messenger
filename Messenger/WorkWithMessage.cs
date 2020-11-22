using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace Messenger
{
    class WorkWithMessage
    {
        IPAddress _ipAddress;
        IPEndPoint _ip;
        Socket _sock;

        public string MyNickName { get; set; }
        public string FriendNickName { get; set; }

        public ulong MyKey { get; set; }
        public ulong OurKey { get; set; }
        public int MessageLength { get; }

        uint _p = 23;
        uint _g = 5;

        List<byte[]> _ListFiles_Image;
        List<byte[]> _ListFiles_Music;

        public WorkWithMessage() : this("Никто", 3)
        {  }

        public WorkWithMessage(string name, ulong myKey)
        {
            _ListFiles_Image = new List<byte[]>();
            _ListFiles_Music = new List<byte[]>();
            IPAddress.TryParse("127.0.0.1", out _ipAddress);
            _ip = new IPEndPoint(_ipAddress, 1200);
            _p = 23;
            _g = 5;
            MyKey = myKey;
            MyNickName = name;
            MessageLength = 3196608;
        }

        public string GetFilePathFromDialog(string filter)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();
            fileDialog.Filter = filter;

            if (fileDialog.ShowDialog() == true)
            {
                return fileDialog.FileName;
            }
            else
            {
                return "";
            }
        }

        public void TakeDecryptedImageMessage(byte[] bt)
        {
            StringBuilder strBl = new StringBuilder();
            byte[] copyBt = new byte[bt.Length - 2];
            Array.Copy(bt, 2, copyBt, 0, copyBt.Length);

            _ListFiles_Image.Add(copyBt);
        }

        public void TakeDecryptedMusicMessage(byte[] bt)
        {
            StringBuilder strBl = new StringBuilder();
            byte[] copyBt = new byte[bt.Length - 2];
            Array.Copy(bt, 2, copyBt, 0, copyBt.Length);

            _ListFiles_Music.Add(copyBt);
        }

        public void GetInfoMessage(byte[] infoMessage)
        {
            FriendNickName = GetFriendNickNameFromInfoMessage(infoMessage);
            OurKey = GetOurKeyFromInfoMessage(infoMessage);
        }

        public uint GetOurKeyFromInfoMessage(byte[] infoMessage)
        {
            return (uint)Math.Pow(_g, Convert.ToUInt32(Encoding.UTF8.GetString(infoMessage).Split(new char[] { ' ' })[1]) * MyKey) % _p;
        }

        public string GetFriendNickNameFromInfoMessage(byte[] infoMessage)
        {
            return Encoding.UTF8.GetString(infoMessage).Split(new char[] { ' ' })[0];
        }

        public void SendMessage(byte[] message)
        {
            DES chipher = new DES(new byte[] { 1 });
            _sock.Send(chipher.ECB_Chipher(message, OurKey));
        }

        public void SendMessage(string message)
        {
            DES chipher = new DES(new byte[] { 1 });
            _sock.Send(chipher.ECB_Chipher(Encoding.UTF8.GetBytes(message), OurKey));
        }

        public void SendInfoMessage()
        {
            _sock.Send(Encoding.UTF8.GetBytes(MyNickName + " " + MyKey.ToString()));
        }

        public void SendImageMessage(byte[] userFile)
        {
            DES chipher = new DES(new byte[] { 1 });
            byte[] bt = userFile;
            byte[] message = new byte[bt.Length + 2];
            Array.Copy(bt, 0, message, 2, bt.Length);

            message[0] = (byte)'/';
            message[1] = (byte)'i';

            _sock.Send(chipher.ECB_Chipher(message, OurKey));
        }

        public void SendMusicMessage(byte[] userFile)
        {
            DES chipher = new DES(new byte[] { 1 });
            byte[] bt = userFile;
            byte[] message = new byte[bt.Length + 2];
            Array.Copy(bt, 0, message, 2, bt.Length);

            message[0] = (byte)'/';
            message[1] = (byte)'m';

            _sock.Send(chipher.ECB_Chipher(message, OurKey));
        }

        public void GetSocket()
        {
            _sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Unspecified);
            _sock.Bind(_ip);
            _sock.Listen(20);
            _sock = _sock.Accept();
        }

        public void SocketConnect()
        {
            _sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Unspecified);
            _sock.Connect(_ip);
        }

        public int SocketReceive(byte[] bt)
        {
            try
            {
                return _sock.Receive(bt);
            }
            catch
            {
                MessageBox.Show("Внимание! Ваш собеседник вышел! Запустите приложение заново, если хотите возобновить чат!", "Вы одни :(");
                return -1;
            }

        }

        public void DownloadFiles()
        {
            string path = System.IO.Path.Combine(Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory).FullName).FullName);
            string pathImage;
            string pathMusic;

            for (int i = 0; i < _ListFiles_Image.Count; i++)
            {
                pathImage = System.IO.Path.Combine(path, (i + 1).ToString() + ".jpg");

                FileWork.WriteInFile(_ListFiles_Image[i], pathImage);
            }

            for (int i = 0; i < _ListFiles_Music.Count; i++)
            {
                pathMusic = System.IO.Path.Combine(path, (i + 1).ToString() + ".mp3");

                FileWork.WriteInFile(_ListFiles_Music[i], pathMusic);
            }
        }
    }
}
