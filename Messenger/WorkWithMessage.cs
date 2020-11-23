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
    /// <summary>
    /// Работа с сообщениями с минимальным функционалом 
    /// (стандарт для айпи можно взять "127.0.0.1")
    /// </summary>
    class WorkWithMessage
    {
        private IPAddress _ipAddress;
        private IPEndPoint _ip;
        private Socket _sock;

        private uint _p = 23;
        private uint _g = 5;

        private List<byte[]> _ListFiles_Image;
        private List<byte[]> _ListFiles_Music;

        /// <summary>
        /// Ваше имя
        /// </summary>
        public string MyNickName { get; set; }

        /// <summary>
        /// Имя собеседника
        /// </summary>
        public string FriendNickName { get; set; }

        /// <summary>
        /// Ваш (введённый) ключ
        /// </summary>
        public ulong MyKey { get; set; }
        /// <summary>
        /// Ваш общий ключ с собеседником
        /// </summary>
        public byte[] OurKeyForCrypt { get; set; }
        /// <summary>
        /// Максимальная длина сообщения
        /// </summary>
        public int MaxMessageLength { get; }

        /// <summary>
        /// Конструктор, в котором все параметры заданы по умолчанию
        /// </summary>
        public WorkWithMessage() : this("Никто")
        {  }

        /// <summary>
        /// Вводится имя пользователя
        /// </summary>
        /// <param name="name"> Имя пользователя </param>
        public WorkWithMessage(string name)
        {
            _ListFiles_Image = new List<byte[]>();
            _ListFiles_Music = new List<byte[]>();

            MyNickName = name;
            MaxMessageLength = 3196608;
        }

        /// <summary>
        /// Вводится секретный ключ пользователя
        /// </summary>
        /// <param name="key"></param>
        public void SetPrivateKeyForMessage(ulong key)
        {
            MyKey = key;
        }
        
        /// <summary>
        /// Попытка создать IPEndPoint
        /// </summary>
        /// <param name="ip"> Айпи </param>
        /// <param name="port"> Порт </param>
        /// <returns> Возвращает true если операция выплнена успешно, иначе false </returns>
        public bool TrySetIPEndPoint(string ip, int port)
        {
            if (IPAddress.TryParse(ip, out _ipAddress))
            {
                _ip = new IPEndPoint(_ipAddress, port);
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Задаётся IPEndPoint без проверки
        /// </summary>
        /// <param name="endPoint"> IPEndPoint </param>
        public void SetIPEndPoint(IPEndPoint endPoint)
        {
            _ip = endPoint;
        }

        /// <summary>
        /// Задает фильтр файлов в диалоге и возвращает путь выбранного файла
        /// </summary>
        /// <param name="filter"> Фильтр </param>
        /// <returns> Путь выбранного файла </returns>
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

        /// <summary>
        /// Получает расшифрованное полное сообщение файла изображения и сохраняет его в массив
        /// </summary>
        /// <param name="bt"> Входные биты </param>
        public void TakeAndAddDecryptedImageFromMessage(byte[] bt)
        {
            StringBuilder strBl = new StringBuilder();
            byte[] copyBt = new byte[bt.Length - 2];
            Array.Copy(bt, 2, copyBt, 0, copyBt.Length);

            _ListFiles_Image.Add(copyBt);
        }

        /// <summary>
        /// Получает расшифрованное полное сообщение файла музыки и сохраняет его в массив
        /// </summary>
        /// <param name="bt"> Входные биты </param>
        public void TakeAndAddDecryptedMusicFromMessage(byte[] bt)
        {
            StringBuilder strBl = new StringBuilder();
            byte[] copyBt = new byte[bt.Length - 2];
            Array.Copy(bt, 2, copyBt, 0, copyBt.Length);

            _ListFiles_Music.Add(copyBt);
        }

        /// <summary>
        /// Получает необходимые данные для взаимодействия с другим пользователем (имя, его ключ)
        /// </summary>
        /// <param name="infoMessage"> Инфо сообщение </param>
        public void GetInfoMessage(byte[] infoMessage)
        {
            FriendNickName = GetFriendNickNameFromInfoMessage(infoMessage);
            OurKeyForCrypt = GetOurKeyFromInfoMessage(infoMessage);
        }

        private byte[] GetOurKeyFromInfoMessage(byte[] infoMessage)
        {
            return BitConverter.GetBytes((uint)Math.Pow(_g, Convert.ToUInt32(Encoding.UTF8.GetString(infoMessage).Split(new char[] { ' ' })[1]) * MyKey) % _p);
        }

        private string GetFriendNickNameFromInfoMessage(byte[] infoMessage)
        {
            return Encoding.UTF8.GetString(infoMessage).Split(new char[] { ' ' })[0];
        }

        /// <summary>
        /// Отправляет сообщение другому пользователю 
        /// </summary>
        /// <param name="message"> Байты сообщения </param>
        public void SendMessage(byte[] message)
        {
            Blowfish blowfish = new Blowfish(123456789);
            _sock.Send(blowfish.ECB_Encrypt(message, OurKeyForCrypt));
        }

        /// <summary>
        /// Отправляет сообщение другому пользователю 
        /// </summary>
        /// <param name="message"> String сообщение </param>
        public void SendMessage(string message)
        {
            Blowfish blowfish = new Blowfish(123456789);
            _sock.Send(blowfish.ECB_Encrypt(Encoding.UTF8.GetBytes(message), OurKeyForCrypt));
        }

        /// <summary>
        /// Отправляет необходимую информацию о себе другому пользователю
        /// </summary>
        public void SendInfoMessage()
        {
            _sock.Send(Encoding.UTF8.GetBytes(MyNickName + " " + MyKey.ToString()));
        }

        /// <summary>
        /// Отправляет изображение другому пользователю
        /// </summary>
        /// <param name="imageBytes"> Байты изображения </param>
        public void SendImageMessage(byte[] imageBytes)
        {
            Blowfish blowfish = new Blowfish(123456789);
            byte[] bt = imageBytes;
            byte[] message = new byte[bt.Length + 2];
            Array.Copy(bt, 0, message, 2, bt.Length);

            message[0] = (byte)'/';
            message[1] = (byte)'i';

            _sock.Send(blowfish.ECB_Encrypt(message, OurKeyForCrypt));
        }

        /// <summary>
        /// Отправляет музыку другому пользователю
        /// </summary>
        /// <param name="musicBytes"> Байты музыки </param>
        public void SendMusicMessage(byte[] musicBytes)
        {
            Blowfish blowfish = new Blowfish(123456789);
            byte[] bt = musicBytes;
            byte[] message = new byte[bt.Length + 2];
            Array.Copy(bt, 0, message, 2, bt.Length);

            message[0] = (byte)'/';
            message[1] = (byte)'m';

            _sock.Send(blowfish.ECB_Encrypt(message, OurKeyForCrypt));
        }

        /// <summary>
        /// Создаёт сокет
        /// </summary>
        /// <returns> Если сокет успешно создан, то возвращает true, иначе - false </returns>
        public bool GetSocket()
        {
            try
            {
                _sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Unspecified);
                _sock.Bind(_ip);
                _sock.Listen(20);
                _sock = _sock.Accept();
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        /// <summary>
        /// Присоединяется к сокету
        /// </summary>
        public void SocketConnect()
        {
            _sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Unspecified);
            _sock.Connect(_ip);
        }

        /// <summary>
        /// Ожидание сообщений
        /// </summary>
        /// <param name="bt"> Массив, куда считаются байты </param>
        /// <returns> Кол-во считанных байт </returns>
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

        /// <summary>
        /// Загрузить все имеющиеся присланные файлы
        /// </summary>
        public void DownloadFiles()
        {
            string path = System.IO.Path.Combine(Directory.GetParent(
                Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory).FullName).FullName).FullName, "Files");
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
