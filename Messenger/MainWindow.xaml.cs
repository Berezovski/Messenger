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
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Messenger
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private WorkWithMessage _workWithMessage;

        public MainWindow()
        {
            InitializeComponent();
        }

        /*================
         *    События
         ================*/

        private void Button_ToSend_Click(object sender, RoutedEventArgs e)
        {
            if (TextBox_Message.Text.Length != 0)
            {
                _workWithMessage.SendMessage(TextBox_Message.Text);
                AppendMyMessage(TextBox_Message.Text);
                TextBox_Message.Clear();
            }
        }

        private void TextBox_Message_KewDown(object sender, KeyEventArgs e)
        {
            if ((e.Key == Key.Enter) && (TextBox_Message.Text.Length != 0))
            {
                _workWithMessage.SendMessage(TextBox_Message.Text);
                AppendMyMessage(TextBox_Message.Text);
                TextBox_Message.Clear();
            }
        }

        private void Button_Connect_Click(object sender, RoutedEventArgs e)
        {
            Button_Connect.IsEnabled = false;
            _workWithMessage = new WorkWithMessage(GetUserNameFromDialog());

            _workWithMessage.SetPrivateKeyForMessage(GetPrivateKeyFromDialog());
            _workWithMessage.SetIPEndPoint(GetIpAdressAndPortFromDialog());

            byte[] bt = new byte[_workWithMessage.MaxMessageLength];
            try
            {
                _workWithMessage.SocketConnect();
                _workWithMessage.SocketReceive(bt);
                _workWithMessage.GetInfoMessage(bt);

                Button_Connect.Visibility = Visibility.Collapsed;
                AllIsEnabledTrue();
                AppendFriendMessage("подключился!");
                _workWithMessage.SendInfoMessage();
                StartReadingMesssageAsync();              
            }
            catch 
            {
                SocketStartWorkAsync();
            }
            
        }

        private void Button_ToSendFileMusic_Click(object sender, RoutedEventArgs e)
        {
            string filePathStr = _workWithMessage.GetFilePathFromDialog("Music|*.mp3");

            if (filePathStr.Length == 0)
            {
                return;
            }
           
            byte[] userFile = FileWork.ReadFullFile(filePathStr);

            if (userFile.Length > _workWithMessage.MaxMessageLength)
            {
                AppendMyMessage("/Внимание! Размер вашего сообщения слишком большой!\\" + " Максимум можно " 
                    + _workWithMessage.MaxMessageLength + " байт.");
                return;
            }

            _workWithMessage.SendMusicMessage(userFile);

            AppendMyMessage("/Вы отправили файл mp3\\ длиной " + userFile.Length + " байт\n");

        }

        private void Button_ToSendFileImage_Click(object sender, RoutedEventArgs e)
        {
            string filePathStr = _workWithMessage.GetFilePathFromDialog("Image|*.jpg");

            if (filePathStr.Length == 0)
            {
                return;
            }

            byte[] userFile = FileWork.ReadFullFile(filePathStr);

            if (userFile.Length >= _workWithMessage.MaxMessageLength)
            {
                AppendMyMessage("/Внимание! Размер вашего сообщения слишком большой!\\" + " Максимум можно "
                    + _workWithMessage.MaxMessageLength + " байт.");
                return;
            }

            _workWithMessage.SendImageMessage(userFile);

            AppendMyMessage("/Вы отправили файл image\\ длиной " + userFile.Length + " байт\n");
        }

        private void Button_Download_Click(object sender, RoutedEventArgs e)
        {
            _workWithMessage.DownloadFiles();
        }

        /*================
       *  Ключевые функции
          ================*/

        private async void SocketStartWorkAsync()
        {
            byte[] bt;

            bt = await Task.Run(() => SocketStartWork());
            _workWithMessage.GetInfoMessage(bt);

            Button_Connect.Visibility = Visibility.Collapsed;
            AllIsEnabledTrue();
            AppendFriendMessage("подключился!");
            StartReadingMesssageAsync();
        }

        private async void StartReadingMesssageAsync()
        {
            Blowfish blowfish = new Blowfish(123456789);

            while (true)
            {
                byte[] bt;
                bt = await Task.Run(() => StartReadingMesssage());

                // Отправленно "ничего", значит пользователь вышел
                if (bt == null)
                {
                    Close();
                    return;
                }

                bt = blowfish.ECB_Decrypt(bt, _workWithMessage.OurKeyForCrypt);

                // Отправлено изображение
                if ((bt[0] == '/') && (bt[1] == 'i'))
                {
                    _workWithMessage.TakeAndAddDecryptedImageFromMessage(bt);
                    AppendFriendMessage("/Отправил файл image\\" + " длинной " + (bt.Length - 2).ToString() + " байт\n");
                    continue;
                }

                // Отправлена музыка
                if ((bt[0] == '/') && (bt[1] == 'm'))
                {
                    _workWithMessage.TakeAndAddDecryptedMusicFromMessage(bt);
                    AppendFriendMessage("/Отправил файл mp3\\" + " длинной " + (bt.Length - 2).ToString() + " байт\n");
                    continue;
                }

                // Отправлен просто текст от собеседника
                AppendFriendMessage(bt);
            }
        }

        private byte[] SocketStartWork()
        {
            byte[] bt = new byte[_workWithMessage.MaxMessageLength];


            while (!_workWithMessage.GetSocket())
            {
                MessageBox.Show("К сожалению создать сокет по такому ip не вышло!\nВам придётся ввести заново адрес", "Ошибочка :(");
                _workWithMessage.SetIPEndPoint(GetIpAdressAndPortFromDialog());
            }
            _workWithMessage.SendInfoMessage();

            _workWithMessage.SocketReceive(bt);
            return bt;
        }

        private byte[] StartReadingMesssage()
        {
            byte[] bt = new byte[_workWithMessage.MaxMessageLength];
            int newSize = _workWithMessage.SocketReceive(bt);

            if (newSize == -1)
            {
                return null;
            }

            Array.Resize(ref bt, newSize);
            return bt;
        }

        /*=========================
          * Вспомогательные функции
          =========================*/

        private string GetUserNameFromDialog()
        {
            string name;
            do
            {
                name = Microsoft.VisualBasic.Interaction.InputBox("Введите ваш ник (меньше 6 символов): ");
            }
            while ((name.Length > 6) || (name.Length == 0));
            return name;
        }

        private IPEndPoint GetIpAdressAndPortFromDialog()
        {
            string checkIp;
            IPAddress trueAdress;
            do
            {
                checkIp = Microsoft.VisualBasic.Interaction.InputBox("Введите ip адресс для создания (подключения): ");
            }
            while (!IPAddress.TryParse(checkIp, out trueAdress));

            string checkPort;
            int port;
            do
            {
                checkPort = Microsoft.VisualBasic.Interaction.InputBox("Введите порт для создания (подключения): ");
            }
            while (!int.TryParse(checkPort, out port));

            return new IPEndPoint(trueAdress, port);
        }

        private ulong GetPrivateKeyFromDialog()
        {
            string checkKey;
            ulong key;
            do
            {
                checkKey = Microsoft.VisualBasic.Interaction.InputBox("Введите ваш приватный ключ (натуральное число): ");
            }
            while (!ulong.TryParse(checkKey, out key));
            return key;
        }

        private void AppendFriendMessage(byte[] message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.FriendNickName).Append(": ").Append(Encoding.UTF8.GetString(message)).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        private void AppendMyMessage(byte[] message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.MyNickName).Append(": ").Append(Encoding.UTF8.GetString(message)).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        private void AppendFriendMessage(string message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.FriendNickName).Append(": ").Append(message).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        private void AppendMyMessage(string message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.MyNickName).Append(": ").Append(message).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        private void AllIsEnabledTrue()
        {
            Button_Download.IsEnabled = true;
            Button_ToSend.IsEnabled = true;
            Button_ToSendFileMusic.IsEnabled = true;
            Button_ToSendFileImage.IsEnabled = true;
            TextBox_Message.IsEnabled = true;
        }
    }
}
