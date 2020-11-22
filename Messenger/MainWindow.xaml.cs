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
        WorkWithMessage _workWithMessage;

        public MainWindow()
        {
            InitializeComponent();
        }

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
            string name;
            do
            {
                name = Microsoft.VisualBasic.Interaction.InputBox("Введите ваш ник (меньше 6 символов): ");
            }
            while ((name.Length > 6)||(name.Length == 0));
            Button_Connect.IsEnabled = false;

            _workWithMessage = new WorkWithMessage(name, 3);

            byte[] bt = new byte[_workWithMessage.MessageLength];
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

            if (userFile.Length > _workWithMessage.MessageLength)
            {
                AppendMyMessage("/Внимание! Размер вашего сообщения слишком большой!\\" + " Максимум можно " 
                    + _workWithMessage.MessageLength + " байт.");
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

            if (userFile.Length >= _workWithMessage.MessageLength)
            {
                AppendMyMessage("/Внимание! Размер вашего сообщения слишком большой!\\" + " Максимум можно "
                    + _workWithMessage.MessageLength + " байт.");
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

        async void SocketStartWorkAsync()
        {
            byte[] bt;

            bt = await Task.Run(() => SocketStartWork());
            _workWithMessage.GetInfoMessage(bt);

            Button_Connect.Visibility = Visibility.Collapsed;
            AllIsEnabledTrue();
            AppendFriendMessage("подключился!");
            StartReadingMesssageAsync();
        }

        async void StartReadingMesssageAsync()
        {
            DES chipher = new DES(new byte[] { 1 });

            while (true)
            {
                byte[] bt;
                bt = await Task.Run(() => StartReadingMesssage());

                if (bt == null)
                {
                    Close();
                    return;
                }

                bt = chipher.ECB_Dechipher(bt, _workWithMessage.OurKey);

                if ((bt[0] == '/') && (bt[1] == 'i'))
                {
                    _workWithMessage.TakeDecryptedImageMessage(bt);
                    AppendFriendMessage("/Отправил файл image\\" + " длинной " + (bt.Length - 2).ToString() + " байт\n");
                    continue;
                }

                if ((bt[0] == '/') && (bt[1] == 'm'))
                {
                    _workWithMessage.TakeDecryptedMusicMessage(bt);
                    AppendFriendMessage("/Отправил файл mp3\\" + " длинной " + (bt.Length - 2).ToString() + " байт\n");
                    continue;
                }

                AppendFriendMessage(bt);
            }
        }

        byte[] StartReadingMesssage()
        {
            byte[] bt = new byte[_workWithMessage.MessageLength];
            int newSize = _workWithMessage.SocketReceive(bt);

            if (newSize == -1)
            {
                return null;
            }

            Array.Resize(ref bt, newSize);
            return bt;
        }

        byte[] SocketStartWork()
        {
            byte[] bt = new byte[_workWithMessage.MessageLength];

            _workWithMessage.GetSocket();
            _workWithMessage.SendInfoMessage();

            _workWithMessage.SocketReceive(bt);
            return bt;
        }

       /*=========================
         * Вспомогательные функции
         =========================*/


        void AppendFriendMessage(byte[] message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.FriendNickName).Append(": ").Append(Encoding.UTF8.GetString(message)).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        void AppendMyMessage(byte[] message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.MyNickName).Append(": ").Append(Encoding.UTF8.GetString(message)).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        void AppendFriendMessage(string message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.FriendNickName).Append(": ").Append(message).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        void AppendMyMessage(string message)
        {
            StringBuilder strBl = new StringBuilder();
            strBl.Append(_workWithMessage.MyNickName).Append(": ").Append(message).Append("\n");
            TextBox_Chat.AppendText(strBl.ToString());
        }

        void AllIsEnabledTrue()
        {
            Button_Download.IsEnabled = true;
            Button_ToSend.IsEnabled = true;
            Button_ToSendFileMusic.IsEnabled = true;
            Button_ToSendFileImage.IsEnabled = true;
            TextBox_Message.IsEnabled = true;
        }
    }
}
