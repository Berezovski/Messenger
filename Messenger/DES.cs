using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace Messenger
{
    class DES
    {
        // переменная которая будет скрывать (отчасти) информацию в последнем блоке по 64 бит.
        const uint _forChipherValue = 1;
        // блок для режимов CBC, OFB, CFB
        ulong _beginingBlock = 0;

        private static uint UintOne
        {
            get
            {
                return (uint)1;
            }
        }

        private static ulong UlongOne
        {
            get
            {
                return (ulong)1;
            }
        }

        public int[][] _S1 = new int[4][]{
            new int[16] { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
            new int[16] {  0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            new int[16] { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
            new int[16] { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
        };

        public int[][] _S2 = new int[4][]{
            new int[16] {  15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            new int[16] {  3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            new int[16] {  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            new int[16] { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
        };

        public int[][] _S3 = new int[4][]{
            new int[16] { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
            new int[16] { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
            new int[16] { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            new int[16] { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
        };

        public int[][] _S4 = new int[4][]{
            new int[16] { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            new int[16] {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            new int[16] {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            new int[16] { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
        };

        public int[][] _S5 = new int[4][]{
            new int[16] {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
            new int[16] { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            new int[16] { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            new int[16] { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
        };

        public int[][] _S6 = new int[4][]{
            new int[16] { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
            new int[16] {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            new int[16] {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
            new int[16] { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
        };

        public int[][] _S7 = new int[4][]{
            new int[16] { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
            new int[16] { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            new int[16] {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
            new int[16] { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
        };

        public int[][] _S8 = new int[4][]{
            new int[16] { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            new int[16] {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            new int[16] { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            new int[16] { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
        };

        int[] _C0 = new int[28] { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36 };
        int[] _D0 = new int[28] { 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

        int[] _KeyPosition = new int[48] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
        int[] _P = new int[32] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

        int[] _IP = new int[64]
        {
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
        };
        int[] _IP_Reverse = new int[64]
        {
            40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
        };

        public int[] _E = new int[48]
        {
             32,1,2,3,4,5
            ,4,5,6,7,8,9
            ,8,9,10,11,12,13
            ,12,13,14,15,16,17
            ,16,17,18,19,20,21
            ,20,21,22,23,24,25
            ,24,25,26,27,28,29
            ,28,29,30,31,32,1
         };

        // наш конструктор единственный который задает значение, которое будет использоватся например в CBC режиме
        public DES(byte[] text)
        {
            byte[] cloneText = new byte[8];

            if (text.Length == 0)
            {
                _beginingBlock = 1234567890;
            }

            if (text.Length < 8)
            {
                for (int i = 0; i < text.Length; i++)
                {
                    cloneText[i] = text[0];
                }

                // просто добавляем самый первый элемент
                for (int i = text.Length - 1; i < 8; i++)
                {
                    cloneText[i] = text[0];
                }
            }

            _beginingBlock = BitConverter.ToUInt64(cloneText, 0);

        }

        // режим электронной книги
        public byte[] ECB_Chipher(byte[] text, ulong userkey)
        {
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppend(text));

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = Cipher(readyBlocks[i], roundsKeys);
            }

            return LongArrayToByteArray(readyBlocks);
        }

        public byte[] ECB_Dechipher(byte[] text, ulong userkey)
        {
            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = DeCipher(blocks[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetRealBytes(LongArrayToByteArray(blocks));
        }

        // режим сцеплений блоков
        public byte[] CBC_Chipher(byte[] text, ulong userkey)
        {
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppend(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = Cipher(forModeArray[i] ^ readyBlocks[i], roundsKeys);
                forModeArray[i + 1] = readyBlocks[i];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        public byte[] CBC_Dechipher(byte[] text, ulong userkey)
        {
            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = blocks[i];
                blocks[i] = forModeArray[i] ^ DeCipher(blocks[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetRealBytes(LongArrayToByteArray(blocks));
        }

        // режим обратной связи по шифротексту
        public byte[] CFB_Chipher(byte[] text, ulong userkey)
        {
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppend(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = readyBlocks[i] ^ Cipher(forModeArray[i], roundsKeys);
                forModeArray[i + 1] = readyBlocks[i];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        public byte[] CFB_Dechipher(byte[] text, ulong userkey)
        {
            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = blocks[i];
                blocks[i] = blocks[i] ^ Cipher(forModeArray[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetRealBytes(LongArrayToByteArray(blocks));
        }

        // режим обратной связи по выходу
        public byte[] OFB_Chipher(byte[] text, ulong userkey)
        {
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppend(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                forModeArray[i + 1] = Cipher(forModeArray[i], roundsKeys);
                readyBlocks[i] = readyBlocks[i] ^ forModeArray[i + 1];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        public byte[] OFB_Dechipher(byte[] text, ulong userkey)
        {
            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            ulong[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = Cipher(forModeArray[i], roundsKeys);
                blocks[i] = blocks[i] ^ forModeArray[i + 1];
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetRealBytes(LongArrayToByteArray(blocks));
        }

        // шифрование по алгоритму des
        private ulong Cipher(ulong textBit64, ulong[] roundsKeys)
        {
            // ключи
            ulong[] keys = (ulong[])roundsKeys.Clone();

            // первоначальная перестановка
            ulong answer = IP_Transformation(textBit64);

            // правая-левая части
            uint[] L = new uint[17];
            uint[] R = new uint[17];

            L[0] = (uint)(answer >> 32);
            R[0] = (uint)(answer & (((ulong)1 << 32) - 1));

            // Наши S матрицы (да мы их запихнём в массив матриц)
            uint[][][] s_Matrixs = new uint[8][][] {
                (uint[][]) _S1.Clone(), (uint[][])_S2.Clone(), (uint[][])_S3.Clone(), (uint[][])_S4.Clone(),
                (uint[][])_S5.Clone(),(uint[][]) _S6.Clone(),(uint[][]) _S7.Clone(), (uint[][])_S8.Clone() };

            // цикл раундов 
            for (int i = 0; i < 16; i++)
            {
                R[i + 1] = L[i] ^ P_Transformation(S_Transformation(keys[i] ^ BitsSwap(R[i], _E, 32), s_Matrixs));
                L[i + 1] = R[i];
            }

            // склеиваем половинки (НЕ ЗАБЫВАЕМ, КАК ЭТО ДЕЛАЕТСЯ, ТУТ ВНИМАТЕЛЬНЕЕ)
            answer = ((ulong)R[16] << 32) | L[16];

            // обратная первоначальной перестановке
            answer = IP_Reverse_Transformation(answer);

            return answer;
        }

        // шифрование только в обратном порядке (IP перестановка та же), т.е. дешифрование
        private ulong DeCipher(ulong textBit64, ulong[] roundsKeys)
        {
            ulong[] keys = (ulong[])roundsKeys.Clone();

            ulong answer = IP_Transformation(textBit64);

            uint[] L = new uint[17];
            uint[] R = new uint[17];

            // тут наоборот в отличии от Cipher
            R[16] = (uint)(answer >> 32);
            L[16] = (uint)(answer & ((DES.UlongOne << 32) - 1));

            uint[][][] s_Matrixs = new uint[8][][] {
                (uint[][]) _S1.Clone(), (uint[][])_S2.Clone(), (uint[][])_S3.Clone(), (uint[][])_S4.Clone(),
                (uint[][])_S5.Clone(),(uint[][]) _S6.Clone(),(uint[][]) _S7.Clone(), (uint[][])_S8.Clone() };

            // тут тоже наоборот
            for (int i = 15; i >= 0; i--)
            {
                L[i] = R[i + 1] ^ P_Transformation(S_Transformation(keys[i] ^ BitsSwap(L[i + 1], _E, 32), s_Matrixs));
                R[i] = L[i + 1];
            }

            // не забываем вырезать младшие биты
            answer = ((ulong)L[0] << 32) | (R[0]);

            answer = IP_Reverse_Transformation(answer);

            return answer;
        }

        // Получаем блоки по 64 бит (последний блок отвечает за информацию о предпоследнем блоке, а точнее сколько байтов нужно будет удалить и
        //  + _forChipherValue чтобы не спалить последний блок)
        private byte[] GetBlocksAndAppend(byte[] text)
        {
            // сколько байт лишних       
            uint missingSize = (uint)(8 - text.Length % 8) % 8;

            // нужный нам текст
            byte[] needText = new byte[text.Length + missingSize];

            for (int i = 0; i < text.Length; i++)
            {
                needText[i] = text[i];
            }

            // заполняем лабудой предпоследний блок до конца
            for (int i = 0; i < missingSize; i++)
            {
                needText[text.Length + i] = (byte)i;
            }

            ulong[] blocks;

            // если по факту всё ровно, то добавляем блок информация в конце это и есть число = 0
            if (missingSize == 0)
            {
                blocks = new ulong[text.Length / 8 + 1];
                blocks[blocks.Length - 1] = missingSize + _forChipherValue;
            }
            else  // если в поледнем блоке не достают биты, то добавляем блок и пишем сколько
            {
                blocks = new ulong[text.Length / 8 + 2];
                blocks[blocks.Length - 1] = missingSize + _forChipherValue;
            }

            // заполняем наш блок (НО ДО ПРЕДПОСЛЕДНЕГО БЛОКА), в последнем у нас данные о предыдущем
            for (int i = 0; i < blocks.Length - 1; i++)
            {
                blocks[i] = BitConverter.ToUInt64(needText, i * 8);
            }

            byte[] answer = new byte[blocks.Length * 8];

            for (int i = 0; i < blocks.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    answer[i * 8 + j] = BitConverter.GetBytes(blocks[i])[j];
                }
            }


            return answer;

        }

        // Получаем реальные блоки по 64 за исключением последнего, который имеет свою реальную длину (от 1 до 64)
        private byte[] GetRealBytes(byte[] bytes)
        {
            ulong[] blocks = ByteArrayToLongArray(bytes);

            // находим наши ненужные байты в последнем блоке в предпоследнем блоке
            uint missingSize = ((uint)(blocks[blocks.Length - 1] - _forChipherValue)) % 8;

            ulong[] text = new ulong[blocks.Length - 1];

            // копируем блоки до предпоследнего
            for (int i = 0; i < text.Length; i++)
            {
                text[i] = blocks[i];
            }

            // убираем ненужные нам байты (missingSize)
            byte[] answer = new byte[text.Length * 8 - missingSize];

            for (int i = 0; i < text.Length; i++)
            {
                // в последнем блоке (по 64 бит) убираем missingSize байт
                if (i == text.Length - 1)
                {
                    for (int j = 0; j < 8 - missingSize; j++)
                    {
                        answer[i * 8 + j] = BitConverter.GetBytes(text[i])[j];
                    }
                    break;
                }

                for (int j = 0; j < 8; j++)
                {
                    answer[i * 8 + j] = BitConverter.GetBytes(text[i])[j];
                }
            }

            return answer;

        }

        // если байты кратны 8-ми в масcиве то все норм
        private ulong[] ByteArrayToLongArray(byte[] text)
        {
            ulong[] answer;
            if (text.Length % 8 == 0)
            {
                answer = new ulong[text.Length / 8];

                for (int i = 0; i < answer.Length; i++)
                {
                    answer[i] = BitConverter.ToUInt64(text, i * 8);
                }

                return answer;
            }
            else // если текст не удовлетворяет условию, (случай, когда понятно что ключ точно не подходит)
            {
                answer = new ulong[text.Length / 8 + 1];

                for (int i = 0; i < answer.Length - 1; i++)
                {
                    answer[i] = BitConverter.ToUInt64(text, i * 8);
                }

                // заполняем последний блок 8 битами == text[text.Length - 1], всё равно уже не получат нормальный ответ
                answer[answer.Length - 1] = BitConverter.ToUInt64(new byte[] { text[text.Length - 1], text[text.Length - 1], text[text.Length - 1],
                    text[text.Length - 1],text[text.Length - 1],text[text.Length - 1],text[text.Length - 1],text[text.Length - 1] }, 0);

                return answer;
            }
        }

        // перевод в массив байтов
        private byte[] LongArrayToByteArray(ulong[] text)
        {
            byte[] answer = new byte[text.Length * 8];

            for (int i = 0; i < text.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    answer[i * 8 + j] = BitConverter.GetBytes(text[i])[j];
                }
            }

            return answer;
        }

        // генерация ключа 
        private ulong[] KeyGeneration(ulong userKey)
        {

            ulong tmp = userKey;

            // 17 элементов учитывая по алгоритму что начинают с 0
            ulong[] C_i = new ulong[17];
            ulong[] D_i = new ulong[17];

            C_i[0] = BitsSwap(tmp, _C0, 56);
            D_i[0] = BitsSwap(tmp, _D0, 56);

            // Заполняем матрицу 
            for (int i = 1; i < C_i.Length; i++)
            {
                if ((i == 2) || (i == 1) || (i == 16) || (i == 9))
                {
                    C_i[i] = CycleLeft(C_i[i - 1], 28, 1);
                    D_i[i] = CycleLeft(D_i[i - 1], 28, 1);
                    continue;
                }

                C_i[i] = CycleLeft(C_i[i - 1], 28, 2);
                D_i[i] = CycleLeft(D_i[i - 1], 28, 2);
            }

            ulong[] keys = new ulong[16];

            // получаем раундовые ключи
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = BitsSwap((C_i[i + 1] << 28) | (D_i[i + 1]), _KeyPosition, 56);
            }

            return keys;

        }

        // P - перестановка
        private uint P_Transformation(uint number)
        {
            return (uint)BitsSwap(number, _P, 32);
        }

        // IP - перестановка
        private ulong IP_Transformation(ulong number)
        {
            return BitsSwap(number, _IP, 64);
        }

        // IP - обратная перестановка
        private ulong IP_Reverse_Transformation(ulong number)
        {
            return BitsSwap(number, _IP_Reverse, 64);
        }

        // S преобразование (фигуррируют S матрицы) и получает B' матрицу
        private uint S_Transformation(ulong b_matrix, uint[][][] s_Matrixs)
        {
            uint answer = 0;
            uint B_number;
            uint B_streak;

            // где i выбранная шестерка битов и также выбранная матрица S
            for (int i = 0; i < 8; i++)
            {

                B_number = СutBitsBlocks(b_matrix, 6, 7 - i);
                // строка - вырезанные крайние биты, столбец врезанная середина (5 бита)
                B_streak = s_Matrixs[i][Glue(B_number, 6, 1)][CuttingMiddleBit(B_number, 6, 1)];

                answer = (answer << 4) | B_streak;
            }

            return answer;
        }

        // расширение Е
        private static ulong Escalation(uint rightPart)
        {
            ulong answer = 0;

            // расширяем биты до 48-ми начиная с конца
            for (int i = 7; i >= 0; i--)
            {
                // для последних битов
                if (i == 7)
                {
                    answer = (answer << 1) | CuttingBit(rightPart, 0);
                    for (int j = 3; j >= -1; j--)
                    {
                        answer = (answer << 1) | CuttingBit(rightPart, (i * 4 + j) % 32);

                    }
                    continue;
                }

                // для 1 бита
                if (i == 7)
                {
                    for (int j = 4; j >= 0; j--)
                    {
                        answer = (answer << 1) | CuttingBit(rightPart, (i * 4 + j) % 32);

                    }
                    answer = (answer << 1) | CuttingBit(rightPart, 31);

                    continue;
                }

                for (int j = 4; j >= -1; j--)
                {
                    answer = (answer << 1) | CuttingBit(rightPart, (i * 4 + j) % 32);

                }


            }


            // меняем местами
            return answer;
        }

        // вырезаем начиная с 0 элемента!
        private static uint CuttingBit(uint number, int nymeration)
        {
            return ((DES.UintOne << nymeration) & number) >> nymeration;
        }

        // Вырезание битов по середине между i битами от краев (нач условие - длина числа в двоичной системе)
        private static uint CuttingMiddleBit(uint number, int len, int removeLeftAndRightBits)
        {
            return (number & ((DES.UintOne << (len - removeLeftAndRightBits)) - 1)) >> removeLeftAndRightBits;
        }

        // вырезаем биты из 32 разрядного числа (по 6) в нашей задаче 
        private static uint СutBitsBlocks(ulong number, int len, int beginingBit)
        {
            return (uint)((number & ((DES.UlongOne << (beginingBit * len + len)) - 1)) >> (len * beginingBit));
        }

        // Склеивание
        private static uint Glue(uint number, int len, int glueLeftAndRightBits)
        {
            uint firstPart = (number >> (len - glueLeftAndRightBits)) & ((DES.UintOne << glueLeftAndRightBits) - 1);
            uint secondPart = number & ((DES.UintOne << glueLeftAndRightBits) - 1);

            return (firstPart << glueLeftAndRightBits) | secondPart;
        }

        // Циклический сдвиг влево на длине числа
        private static ulong CycleLeft(ulong number, int len, int n)
        {
            //во избежание ошибок мы смещааем только на допустимую длину и на допустимое количество символов (цикл же не на 32 разрядное число)
            n = n % len;
            int push = (len - n) % len;

            // два бита в начало
            return (number >> push) | ((number & ((DES.UintOne << push) - 1)) << n);
        }

        // Вывести бит
        private static ulong PruintBit(ulong number, int k)
        {
            return (number & (DES.UlongOne << k)) >> k;
        }

        // Свап битами
        private static ulong BitsSwap(ulong number, int[] userNumeration, int beginSizeBits)
        {
            // неполная копия
            userNumeration = (int[])userNumeration.Clone();

            // разница между входными и выходными массивами
            int minusSize = userNumeration.Length - beginSizeBits;

            // декремент , так как нам даются с нумерацией начиная с 1
            for (int i = 0; i < userNumeration.Length; i++)
            {
                userNumeration[i]--;
            }

            // так как в википедии первые элементы это [0]


            ulong answer = 0;



            for (int i = 0; i < userNumeration.Length; i++)
            {

                // если данный бит = 0 в самом числе то добавляем ноль
                if ((((DES.UlongOne << ((userNumeration.Length - 1) - userNumeration[i] - minusSize)) & number) >> ((userNumeration.Length - 1) - userNumeration[i] - minusSize)) == 0)
                {
                    answer <<= 1;
                }
                else
                {
                    answer = (answer << 1) | 1;
                }

            }

            return answer;

        }

    }
}
