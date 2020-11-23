using System;
using System.Runtime.InteropServices;


namespace Messenger
{
    /// <summary>
    /// Биты нумеруются справа налево, т.е. [63-ый, 62-ой, ... , 0-ой].
    /// </summary>
    public static class WorkWithBits
    {
        private static ulong One
        {
            get
            {
                return 1;
            }
        }

        /// <summary>
        /// Выводит нужный бит
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="place"> номер нужного бита, возможные значения [0, 63] </param> 
        public static ulong PrintBit(ulong number, int place)
        {
            return (number & (One << place)) >> place;
        }

        /// <summary>
        /// Возвращает младшие биты
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="count"> нужное количество младших битов, которые хотим получить; возможные значения [0, 64] </param> 
        public static ulong GetLowBits(ulong number, int count)
        {

            if (Marshal.SizeOf(number) * 8 == count)
            {
                return number;
            }

            return number & ((One << count) - 1);
        }

        /// <summary>
        /// Ставит указанный бит на определённое место
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="bit"> бит, который нужно поставить = 0,1. </param> 
        /// <param name="place"> номер нужного бита, возможные значения [0, 63] </param> 
        public static ulong SetOrRemove(ulong number, ulong bit, int place)
        {
            return number & ~(One << place) | (bit << place);
        }

        /// <summary>
        /// Меняет местами два бита
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="firstBitPlace"> номер нужного первого бита, возможные значения [0, 63] </param> 
        /// <param name="secondBitPlace"> номер нужного второго бита, возможные значения [0, 63] </param> 
        public static ulong SwapOnlyTwoBits(ulong number, int firstBitPlace, int secondBitPlace)
        {
            // получить значения нужных нам битов
            ulong firstBit = PrintBit(number, firstBitPlace);
            ulong secondBit = PrintBit(number, secondBitPlace);

            // меняем местами полученные биты
            ulong answer = SetOrRemove(number, firstBit, secondBitPlace); 
            answer = SetOrRemove(answer, secondBit, firstBitPlace);

            return answer;
        }

        /// <summary>
        /// Зануляет младшие биты
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="count">  кол-во битов </param> 
        public static ulong LowBitsToZero(ulong number, int count)
        {
            return (number >> count) << count;
        }

        /// <summary>
        /// Склеивание крайних битов 
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="numberLength"> длина используемых битов </param>
        /// <param name="leftOrRightBitCount">  кол-во битов которые мы хотим оставить справа (или слева соответственно) </param> 
        public static ulong GlueBitsOnLeftAndRightSides(ulong number, int numberLength, int leftOrRightBitCount)
        {
            ulong leftPart = GetLowBits(number >> (numberLength - leftOrRightBitCount), leftOrRightBitCount);
            ulong rightPart = GetLowBits(number, leftOrRightBitCount);

            return (leftPart << leftOrRightBitCount) | rightPart;
        }

        /// <summary>
        /// Вырезание битов по середине от крайних
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="numberLength"> длина используемых битов </param>
        /// <param name="leftOrRightBitCount"> кол-во битов которые мы хотим вырезать справа (или слева соответственно) </param> 
        public static ulong CutMiddleBits(ulong number, int numberLength, int leftOrRightBitCount)
        {
            return GetLowBits( GetLowBits(number, numberLength - leftOrRightBitCount) >> leftOrRightBitCount , numberLength);
        }

        /// <summary>
        /// Вырезание битов в промежутке [beginningPlace,endingPlace] 
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="beginningPlace"> порядок начального бита (включительно) </param>
        /// <param name="endingPlace">  порядок конечного бита (включительно) </param> 
        public static ulong CutBitsWithBeginningAndEndingPlaces(ulong number, int beginningPlace, int endingPlace)
        {
            return GetLowBits(number, endingPlace + 1) >> beginningPlace;
        }

        /// <summary>
        /// Свап байтов в соответствии с userBtNumeration
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="userBtNumeration"> порядок байтов (изначальный порядок [7,6,...,0])</param>
        public static ulong SwapBytes(ulong number, int[] userBtNumeration)
        {
            int userBtNumerationTrueLength = Marshal.SizeOf(number);

            // значения байтов от 0 до userBtNumerationTrueLength - 1
            ulong[] byteValue = new ulong[userBtNumerationTrueLength];
            for (int i = 0; i < byteValue.Length; i++)
            {
                byteValue[i]= CutBitsWithBeginningAndEndingPlaces(number, i * 8, i * 8 + 7);
            }

            ulong answer = 0;
            for (int i = 0; i < userBtNumeration.Length; i++)
            {
                answer = (answer << 8) | byteValue[ userBtNumeration[i] ];
            }

            return answer;
        }

        /// <summary>
        /// Нахождение степени двойки числа
        /// </summary>
        /// <param name="number"> число </param> 
        public static int FindSecondDegree(ulong number)
        {
            return (int)Math.Log(number & ((~number) + 1));
        }

        /// <summary>
        /// Найти степень двойки p, чтобы в промежутке (2^p ; 2^(p+1)) лежало число number
        /// </summary>
        /// <param name="number"> число </param> 
        public static int FindSecondDegreeWithThisTask(ulong number)
        {
            ulong answer = 1;

            while (!(number == 0))
            {
                number = number >> 1;
                answer = answer << 1;
            }

            return (int)Math.Log(answer >> 1);
        }

        /// <summary>
        /// Проксорить все биты
        /// </summary>
        /// <param name="number"> число </param> 
        public static ulong XorBits(ulong number)
        {
            int s = Marshal.SizeOf(number) * 8;

            while (s != 1)
            {
                s = s >> 1;

                // вырезаем левую и правую части и сразу ксорим
                number = (number >> s) ^ GetLowBits(number, s);
            }

            return number;
        }

        /// <summary>
        /// Циклический сдвиг влево
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="numberLength"> длина активных битов number </param> 
        /// <param name="count"> число, на которое будет произведён сдвиг битов </param> 
        public static ulong CycleLeft(ulong number, int numberLength, int count)
        {
            // сразу ограничиваем наше число
            number = GetLowBits(number , numberLength);

            // цикл не может быть больше его длины (это бессмысленно)
            count = count % numberLength;
            int tmpSurplus = numberLength - count;

            // два бита в начало
            return  (GetLowBits(number, tmpSurplus) << count) | (number >> tmpSurplus);
        }

        /// <summary>
        /// Циклический сдвиг вправо
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="numberLength"> длина активных битов number </param> 
        /// <param name="count"> число, на которое будет произведён сдвиг битов </param> 
        public static ulong CycleRight(ulong number, int numberLength, int count)
        {
            // сразу ограничиваем наше число
            number = GetLowBits(number, numberLength);

            // цикл не может быть больше его длины (это бессмысленно)
            count = count % numberLength;
            int tmpSurplus = numberLength - count;

            // два бита в начало
            return (GetLowBits(number, count) << tmpSurplus) | (number >> count);
        }

        /// <summary>
        /// Свап битами, упорядоченный в соответствии с userNumeration
        /// </summary>
        /// <param name="number"> число </param> 
        /// <param name="userNumeration"> новый порядок битов (изначальный [63,62,...,0]) </param> 
        public static ulong SwapBits(ulong number, int[] userNumeration)
        {
            ulong answer = 0;

            for (int i = 0; i < userNumeration.Length; i++)
            {
                answer = (answer << 1) | PrintBit(number, userNumeration[i]);
            }

            return answer;

        }

        /// <summary>
        /// Поиск двоичной длины числа (до последней единицы справа налево)
        /// </summary>
        /// <param name="number"> число </param> 
        public static int FindBinaryLength(uint number)
        {
            int count = 0;

            while (!(number == 0))
            {
                number = number >> 1;
                count++;
            }
            return count;
        }
    }
}
