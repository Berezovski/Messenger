using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Messenger
{
    /// <summary>
    /// Алгоритм Blowfish в 4-ёх режимах
    /// В одном режиме реализовано многопоточное шифрование
    /// (другими режимами эффективное многопоточное шифрование невозможно, т.к. строгая зависимость блока от предыдущих)
    /// </summary>
    class Blowfish
    {
        // Дополнительный блок для режимов CBC, OFB, CFB
        private ulong _beginingBlock = 0;       

        private ulong[][] _Sblocks;

        // S - блоки
        private ulong[] _S1 = new ulong[256]{
                    0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,
                    0xba7c9045,0xf12c7f99,0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,
                    0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e,0x0d95748f,0x728eb658,
                    0x718bcd58,0x82154aee,0x7b54a41d,0xc25a59b5,0x9c30d539,0x2af26013,
                    0xc5d1b023,0x286085f0,0xca417918,0xb8db38ef,0x8e79dcb0,0x603a180e,
                    0x6c9e0e8b,0xb01e8a3e,0xd71577c1,0xbd314b27,0x78af2fda,0x55605c60,
                    0xe65525f3,0xaa55ab94,0x57489862,0x63e81440,0x55ca396a,0x2aab10b6,
                    0xb4cc5c34,0x1141e8ce,0xa15486af,0x7c72e993,0xb3ee1411,0x636fbc2a,
                    0x2ba9c55d,0x741831f6,0xce5c3e16,0x9b87931e,0xafd6ba33,0x6c24cf5c,
                    0x7a325381,0x28958677,0x3b8f4898,0x6b4bb9af,0xc4bfe81b,0x66282193,
                    0x61d809cc,0xfb21a991,0x487cac60,0x5dec8032,0xef845d5d,0xe98575b1,
                    0xdc262302,0xeb651b88,0x23893e81,0xd396acc5,0x0f6d6ff3,0x83f44239,
                    0x2e0b4482,0xa4842004,0x69c8f04a,0x9e1f9b5e,0x21c66842,0xf6e96c9a,
                    0x670c9c61,0xabd388f0,0x6a51a0d2,0xd8542f68,0x960fa728,0xab5133a3,
                    0x6eef0b6c,0x137a3be4,0xba3bf050,0x7efb2a98,0xa1f1651d,0x39af0176,
                    0x66ca593e,0x82430e88,0x8cee8619,0x456f9fb4,0x7d84a5c3,0x3b8b5ebe,
                    0xe06f75d8,0x85c12073,0x401a449f,0x56c16aa6,0x4ed3aa62,0x363f7706,
                    0x1bfedf72,0x429b023d,0x37d0d724,0xd00a1248,0xdb0fead3,0x49f1c09b,
                    0x075372c9,0x80991b7b,0x25d479d8,0xf6e8def7,0xe3fe501a,0xb6794c3b,
                    0x976ce0bd,0x04c006ba,0xc1a94fb6,0x409f60c4,0x5e5c9ec2,0x196a2463,
                    0x68fb6faf,0x3e6c53b5,0x1339b2eb,0x3b52ec6f,0x6dfc511f,0x9b30952c,
                    0xcc814544,0xaf5ebd09,0xbee3d004,0xde334afd,0x660f2807,0x192e4bb3,
                    0xc0cba857,0x45c8740f,0xd20b5f39,0xb9d3fbdb,0x5579c0bd,0x1a60320a,
                    0xd6a100c6,0x402c7279,0x679f25fe,0xfb1fa3cc,0x8ea5e9f8,0xdb3222f8,
                    0x3c7516df,0xfd616b15,0x2f501ec8,0xad0552ab,0x323db5fa,0xfd238760,
                    0x53317b48,0x3e00df82,0x9e5c57bb,0xca6f8ca0,0x1a87562e,0xdf1769db,
                    0xd542a8f6,0x287effc3,0xac6732c6,0x8c4f5573,0x695b27b0,0xbbca58c8,
                    0xe1ffa35d,0xb8f011a0,0x10fa3d98,0xfd2183b8,0x4afcb56c,0x2dd1d35b,
                    0x9a53e479,0xb6f84565,0xd28e49bc,0x4bfb9790,0xe1ddf2da,0xa4cb7e33,
                    0x62fb1341,0xcee4c6e8,0xef20cada,0x36774c01,0xd07e9efe,0x2bf11fb4,
                    0x95dbda4d,0xae909198,0xeaad8e71,0x6b93d5a0,0xd08ed1d0,0xafc725e0,
                    0x8e3c5b2f,0x8e7594b7,0x8ff6e2fb,0xf2122b64,0x8888b812,0x900df01c,
                    0x4fad5ea0,0x688fc31c,0xd1cff191,0xb3a8c1ad,0x2f2f2218,0xbe0e1777,
                    0xea752dfe,0x8b021fa1,0xe5a0cc0f,0xb56f74e8,0x18acf3d6,0xce89e299,
                    0xb4a84fe0,0xfd13e0b7,0x7cc43b81,0xd2ada8d9,0x165fa266,0x80957705,
                    0x93cc7314,0x211a1477,0xe6ad2065,0x77b5fa86,0xc75442f5,0xfb9d35cf,
                    0xebcdaf0c,0x7b3e89a0,0xd6411bd3,0xae1e7e49,0x00250e2d,0x2071b35e,
                    0x226800bb,0x57b8e0af,0x2464369b,0xf009b91e,0x5563911d,0x59dfa6aa,
                    0x78c14389,0xd95a537f,0x207d5ba2,0x02e5b9c5,0x83260376,0x6295cfa9,
                    0x11c81968,0x4e734a41,0xb3472dca,0x7b14a94a,0x1b510052,0x9a532915,
                    0xd60f573f,0xbc9bc6e4,0x2b60a476,0x81e67400,0x08ba6fb5,0x571be91f,
                    0xf296ec6b,0x2a0dd915,0xb6636521,0xe7b9f9b6,0xff34052e,0xc5855664,
                    0x53b02d5d,0xa99f8fa1,0x08ba4799,0x6e85076a
        };
        private ulong[] _S2 = new ulong[256]{
                    0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,
                    0xba7c9045,0xf12c7f99,0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,
                    0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e,0x0d95748f,0x728eb658,
                    0x718bcd58,0x82154aee,0x7b54a41d,0xc25a59b5,0x9c30d539,0x2af26013,
                    0xc5d1b023,0x286085f0,0xca417918,0xb8db38ef,0x8e79dcb0,0x603a180e,
                    0x6c9e0e8b,0xb01e8a3e,0xd71577c1,0xbd314b27,0x78af2fda,0x55605c60,
                    0xe65525f3,0xaa55ab94,0x57489862,0x63e81440,0x55ca396a,0x2aab10b6,
                    0xb4cc5c34,0x1141e8ce,0xa15486af,0x7c72e993,0xb3ee1411,0x636fbc2a,
                    0x2ba9c55d,0x741831f6,0xce5c3e16,0x9b87931e,0xafd6ba33,0x6c24cf5c,
                    0x7a325381,0x28958677,0x3b8f4898,0x6b4bb9af,0xc4bfe81b,0x66282193,
                    0x61d809cc,0xfb21a991,0x487cac60,0x5dec8032,0xef845d5d,0xe98575b1,
                    0xdc262302,0xeb651b88,0x23893e81,0xd396acc5,0x0f6d6ff3,0x83f44239,
                    0x2e0b4482,0xa4842004,0x69c8f04a,0x9e1f9b5e,0x21c66842,0xf6e96c9a,
                    0x670c9c61,0xabd388f0,0x6a51a0d2,0xd8542f68,0x960fa728,0xab5133a3,
                    0x6eef0b6c,0x137a3be4,0xba3bf050,0x7efb2a98,0xa1f1651d,0x39af0176,
                    0x66ca593e,0x82430e88,0x8cee8619,0x456f9fb4,0x7d84a5c3,0x3b8b5ebe,
                    0xe06f75d8,0x85c12073,0x401a449f,0x56c16aa6,0x4ed3aa62,0x363f7706,
                    0x1bfedf72,0x429b023d,0x37d0d724,0xd00a1248,0xdb0fead3,0x49f1c09b,
                    0x075372c9,0x80991b7b,0x25d479d8,0xf6e8def7,0xe3fe501a,0xb6794c3b,
                    0x976ce0bd,0x04c006ba,0xc1a94fb6,0x409f60c4,0x5e5c9ec2,0x196a2463,
                    0x68fb6faf,0x3e6c53b5,0x1339b2eb,0x3b52ec6f,0x6dfc511f,0x9b30952c,
                    0xcc814544,0xaf5ebd09,0xbee3d004,0xde334afd,0x660f2807,0x192e4bb3,
                    0xc0cba857,0x45c8740f,0xd20b5f39,0xb9d3fbdb,0x5579c0bd,0x1a60320a,
                    0xd6a100c6,0x402c7279,0x679f25fe,0xfb1fa3cc,0x8ea5e9f8,0xdb3222f8,
                    0x3c7516df,0xfd616b15,0x2f501ec8,0xad0552ab,0x323db5fa,0xfd238760,
                    0x53317b48,0x3e00df82,0x9e5c57bb,0xca6f8ca0,0x1a87562e,0xdf1769db,
                    0xd542a8f6,0x287effc3,0xac6732c6,0x8c4f5573,0x695b27b0,0xbbca58c8,
                    0xe1ffa35d,0xb8f011a0,0x10fa3d98,0xfd2183b8,0x4afcb56c,0x2dd1d35b,
                    0x9a53e479,0xb6f84565,0xd28e49bc,0x4bfb9790,0xe1ddf2da,0xa4cb7e33,
                    0x62fb1341,0xcee4c6e8,0xef20cada,0x36774c01,0xd07e9efe,0x2bf11fb4,
                    0x95dbda4d,0xae909198,0xeaad8e71,0x6b93d5a0,0xd08ed1d0,0xafc725e0,
                    0x8e3c5b2f,0x8e7594b7,0x8ff6e2fb,0xf2122b64,0x8888b812,0x900df01c,
                    0x4fad5ea0,0x688fc31c,0xd1cff191,0xb3a8c1ad,0x2f2f2218,0xbe0e1777,
                    0xea752dfe,0x8b021fa1,0xe5a0cc0f,0xb56f74e8,0x18acf3d6,0xce89e299,
                    0xb4a84fe0,0xfd13e0b7,0x7cc43b81,0xd2ada8d9,0x165fa266,0x80957705,
                    0x93cc7314,0x211a1477,0xe6ad2065,0x77b5fa86,0xc75442f5,0xfb9d35cf,
                    0xebcdaf0c,0x7b3e89a0,0xd6411bd3,0xae1e7e49,0x00250e2d,0x2071b35e,
                    0x226800bb,0x57b8e0af,0x2464369b,0xf009b91e,0x5563911d,0x59dfa6aa,
                    0x78c14389,0xd95a537f,0x207d5ba2,0x02e5b9c5,0x83260376,0x6295cfa9,
                    0x11c81968,0x4e734a41,0xb3472dca,0x7b14a94a,0x1b510052,0x9a532915,
                    0xd60f573f,0xbc9bc6e4,0x2b60a476,0x81e67400,0x08ba6fb5,0x571be91f,
                    0xf296ec6b,0x2a0dd915,0xb6636521,0xe7b9f9b6,0xff34052e,0xc5855664,
                    0x53b02d5d,0xa99f8fa1,0x08ba4799,0x6e85076a
        };
        private ulong[] _S3 = new ulong[256]{
                    0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,
                    0xba7c9045,0xf12c7f99,0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,
                    0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e,0x0d95748f,0x728eb658,
                    0x718bcd58,0x82154aee,0x7b54a41d,0xc25a59b5,0x9c30d539,0x2af26013,
                    0xc5d1b023,0x286085f0,0xca417918,0xb8db38ef,0x8e79dcb0,0x603a180e,
                    0x6c9e0e8b,0xb01e8a3e,0xd71577c1,0xbd314b27,0x78af2fda,0x55605c60,
                    0xe65525f3,0xaa55ab94,0x57489862,0x63e81440,0x55ca396a,0x2aab10b6,
                    0xb4cc5c34,0x1141e8ce,0xa15486af,0x7c72e993,0xb3ee1411,0x636fbc2a,
                    0x2ba9c55d,0x741831f6,0xce5c3e16,0x9b87931e,0xafd6ba33,0x6c24cf5c,
                    0x7a325381,0x28958677,0x3b8f4898,0x6b4bb9af,0xc4bfe81b,0x66282193,
                    0x61d809cc,0xfb21a991,0x487cac60,0x5dec8032,0xef845d5d,0xe98575b1,
                    0xdc262302,0xeb651b88,0x23893e81,0xd396acc5,0x0f6d6ff3,0x83f44239,
                    0x2e0b4482,0xa4842004,0x69c8f04a,0x9e1f9b5e,0x21c66842,0xf6e96c9a,
                    0x670c9c61,0xabd388f0,0x6a51a0d2,0xd8542f68,0x960fa728,0xab5133a3,
                    0x6eef0b6c,0x137a3be4,0xba3bf050,0x7efb2a98,0xa1f1651d,0x39af0176,
                    0x66ca593e,0x82430e88,0x8cee8619,0x456f9fb4,0x7d84a5c3,0x3b8b5ebe,
                    0xe06f75d8,0x85c12073,0x401a449f,0x56c16aa6,0x4ed3aa62,0x363f7706,
                    0x1bfedf72,0x429b023d,0x37d0d724,0xd00a1248,0xdb0fead3,0x49f1c09b,
                    0x075372c9,0x80991b7b,0x25d479d8,0xf6e8def7,0xe3fe501a,0xb6794c3b,
                    0x976ce0bd,0x04c006ba,0xc1a94fb6,0x409f60c4,0x5e5c9ec2,0x196a2463,
                    0x68fb6faf,0x3e6c53b5,0x1339b2eb,0x3b52ec6f,0x6dfc511f,0x9b30952c,
                    0xcc814544,0xaf5ebd09,0xbee3d004,0xde334afd,0x660f2807,0x192e4bb3,
                    0xc0cba857,0x45c8740f,0xd20b5f39,0xb9d3fbdb,0x5579c0bd,0x1a60320a,
                    0xd6a100c6,0x402c7279,0x679f25fe,0xfb1fa3cc,0x8ea5e9f8,0xdb3222f8,
                    0x3c7516df,0xfd616b15,0x2f501ec8,0xad0552ab,0x323db5fa,0xfd238760,
                    0x53317b48,0x3e00df82,0x9e5c57bb,0xca6f8ca0,0x1a87562e,0xdf1769db,
                    0xd542a8f6,0x287effc3,0xac6732c6,0x8c4f5573,0x695b27b0,0xbbca58c8,
                    0xe1ffa35d,0xb8f011a0,0x10fa3d98,0xfd2183b8,0x4afcb56c,0x2dd1d35b,
                    0x9a53e479,0xb6f84565,0xd28e49bc,0x4bfb9790,0xe1ddf2da,0xa4cb7e33,
                    0x62fb1341,0xcee4c6e8,0xef20cada,0x36774c01,0xd07e9efe,0x2bf11fb4,
                    0x95dbda4d,0xae909198,0xeaad8e71,0x6b93d5a0,0xd08ed1d0,0xafc725e0,
                    0x8e3c5b2f,0x8e7594b7,0x8ff6e2fb,0xf2122b64,0x8888b812,0x900df01c,
                    0x4fad5ea0,0x688fc31c,0xd1cff191,0xb3a8c1ad,0x2f2f2218,0xbe0e1777,
                    0xea752dfe,0x8b021fa1,0xe5a0cc0f,0xb56f74e8,0x18acf3d6,0xce89e299,
                    0xb4a84fe0,0xfd13e0b7,0x7cc43b81,0xd2ada8d9,0x165fa266,0x80957705,
                    0x93cc7314,0x211a1477,0xe6ad2065,0x77b5fa86,0xc75442f5,0xfb9d35cf,
                    0xebcdaf0c,0x7b3e89a0,0xd6411bd3,0xae1e7e49,0x00250e2d,0x2071b35e,
                    0x226800bb,0x57b8e0af,0x2464369b,0xf009b91e,0x5563911d,0x59dfa6aa,
                    0x78c14389,0xd95a537f,0x207d5ba2,0x02e5b9c5,0x83260376,0x6295cfa9,
                    0x11c81968,0x4e734a41,0xb3472dca,0x7b14a94a,0x1b510052,0x9a532915,
                    0xd60f573f,0xbc9bc6e4,0x2b60a476,0x81e67400,0x08ba6fb5,0x571be91f,
                    0xf296ec6b,0x2a0dd915,0xb6636521,0xe7b9f9b6,0xff34052e,0xc5855664,
                    0x53b02d5d,0xa99f8fa1,0x08ba4799,0x6e85076a
        };
        private ulong[] _S4 = new ulong[256]{
                    0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,
                    0xba7c9045,0xf12c7f99,0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,
                    0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e,0x0d95748f,0x728eb658,
                    0x718bcd58,0x82154aee,0x7b54a41d,0xc25a59b5,0x9c30d539,0x2af26013,
                    0xc5d1b023,0x286085f0,0xca417918,0xb8db38ef,0x8e79dcb0,0x603a180e,
                    0x6c9e0e8b,0xb01e8a3e,0xd71577c1,0xbd314b27,0x78af2fda,0x55605c60,
                    0xe65525f3,0xaa55ab94,0x57489862,0x63e81440,0x55ca396a,0x2aab10b6,
                    0xb4cc5c34,0x1141e8ce,0xa15486af,0x7c72e993,0xb3ee1411,0x636fbc2a,
                    0x2ba9c55d,0x741831f6,0xce5c3e16,0x9b87931e,0xafd6ba33,0x6c24cf5c,
                    0x7a325381,0x28958677,0x3b8f4898,0x6b4bb9af,0xc4bfe81b,0x66282193,
                    0x61d809cc,0xfb21a991,0x487cac60,0x5dec8032,0xef845d5d,0xe98575b1,
                    0xdc262302,0xeb651b88,0x23893e81,0xd396acc5,0x0f6d6ff3,0x83f44239,
                    0x2e0b4482,0xa4842004,0x69c8f04a,0x9e1f9b5e,0x21c66842,0xf6e96c9a,
                    0x670c9c61,0xabd388f0,0x6a51a0d2,0xd8542f68,0x960fa728,0xab5133a3,
                    0x6eef0b6c,0x137a3be4,0xba3bf050,0x7efb2a98,0xa1f1651d,0x39af0176,
                    0x66ca593e,0x82430e88,0x8cee8619,0x456f9fb4,0x7d84a5c3,0x3b8b5ebe,
                    0xe06f75d8,0x85c12073,0x401a449f,0x56c16aa6,0x4ed3aa62,0x363f7706,
                    0x1bfedf72,0x429b023d,0x37d0d724,0xd00a1248,0xdb0fead3,0x49f1c09b,
                    0x075372c9,0x80991b7b,0x25d479d8,0xf6e8def7,0xe3fe501a,0xb6794c3b,
                    0x976ce0bd,0x04c006ba,0xc1a94fb6,0x409f60c4,0x5e5c9ec2,0x196a2463,
                    0x68fb6faf,0x3e6c53b5,0x1339b2eb,0x3b52ec6f,0x6dfc511f,0x9b30952c,
                    0xcc814544,0xaf5ebd09,0xbee3d004,0xde334afd,0x660f2807,0x192e4bb3,
                    0xc0cba857,0x45c8740f,0xd20b5f39,0xb9d3fbdb,0x5579c0bd,0x1a60320a,
                    0xd6a100c6,0x402c7279,0x679f25fe,0xfb1fa3cc,0x8ea5e9f8,0xdb3222f8,
                    0x3c7516df,0xfd616b15,0x2f501ec8,0xad0552ab,0x323db5fa,0xfd238760,
                    0x53317b48,0x3e00df82,0x9e5c57bb,0xca6f8ca0,0x1a87562e,0xdf1769db,
                    0xd542a8f6,0x287effc3,0xac6732c6,0x8c4f5573,0x695b27b0,0xbbca58c8,
                    0xe1ffa35d,0xb8f011a0,0x10fa3d98,0xfd2183b8,0x4afcb56c,0x2dd1d35b,
                    0x9a53e479,0xb6f84565,0xd28e49bc,0x4bfb9790,0xe1ddf2da,0xa4cb7e33,
                    0x62fb1341,0xcee4c6e8,0xef20cada,0x36774c01,0xd07e9efe,0x2bf11fb4,
                    0x95dbda4d,0xae909198,0xeaad8e71,0x6b93d5a0,0xd08ed1d0,0xafc725e0,
                    0x8e3c5b2f,0x8e7594b7,0x8ff6e2fb,0xf2122b64,0x8888b812,0x900df01c,
                    0x4fad5ea0,0x688fc31c,0xd1cff191,0xb3a8c1ad,0x2f2f2218,0xbe0e1777,
                    0xea752dfe,0x8b021fa1,0xe5a0cc0f,0xb56f74e8,0x18acf3d6,0xce89e299,
                    0xb4a84fe0,0xfd13e0b7,0x7cc43b81,0xd2ada8d9,0x165fa266,0x80957705,
                    0x93cc7314,0x211a1477,0xe6ad2065,0x77b5fa86,0xc75442f5,0xfb9d35cf,
                    0xebcdaf0c,0x7b3e89a0,0xd6411bd3,0xae1e7e49,0x00250e2d,0x2071b35e,
                    0x226800bb,0x57b8e0af,0x2464369b,0xf009b91e,0x5563911d,0x59dfa6aa,
                    0x78c14389,0xd95a537f,0x207d5ba2,0x02e5b9c5,0x83260376,0x6295cfa9,
                    0x11c81968,0x4e734a41,0xb3472dca,0x7b14a94a,0x1b510052,0x9a532915,
                    0xd60f573f,0xbc9bc6e4,0x2b60a476,0x81e67400,0x08ba6fb5,0x571be91f,
                    0xf296ec6b,0x2a0dd915,0xb6636521,0xe7b9f9b6,0xff34052e,0xc5855664,
                    0x53b02d5d,0xa99f8fa1,0x08ba4799,0x6e85076a
        };

        private uint[] _P = new uint[18]
        {
                    0x243f6a88,0x85a308d3,0x13198a2e,0x03707344,0xa4093822,0x299f31d0,
                    0x082efa98,0xec4e6c89,0x452821e6,0x38d01377,0xbe5466cf,0x34e90c6c,
                    0xc0ac29b7,0xc97c50dd,0x3f84d5b5,0xb5470917,0x9216d5d9,0x8979fb1b
        };

        /// <summary>
        /// Конструктор
        /// </summary>
        /// <param name="beginningBlock"> Блок, с которого начинается шифрование в CBC, OFB, CFB </param> 
        public Blowfish(ulong beginningBlock)
        {
            _Sblocks = new ulong[4][] { _S1, _S2, _S3, _S4 };
            _beginingBlock = beginningBlock;
        }

        /// <summary>
        /// Шифрует данные text, ключом userkey (Режим электронной книги) многопоточно в 3-4 раза быстрее
        /// </summary>
        /// <param name="text"> Текст, который будет шифроваться </param> 
        /// <param name="userkey"> Ключ, вводимый для шифрования </param>
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public async Task<byte[]> ECB_MultithreadedEncrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }

            int processorCount = Environment.ProcessorCount;
            if (processorCount == 1) // многопоточность бесполезна
            {
                return ECB_Encrypt(text, userkey);
            }
            if (text.Length / (processorCount * 8) == 0) // многопоточность бесполезна
            {
                return ECB_Encrypt(text, userkey);
            }

            // сплитим массив, каждый из которых будет шифроваться отдельным потоком
            byte[][] splitedText = FullTextToSplitedTextForThreads(text);

            // последний сплит с инфо блоком
            splitedText[splitedText.Length - 1] = GetBlocksAndAppendInfoBlock(splitedText[splitedText.Length - 1]);

            uint[] roundsKeys = KeyGeneration(userkey);

            // многопоточное шифрование
            Task<byte[]>[] allTasks = new Task<byte[]>[processorCount];
            for (int i = 0; i < processorCount; i++)
            {
                int indexI = i; // т.к. значение i может поменяться при EndInvoke
                allTasks[indexI] = Task.Run(() => MultithreadedEncryptSplitedBlock_ForECB(splitedText[indexI], roundsKeys));
            }
            await Task.WhenAll(allTasks);

            for (int i = 0; i < processorCount; i++)
            {
                splitedText[i] = allTasks[i].Result;
            }

            // собираем все сплиты в 1 массив
            byte[] answer = SplitedTextToFullTextAfterThreads(splitedText);
            return answer;
        }

        /// <summary>
        /// Дешифрует данные text, ключом userkey (Режим электронной книги) многопоточно в 3-4 раза быстрее  
        /// </summary>
        /// <param name="text"> Текст, который будет дешифроваться (больше 64 бит, иначе просто вернёт текст) </param> 
        /// <param name="userkey"> Ключ, вводимый для дешифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public async Task<byte[]> ECB_MultithreadedDecrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            if (text.Length < 9)
            {
                return text;
            }

            int processorCount = Environment.ProcessorCount;
            if (processorCount == 1) // многопоточность бесполезна
            {
                return ECB_Decrypt(text, userkey);
            }
            if (text.Length / (processorCount * 8) == 0) // многопоточность бесполезна
            {
                return ECB_Decrypt(text, userkey);
            }

            byte[][] splitedText = FullTextToSplitedTextForThreads(text);
            uint[] roundsKeys = KeyGeneration(userkey);

            Task<byte[]>[] allTasks = new Task<byte[]>[processorCount];
            for (int i = 0; i < processorCount; i++)
            {
                int indexI = i; // т.к. значение i меняется
                allTasks[indexI] = Task.Run(() => MultithreadedDecryptSplitedBlock_ForECB(splitedText[indexI], roundsKeys));
            }
            await Task.WhenAll(allTasks);

            for (int i = 0; i < processorCount; i++)
            {
                splitedText[i] = allTasks[i].Result;
            }
            splitedText[splitedText.Length - 1] = GetBytesWithoutInfoBlock(splitedText[splitedText.Length - 1]);

            byte[] answer = SplitedTextToFullTextAfterThreads(splitedText);
            return answer;
        }

        /// <summary>
        /// Шифрует данные text, ключом userkey (Режим электронной книги)
        /// </summary>
        /// <param name="text"> Текст, который будет шифроваться </param> 
        /// <param name="userkey"> Ключ, вводимый для шифрования </param>
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] ECB_Encrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }

            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppendInfoBlock(text));

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = Encrypt(readyBlocks[i], roundsKeys);
            }

            return LongArrayToByteArray(readyBlocks);
        }

        /// <summary>
        /// Дешифрует данные text, ключом userkey (Режим электронной книги)
        /// </summary>
        /// <param name="text"> Текст, который будет дешифроваться (больше 64 бит, иначе просто вернёт текст) </param> 
        /// <param name="userkey"> Ключ, вводимый для дешифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] ECB_Decrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            if (text.Length < 9)
            {
                return text;
            }

            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = Decrypt(blocks[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetBytesWithoutInfoBlock(LongArrayToByteArray(blocks));
        }

        /// <summary>
        /// Шифрует данные text, ключом userkey (Режим сцеплений блоков)
        /// </summary>
        /// <param name="text"> Текст, который будет шифроваться </param> 
        /// <param name="userkey"> Ключ, вводимый для шифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] CBC_Encrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppendInfoBlock(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = Encrypt(forModeArray[i] ^ readyBlocks[i], roundsKeys);
                forModeArray[i + 1] = readyBlocks[i];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        /// <summary>
        /// Дешифрует данные text, ключом userkey (Режим сцеплений блоков)
        /// </summary>
        /// <param name="text"> Текст, который будет дешифроваться (больше 64 бит, иначе просто вернёт текст)</param> 
        /// <param name="userkey"> Ключ, вводимый для дешифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] CBC_Decrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            if (text.Length < 9)
            {
                return text;
            }

            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = blocks[i];
                blocks[i] = forModeArray[i] ^ Decrypt(blocks[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetBytesWithoutInfoBlock(LongArrayToByteArray(blocks));
        }

        /// <summary>
        /// Шифрует данные text, ключом userkey (Режим обратной связи по выходу)
        /// </summary>
        /// <param name="text"> Текст, который будет шифроваться </param> 
        /// <param name="userkey"> Ключ, вводимый для шифрования</param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] OFB_Encrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }

            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppendInfoBlock(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                forModeArray[i + 1] = Encrypt(forModeArray[i], roundsKeys);
                readyBlocks[i] = readyBlocks[i] ^ forModeArray[i + 1];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        /// <summary>
        /// Дешифрует данные text, ключом userkey (Режим обратной связи по выходу)
        /// </summary>
        /// <param name="text"> Текст, который будет дешифроваться (больше 64 бит, иначе просто вернёт текст)</param> 
        /// <param name="userkey"> Ключ, вводимый для дешифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] OFB_Decrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            if (text.Length < 9)
            {
                return text;
            }

            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = Encrypt(forModeArray[i], roundsKeys);
                blocks[i] = blocks[i] ^ forModeArray[i + 1];
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetBytesWithoutInfoBlock(LongArrayToByteArray(blocks));
        }

        /// <summary>
        /// Шифрует данные text, ключом userkey (Режим обратной связи по шифротексту)
        /// </summary>
        /// <param name="text"> Текст, который будет шифроваться </param> 
        /// <param name="userkey"> Ключ, вводимый для шифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] CFB_Encrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }

            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(GetBlocksAndAppendInfoBlock(text));

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[readyBlocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = readyBlocks[i] ^ Encrypt(forModeArray[i], roundsKeys);
                forModeArray[i + 1] = readyBlocks[i];
            }

            return LongArrayToByteArray(readyBlocks);
        }

        /// <summary>
        /// Дешифрует данные text, ключом userkey (Режим обратной связи по шифротексту)
        /// </summary>
        /// <param name="text"> Текст, который будет дешифроваться (больше 64 бит, иначе просто вернёт текст)</param> 
        /// <param name="userkey"> Ключ, вводимый для дешифрования </param> 
        /// <exception cref="ArgumentException"> Длина ключа (или текста) == 0 </exception>
        public byte[] CFB_Decrypt(byte[] text, byte[] userkey)
        {
            if ((userkey.Length == 0) || (text.Length == 0))
            {
                throw new ArgumentException("Длины текста и ключа в байтах равны " + text.Length +
                    ", " + userkey.Length + " (не должны быть == 0)");
            }
            if (text.Length < 9)
            {
                return text;
            }

            // достаем массив ulong для дешифра
            ulong[] blocks = ByteArrayToLongArray(text);

            // дополнительный массив с Z0 (только для 3-ёх режимов)
            ulong[] forModeArray = new ulong[blocks.Length + 1];
            forModeArray[0] = _beginingBlock;

            uint[] roundsKeys = KeyGeneration(userkey);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                forModeArray[i + 1] = blocks[i];
                blocks[i] = blocks[i] ^ Encrypt(forModeArray[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return GetBytesWithoutInfoBlock(LongArrayToByteArray(blocks));
        }

        private byte[] MultithreadedEncryptSplitedBlock_ForECB(byte[] splitedText, uint[] roundsKeys)
        {
            //Достаём Блоки, к которым уже добавлен блок информации (о предпоследнем блоке)
            ulong[] readyBlocks = ByteArrayToLongArray(splitedText);

            // после этого цикла readyBlocks будет уже зашифрованный текст
            for (int i = 0; i < readyBlocks.Length; i++)
            {
                readyBlocks[i] = Encrypt(readyBlocks[i], roundsKeys);
            }

            return LongArrayToByteArray(readyBlocks);
        }

        private byte[] MultithreadedDecryptSplitedBlock_ForECB(byte[] splitedText, uint[] roundsKeys)
        {
            ulong[] blocks = ByteArrayToLongArray(splitedText);

            // после этого цикла blocks будет уже расшифрованный текст
            for (int i = 0; i < blocks.Length; i++)
            {
                blocks[i] = Decrypt(blocks[i], roundsKeys);
            }

            // достаем его реальные байты из массива ulong (без дополнительного блока)
            return LongArrayToByteArray(blocks);
        }

        private byte[][] FullTextToSplitedTextForThreads(byte[] text)
        {
            int processorCount = Environment.ProcessorCount;

            int splitedTextBlockCount = text.Length / (processorCount * 8);
            int splitedTextBlock_ByteLength = splitedTextBlockCount * 8;
            int splitedTextBlock_ByteLengthLastTextBlock = splitedTextBlock_ByteLength + text.Length % (splitedTextBlock_ByteLength * processorCount);

            byte[][] answer = new byte[processorCount][];

            for (int i = 0; i < processorCount; i++)
            {
                if (i == processorCount - 1)
                {
                    answer[i] = new byte[splitedTextBlock_ByteLengthLastTextBlock];
                    Array.Copy(text, i * splitedTextBlock_ByteLength, answer[i], 0, splitedTextBlock_ByteLengthLastTextBlock);
                    break;
                }

                answer[i] = new byte[splitedTextBlock_ByteLength];
                Array.Copy(text, i * splitedTextBlock_ByteLength, answer[i], 0, splitedTextBlock_ByteLength);
            }

            return answer;
        }

        private byte[] SplitedTextToFullTextAfterThreads(byte[][] splitedText)
        {
            int answerLength = 0;
            int splitedTextLengthWithoutLast = splitedText[0].Length;

            // длина всего answer
            for (int i = 0; i < splitedText.Length; i++)
            {
                answerLength += splitedText[i].Length;
            }

            byte[] answer = new byte[answerLength];

            for (int i = 0; i < splitedText.Length; i++)
            {
                Array.Copy(splitedText[i], 0, answer, i * splitedTextLengthWithoutLast, splitedText[i].Length);
            }

            return answer;
        }

        // Получаем блоки по 64 бит (последний блок отвечает за информацию о предпоследнем блоке)
        private byte[] GetBlocksAndAppendInfoBlock(byte[] text)
        {
            // сколько байт лишних       
            uint missingSize = (uint)(8 - text.Length % 8) % 8;

            // нужный нам текст
            byte[] appendedText = new byte[text.Length + missingSize + 8];

            Array.Copy(text, appendedText, text.Length);

            appendedText[text.Length + missingSize] = (byte)missingSize;      

            return appendedText;

        }

        // Получаем реальные блоки по 64 за исключением последнего, который имеет свою реальную длину (от 1 до 64)
        private byte[] GetBytesWithoutInfoBlock(byte[] textBytes)
        {
            // находим наши ненужные байты в последнем блоке в предпоследнем блоке
            int missingSize = textBytes[textBytes.Length - 8] % 8 ;

            byte[] answer = new byte[textBytes.Length - 8 - missingSize];
            Array.Copy(textBytes, answer, answer.Length);
            
            return answer;

        }

        private ulong[] ByteArrayToLongArray(byte[] text)
        {
            byte[] checkedText;

            if (text.Length % 8 != 0)
            {
                checkedText = new byte[text.Length + (8 - text.Length % 8)];
            }
            else
            {
                checkedText = new byte[text.Length];
            }

            Array.Copy(text, checkedText, text.Length);

            ulong[] answer;
            answer = new ulong[text.Length / 8];

            for (int i = 0; i < answer.Length; i++)
            {
               answer[i] = BitConverter.ToUInt64(text, i * 8);
            }

             return answer;
            
        }

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

        // Шифрование одного блока
        private ulong Encrypt(ulong textBit64, uint[] roundsKeys)
        {
            // правая-левая части
            ulong[] L = new ulong[18];
            ulong[] R = new ulong[18];

            L[0] = (textBit64 >> 32);
            R[0] = WorkWithBits.GetLowBits(textBit64, 32);

            // цикл раундов 
            for (int i = 0; i < 16; i++)
            {
                L[i + 1] = R[i] ^ F_Transformation( (uint)(roundsKeys[i] ^ L[i]) );
                R[i + 1] = L[i];
            }

            uint tmp = (uint)R[16];
            R[16] = L[16];
            L[16] = tmp;

            R[17] = R[16] ^ roundsKeys[16];
            L[17] = L[16] ^ roundsKeys[17];

            // склеиваем половинки
            ulong answer = (L[17] << 32) | R[17];

            return answer;
        }

        // Дешифрование одного блока
        private ulong Decrypt(ulong textBit64, uint[] roundsKeys)
        {
            ulong[] L = new ulong[18];
            ulong[] R = new ulong[18];

            // тут наоборот в отличии от Encrypt
            L[17] = (textBit64 >> 32);
            R[17] = WorkWithBits.GetLowBits(textBit64, 32);

            R[16] = R[17] ^ roundsKeys[16];
            L[16] = L[17] ^ roundsKeys[17];

            uint tmp = (uint)R[16];
            R[16] = L[16];
            L[16] = tmp;

            // тут тоже наоборот
            for (int i = 15; i >= 0; i--)
            {
                R[i] = L[i + 1] ^ F_Transformation((uint) (roundsKeys[i] ^ R[i + 1]));
                L[i] = R[i + 1];

            }

            ulong answer = (L[0] << 32) | R[0];

            return answer;
        }

        // Генерация ключа 
        private uint[] KeyGeneration(byte[] userKey)
        {
            byte[] appendedUserKeys = KeyExpend(userKey);

            uint[] answer = new uint[18];
            int j = 0;
            for (int i = 0; i < _P.Length; i++)
            {
                answer[i] = _P[i] ^ BitConverter.ToUInt32(appendedUserKeys,j) ;
                j = (j + 4) % appendedUserKeys.Length;
            }

            return answer;
        }

        // Расширение ключа, для кратности 32-ум битам
        private byte[] KeyExpend(byte[] key)
        {
            if (key.Length % 4 == 0)
            {
                return (byte[])key.Clone();
            }

            byte[] answer = new byte[key.Length + (4 - key.Length % 4)];
            Array.Copy(key, answer, key.Length);

            return answer;
        }

        // F преобразование
        private uint F_Transformation(uint block)
        {
            uint answer = BlowfishSumWithMod(_Sblocks[0][WorkWithBits.CutBitsWithBeginningAndEndingPlaces(block, 0, 7)],
                _Sblocks[1][WorkWithBits.CutBitsWithBeginningAndEndingPlaces(block, 8, 15)]);
            answer = answer ^(uint)_Sblocks[2][WorkWithBits.CutBitsWithBeginningAndEndingPlaces(block, 16, 23)];
            answer = BlowfishSumWithMod(answer , _Sblocks[3][WorkWithBits.CutBitsWithBeginningAndEndingPlaces(block, 24, 31)]);

            return answer;
        }

        // Сложение по модулю 2^(32)
        private uint BlowfishSumWithMod(ulong firstNumber, ulong secondNumber)
        {
            return (uint) ((firstNumber + secondNumber) % 4294967296);
        }

    }
}
