#include "ue_auth_cipher_algo_Rijndael.h"

namespace saue_mm
{
    cipher_algo_Rijndael::cipher_algo_Rijndael() {}

    cipher_algo_Rijndael::~cipher_algo_Rijndael() {}

    cipher_algo_Rijndael* cipher_algo_Rijndael::get_instance()
    {
        static cipher_algo_Rijndael *instance = new cipher_algo_Rijndael();
        return instance;
    }

    /*-------------------------------------------------------------------
     *  Rijndael key schedule function.  Takes 16-byte key and creates 
     *  all Rijndael's internal subkeys ready for encryption.
     *-----------------------------------------------------------------*/
    void cipher_algo_Rijndael::keySchedule(const uint8_t key[16])
    {
        uint8_t roundConst;
        int i, j;

        /* first round key equals key */
        for (i=0; i<16; i++)
            roundKeys[0][i & 0x03][i>>2] = key[i];

        roundConst = 1;

        /* now calculate round keys */
        for (i=1; i<11; i++)
        {
            roundKeys[i][0][0] = S[roundKeys[i-1][1][3]]
                ^ roundKeys[i-1][0][0] ^ roundConst;
            roundKeys[i][1][0] = S[roundKeys[i-1][2][3]]
                ^ roundKeys[i-1][1][0];
            roundKeys[i][2][0] = S[roundKeys[i-1][3][3]]
                ^ roundKeys[i-1][2][0];
            roundKeys[i][3][0] = S[roundKeys[i-1][0][3]]
                ^ roundKeys[i-1][3][0];

            for (j=0; j<4; j++)
            {
                roundKeys[i][j][1] = roundKeys[i-1][j][1] ^ roundKeys[i][j][0];
                roundKeys[i][j][2] = roundKeys[i-1][j][2] ^ roundKeys[i][j][1];
                roundKeys[i][j][3] = roundKeys[i-1][j][3] ^ roundKeys[i][j][2];
            }

            /* update round constant */
            roundConst = Xtime[roundConst];
        }

        return;
    } /* end of function RijndaelKeySchedule */

    /*-------------------------------------------------------------------
     *  Rijndael encryption function.  Takes 16-byte input and creates 
     *  16-byte output (using round keys already derived from 16-byte 
     *  key).
     *-----------------------------------------------------------------*/
    void cipher_algo_Rijndael::encrypt(uint8_t input[16], uint8_t output[16])
    {
        uint8_t state[4][4];
        int i, r;

        /* initialise state array from input byte string */
        for (i=0; i<16; i++)
            state[i & 0x3][i>>2] = input[i];

        /* add first round_key */
        KeyAdd(state, roundKeys, 0);

        /* do lots of full rounds */
        for (r=1; r<=9; r++)
        {
            ByteSub(state);
            ShiftRow(state);
            MixColumn(state);
            KeyAdd(state, roundKeys, r);
        }

        /* final round */
        ByteSub(state);
        ShiftRow(state);
        KeyAdd(state, roundKeys, r);

        /* produce output byte string from state array */
        for (i=0; i<16; i++)
        {
            output[i] = state[i & 0x3][i>>2];
        }

        return;
    } /* end of function RijndaelEncrypt */

}
