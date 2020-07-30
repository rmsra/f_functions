#include "ue_auth_vector_algo_milenage.h"
#include "ue_auth_cipher_algo_Rijndael.h"

#include <memory.h>

namespace saue_mm
{

    vector_algo_milenage::vector_algo_milenage(): cipher(cipher_algo_Rijndael::get_instance()) {}

    vector_algo_milenage::~vector_algo_milenage() {}

    vector_algo_milenage* vector_algo_milenage::get_instance()
    {
        static vector_algo_milenage* pthis = new vector_algo_milenage();
        return pthis;
    }

    /*-------------------------------------------------------------------
     *                            Algorithm f1
     *-------------------------------------------------------------------
     *
     *  Computes network authentication code MAC-A from key K, random
     *  challenge RAND, sequence number SQN and authentication management
     *  field AMF.
     *
     *-----------------------------------------------------------------*/
    void vector_algo_milenage::f1(uint8_t op[16], bool is_opc, uint8_t k[16], uint8_t rand[16],
            uint8_t sqn[6], uint8_t amf[2], uint8_t mac_a[8])
    {
        uint8_t temp[16];
        uint8_t opc[16];
        uint8_t in1[16];
        uint8_t out1[16];
        uint8_t rijndaelInput[16];
        uint8_t i;
        //memset((uint8_t*)tempdd, 0, sizeof(nas_security_params_t));

        cipher->keySchedule(k);

        if(is_opc)
            memcpy(opc, op, sizeof(opc));
        else
        {
            computeOPc(op, opc);
        }

        for (i=0; i<16; i++)
            rijndaelInput[i] = rand[i] ^ opc[i];
        cipher->encrypt( rijndaelInput, temp );

        for (i=0; i<6; i++)
        {
            in1[i]    = sqn[i];
            in1[i+8]  = sqn[i];
        }
        for (i=0; i<2; i++)
        {
            in1[i+6]  = amf[i];
            in1[i+14] = amf[i];
        }

        /* XOR op_c and in1, rotate by r1=64, and XOR *
         * on the constant c1 (which is all zeroes)   */

        for (i=0; i<16; i++)
            rijndaelInput[(i+8) % 16] = in1[i] ^ opc[i];

        /* XOR on the value temp computed before */

        for (i=0; i<16; i++)
            rijndaelInput[i] ^= temp[i];

        cipher->encrypt( rijndaelInput, out1 );
        for (i=0; i<16; i++)
            out1[i] ^= opc[i];

        for (i=0; i<8; i++)
            mac_a[i] = out1[i];

        return;
    } /* end of function f1 */

    /*-------------------------------------------------------------------
         *                            Algorithms f2-f5
         *-------------------------------------------------------------------
         *
         *  Takes key K and random challenge RAND, and returns response RES,
         *  confidentiality key CK, integrity key IK and anonymity key AK.
         *
         *-----------------------------------------------------------------*/
    void vector_algo_milenage::f2345(uint8_t op[16], bool is_opc, uint8_t k[16],
            uint8_t rand[16], uint8_t res[8], uint8_t ck[16], uint8_t ik[16], uint8_t ak[6])
    {
        uint8_t temp[16];
        uint8_t opc[16];
        uint8_t out[16];
        uint8_t rijndaelInput[16];
        uint8_t i;

        cipher->keySchedule(k);
        if(is_opc)
            memcpy(opc, op, sizeof(opc));
        else
            computeOPc(op, opc);

        for (i=0; i<16; i++)
            rijndaelInput[i] = rand[i] ^ opc[i];
        cipher->encrypt( rijndaelInput, temp );

        /* To obtain output block OUT2: XOR OPc and TEMP,    *
         * rotate by r2=0, and XOR on the constant c2 (which *
         * is all zeroes except that the last bit is 1).     */

        for (i=0; i<16; i++)
            rijndaelInput[i] = temp[i] ^ opc[i];
        rijndaelInput[15] ^= 1;

        cipher->encrypt( rijndaelInput, out );
        for (i=0; i<16; i++)
            out[i] ^= opc[i];

        for (i=0; i<8; i++)
            res[i] = out[i+8];
        for (i=0; i<6; i++)
            ak[i]  = out[i];

        /* To obtain output block OUT3: XOR OPc and TEMP,        *
         * rotate by r3=32, and XOR on the constant c3 (which    *
         * is all zeroes except that the next to last bit is 1). */

        for (i=0; i<16; i++)
            rijndaelInput[(i+12) % 16] = temp[i] ^ opc[i];
        rijndaelInput[15] ^= 2;

        cipher->encrypt( rijndaelInput, out );
        for (i=0; i<16; i++)
            out[i] ^= opc[i];

        for (i=0; i<16; i++)
            ck[i] = out[i];

        /* To obtain output block OUT4: XOR OPc and TEMP,         *
         * rotate by r4=64, and XOR on the constant c4 (which     *
         * is all zeroes except that the 2nd from last bit is 1). */

        for (i=0; i<16; i++)
            rijndaelInput[(i+8) % 16] = temp[i] ^ opc[i];
        rijndaelInput[15] ^= 4;

        cipher->encrypt( rijndaelInput, out );
        for (i=0; i<16; i++)
            out[i] ^= opc[i];

        for (i=0; i<16; i++)
            ik[i] = out[i];

        return;
    } /* end of function f2345 */


    /*-------------------------------------------------------------------
     *                            Algorithm f1*
     *-------------------------------------------------------------------
     *
     *  Computes resynch authentication code MAC-S from key K, random
     *  challenge RAND, sequence number SQN and authentication management
     *  field AMF.
     *
     *-----------------------------------------------------------------*/
    void vector_algo_milenage::f1star(uint8_t op[16],
            bool is_opc,
            uint8_t k[16],
            uint8_t rand[16],
            uint8_t sqn[6],
            uint8_t amf[2],
            uint8_t mac_s[8])
    {
        uint8_t temp[16];
        uint8_t opc[16];
        uint8_t in1[16];
        uint8_t out1[16];
        uint8_t rijndaelInput[16];
        uint8_t i;

        cipher->keySchedule(k);
        if(is_opc)
            memcpy(opc, op, sizeof(opc));
        else
            computeOPc(op, opc);

        for (i=0; i<16; i++)
            rijndaelInput[i] = rand[i] ^ opc[i];
        cipher->encrypt( rijndaelInput, temp );

        for (i=0; i<6; i++)
        {
            in1[i]    = sqn[i];
            in1[i+8]  = sqn[i];
        }
        for (i=0; i<2; i++)
        {
            in1[i+6]  = amf[i];
            in1[i+14] = amf[i];
        }

        /* XOR op_c and in1, rotate by r1=64, and XOR *
         * on the constant c1 (which is all zeroes)   */

        for (i=0; i<16; i++)
            rijndaelInput[(i+8) % 16] = in1[i] ^ opc[i];

        /* XOR on the value temp computed before */

        for (i=0; i<16; i++)
            rijndaelInput[i] ^= temp[i];

        cipher->encrypt( rijndaelInput, out1 );
        for (i=0; i<16; i++)
            out1[i] ^= opc[i];

        for (i=0; i<8; i++)
            mac_s[i] = out1[i+8];

        return;
    } /* end of function f1star */


    /*-------------------------------------------------------------------
     *                            Algorithm f5*
     *-------------------------------------------------------------------
     *
     *  Takes key K and random challenge RAND, and returns resynch
     *  anonymity key AK.
     *
     *-----------------------------------------------------------------*/
    void vector_algo_milenage::f5star(uint8_t op[16], bool is_opc, uint8_t k[16], uint8_t rand[16], uint8_t ak[6])
    {
        uint8_t temp[16];
        uint8_t opc[16];
        uint8_t out[16];
        uint8_t rijndaelInput[16];
        uint8_t i;

        cipher->keySchedule(k);
        if(is_opc)
            memcpy(opc, op, sizeof(opc));
        else
            computeOPc(op, opc);

        for (i=0; i<16; i++)
            rijndaelInput[i] = rand[i] ^ opc[i];
        cipher->encrypt( rijndaelInput, temp );

        /* To obtain output block OUT5: XOR OPc and TEMP,         *
         * rotate by r5=96, and XOR on the constant c5 (which     *
         * is all zeroes except that the 3rd from last bit is 1). */

        for (i=0; i<16; i++)
            rijndaelInput[(i+4) % 16] = temp[i] ^ opc[i];
        rijndaelInput[15] ^= 8;

        cipher->encrypt( rijndaelInput, out );
        for (i=0; i<16; i++)
            out[i] ^= opc[i];

        for (i=0; i<6; i++)
            ak[i] = out[i];

        return;
    }/* end of function f5star */


    /*-------------------------------------------------------------------
     *  Function to compute OPc from OP and K.  Assumes key schedule has
     already been performed.
     *-----------------------------------------------------------------*/
    void vector_algo_milenage::computeOPc(uint8_t OP[16], uint8_t op_c[16])
    {
        uint8_t i;

        cipher->encrypt(OP, op_c );
        for (i=0; i<16; i++)
            op_c[i] ^= OP[i];

        return;
    }/* end of function ComputeOPc */
}
