#ifndef AUTH_VECTOR_ALGO_MILENAGE_H
#define AUTH_VECTOR_ALGO_MILENAGE_H

#include "auth_vector_algo.h"
#include "auth_cipher_algo.h"

namespace saue_mm
{
   class vector_algo_milenage: public vector_algo
   {
      private:
         cipher_algo *cipher;
      public:

         vector_algo_milenage();
         ~vector_algo_milenage();

         static vector_algo_milenage* get_instance();

         void f1(uint8_t op[16], bool is_opc, uint8_t k[16], uint8_t rand[16],
               uint8_t sqn[6], uint8_t amf[2], uint8_t mac_a[8]);

         void f2345(uint8_t op[16], bool is_opc, uint8_t k[16], uint8_t rand[16],
               uint8_t res[8], uint8_t ck[16], uint8_t ik[16], uint8_t ak[6]);

         void f1star(uint8_t op[16], bool is_opc, uint8_t k[16],
               uint8_t rand[16], uint8_t sqn[6],
               uint8_t amf[2], uint8_t mac_s[8]);

         void f5star(uint8_t op[16], bool is_opc, uint8_t k[16],
               uint8_t rand[16], uint8_t ak[6]);

         void computeOPc(uint8_t OP[16], uint8_t op_c[16]);
   };

}
#endif /* AUTH_VECTOR_ALGO_MILENAGE_H */
