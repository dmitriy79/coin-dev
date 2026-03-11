/**********************************************************************
 * Copyright (c) 2014, 2015 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>
#include <secp256k1.h>

#include "lax_der_privatekey_parsing.h"

int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80)) {
        return 0;
    }
    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end < privkey+lenb) {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;
    if (end < privkey+len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1]) {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) return 0;

    // Заголовок: SEQUENCE, Version 1, Private Key (32 bytes), [0] Named Curve OID
    static const unsigned char head[] = {
        0x30, 0x00, 0x02, 0x01, 0x01, 0x04, 0x20
    };
    // OID secp256k1 (1.3.132.0.10) + заголовок публичного ключа
    static const unsigned char mid[] = {
        0xA0, 0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 
        0xA1, 0x00, 0x03, 0x00, 0x00
    };

    unsigned char *ptr = privkey;
    memcpy(ptr, head, sizeof(head)); ptr += sizeof(head);
    memcpy(ptr, key32, 32); ptr += 32;
    
    // Копируем блок с OID и готовим место под публичный ключ
    unsigned char *mid_ptr = ptr;
    memcpy(ptr, mid, sizeof(mid)); ptr += sizeof(mid);

    size_t plen = compressed ? 33 : 65;
    // Корректируем длину BIT STRING для публичного ключа (длина ключа + 1 байт для '0x00')
    mid_ptr[10] = (unsigned char)(plen + 3); // Длина тега [1]
    mid_ptr[12] = (unsigned char)(plen + 1); // Длина BIT STRING

    secp256k1_ec_pubkey_serialize(ctx, ptr - 1, &plen, &pubkey, 
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

    *privkeylen = (ptr - 1 + plen) - privkey;
    privkey[1] = (unsigned char)(*privkeylen - 2); // Итоговая длина SEQUENCE
    return 1;
}
