/*
 * Copyright (c) 2017 Kentaro Sekimoto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include <string.h>
#include "twitter.h"
#include "https_request.h"
#include "ntp-client/NTPClient.h"

//#define URL_DECODE
//#define BASE64_DECODE
//#define DEBUG_PARAMS
//#define CHECK_AUTH_STRING
#define DEBUG_STATUSES_UPDATE
#define DEBUG_UPLOAD
#define DEBUG_HTTP_POST
//#define DUMP_RESPONSE
//#define SKIP_STATUSES_UPLOAD

#ifndef NULL
#define NULL 0
#endif

#define OAUTH_SIGNATURE_METHOD  "HMAC-SHA1"
#define OAUTH_VERSION           "1.0"
#define TWITTER_API_UPDATE      "https://api.twitter.com/1.1/statuses/update.json"
#define TWITTER_API_UPLOAD      "https://upload.twitter.com/1.1/media/upload.json"

#define MAX_MESSAGE_LENGTH 2048

#define ENCODE_BUF_MAX  (1024*3)
#define PARAM_BUF_MAX   512
#define SIG_KEY_MAX     256
#define SIG_DATA_MAX    512
#define SIG_STR_MAX     512
#define AUTH_STR_MAX    1024

static char encode_buf[ENCODE_BUF_MAX];
static char param_buf[PARAM_BUF_MAX];
static char sig_key[SIG_KEY_MAX];
static char sig_data[SIG_DATA_MAX];
static char sig_str[SIG_STR_MAX];
static char auth_str[AUTH_STR_MAX];

static char body[4096];

#define BOUNDARY_MAX   20
#define UPLOAD_HEADER_MAX   128
#define MEDIA_BUF_MAX   100*1024

static char boundary_buf[BOUNDARY_MAX];
static char upload_header_buf[UPLOAD_HEADER_MAX];
static char upload_body_top[256];
static char upload_body_end[256];
static char media_buf[MEDIA_BUF_MAX];

typedef struct _PARAM {
    char *key;
    char *value;
} PARAM;

PARAM req_params[] = {
        {(char *)"oauth_consumer_key", (char *)""},
        {(char *)"oauth_nonce", (char *)""},
        {(char *)"oauth_signature_method", (char *)OAUTH_SIGNATURE_METHOD},
        {(char *)"oauth_timestamp", (char *)""},
        {(char *)"oauth_token", (char *)""},
        {(char *)"oauth_version", (char *)OAUTH_VERSION},
        {(char *)NULL, (char *)NULL},
};

PARAM statuses_oauth_params1[] = {
        {(char *)"oauth_consumer_key", (char *)""},
        {(char *)"oauth_nonce", (char *)""},
        {(char *)"oauth_signature_method", (char *)OAUTH_SIGNATURE_METHOD},
        {(char *)"oauth_timestamp", (char *)""},
        {(char *)"oauth_token", (char *)""},
        {(char *)"oauth_version", (char *)OAUTH_VERSION},
        {(char *)"status", (char *)""},
        {(char *)"oauth_signature", (char *)""},
        {(char *)NULL, (char *)NULL},
};

PARAM statuses_oauth_params2[] = {
        {(char *)"media_ids", (char *)""},
        {(char *)"oauth_consumer_key", (char *)""},
        {(char *)"oauth_nonce", (char *)""},
        {(char *)"oauth_signature_method", (char *)OAUTH_SIGNATURE_METHOD},
        {(char *)"oauth_timestamp", (char *)""},
        {(char *)"oauth_token", (char *)""},
        {(char *)"oauth_version", (char *)OAUTH_VERSION},
        {(char *)"status", (char *)""},
        {(char *)"oauth_signature", (char *)""},
        {(char *)NULL, (char *)NULL},
};

PARAM upload_oauth_params[] = {
        {(char *)"oauth_consumer_key", (char *)""},
        {(char *)"oauth_nonce", (char *)""},
        {(char *)"oauth_signature_method", (char *)OAUTH_SIGNATURE_METHOD},
        {(char *)"oauth_timestamp", (char *)""},
        {(char *)"oauth_token", (char *)""},
        {(char *)"oauth_version", (char *)OAUTH_VERSION},
        {(char *)"oauth_signature", (char *)""},
        {(char *)NULL, (char *)NULL},
};

//#define GlobalSign_Root_CA
//#define GeoTrust_Global_CA
#define DigiCert_High_Assurance_EV_Root_CA
static const char SSL_CA_PEM[] =
#include "cacert.h"
;

static char hex[] = "0123456789ABCDEF";
static char num_to_hex(char num) {
    return hex[num & 0xf];
}

static int _isalnum(char ch)
{
    if ((('0' <= ch) && (ch <= '9')) || (('A' <= ch) && (ch <= 'Z')) || (('a' <= ch) && (ch <= 'z')))
        return 1;
    else
        return 0;
}

static char *_url_encode(char *str, char *dst, int size)
{
    char *pstr = str;
    char *pbuf = dst;
    if (size == 0)
        return dst;
    size--;
    while (size && (*pstr)) {
        if (_isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
            *pbuf++ = *pstr;
            size--;
        } else if (*pstr == ' ') {
            *pbuf++ = '+';
            size --;
        } else {
            *pbuf++ = '%';
            size--; if (size == 0) break;
            *pbuf++ = num_to_hex(*pstr >> 4);
            size--; if (size == 0) break;
            *pbuf++ = num_to_hex(*pstr & 0xf);
        }
        pstr++;
    }
    *pbuf = '\0';
    return dst;
}

#ifdef URL_DECODE
static char hex_to_num(char ch)
{
    if (('0' <= ch) && (ch <= '9')) {
        return (ch - '0');
    } else if (('A' <= ch) && (ch <= 'F')) {
        return (ch - 'A' + 10);
    } else if (('a' <= ch) && (ch <= 'f')) {
        return (ch - 'a' + 10);
    }
    return ch;
}

static char *_url_decode(char *str, char *dst, int size)
{
    char *pstr = str;
    char *pbuf = dst;
    if (size == 0)
        return dst;
    size --;
    while (size && (*pstr)) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = hex_to_num(pstr[1]) << 4 | hex_to_num(pstr[2]);
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
        size--;
    }
    *pbuf = '\0';
    return dst;
}
#endif

//**************************************************
// hmac-sha1
// ref: http://www.deadhat.com/wlancrypto/hmac_sha1.c
//**************************************************

/****************************************************************/
/* 802.11i HMAC-SHA-1 Test Code                                 */
/* Copyright (c) 2002, David Johnston                           */
/* Author: David Johnston                                       */
/* Email (home): dj@deadhat.com                                 */
/* Email (general): david.johnston@ieee.org                     */
/* Version 0.1                                                  */
/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*                                                              */
/* This code implements the NIST HMAC-SHA-1 algorithm as used   */
/* the IEEE 802.11i security spec.                              */
/*                                                              */
/* Supported message length is limited to 4096 characters       */
/* ToDo:                                                        */
/*   Sort out endian tolerance. Currently little endian.        */
/****************************************************************/

/****************************************/
/* sha1()                               */
/* Performs the NIST SHA-1 algorithm    */
/****************************************/
static unsigned long int ft(int t, unsigned long int x, unsigned long int y, unsigned long int z)
{
    unsigned long int a,b,c;
    if (t < 20) {
        a = x & y;
        b = (~x) & z;
        c = a ^ b;
    } else if (t < 40) {
        c = x ^ y ^ z;
    } else if (t < 60) {
        a = x & y;
        b = a ^ (x & z);
        c = b ^ (y & z);
    } else if (t < 80) {
        c = (x ^ y) ^ z;
    }
    return c;
}

static unsigned long int k(int t)
{
    unsigned long int c;
    if (t < 20) {
        c = 0x5a827999;
    } else if (t < 40) {
        c = 0x6ed9eba1;
    } else if (t < 60) {
        c = 0x8f1bbcdc;
    } else if (t < 80) {
        c = 0xca62c1d6;
    }
    return c;
}

//static unsigned long int rotr(int bits, unsigned long int a)
//{
//  unsigned long int c,d,e,f,g;
//  c = (0x0001 << bits)-1;
//  d = ~c;
//  e = (a & d) >> bits;
//  f = (a & c) << (32 - bits);
//  g = e | f;
//  return (g & 0xffffffff );
//}

static unsigned long int rotl(int bits, unsigned long int a)
{
    unsigned long int c,d,e,f,g;
    c = (0x0001 << (32-bits))-1;
    d = ~c;
    e = (a & c) << bits;
    f = (a & d) >> (32 - bits);
    g = e | f;
    return (g & 0xffffffff );
}

static void sha1(unsigned char *message, int message_length, unsigned char *digest)
{
    int i;
    int num_blocks;
    int block_remainder;
    int padded_length;

    unsigned long int l;
    unsigned long int t;
    unsigned long int h[5];
    unsigned long int a, b, c, d, e;
    unsigned long int w[80];
    unsigned long int temp;

    /* Calculate the number of 512 bit blocks */
    padded_length = message_length + 8; /* Add length for l */
    padded_length = padded_length + 1; /* Add the 0x01 bit postfix */

    l = message_length * 8;

    num_blocks = padded_length / 64;
    block_remainder = padded_length % 64;

    if (block_remainder > 0) {
        num_blocks++;
    }

    padded_length = padded_length + (64 - block_remainder);

    /* clear the padding field */
    for (i = message_length; i < (num_blocks * 64); i++) {
        message[i] = 0x00;
    }

    /* insert b1 padding bit */
    message[message_length] = 0x80;

    /* Insert l */
    message[(num_blocks * 64) - 1] = (unsigned char) (l & 0xff);
    message[(num_blocks * 64) - 2] = (unsigned char) ((l >> 8) & 0xff);
    message[(num_blocks * 64) - 3] = (unsigned char) ((l >> 16) & 0xff);
    message[(num_blocks * 64) - 4] = (unsigned char) ((l >> 24) & 0xff);

    /* Set initial hash state */
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;

    for (i = 0; i < num_blocks; i++) {
        /* Prepare the message schedule */
        for (t = 0; t < 80; t++) {
            if (t < 16) {
                w[t] = (256 * 256 * 256) * message[(i * 64) + (t * 4)];
                w[t] += (256 * 256) * message[(i * 64) + (t * 4) + 1];
                w[t] += (256) * message[(i * 64) + (t * 4) + 2];
                w[t] += message[(i * 64) + (t * 4) + 3];
            } else if (t < 80) {
                w[t] = rotl(1, (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]));
            }
        }
        /* Initialize the five working variables */
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

        /* iterate a-e 80 times */
        for (t = 0; t < 80; t++) {
            temp = (rotl(5, a) + ft(t, b, c, d)) & 0xffffffff;
            temp = (temp + e) & 0xffffffff;
            temp = (temp + k(t)) & 0xffffffff;
            temp = (temp + w[t]) & 0xffffffff;
            e = d;
            d = c;
            c = rotl(30, b);
            b = a;
            a = temp;
        }

        /* compute the ith intermediate hash value */
        h[0] = (a + h[0]) & 0xffffffff;
        h[1] = (b + h[1]) & 0xffffffff;
        h[2] = (c + h[2]) & 0xffffffff;
        h[3] = (d + h[3]) & 0xffffffff;
        h[4] = (e + h[4]) & 0xffffffff;
    }

    digest[3] = (unsigned char) (h[0] & 0xff);
    digest[2] = (unsigned char) ((h[0] >> 8) & 0xff);
    digest[1] = (unsigned char) ((h[0] >> 16) & 0xff);
    digest[0] = (unsigned char) ((h[0] >> 24) & 0xff);
    digest[7] = (unsigned char) (h[1] & 0xff);
    digest[6] = (unsigned char) ((h[1] >> 8) & 0xff);
    digest[5] = (unsigned char) ((h[1] >> 16) & 0xff);
    digest[4] = (unsigned char) ((h[1] >> 24) & 0xff);
    digest[11] = (unsigned char) (h[2] & 0xff);
    digest[10] = (unsigned char) ((h[2] >> 8) & 0xff);
    digest[9] = (unsigned char) ((h[2] >> 16) & 0xff);
    digest[8] = (unsigned char) ((h[2] >> 24) & 0xff);
    digest[15] = (unsigned char) (h[3] & 0xff);
    digest[14] = (unsigned char) ((h[3] >> 8) & 0xff);
    digest[13] = (unsigned char) ((h[3] >> 16) & 0xff);
    digest[12] = (unsigned char) ((h[3] >> 24) & 0xff);
    digest[19] = (unsigned char) (h[4] & 0xff);
    digest[18] = (unsigned char) ((h[4] >> 8) & 0xff);
    digest[17] = (unsigned char) ((h[4] >> 16) & 0xff);
    digest[16] = (unsigned char) ((h[4] >> 24) & 0xff);
}

/******************************************************/
/* hmac-sha1()                                        */
/* Performs the hmac-sha1 keyed secure hash algorithm */
/******************************************************/
/* Moving local variables to static variables for not using stack  */
static unsigned char k0[64];
static unsigned char k0xorIpad[64];
static unsigned char step7data[64];
static unsigned char step8data[64 + 20];
static unsigned char step5data[MAX_MESSAGE_LENGTH + 128];

static void hmac_sha1(unsigned char *key, int key_length, unsigned char *data, int data_length, unsigned char *digest)
{
    int b = 64; /* blocksize */
    unsigned char ipad = 0x36;
    unsigned char opad = 0x5c;
    int i;

    for (i = 0; i < 64; i++) {
        k0[i] = 0x00;
    }
    if (key_length != b) /* Step 1 */
    {
        /* Step 2 */
        if (key_length > b) {
            sha1(key, key_length, digest);
            for (i = 0; i < 20; i++) {
                k0[i] = digest[i];
            }
        } else if (key_length < b) /* Step 3 */
        {
            for (i = 0; i < key_length; i++) {
                k0[i] = key[i];
            }
        }
    } else {
        for (i = 0; i < b; i++) {
            k0[i] = key[i];
        }
    }
    /* Step 4 */
    for (i = 0; i < 64; i++) {
        k0xorIpad[i] = k0[i] ^ ipad;
    }
    /* Step 5 */
    for (i = 0; i < 64; i++) {
        step5data[i] = k0xorIpad[i];
    }
    for (i = 0; i < data_length; i++) {
        step5data[i + 64] = data[i];
    }
    /* Step 6 */
    sha1(step5data, data_length + b, digest);
    /* Step 7 */
    for (i = 0; i < 64; i++) {
        step7data[i] = k0[i] ^ opad;
    }
    /* Step 8 */
    for (i = 0; i < 64; i++) {
        step8data[i] = step7data[i];
    }
    for (i = 0; i < 20; i++) {
        step8data[i + 64] = digest[i];
    }
    /* Step 9 */
    sha1(step8data, b + 20, digest);
}

#define DIGEST_SIZE 20
static unsigned char digest[DIGEST_SIZE];

//**************************************************
// base64 encode and decode
// http://www.mycplus.com/source-code/c-source-code/base64-encode-decode/
//**************************************************
static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
        'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
        'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
        'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
static int mod_table[] = { 0, 2, 1 };

static char *base64_encode(const unsigned char *data, int input_length, char *encoded_data, int *output_length)
{
    *output_length = 4 * ((input_length + 2) / 3);

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';
    return encoded_data;
}

#ifdef BASE64_DECODE
static char decoding_init = 0;
static char decoding_table[256] = {0};

static void build_decoding_table()
{
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

static char *base64_decode(const unsigned char *data, int input_length, char *decoded_data, int *output_length)
{
    if (decoding_init == 0) {
        build_decoding_table();
        decoding_init = 1;
    }
    if (input_length % 4 != 0)
        return NULL;
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=')
        (*output_length)--;
    if (data[input_length - 2] == '=')
        (*output_length)--;

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a =
                data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b =
                data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c =
                data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d =
                data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6)
                + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length)
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    return decoded_data;
}
#endif

static PARAM *get_param_by_key(PARAM *p, char *k)
{
    while (p->key != NULL) {
        if (p->key == k) {
            return p;
        }
        p++;
    }
    return NULL;
}

static void set_param_value(PARAM *p, char *k, char *v)
{
    PARAM *t;
    t = get_param_by_key(p, k);
    if (t != NULL) {
        t->value = v;
    }
}

#ifdef DEBUG_PARAMS
static void print_param_value(PARAM *p)
{
    while (p->key != NULL) {
        printf("%s: %s\n", p->key, p->value);
        p++;
    }
}
#endif

static void create_signature(char *sig_str, char *sec1, char *sec2, char *req_method, char *req_url, PARAM *params)
{
    int sig_key_len;
    int sig_data_len;
    int sig_str_len;
    _url_encode(sec1, encode_buf, ENCODE_BUF_MAX);
    strcpy(sig_key, encode_buf);
    strcat(sig_key, "&");
    _url_encode(sec2, encode_buf, ENCODE_BUF_MAX);
    strcat(sig_key, encode_buf);
    strcpy(param_buf, "");
    while (params->key != NULL) {
        strcat(param_buf, params->key);
        strcat(param_buf, "=");
        strcat(param_buf, params->value);
        params++;
        if (params->key != NULL) {
            strcat(param_buf, "&");
        }
    }
    strcpy(sig_data, req_method);
    strcat(sig_data, "&");
    _url_encode(req_url, encode_buf, ENCODE_BUF_MAX);
    strcat(sig_data, encode_buf);
    strcat(sig_data, "&");
    _url_encode(param_buf, encode_buf, ENCODE_BUF_MAX);
    strcat(sig_data, encode_buf);
    sig_key_len = strlen(sig_key);
    sig_data_len = strlen(sig_data);
    hmac_sha1((unsigned char *)sig_key, sig_key_len, (unsigned char *)sig_data, sig_data_len, (unsigned char *)digest);
    base64_encode(digest, DIGEST_SIZE, sig_str, &sig_str_len);
}

static void create_oauth_params(char *oauth_str, PARAM *params)
{
    strcpy(oauth_str, "OAuth ");
    strcpy(param_buf, "");
    while (params->key != NULL) {
        _url_encode(params->key, encode_buf, ENCODE_BUF_MAX);
        strcat(param_buf, encode_buf);
        strcat(param_buf, "=");
        _url_encode(params->value, encode_buf, ENCODE_BUF_MAX);
        strcat(param_buf, encode_buf);
        params++;
        if (params->key != NULL) {
            strcat(param_buf, ",");
        }
    }
    strcat(oauth_str, param_buf);
}

static void _statuses_update(NetworkInterface *iface, char *ckey, char *csec, char *akey, char *asec, char *str, char *media_id_string)
{
    char timestamp_str[11];
    NTPClient ntp(iface);
    unsigned int timestamp = (unsigned int)ntp.get_timestamp();
    //timestamp -= 2208988800;
    sprintf(timestamp_str, "%u", (unsigned int)timestamp);
    set_param_value((PARAM *)req_params, (char *)"oauth_consumer_key", (char *)ckey);
    set_param_value((PARAM *)req_params, (char *)"oauth_nonce", (char *)timestamp_str);
    set_param_value((PARAM *)req_params, (char *)"oauth_timestamp", (char *)timestamp_str);
    set_param_value((PARAM *)req_params, (char *)"oauth_token", (char *)akey);
    //print_param_value((PARAM *)req_params);
    create_signature((char *)sig_str,
            (char *)csec,
            (char *)asec,
            (char *)"POST",
            (char *)TWITTER_API_UPDATE,
            req_params);
    //printf("sig_str: %s\n", sig_str);
    if ((media_id_string != NULL) && (strlen(media_id_string) > 0)) {
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"oauth_consumer_key", (char *)ckey);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"oauth_nonce", (char *)timestamp_str);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"oauth_timestamp", (char *)timestamp_str);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"oauth_token", (char *)akey);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"oauth_signature", (char *)sig_str);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"media_ids", (char *)media_id_string);
        set_param_value((PARAM *)statuses_oauth_params2, (char *)"status", (char *)str);
        //print_param_value((PARAM *)statuses_oauth_params);
        create_oauth_params((char *)auth_str, (PARAM *)statuses_oauth_params2);
    } else {
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"oauth_consumer_key", (char *)ckey);
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"oauth_nonce", (char *)timestamp_str);
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"oauth_timestamp", (char *)timestamp_str);
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"oauth_token", (char *)akey);
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"oauth_signature", (char *)sig_str);
        set_param_value((PARAM *)statuses_oauth_params1, (char *)"status", (char *)str);
        //print_param_value((PARAM *)statuses_oauth_params);
        create_oauth_params((char *)auth_str, (PARAM *)statuses_oauth_params1);
    }
#ifdef CHECK_AUTH_STRING
    printf("auth_str: %s\n", auth_str);
#endif
}

#ifdef DEBUG_PARAMS
// expected result
// signature = mu4s4b2t4T0HsjD0z0J749fMGPA=
static void test_create_signature(void)
{
    PARAM param[] = {{(char *)"name", (char *)"BBB"},
            {(char *)"text", (char *)"CCC"},
            {(char *)"title", (char *)"AAA"},
            {(char *)NULL, (char *)NULL}};
    create_signature((char *)sig_str,
            (char *)"bbbbbb",
            (char *)"dddddd",
            (char *)"POST",
            (char *)"http://example.com/sample.php",
            (PARAM *)param);
    printf("sig_str: %s\n", sig_str);
}

static void test_create_oauth_params(void)
{
    PARAM param[] = {{(char *)"name", (char *)"BBB"},
            {(char *)"text", (char *)"CCC"},
            {(char *)"title", (char *)"AAA"},
            {(char *)NULL, (char *)NULL}};
    create_oauth_params((char *)auth_str, (PARAM *)param);
    printf("auth_str: %s\n", auth_str);
}
#endif

#ifdef DUMP_RESPONSE
static void dump_response(HttpResponse* res) {
    mbedtls_printf("Status: %d - %s\n", res->get_status_code(), res->get_status_message().c_str());

    mbedtls_printf("Headers:\n");
    for (size_t ix = 0; ix < res->get_headers_length(); ix++) {
        mbedtls_printf("\t%s: %s\n", res->get_headers_fields()[ix]->c_str(), res->get_headers_values()[ix]->c_str());
    }
    mbedtls_printf("\nBody (%d bytes):\n\n%s\n", res->get_body_length(), res->get_body_as_string().c_str());
}
#endif

Twitter::Twitter(NetworkInterface *iface)
{
    _iface = iface;
#ifdef DEBUG_PARAMS
    test_create_signature();
    test_create_oauth_params();
#endif
}

Twitter::~Twitter()
{
}

void Twitter::set_keys(char *cons_key, char *cons_sec, char *accs_key, char *accs_sec)
{
    _cons_key = cons_key;
    _cons_sec = cons_sec;
    _accs_key = accs_key;
    _accs_sec = accs_sec;
}

void Twitter::statuses_update(char *str, char *media_id_string)
{
#ifdef DEBUG_STATUSES_UPDATE
    printf("\n----- Twitter tweet start -----\n");
#endif
    _statuses_update(_iface, _cons_key, _cons_sec, _accs_key, _accs_sec, str, media_id_string);

    HttpsRequest* post_req = new HttpsRequest(_iface, SSL_CA_PEM, HTTP_POST, TWITTER_API_UPDATE);
#ifdef DEBUG_HTTP_POST
    post_req->set_debug(true);
#endif
    post_req->set_header("User-Agent", "gr-peach");
    post_req->set_header("Content-Type", "application/x-www-form-urlencoded");
    post_req->set_header("Authorization", auth_str);

    body[0] = 0;
    if ((media_id_string != NULL) && (strlen(media_id_string) > 0)) {
        strcat(body, "media_ids=");
        _url_encode(media_id_string, encode_buf, ENCODE_BUF_MAX);
        strcat(body, encode_buf);
        strcat(body,"&");
    }
    strcat(body, "status=");
    _url_encode(str, encode_buf, ENCODE_BUF_MAX);
    strcat(body, encode_buf);
    strcat(body, "\r\n");
#ifdef DEBUG_STATUSES_UPDATE
    printf("Tweet body size: %d\n", strlen(body));
    printf("Tweet body string: %s\n", body);
#endif

    HttpResponse* post_res = post_req->send(body, strlen(body));
    if (!post_res) {
        printf("HttpRequest failed (error code %d)\n", post_req->get_error());
        //return;
    }
#ifdef DUMP_RESPONSE
    dump_response(post_res);
#endif
#ifdef DEBUG_STATUSES_UPDATE
    printf("\n----- Twitter tweet end -----\n");
#endif
    delete post_req;
}

static void create_boundary(void)
{
    unsigned int irandom;
    irandom = (unsigned int)rand();
    itoa(irandom, (char *)boundary_buf, 16);
}

static void _upload(NetworkInterface *iface, char *ckey, char *csec, char *akey, char *asec, char *buf, int size)
{
    char timestamp_str[11];
    NTPClient ntp(iface);
    unsigned int timestamp = (unsigned int)ntp.get_timestamp();
    //timestamp -= 2208988800;
    sprintf(timestamp_str, "%u", (unsigned int)timestamp);
    set_param_value((PARAM *)req_params, (char *)"oauth_consumer_key", (char *)ckey);
    set_param_value((PARAM *)req_params, (char *)"oauth_nonce", (char *)timestamp_str);
    set_param_value((PARAM *)req_params, (char *)"oauth_timestamp", (char *)timestamp_str);
    set_param_value((PARAM *)req_params, (char *)"oauth_token", (char *)akey);
    //print_param_value((PARAM *)req_params);
    create_signature((char *)sig_str,
            (char *)csec,
            (char *)asec,
            (char *)"POST",
            (char *)TWITTER_API_UPLOAD,
            req_params);
    //printf("sig_str: %s\n", sig_str);
    set_param_value((PARAM *)upload_oauth_params, (char *)"oauth_consumer_key", (char *)ckey);
    set_param_value((PARAM *)upload_oauth_params, (char *)"oauth_nonce", (char *)timestamp_str);
    set_param_value((PARAM *)upload_oauth_params, (char *)"oauth_timestamp", (char *)timestamp_str);
    set_param_value((PARAM *)upload_oauth_params, (char *)"oauth_token", (char *)akey);
    set_param_value((PARAM *)upload_oauth_params, (char *)"oauth_signature", (char *)sig_str);
    //print_param_value((PARAM *)oauth_params);
    create_oauth_params((char *)auth_str, (PARAM *)upload_oauth_params);
#ifdef CHECK_AUTH_STRING
    printf("auth_str: %s\n", auth_str);
#endif
    create_boundary();
    sprintf(upload_body_top, "--%s\r\n", boundary_buf);
    strcat(upload_body_top, "Content-Disposition: form-data; name=\"media_data\"; \r\n\r\n");
    sprintf(upload_body_end, "\r\n--%s--\r\n\r\n", boundary_buf);
    sprintf(upload_header_buf, "multipart/form-data; boundary=%s", boundary_buf);
}

static void get_media_id_string(char *body, char *media_id_string)
{
    static char key[] = "media_id_string";
    char *start = body;
    char *end;
    int len;

    media_id_string[0] = 0;
    if ((start = strstr(body, (char *)key)) != NULL ) {
        start += strlen(key) + 3;
        if ((end = strchr(start, '"')) != NULL) {
            len = end - start;
            strncpy(media_id_string, start, len);
            media_id_string[len] = 0;
        }
    }
}

void Twitter::upload(char *media_id_string, char *buf, int size)
{
    int idx;
    int encode_len;

#ifdef DEBUG_UPLOAD
    printf("\n----- Twitter image upload start -----\n");
#endif
    _upload(_iface, _cons_key, _cons_sec, _accs_key, _accs_sec, buf, size);

    idx = strlen(upload_body_top);
    strcpy(media_buf, upload_body_top);
    base64_encode((const unsigned char *)buf, size, (char *)&media_buf[idx], &encode_len);
    idx += encode_len;
    strcpy((char *)&media_buf[idx], upload_body_end);
    idx += strlen(upload_body_end);
#ifdef DEBUG_UPLOAD
    printf("body size: %d\r\n", idx);
    //printf("body: %s\r\n", media_buf);
#endif
    HttpsRequest* post_req = new HttpsRequest(_iface, SSL_CA_PEM, HTTP_POST, TWITTER_API_UPLOAD);
#ifdef DEBUG_HTTP_POST
    post_req->set_debug(true);
#endif
    post_req->set_header("User-Agent", "gr-peach");
    post_req->set_header("Content-Type", upload_header_buf);
    post_req->set_header("Authorization", auth_str);
    HttpResponse* post_res = post_req->send((const void *)media_buf, idx);
    if (!post_res) {
        printf("HttpRequest failed (error code %d)\n", post_req->get_error());
        return;
    }
#ifdef DUMP_RESPONSE
    dump_response(post_res);
#endif
    get_media_id_string((char *)post_res->get_body_as_string().c_str(), (char *)media_id_string);
#ifdef DEBUG_UPLOAD
    printf("media_id_string: %s\r\n", media_id_string);
    printf("\n----- Twitter image upload end -----\n");
#endif
    delete post_req;
}

void Twitter::upload_and_statuses_update(char *str, char *media_id_string, char *buf, int size)
{
    upload(media_id_string, buf, size);
#ifndef SKIP_STATUSES_UPLOAD
    statuses_update(str, media_id_string);
#endif
}
