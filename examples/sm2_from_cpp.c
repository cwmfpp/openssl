#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#define LOGE(fmt, x...)  printf("%s:%s:%d: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##x);

static int CreateEVP_PKEY(unsigned char* key, int is_public, EVP_PKEY** out_ecKey);
static int cry_prikey2pubkey(char *in_prikey, char *out_pubkey);
static int cry_gen_ec_pair_key(char *out_prikey, int prikey_len, char *out_pubkey, int pubkey_len);
static int cry_sign(char *in_buf, int in_buflen, char *out_sig, int *len_sig, char *prikey, int prikey_len);
static int cry_verify(char *in_buf, const int buflen, char *sig, const int siglen, char *pubkey, const int keylen);
static int cry_encrypto(char *in_buf, int in_buflen, char *out_encrypted, int *len_encrypted, char *pubKey);
static int cry_decrypto(char *in_buf, int in_buflen, char *out_plaint, int *len_plaint, char *prikey);
 
int cry_gen_ec_pair_key(char *out_prikey, int prikey_len, char *out_pubkey, int pubkey_len)
{
    EC_KEY *ecKey;
    EC_GROUP *ecGroup;
    int ret = 0;
    if (NULL == (ecKey = EC_KEY_new())) {
        return -1;
    }

    if (NULL == (ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) {
        EC_KEY_free(ecKey);
        return -2;
    }

    if (EC_KEY_set_group(ecKey, ecGroup) != 1) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    if (!EC_KEY_generate_key(ecKey)) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    //可以从EC_KEY类型返回char*数组
    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);
	if (prikey_len < pri_len) {
		ret = -1;
		goto end;
	}
	if (pubkey_len < pub_len) {
		ret = -1;
		goto end;
	}

    BIO_read(pri, out_prikey, pri_len);
    BIO_read(pub, out_pubkey, pub_len);

    out_prikey[pri_len] = '\0';
    out_pubkey[pub_len] = '\0';

end:
    BIO_free_all(pub);
    BIO_free_all(pri);
    // free(pri_key);
    // free(pub_key);
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return 0;
}
 
int CreateEVP_PKEY(unsigned char* key, int is_public, EVP_PKEY** out_pKey)
{
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed.\n");
        return -1;
    }

    if (is_public) {
        //*out_ecKey = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
        *out_pKey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    } else {
        //*out_ecKey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
        *out_pKey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    }

    if (*out_pKey == NULL) {
        LOGE("Failed to Get Key");
        BIO_free(keybio);
        return -1;
    }

    BIO_free(keybio);
    return 0;
}
 
int cry_prikey2pubkey(char *in_prikey, char *out_pubkey)
{
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(in_prikey, -1);

    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed.\n");
        return -1;
    }

    EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    if (ecKey == NULL) {
        LOGE("PEM_read_bio_ECPrivateKey failed.");
        BIO_free(keybio);
        return -1;
    }

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(pub, ecKey);
    int pub_len = BIO_pending(pub);
    BIO_read(pub,out_pubkey, pub_len);
    out_pubkey[pub_len] = '\0';

    BIO_free(pub);
    BIO_free(keybio);

    return 0;
}
 
int cry_sign(char *in_buf, int in_buflen, char *out_sig, int *len_sig, char *prikey, int prikey_len)
{
    int ret_val = 0;
    //通过私钥得到EC_KEY
    EC_KEY *eckey = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(prikey, -1);
    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed\n");
        return -1;
    }
    eckey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    if (eckey == NULL) {
        LOGE("PEM_read_bio_ECPrivateKey failed\n");
        BIO_free(keybio);
        return -2;
    }

    unsigned char szSign[256] = {0};
    if (1 != ECDSA_sign(0, (const unsigned char *)in_buf, in_buflen, szSign,
                        (unsigned int *)len_sig, eckey)) {
        LOGE("ECDSA_sign failed\n");
        ret_val = -3;
    } else {
        memcpy(out_sig, szSign, *len_sig);
        ret_val = 0;
    }
    BIO_free(keybio);
	EC_KEY_free(eckey);
	return ret_val;
}
 
int cry_verify(char *in_buf, const int buflen, char *sig, const int siglen,
	char *pubkey, const int keylen)
{
    int ret_val = 0;
    //通过公钥得到EC_KEY
    EC_KEY *eckey = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(pubkey, -1);
    if (keybio == NULL) {
        LOGE("BIO_new_mem_buf failed\n");
        return -1;
    }
    eckey = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    if (eckey == NULL) {
        LOGE("PEM_read_bio_EC_PUBKEY failed\n");
        BIO_free(keybio);
        return -2;
    }
    if (1 != ECDSA_verify(0, (const unsigned char *)in_buf, buflen,
                          (const unsigned char *)sig, siglen, eckey)) {
        LOGE("ECDSA_verify failed\n");
        ret_val = -3;
    } else {
        ret_val = 0;
    }
    BIO_free(keybio);
	EC_KEY_free(eckey);
 
	return ret_val;
}
 
int cry_encrypto(char *in_buf, int in_buflen, char *out_encrypted, int *len_encrypted, char *pubKey)
{
    int ret = -1, i;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0, plaintext_len;

    CreateEVP_PKEY((unsigned char *)pubKey, 1, &pkey);

    /* compute SM2 encryption */
    if ((EVP_PKEY_set_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGE("EVP_PKEY_set_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        LOGE("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt_init(ectx)) != 1) {
        LOGE("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, NULL, &ciphertext_len,
                          (const unsigned char *)in_buf, in_buflen)) != 1) {
        LOGE("EVP_PKEY_set_type failed.");
        goto clean_up;
    }

    if (!(ciphertext = (unsigned char *)malloc(ciphertext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, ciphertext, &ciphertext_len,
                          (const unsigned char *)in_buf, in_buflen)) != 1) {
        LOGE("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }
    memcpy(out_encrypted, ciphertext, ciphertext_len);
    *len_encrypted = ciphertext_len;
    ret = 0;
clean_up:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (ciphertext) {
        free(ciphertext);
    }

    return ret;
}
 
int cry_decrypto(char *in_buf, int in_buflen, char *out_plaint, int *len_plaint, char *prikey)
{
    int ret = -1, i;
    EVP_PKEY_CTX *pctx = NULL, *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *plaintext = NULL;
    size_t ciphertext_len, plaintext_len;

    CreateEVP_PKEY((unsigned char *)prikey, 0, &pkey);

    if ((EVP_PKEY_set_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGE("EVP_PKEY_set_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        LOGE("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    /* compute SM2 decryption */
    if ((EVP_PKEY_decrypt_init(ectx)) != 1) {
        LOGE("EVP_PKEY_decrypt_init failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, NULL, &plaintext_len,
                          (const unsigned char *)in_buf, in_buflen)) != 1) {
        LOGE("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }

    if (!(plaintext = (unsigned char *)malloc(plaintext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, plaintext, &plaintext_len,
                          (const unsigned char *)in_buf, in_buflen)) != 1) {
        LOGE("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }

    memcpy(out_plaint, plaintext, plaintext_len);
    *len_plaint = plaintext_len;
    ret = 0;
clean_up:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (plaintext) {
        free(plaintext);
    }

    return ret;
}

int main(int argc, char **argv)
{

    // static int cry_prikey2pubkey(char *in_prikey, char **out_pubkey);
    // static int cry_gen_ec_pair_key(char **out_prikey, char **out_pubkey);
    // static int cry_sign(char *in_buf, int in_buflen, char *out_sig, int
    // *len_sig, char *prikey); static int cry_verify(char *in_buf, const int
    // buflen, char *sig, const int siglen, char *pubkey, const int keylen);
    // static int cry_encrypto(char *in_buf, int in_buflen, char *out_encrypted,
    // int *len_encrypted, char *pubKey); static int cry_decrypto(char *in_buf,
    // int in_buflen, char *out_plaint, int *len_plaint, char *prikey);

    int ret = 0;
    char prikey[256] = {0};
    char pubkey[256] = {0};

    ret = cry_gen_ec_pair_key(prikey, sizeof(prikey), pubkey, sizeof(pubkey));
    LOGE("ret=%d\n", ret);
    printf("%s\n", prikey);
    printf("%s\n", pubkey);

	ret = cry_prikey2pubkey(prikey, pubkey);
    printf("aaa %s\n", pubkey);

    char *raw_data = "aaaaa";
    int raw_data_len = strlen(raw_data);
    char sign_data[256] = {0};
    int sign_data_len = 0;

    ret = cry_sign(raw_data, raw_data_len, sign_data, &sign_data_len, prikey, strlen(prikey));
    LOGE("ret=%d\n", ret);
    if (0 == ret) {
        LOGE("sing successful\n");
    } else {
        LOGE("sign failed\n");
    }
    LOGE("sign_data_len=%d\n", sign_data_len);

    ret = cry_verify(raw_data, raw_data_len, sign_data, sign_data_len, pubkey,
                     strlen(pubkey));
    LOGE("ret=%d\n", ret);
    if (0 == ret) {
        LOGE("verify successful\n");
    } else {
        LOGE("verify failed\n");
    }

    return 0;
}
