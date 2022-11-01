#include "pch.h"
#include <EccAlgorithmApi.h>
#include <string>
#include <openssl/ec.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#pragma comment(lib, "libeay32")

#define goto_fault(x) \
{\
	ret_val = -x;\
	goto FAULT_##x;\
}

/*
	通过名称获取曲线代号
*/
static int GetNIDbyCurveName(const char* curve_name)
{
	int nid;
	/* workaround for the SECG curve names secp192r1
	* and secp256r1 (which are the same as the curves
	* prime192v1 and prime256v1 defined in X9.62)
	*/
	if (!strcmp(curve_name, "secp192r1"))
	{
		printf("using curve name prime192v1 instead of secp192r1\n");
		nid = NID_X9_62_prime192v1;
	}
	else if (!strcmp(curve_name, "secp256r1"))
	{
		printf("using curve name prime256v1 instead of secp256r1\n");
		nid = NID_X9_62_prime256v1;
	}
	else
		nid = OBJ_sn2nid(curve_name);

	if (nid == 0)
	{
		printf("unknown curve name (%s)\n", curve_name);
	}
	return nid;
}

/*
	生成 EC 私钥
	/privKey	生成的私钥
	/maxLen		私钥 buff 最大长度
	/curve_name 生成私钥所用的曲线名称
	/return		成功返回正数代表私钥长度，失败返回负数
*/
ECCAPI int GenEcPrivKey(uchar* privKey, int maxLen, const char* curve_name)
{
	EC_KEY* ecKey;
	EC_GROUP* ecGroup;
	uchar* pp = privKey;
	int ret_val;

	if (NULL == (ecKey = EC_KEY_new()))
		goto_fault(1);

	if (NULL == (ecGroup = EC_GROUP_new_by_curve_name(GetNIDbyCurveName(curve_name))))
		goto_fault(2);

	if (EC_KEY_set_group(ecKey, ecGroup) != 1)
		goto_fault(3);

	if (!EC_KEY_generate_key(ecKey))
		goto_fault(3);

	ret_val = i2d_ECPrivateKey(ecKey, &pp);
	if (!ret_val || ret_val > maxLen)
		ret_val = -4;

FAULT_3:
	EC_GROUP_free(ecGroup);
FAULT_2:
	EC_KEY_free(ecKey);
FAULT_1:
	return ret_val;
}

/*
	通过已有的私钥生成对应的公钥
	/privKey  私钥 HEX 格式数据
	/privLen  私钥长度
	/pubKey   生成的公钥
	/maxLen   公钥 buff 最大长度
	/return   返回负数表示失败，正数表示公钥的长度
	/return	  成功返回正数代表公钥长度，失败返回负数
*/
ECCAPI int GenEcPubKey(const uchar* privKey, int privLen, uchar* pubKey, int maxLen)
{
	int ret_val;
	EC_KEY* eckey;
	uchar* pp = (uchar*)privKey;
	eckey = d2i_ECPrivateKey(NULL, (const uchar**)&pp, privLen);
	if (!eckey)
		goto_fault(1);

	pp = pubKey;
	ret_val = i2o_ECPublicKey(eckey, &pp);
	if (!ret_val)
		ret_val = -2;

	EC_KEY_free(eckey);
FAULT_1:
	return ret_val;
}

/*
	保存密钥
	/eckey		需要保存的密钥
	/file		文件路径
	/keyType	公钥、私钥
	/keyFormat	保存格式：DER、PEM
	/password	文件密码
	/return		成功返回 true
*/
static bool DoSavingKey(EC_KEY* eckey, const char* file,
	int keyType, int keyFormat, const char* password)
{
	(void)password;
	int ret_val = 0;
	BIO* out;

	if (file == NULL)
		goto_fault(1);

	out = BIO_new(BIO_s_file());
	if (!out)
		goto_fault(1);

	if (0 >= BIO_write_filename(out, (void*)file))
		goto_fault(2);

	if (keyType == KEY_TYPE_PRIVATE) {
		if (keyFormat == KEY_FORMAT_DER) {
			ret_val = i2d_ECPrivateKey_bio(out, eckey);
			if (!ret_val) goto_fault(2);
		}
		else if (keyFormat == KEY_FORMAT_PEM) {
			ret_val = PEM_write_bio_ECPrivateKey(out,eckey, NULL, NULL, 0, NULL, NULL);
			if(!ret_val) goto_fault(2);
		}
		else goto_fault(2);
	}
	else if (keyType == KEY_TYPE_PUBLIC) {
		if (keyFormat == KEY_FORMAT_DER) {
			ret_val = i2d_EC_PUBKEY_bio(out, eckey);
			if (!ret_val) goto_fault(2);
		}
		else if (keyFormat == KEY_FORMAT_PEM) {
			ret_val = PEM_write_bio_EC_PUBKEY(out, eckey);
			if (!ret_val) goto_fault(2);
		}
		else goto_fault(2);
	}
	else ret_val = -100;

FAULT_2:
	BIO_free_all(out);
FAULT_1:
	return ret_val < 0 ? false : true;
}

/*
	保存钥匙到文件
	/file		保存路径
	/key		密钥 HEX 码
	/keyLen		密钥长度
	/keyType	公钥、私钥
	/keyFormat	保存格式：DER、PEM
	/password	文件密码
	/return		成功返回 0
*/
ECCAPI int SavekEeyToFile(const char* file, const uchar* privKey, int privLen,
	int outKeyType, int outKeyFormat, const char* password)
{
	(void)password;
	int ret_val = 0;
	EC_KEY* eckey;
	const uchar* pp = privKey;
	/*switch (keyType) {
	case KEY_TYPE_PRIVATE:
		if(!(eckey = d2i_ECPrivateKey(NULL, &pp, keyLen)))
			goto_fault(1);
		break;
	case KEY_TYPE_PUBLIC:
		if (!(eckey = o2i_ECPublicKey(NULL, &pp, keyLen)))
			goto_fault(1);
		break;
	default: goto_fault(1);
	}*/

	if (!(eckey = d2i_ECPrivateKey(NULL, &pp, privLen)))
		goto_fault(1);

	if (!DoSavingKey(eckey, file, outKeyType, outKeyFormat, password))
		goto_fault(2);

FAULT_2:
	EC_KEY_free(eckey);
FAULT_1:
	return ret_val;
}

/*
	从文件中读取密钥
	/infile		输入文件
	/keyType	公钥、私钥
	/keyFormat	文件格式
	/outKey		密钥 HEX (输出)
	/maxLen		输出密钥 buff 的最大长度
	/password	文件密码
	/return		负数表示错误编号，正数表示输出字节码的长度
*/
ECCAPI int LoadKeyFormFile(const char* infile,const int keyType, 
	const int keyFormat, uchar* outKey, const int maxLen, void* password)
{
	int ret_val = 0;
	BIO* in;
	EC_KEY* eckey;
	uchar* pp = outKey;
	in = BIO_new(BIO_s_file());

	if (in == NULL)
		goto_fault(1);

	if (0 >= BIO_read_filename(in, infile))
		goto_fault(2);

	if (keyFormat == KEY_FORMAT_DER) {
		if (keyType == KEY_TYPE_PUBLIC) {
			eckey = d2i_EC_PUBKEY_bio(in, NULL);
		}
		else if (keyType == KEY_TYPE_PRIVATE) {
			eckey = d2i_ECPrivateKey_bio(in, NULL);
		}
		else goto_fault(2);
	}
	else if (keyFormat == KEY_FORMAT_PEM) {
		if (keyType == KEY_TYPE_PUBLIC) {
			eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
		}
		else if (keyType == KEY_TYPE_PRIVATE) {
			eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, password);
		}
		else goto_fault(2);
	}
	else goto_fault(2);

	if(eckey == NULL)
		goto_fault(3);

	if (keyType == KEY_TYPE_PRIVATE) {
		ret_val = i2d_ECPrivateKey(eckey, &pp);
	}
	else if (keyType == KEY_TYPE_PUBLIC) {
		ret_val = i2o_ECPublicKey(eckey, &pp);
	}
	else goto_fault(4);
	if (!ret_val || ret_val > maxLen)
		ret_val = -5;

FAULT_4:
	EC_KEY_free(eckey);
FAULT_3:
FAULT_2:
	BIO_free(in);
FAULT_1:
	return ret_val;
}

/*
	对buf使用key进行签名
	/sig		存放输出的签名
	/maxlen		签名的最大长度
	/buf		需要进行签名的内容
	/buflen		需要进行签名的内容长度
	/key		密钥 HEX
	/keyType	公钥、私钥
	/keylen		密钥长度
	/curve		如果提供的是公钥，必须提供曲线
	/return		负数表示错误编号，正数表示签名的长度
*/
ECCAPI int Sign(uchar* sig, const int maxlen, const uchar* buf, int buflen,
	const uchar* key, const int keyType, const int keylen, const char* curve)
{
	(void)curve;
	unsigned int siglen = maxlen;
	int ret_val = 0;
	EC_KEY* eckey;
	const unsigned char* pp = key;
	if (keyType == KEY_TYPE_PRIVATE) {
		if(NULL == (eckey = d2i_ECPrivateKey(NULL, &pp, keylen)))
			goto_fault(1);
	}
	else if (keyType == KEY_TYPE_PUBLIC) {
		goto_fault(1);
	}
	else {
		goto_fault(1);
	}
	
	if (ECDSA_sign(0, buf, buflen, sig, &siglen, eckey)) {
		ret_val = (int)siglen;
		if (siglen > maxlen || siglen <= 0)
			ret_val = -3;
	}
	else ret_val = -2; 

	EC_KEY_free(eckey);
FAULT_1:
	return ret_val;
}


/*
	获得合法的 ecKey 对象，返回非空需要调用方释放
	/key		密钥 HEX
	/kenlen		密钥长度
	/keyType	公钥、私钥
	/curve		提供公钥时必须提供该参数，曲线名称
	/return		没有合法的对象返回空，非空需要调用方释放
*/
static EC_KEY* GetValidEcKey(const uchar* key, const int keylen,
	const int keyType, const char* curve)
{
	EC_KEY* ret;
	EC_KEY* eckey = NULL;
	EC_GROUP* ecgroup = NULL;
	int ret_val = 0;
	const unsigned char* pp = key;
	if (keyType == KEY_TYPE_PRIVATE) {
		if (NULL == (eckey = d2i_ECPrivateKey(NULL, &pp, keylen)))
			goto_fault(1);
	}
	else if (keyType == KEY_TYPE_PUBLIC) {
		if(curve == NULL)
			goto_fault(1);

		if(!(eckey = EC_KEY_new()))
			goto_fault(1);

		if(!(ecgroup = EC_GROUP_new_by_curve_name(GetNIDbyCurveName(curve))))
			goto_fault(1);
		
		(void)EC_KEY_set_group(eckey, ecgroup); // 该函数会复制一份 group 对象，所以应该释放

		ret = o2i_ECPublicKey(&eckey, &pp, keylen);
		if(ret != eckey)
			goto_fault(1);
	}
	else goto_fault(1);

FAULT_1:
	if (ret_val)
		if (eckey) {
			EC_KEY_free(eckey);
			eckey = NULL;
		}
	if (ecgroup)
		EC_GROUP_free(ecgroup);
	return eckey;
}

/*
	验证签名是否正确
	/sig		签名
	/siglen		签名长度
	/buf		验签内容
	/buflen		验签内容长度
	/key		密钥 HEX
	/kenlen		密钥长度
	/keyType	公钥、私钥
	/curve		提供公钥时必须提供该参数，曲线名称
	/return		发生错误返回负数，验证失败返回 0，验证成功返回 1
*/
ECCAPI int Verify(
	const uchar* sig, const int siglen,
	const uchar* buf, const int buflen,
	const uchar* key, const int keylen,
	const int keyType, const char* curve)
{
	int ret_val = 0;
	EC_KEY* eckey = GetValidEcKey(key, keylen, keyType, curve);
	if (eckey == NULL)
		goto_fault(1);

	ret_val = ECDSA_verify(0, buf, buflen, sig, siglen, eckey);

	EC_KEY_free(eckey);
FAULT_1:
	return ret_val;
}

int main(int argc, char **argv)
{

    return 0;
}
