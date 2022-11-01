#ifndef _ECC_API_H_
#define _ECC_API_H_

#ifdef _ECC_API_EXPORTS_
#define ECCAPI extern "C" __declspec(dllexport)
#else
#define ECCAPI extern "C" __declspec(dllimport)
#endif

typedef unsigned char uchar;

#define KEY_TYPE_PRIVATE (0x1234)
#define KEY_TYPE_PUBLIC  (0x4321)

#define KEY_FORMAT_DER   (0xABCD)
#define KEY_FORMAT_PEM   (0xDCBA)

/*
	生成 EC 私钥
	/privKey	生成的私钥
	/maxLen		私钥 buff 最大长度
	/curve_name 生成私钥所用的曲线名称
	/return		成功返回正数代表私钥长度，失败返回负数
*/
ECCAPI int GenEcPrivKey(uchar* privKey, int maxLen, const char* curve_name);

/*
	通过已有的私钥生成对应的公钥
	/privKey  私钥 HEX 格式数据
	/privLen  私钥长度
	/pubKey   生成的公钥
	/maxLen   公钥 buff 最大长度
	/return	  成功返回正数代表公钥长度，失败返回负数
*/
ECCAPI int GenEcPubKey(const uchar* privKey, int privLen, uchar* pubKey, int maxLen);

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
	int outKeyType, int outKeyFormat, const char* password);


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
ECCAPI int LoadKeyFormFile(const char* infile, const int keyType,
	const int keyFormat, uchar* outKey, const int maxLen, void* password);


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
	const uchar* key, const int keyType, const int keylen, const char* curve);


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
	const int keyType, const char* curve);

#endif // !_ECC_API_H_
