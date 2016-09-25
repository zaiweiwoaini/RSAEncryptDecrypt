//
//  ZWOpenSSLRSA.h
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//


/**
 使用系统OpenSSLRSA，无证书的公私钥

 需要第三方库 pod 'OpenSSL' 或者手动加入这些文件
 */

#import <Foundation/Foundation.h>
#import <openssl/engine.h>
#import <openssl/pem.h>
#import <openssl/rsa.h>

/**
 @abstract  padding type
 */
typedef NS_ENUM(NSInteger, RSA_PADDING_TYPE) {
    
    RSA_PADDING_TYPE_NONE = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1 = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23 = RSA_SSLV23_PADDING
};

typedef NS_ENUM(int, RSA_SIGN_DIGEST_TYPE) {
    RSA_SIGN_DIGEST_TYPE_SHA1 = NID_sha1,
    RSA_SIGN_DIGEST_TYPE_SHA256 = NID_sha256,
    RSA_SIGN_DIGEST_TYPE_SHA384 = NID_sha384,
    RSA_SIGN_DIGEST_TYPE_SHA512 = NID_sha512,
    RSA_SIGN_DIGEST_TYPE_SHA224 = NID_sha224,
    RSA_SIGN_DIGEST_TYPE_MD5 = NID_md5
};



@interface ZWOpenSSLRSA : NSObject{
    RSA *_rsaPublic;
    RSA *_rsaPrivate;
    
@public
    RSA *_rsa;
}
+ (ZWOpenSSLRSA *)sharedInstance;


#pragma mark - 导入证书
// Generate rsa key pair by the key size.
// @param keySize RSA key bits . The value could be `512`,`1024`,`2048` and so on.
// Normal is `1024`.
// */
//- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize;

/**
 *  read public key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN PUBLIC KEY-----   xxxxx  -----END PUBLIC KEY-----
 *  @return success or not.
 *  @discussion how to get the data. I write a tool in `rsatool` target.
 *         1、  build `rsatool` target, get rsatool command
 *         2、  use rsatool to convert file to byte array.
 *               ./rsatool read public.pem
 *         3、  copy the byte array to code like this:
 
 char keyBytes[] =
 {45,45,45,45,45,66,69,71,73,78,32,80,85,66,76,73,67,32,75,69,89,45,45,45,45,45,10,77,73,73,66,73,106,65,78,66,103,107,113,104,107,105,71,57,119,48,66,65,81,69,70,65,65,79,67,65,81,56,65,77,73,73,66,67,103,75,67,65,81,69,65,49,71,83,49,72,103,51,69,53,105,55,113,114,75,115,69,114,81,70,116,10,90,49,110,,49,118,80,84,85,101,79,113,107,117,74,110,99,105,115,86,53,121,101,89,104,75,10,83,83,66,107,67,114,65,88,114,105,52,81,76,110,121,85,57,87,73,57,80,70,115,76,89,119,109,82,121,109,102,102,104,121,73,57,97,108,106,107,77,108,55,112,122,82,115,105,117,51,72,117,50,52,47,68,79,97,99,78,103,80,83,121,10,115,119,73,68,65,81,65,66,10,45,45,45,45,45,69,78,68,32,80,85,66,76,73,67,32,75,69,89,45,45,45,45,45,10};
 NSData *pemData = [NSData dataWithBytes:keyBytes length:sizeof(keyBytes)];
 
 [rsaCryptor importRSAPublicKeyPEMData:pemData];
 */
- (BOOL)importRSAPublicKeyPEMData:(NSData *)PEMData;
- (BOOL)importRSAPublicKeyPEMFilePath:(NSString *)path;
/**
 *  read public key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 *  @discussion how to get the data. I write a tool in `rsatool` target.
 *         1、  build `rsatool` target, get rsatool command
 *         2、  use rsatool to convert file to byte array.
 *               ./rsatool read public.der
 *         3、  copy the byte array to code like this:
 
 char keyBytes[] =
 {48,-126,1,34,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-126,1,15,0,48,-126,1,10,2,-126,1,1,0,-44,100,-75,30,13,-60,-26,46,-22,-84,-85,4,-83,1,109,103,89,-19,-113,80,-21,-59,-82,85,-19,119,-87,-42,-43,-119,18,0,-107,78,-63,42,-95,-58,49,-107,25,119,-42,75,-26,-30,96,-127,100,-115,58,-111,27,57,-57,84,77,111,61,53,30,58,-87,46,38,119,34,-79,94,114,121,-120,74,73,32,100,10,-80,23,-82,46,16,46,124,-108,-11,98,61,60,91,11,99,9,-111,-54,103,-33,-121,34,61,106,88,-28,50,94,-23,-51,27,34,-69,113,-18,-37,-113,-61,57,-89,13,-128,-12,-78,-77,2,3,1,0,1};
 NSData *derData = [NSData dataWithBytes:keyBytes length:sizeof(keyBytes)];
 
 [rsaCryptor importRSAPublicKeyDERData:derData];
 */
- (BOOL)importRSAPublicKeyDERData:(NSData *)DERData;
- (BOOL)importRSAPublicKeyDERFilePath:(NSString *)path;
/**
 *  read private key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN RSA PRIVATE KEY-----   xxxxx  -----END RSA PRIVATE KEY-----
 *  @return success or not.
 *  @see   `importRSAPublicKeyPEMData:`
 */
- (BOOL)importRSAPrivateKeyPEMData:(NSData *)PEMData;
- (BOOL)importRSAPrivateKeyPEMFilePath:(NSString *)path;
/**
 *  read private key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 *  @see   `importRSAPublicKeyDERData:`
 */
- (BOOL)importRSAPrivateKeyDERData:(NSData *)DERData;
- (BOOL)importRSAPrivateKeyDERFilePath:(NSString *)path;


#pragma mark - 提取证书
/**
 *  get PEM format string of public key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPublicKey;

/**
 *  get PEM format string of private key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPrivateKey;

#pragma mark - 加解密

/**
 @abstract  encrypt text using RSA public key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData;
- (NSString *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding plainString:(NSString *)plainString;
/**
 @abstract  encrypt text using RSA private key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData;
- (NSString *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainString:(NSString *)plainString;
/**
 @abstract  decrypt text using RSA private key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData;
- (NSString *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherString:(NSString *)cipherString;
/**
 @abstract  decrypt text using RSA public key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData;
- (NSString *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherString:(NSString *)cipherString;

#pragma mark - 签名校验
/**
 *  sign data with private key.
 *  @param type      digest type
 *  @param plainData data will be sign
 *  @return sign data
 */
- (NSData *)signWithPrivateKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type plainData:(NSData *)plainData;
- (NSString *)signWithPrivateKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type plainString:(NSString *)plainString;
/**
 *  verify the sign is ok or not using public key.
 */
- (BOOL)verifyWithPublicKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type signData:(NSData *)signData plainData:(NSData *)plainData;
- (BOOL)verifyWithPublicKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type signString:(NSString *)signString plainString:(NSString *)plainString;


@end
