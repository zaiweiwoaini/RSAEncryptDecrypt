//
//  ZWRSA.h
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//



/*
 * 使用系统加解密方法，即有证书的RSA。 例如DER格式的文件公钥，或者P12文件私钥。
 */




/*
 用法示例：
 ZWRSA *rsa = [ZWRSA sharedInstance];
 [rsa loadPublicKeyFromCertificateFile:[[NSBundle mainBundle]
 pathForResource:@"cert" ofType:@"der"]];
 [rsa loadEveryThingFromPKCS12File:[[NSBundle mainBundle]
 pathForResource:@"pkcs" ofType:@"p12"] passphrase:@"123456"];
 
 NSString *str111 = [rsa encryptStringWithKeyType:HCRSATypeDefault
 sourceString:@"qwerty"];//加密
 NSString *str222 = [rsa decryptStringWithKeyType:HCRSATypeDefault
 sourceDataString:str111];//解密
 
 
 */

#import <Foundation/Foundation.h>


@interface ZWRSA : NSObject
{
    SecKeyRef _privateKey;
    SecKeyRef _publicKey;
}

@property(nonatomic, readonly) SecKeyRef privateKey;
@property(nonatomic, readonly) SecKeyRef publicKey;



+ (ZWRSA *)sharedInstance;

///获取私钥
///可以从PKCS#12文件中提取身份、信任、证书、公钥、私钥，这里，我们只需要保留私钥；文件一般为p12或者pfx格式
- (OSStatus)loadEveryThingFromPKCS12File:(NSString *)pkcsPath
                              passphrase:(NSString *)pkcsPassword;
///提取公钥 从证书文件中提取公钥 一般为der格式
- (OSStatus)loadPublicKeyFromCertificateFile:(NSString *)certPath;


/// RSA公钥加密，支持长数据加密;
- (NSData *)encryptWithSourceData:(NSData *)sourceData;
/// RSA私钥解密，支持长数据解密;
- (NSData *)decryptWithSourceData:(NSData *)sourceData;

/// RSA公钥加密，支持长数据加密;
- (NSString *)encryptStringWithSourceString:(NSString *)sourceString;
/// RSA私钥解密，支持长数据解密;
- (NSString *)decryptStringWithSourceString:(NSString *)sourceString;


//私钥签名
- (NSData *)rsaSHA256SignData:(NSData *)plainData;
- (NSString *)rsaSHA256SignString:(NSString *)string;

//公钥效验 sourceData:签名源数据；signData签名后的数据
- (BOOL)rsaSHA256VerifySourceData:(NSData *)sourceData
              withSignData:(NSData *)signData;
- (BOOL)rsaSHA256VerifySourceString:(NSString *)sourceString
              withSignString:(NSString *)signString;



@end



