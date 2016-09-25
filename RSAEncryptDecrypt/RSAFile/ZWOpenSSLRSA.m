//
//  ZWOpenSSLRSA.m
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//

#import "ZWOpenSSLRSA.h"
#import <CommonCrypto/CommonCrypto.h>


@implementation ZWOpenSSLRSA
+ (ZWOpenSSLRSA *)sharedInstance {
    static ZWOpenSSLRSA *hcRSA = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (!hcRSA) {
            hcRSA = [[ZWOpenSSLRSA alloc] init];
        }
    });
    return hcRSA;
}
//- (instancetype)init
//{
//    self = [super init];
//    if (self) {
//        
////        // mkdir for key dir
////        NSFileManager *fm = [NSFileManager defaultManager];
////        if (![fm fileExistsAtPath:OpenSSLRSAKeyDir])
////        {
////            [fm createDirectoryAtPath:OpenSSLRSAKeyDir withIntermediateDirectories:YES attributes:nil error:nil];
////        }
//    }
//    return self;
//}

#pragma mark - 导入证书
/**
 *  read public key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN PUBLIC KEY-----   xxxxx  -----END PUBLIC KEY-----
 *  @return success or not.
 */

- (BOOL)importRSAPublicKeyPEMData:(NSData *)PEMData
{
    const void *bytes = [PEMData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)PEMData.length);
    _rsaPublic = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    assert(_rsaPublic != NULL);
    BIO_free_all(bio);
    
    return _rsaPublic ? YES : NO;
}
- (BOOL)importRSAPublicKeyPEMFilePath:(NSString *)path{
    return [self importRSAPublicKeyPEMData:[NSData dataWithContentsOfFile:path]];
}
/**
 *  read public key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 */
- (BOOL)importRSAPublicKeyDERData:(NSData *)DERData
{
    const void *bytes = [DERData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)DERData.length);
    _rsaPublic = d2i_RSA_PUBKEY_bio(bio, NULL);
    assert(_rsaPublic != NULL);
    BIO_free_all(bio);
    
    return _rsaPublic ? YES : NO;
}
- (BOOL)importRSAPublicKeyDERFilePath:(NSString *)path{
    return [self importRSAPublicKeyDERData:[NSData dataWithContentsOfFile:path]];
}

/**
 *  read private key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN RSA PRIVATE KEY-----   xxxxx  -----END RSA PRIVATE KEY-----
 *  @return success or not.
 */
- (BOOL)importRSAPrivateKeyPEMData:(NSData *)PEMData
{
    const void *bytes = [PEMData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)PEMData.length);
    _rsaPrivate = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    assert(_rsaPrivate != NULL);
    BIO_free_all(bio);
    
    return _rsaPrivate ? YES : NO;
}

- (BOOL)importRSAPrivateKeyPEMFilePath:(NSString *)path{
    NSString *resPath = path;

    
    if (!resPath) {
        NSLog(@"PRSAPrivateKey file load failed!");
        return NO;
    }
    
    FILE *keyFile =
    fopen([resPath cStringUsingEncoding:NSUTF8StringEncoding], "rb");
    _rsaPrivate = PEM_read_RSAPrivateKey(keyFile, NULL, 0, NULL);
    return _rsaPrivate ? YES : NO;

}
/**
 *  read private key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 */
- (BOOL)importRSAPrivateKeyDERData:(NSData *)DERData
{
    const void *bytes = [DERData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)DERData.length);
    _rsaPrivate = d2i_RSAPrivateKey_bio(bio, NULL);
    assert(_rsaPrivate != NULL);
    BIO_free_all(bio);
    
    return _rsaPrivate ? YES : NO;
}
- (BOOL)importRSAPrivateKeyDERFilePath:(NSString *)path{
    return [self importRSAPrivateKeyDERData:[NSData dataWithContentsOfFile:path]];
}
#pragma mark - 提取证书
/**
 *  get PEM format string of public key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPublicKey
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    if (!_rsaPublic) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, _rsaPublic);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    
    return [NSString stringWithUTF8String:bptr->data];
}

/**
 *  get PEM format string of private key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPrivateKey
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    if (!_rsaPrivate) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, _rsaPrivate, NULL, NULL, 0, NULL, NULL);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    
    return [NSString stringWithUTF8String:bptr->data];
}

//- (NSString *)base64EncodedPublicKey
//{
//    NSFileManager *fm = [NSFileManager defaultManager];
//    if ([fm fileExistsAtPath:OpenSSLRSAPublicKeyFile])
//    {
//        NSString *str = [NSString stringWithContentsOfFile:OpenSSLRSAPublicKeyFile encoding:NSUTF8StringEncoding error:nil];
//        NSString *string = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
//        string = [string stringByReplacingOccurrencesOfString:@"\n" withString:@""];
//        string = [string stringByReplacingOccurrencesOfString:@"\r" withString:@""];
//        return string;
//    }
//    return nil;
//}

//- (NSString *)base64EncodedPrivateKey
//{
//    NSFileManager *fm = [NSFileManager defaultManager];
//    if ([fm fileExistsAtPath:OpenSSLRSAPrivateKeyFile])
//    {
//        NSString *str = [NSString stringWithContentsOfFile:OpenSSLRSAPrivateKeyFile encoding:NSUTF8StringEncoding error:nil];
//        NSString *string = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
//        string = [string stringByReplacingOccurrencesOfString:@"\n" withString:@""];
//        string = [string stringByReplacingOccurrencesOfString:@"\r" withString:@""];
//        return string;
//    }
//    return nil;
//}
#pragma mark - 加解密
- (NSData *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    
    if ([plainData length])
    {
        int len = (int)[plainData length];
        unsigned char *plainBuffer = (unsigned char *)[plainData bytes];
        
        //result len
        int clen = RSA_size(_rsaPublic);
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        
        RSA_public_encrypt(len,plainBuffer,cipherBuffer, _rsaPublic,  padding);
        
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        
        free(cipherBuffer);
        
        return cipherData;
    }
    
    return nil;
}
- (NSString *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding plainString:(NSString *)plainString{
    NSData *data = [self encryptWithPublicKeyUsingPadding:padding plainData:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    
    NSString *base64Str = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return base64Str;
}



- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([plainData length])
    {
        int len = (int)[plainData length];
        unsigned char *plainBuffer = (unsigned char *)[plainData bytes];
        
        //result len
        int clen = RSA_size(_rsaPrivate);
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        
        RSA_private_encrypt(len,plainBuffer,cipherBuffer, _rsaPrivate,  padding);
        
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        
        free(cipherBuffer);
        
        return cipherData;
    }
    
    return nil;
}
- (NSString *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainString:(NSString *)plainString{
    NSData *data = [self encryptWithPrivateKeyUsingPadding:padding plainData:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *base64Str = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return base64Str;
}




- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        unsigned char *cipherBuffer = (unsigned char *)[cipherData bytes];
        
        //result len
        int mlen = RSA_size(_rsaPrivate);
        unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
        
        RSA_private_decrypt(len, cipherBuffer, plainBuffer, _rsaPrivate, padding);
        
        NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:mlen];
        
        free(plainBuffer);
        
        return plainData;
    }
    
    return nil;
}
- (NSString *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherString:(NSString *)cipherString{
    NSData *decodeData = [[NSData alloc] initWithBase64EncodedString:cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *data = [self decryptWithPrivateKeyUsingPadding:padding cipherData:decodeData];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        unsigned char *cipherBuffer = (unsigned char *)[cipherData bytes];
        
        //result len
        int mlen = RSA_size(_rsaPublic);
        unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
        
        RSA_public_decrypt(len, cipherBuffer, plainBuffer, _rsaPublic, padding);
        
        NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:mlen];
        
        free(plainBuffer);
        
        return plainData;
    }
    
    return nil;
}
- (NSString *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherString:(NSString *)cipherString{

    NSData *decodeData = [[NSData alloc] initWithBase64EncodedString:cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    decodeData = [self decryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:decodeData];
    NSString *strrrr = [[NSString alloc] initWithData:decodeData encoding:NSUTF8StringEncoding];
    
    return strrrr;
}

#pragma mark - 签名-验签
- (NSData *)signWithPrivateKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type plainData:(NSData *)plainData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    NSData *digestData = [self digestDataOfData:plainData withType:type];
    
    unsigned int len = 0;
    unsigned int signLen = RSA_size(_rsaPrivate);
    unsigned char *sign = malloc(signLen);
    memset(sign, 0, signLen);
    
    int ret = RSA_sign(type, [digestData bytes], (unsigned int)[digestData length], sign, &len, _rsaPrivate);
    if (ret == 1) {
        NSData *data = [NSData dataWithBytes:sign length:len];
        free(sign);
        return data;
    }
    free(sign);
    return nil;
}

- (BOOL)verifyWithPublicKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type signData:(NSData *)signData plainData:(NSData *)plainData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    NSData *digestData = [self digestDataOfData:plainData withType:type];
    
    int ret = RSA_verify(type, [digestData bytes], (unsigned int)[digestData length], [signData bytes], (unsigned int)[signData length], _rsaPublic);
    if (ret == 1) {
        return YES;
    }
    return NO;
}


#pragma mark - private
- (NSData *)digestDataOfData:(NSData *)plainData withType:(RSA_SIGN_DIGEST_TYPE)type
{
    if (!plainData.length) {
        return nil;
    }
    
#define digestWithType(type) \
unsigned char digest[CC_##type##_DIGEST_LENGTH];\
CC_##type([plainData bytes], (unsigned int)[plainData length], digest);\
NSData *result = [NSData dataWithBytes:digest length:CC_##type##_DIGEST_LENGTH];\
return result;\

    switch (type) {
            case RSA_SIGN_DIGEST_TYPE_SHA1:
        {
            digestWithType(SHA1);
        }
            break;
            case RSA_SIGN_DIGEST_TYPE_SHA256:
        {
            digestWithType(SHA256);
        }
            break;
            case RSA_SIGN_DIGEST_TYPE_SHA224:
        {
            digestWithType(SHA224);
        }
            break;
            case RSA_SIGN_DIGEST_TYPE_SHA384:
        {
            digestWithType(SHA384);
        }
            break;
            case RSA_SIGN_DIGEST_TYPE_SHA512:
        {
            digestWithType(SHA512);
        }
            break;
            case RSA_SIGN_DIGEST_TYPE_MD5:
        {
            digestWithType(MD5);
        }
            break;
        default:
            break;
    }
    return nil;
}






#pragma mark - testMethod

#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@".openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"rsa_public_key.pem"]
#define OpenSSLRSAPrivateKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"rsa_private_key.pem"]
//在客户端生成rsa公私钥
- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize
{
    if (NULL != _rsa)
    {
        RSA_free(_rsa);
        _rsa = NULL;
    }
    _rsa = RSA_generate_key(keySize,RSA_F4,NULL,NULL);
    assert(_rsa != NULL);
    
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    
    //写入私钥和公钥
    RSA_blinding_on(_rsa, NULL);
    
    BIO *priBio = BIO_new_file(privateKeyFileName, "w");
    PEM_write_bio_RSAPrivateKey(priBio, _rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO *pubBio = BIO_new_file(publicKeyFileName, "w");
    
    
    PEM_write_bio_RSA_PUBKEY(pubBio, _rsa);
    //    PEM_write_bio_RSAPublicKey(pubBio, _rsa);
    
    BIO_free(priBio);
    BIO_free(pubBio);
    
    //分别获取公钥和私钥
    _rsaPrivate = RSAPrivateKey_dup(_rsa);
    assert(_rsaPrivate != NULL);
    
    _rsaPublic = RSAPublicKey_dup(_rsa);
    assert(_rsaPublic != NULL);
    
    if (_rsa && _rsaPublic && _rsaPrivate)
    {
        return YES;
    }
    else
    {
        return NO;
    }
}
- (BOOL)importRSAPublicKeyBase64:(NSString *)publicKey
{
    //格式化公钥
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----"];
    [result writeToFile:OpenSSLRSAPublicKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    
    FILE *publicKeyFile;
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    publicKeyFile = fopen(publicKeyFileName,"rb");
    if (NULL != publicKeyFile)
    {
        BIO *bpubkey = NULL;
        bpubkey = BIO_new(BIO_s_file());
        BIO_read_filename(bpubkey, publicKeyFileName);
        
        _rsaPublic = PEM_read_bio_RSA_PUBKEY(bpubkey, NULL, NULL, NULL);
        assert(_rsaPublic != NULL);
        BIO_free_all(bpubkey);
    }
    
    return YES;
}

- (BOOL)importRSAPrivateKeyBase64:(NSString *)privateKey
{
    //格式化私钥
    const char *pstr = [privateKey UTF8String];
    int len = (int)[privateKey length];
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int index = 0;
    int count = 0;
    while (index < len) {
        char ch = pstr[index];
        if (ch == '\r' || ch == '\n') {
            ++index;
            continue;
        }
        [result appendFormat:@"%c", ch];
        if (++count == 64)
        {
            [result appendString:@"\n"];
            count = 0;
        }
        index++;
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    [result writeToFile:OpenSSLRSAPrivateKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    
    FILE *privateKeyFile;
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    privateKeyFile = fopen(privateKeyFileName,"rb");
    if (NULL != privateKeyFile)
    {
        BIO *bpubkey = NULL;
        bpubkey = BIO_new(BIO_s_file());
        BIO_read_filename(bpubkey, privateKeyFileName);
        
        _rsaPrivate = PEM_read_bio_RSAPrivateKey(bpubkey, NULL, NULL, NULL);
        assert(_rsaPrivate != NULL);
        BIO_free_all(bpubkey);
    }
    
    return YES;
}
#pragma mark  testMethodEnd



@end
