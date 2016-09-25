//
//  ZWRSA.m
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//

#import "ZWRSA.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>


#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH  // SHA-1消息摘要的数据位数160位

@implementation ZWRSA
+ (ZWRSA *)sharedInstance {
    static ZWRSA *hcRSA = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (!hcRSA) {
            hcRSA = [[ZWRSA alloc] init];
        }
    });
    return hcRSA;
}
-(SecKeyRef)privateKey{
    if (_privateKey) {
        return _privateKey;
    }
    NSLog(@"请调用如下方法初始化_privateKey方法：\n- (OSStatus)extractEveryThingFromPKCS12File:(NSString *)pkcsPath passphrase:(NSString *)pkcsPassword");
    return nil;
}
-(SecKeyRef)publicKey{
    if (_publicKey) {
        return _publicKey;
    }
    NSLog(@"请调用如下方法初始化_privateKey方法：\n- (OSStatus)extractPublicKeyFromCertificateFile:(NSString *)certPath");
    return nil;
}
//获取私钥。
- (OSStatus)loadEveryThingFromPKCS12File:(NSString *)pkcsPath passphrase:(NSString *)pkcsPassword {
    if (!pkcsPath || pkcsPath.length ==0) {
        NSLog(@"私钥文件路径不存在");
    }
    SecIdentityRef identity;
    SecTrustRef trust;
    OSStatus status = -1;
    if (_privateKey == nil) {
        NSData *p12Data = [NSData dataWithContentsOfFile:pkcsPath];
        if (p12Data) {
            CFStringRef password = (__bridge CFStringRef)pkcsPassword;
            const void *keys[] = {
                kSecImportExportPassphrase
            };
            const void *values[] = {
                password
            };
            CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL, NULL);
            CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, NULL, 0, NULL);
            status = SecPKCS12Import((CFDataRef)p12Data, options, &items);
            if (status == errSecSuccess) {
                CFDictionaryRef identity_trust_dic = CFArrayGetValueAtIndex(items, 0);
                identity = (SecIdentityRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemIdentity);
                trust = (SecTrustRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemTrust);
                // certs数组中包含了所有的证书
                CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemCertChain);
                if ([(__bridge NSArray *)certs count] && trust && identity) {
                    // 如果没有下面一句，自签名证书的评估信任结果永远是kSecTrustResultRecoverableTrustFailure
                    status = SecTrustSetAnchorCertificates(trust, certs);
                    if (status == errSecSuccess) {
                        SecTrustResultType trustResultType;
                        // 通常, 返回的trust result type应为kSecTrustResultUnspecified，如果是，就可以说明签名证书是可信的
                        status = SecTrustEvaluate(trust, &trustResultType);
                        if ((trustResultType == kSecTrustResultUnspecified || trustResultType == kSecTrustResultProceed) && status == errSecSuccess) {
                            // 证书可信，可以提取私钥与公钥，然后可以使用公私钥进行加解密操作
                            status = SecIdentityCopyPrivateKey(identity, &_privateKey);
                            if (status == errSecSuccess && _privateKey) {
                                // 成功提取私钥
                                NSLog(@"Get private key successfully~ %@", _privateKey);
                            }
                            
                        }
                    }
                }
            }
            if (options) {
                CFRelease(options);
            }
        }
    }
    return status;
}
//提取公钥。
- (OSStatus)loadPublicKeyFromCertificateFile:(NSString *)certPath {
    if (!certPath || certPath.length ==0) {
        NSLog(@"公钥文件路径不存在");
    }
    OSStatus status = -1;
    if (_publicKey == nil) {
        SecTrustRef trust;
        SecTrustResultType trustResult;
        NSData *derData = [NSData dataWithContentsOfFile:certPath];
        if (derData) {
            SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)derData);
            SecPolicyRef policy = SecPolicyCreateBasicX509();
            status = SecTrustCreateWithCertificates(cert, policy, &trust);
            if (status == errSecSuccess && trust) {
                NSArray *certs = [NSArray arrayWithObject:(__bridge id)cert];
                status = SecTrustSetAnchorCertificates(trust, (CFArrayRef)certs);
                if (status == errSecSuccess) {
                    status = SecTrustEvaluate(trust, &trustResult);
                    // 自签名证书可信
                    if (status == errSecSuccess && (trustResult == kSecTrustResultUnspecified || trustResult == kSecTrustResultProceed)) {
                        _publicKey = SecTrustCopyPublicKey(trust);
                        if (_publicKey) {
                            NSLog(@"Get public key successfully~ %@", _publicKey);
                        }
                        if (cert) {
                            CFRelease(cert);
                        }
                        if (policy) {
                            CFRelease(policy);
                        }
                        if (trust) {
                            CFRelease(trust);
                        }
                    }
                }
            }
        }
    }
    return status;
}

//公钥加密，因为每次的加密长度有限，所以用到了分段加密，苹果官方文档中提到了分段加密思想。
- (NSData *)encryptWithSourceData:(NSData *)sourceData{
    
    SecKeyRef secKeyRef = [self publicKey];
    if (secKeyRef == nil) {
        NSLog(@"请加载公钥");
        return nil;
    };
    
    
    // 分配内存块，用于存放加密后的数据段
    size_t cipherBufferSize = SecKeyGetBlockSize(secKeyRef);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    /*
     为什么这里要减12而不是减11?
     苹果官方文档给出的说明是，加密时，如果sec padding使用的是kSecPaddingPKCS1，
     那么支持的最长加密长度为SecKeyGetBlockSize()-11，
     这里说的最长加密长度，我估计是包含了字符串最后的空字符'\0'，
     因为在实际应用中我们是不考虑'\0'的，所以，支持的真正最长加密长度应为SecKeyGetBlockSize()-12
     */
    double totalLength = [sourceData length];
    size_t blockSize = cipherBufferSize - 12;// 使用cipherBufferSize - 11是错误的!
    size_t blockCount = (size_t)ceil(totalLength / blockSize);
    NSMutableData *encryptedData = [NSMutableData data];
    // 分段加密
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        // 数据段的实际大小。最后一段可能比blockSize小。
        long dataSegmentRealSize = MIN(blockSize, [sourceData length] - loc);
        // 截取需要加密的数据段
        NSData *dataSegment = [sourceData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        OSStatus status = SecKeyEncrypt(secKeyRef, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, cipherBuffer, &cipherBufferSize);
        if (status == errSecSuccess) {
            NSData *encryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            // 追加加密后的数据段
            [encryptedData appendData:encryptedDataSegment];
        } else {
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer) {
        free(cipherBuffer);
    }
    return encryptedData;
}
//私钥解密，用到分段解密。
- (NSData *)decryptWithSourceData:(NSData *)sourceData{
    SecKeyRef secKeyRef = [self privateKey];
    
    if (secKeyRef == nil) {
        NSLog(@"请加载私钥");
        return nil;
    };
    
    // 分配内存块，用于存放解密后的数据段
    size_t plainBufferSize = SecKeyGetBlockSize(secKeyRef);
    NSLog(@"plainBufferSize = %zd", plainBufferSize);
    uint8_t *plainBuffer = malloc(plainBufferSize * sizeof(uint8_t));
    // 计算数据段最大长度及数据段的个数
    double totalLength = [sourceData length];
    size_t blockSize = plainBufferSize;
    size_t blockCount = (size_t)ceil(totalLength / blockSize);
    NSMutableData *decryptedData = [NSMutableData data];
    // 分段解密
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        // 数据段的实际大小。最后一段可能比blockSize小。
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        // 截取需要解密的数据段
        NSData *dataSegment = [sourceData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        OSStatus status = SecKeyDecrypt(secKeyRef, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, plainBuffer, &plainBufferSize);
        if (status == errSecSuccess) {
            NSData *decryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)plainBuffer length:plainBufferSize];
            [decryptedData appendData:decryptedDataSegment];
        } else {
            if (plainBuffer) {
                free(plainBuffer);
            }
            return nil;
        }
    }
    if (plainBuffer) {
        free(plainBuffer);
    }
    return decryptedData;
}

/// RSA公钥加密，支持长数据加密;
- (NSString *)encryptStringWithSourceString:(NSString *)sourceString{
    NSData *data =  [self encryptWithSourceData:[sourceString dataUsingEncoding:NSUTF8StringEncoding]];
    return [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}
/// RSA私钥解密，支持长数据解密;
- (NSString *)decryptStringWithSourceString:(NSString *)sourceString{
    NSData *dataSource = [[NSData alloc] initWithBase64EncodedString:sourceString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *dataDecrypt = [self decryptWithSourceData:dataSource];
    return [[NSString alloc] initWithData:dataDecrypt encoding:NSUTF8StringEncoding];
}


#pragma mark - sha256签名
- (NSData *)rsaSHA256SignData:(NSData *)plainData {
    SecKeyRef key = [self privateKey];
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    SecKeyRawSign(key,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    if (hashBytes)
    free(hashBytes);
    if (signedHashBytes)
    free(signedHashBytes);
    
    //    [self rsaSHA256VerifyData:plainData withSignature:signedHash];
    return signedHash;
}
- (NSString *)rsaSHA256SignString:(NSString *)string{
    NSData *signData = [self rsaSHA256SignData:[string dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *base64String = [signData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return base64String;
}
#pragma mark - sha256效验
- (BOOL)rsaSHA256VerifySourceData:(NSData *)sourceData
                     withSignData:(NSData *)signData{
    NSData *plainData = sourceData;
    NSData *signature = signData;
    if (!plainData || !signature) {
        return NO;
    }
    SecKeyRef key = [self publicKey];
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    const void* signedHashBytes = [signature bytes];
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes],
                   (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }
    OSStatus status = SecKeyRawVerify(key,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    return status == errSecSuccess;
}
- (BOOL)rsaSHA256VerifySourceString:(NSString *)sourceString
                     withSignString:(NSString *)signString{
    NSData *sourceData = [sourceString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [[NSData alloc] initWithBase64EncodedString:signString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self rsaSHA256VerifySourceData:sourceData withSignData:signData];
}


#pragma mark - sha1签名
-(NSString *)signTheDataSHA1WithRSA:(NSString *)plainText
{
    uint8_t* signedBytes = NULL;
    size_t signedBytesSize = 0;
    OSStatus sanityCheck = noErr;
    NSData* signedHash = nil;
    
    NSString * path = [[NSBundle mainBundle]pathForResource:@"pkcs" ofType:@"p12"];
    NSData * data = [NSData dataWithContentsOfFile:path];
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init]; // Set the private key query dictionary.
    [options setObject:@"123456" forKey:(id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((CFDataRef) data, (CFDictionaryRef)options, &items);
    if (securityError!=noErr) {
        return nil ;
    }
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
    SecKeyRef privateKeyRef=nil;
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    signedBytesSize = SecKeyGetBlockSize(privateKeyRef);
    
    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    signedBytes = malloc( signedBytesSize * sizeof(uint8_t) ); // Malloc a buffer to hold signature.
    memset((void *)signedBytes, 0x0, signedBytesSize);
    
    sanityCheck = SecKeyRawSign(privateKeyRef,
                                kSecPaddingPKCS1SHA1,
                                (const uint8_t *)[[self getHashBytes:plainTextBytes] bytes],
                                kChosenDigestLength,
                                (uint8_t *)signedBytes,
                                &signedBytesSize);
    
    if (sanityCheck == noErr)
    {
        signedHash = [NSData dataWithBytes:(const void *)signedBytes length:(NSUInteger)signedBytesSize];
    }
    else
    {
        return nil;
    }
    
    if (signedBytes)
    {
        free(signedBytes);
    }
    NSString *signatureResult=[signedHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    return signatureResult;
}

- (NSData *)getHashBytes:(NSData *)plainText{
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], [plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    if (hashBytes) free(hashBytes);
    
    return hash;
}
@end
