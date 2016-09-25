//
//  ViewController.m
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//

#import "ViewController.h"
#import "ZWRSA.h"
#import "ZWOpenSSLRSA.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

}


#pragma mark - userAction
#pragma mark 系统RSA加解密 (必须是证书版，常用的rsa加解密)
- (IBAction)encryptA:(UIButton *)sender {
    //加载公私钥
    [self rsaLoadKey];
    NSString *str = [[ZWRSA sharedInstance] encryptStringWithSourceString:_textFiledA.text];
    _labelA.text = [NSString stringWithFormat:@"加密结果:%@",str];

    NSLog(@"加密结果为:%@",_labelA.text);
}

- (IBAction)decryptA:(UIButton *)sender {
    //加载公私钥
    [self rsaLoadKey];
    
    NSString *str  = [[ZWRSA sharedInstance] decryptStringWithSourceString:_labelA.text];
    _labelA.text = [NSString stringWithFormat:@"解密结果:%@",str];

    NSLog(@"解密结果为:%@",_labelA.text);
}
#pragma mark 系统签名效验
- (IBAction)signA:(UIButton *)sender {
    //加载公私钥
    [self rsaLoadKey];
    
    NSString *signString = [[ZWRSA sharedInstance] rsaSHA256SignString:_textFiledA.text];
    _labelA.text = signString;
}
- (IBAction)deSignA:(id)sender {
    //加载公私钥
    [self rsaLoadKey];

    BOOL aBool = [[ZWRSA sharedInstance] rsaSHA256VerifySourceString:_textFiledA.text withSignString:_labelA.text];
    if (aBool) {
        _labelA.text = @"恭喜你签名效验通过";
         NSLog(@"恭喜你签名效验通过");
    }else{
        NSLog(@"效验未通过");
    }
    
    
}



#pragma mark OpensslRSA加解密 (无证书版)
- (IBAction)encryptB:(UIButton *)sender {

    //加载公私钥
    [self opensslRSALoadKey];

    ZWOpenSSLRSA *rsa = [ZWOpenSSLRSA sharedInstance];
    NSString *str1 = [rsa encryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainString:_TextFiledB.text];
    NSString *str2 = [rsa encryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainString:_TextFiledB.text];
    _labelB.text = [NSString stringWithFormat:@"加密结果:%@",str1];
    NSLog(@"encrypt-%@,%@",str1,str2);

}

- (IBAction)decryptB:(UIButton *)sender {
    //加载公私钥
    [self opensslRSALoadKey];
    ZWOpenSSLRSA *rsa = [ZWOpenSSLRSA sharedInstance];
    NSString *str1 = [rsa decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherString:_labelB.text];
    _labelB.text = [NSString stringWithFormat:@"解密结果:%@",str1];;
}

#pragma mark openssl签名效验
- (IBAction)signB:(id)sender {
    //加载公私钥
    [self opensslRSALoadKey];
    NSString *signString = [[ZWOpenSSLRSA sharedInstance] signWithPrivateKeyUsingDigest:RSA_SIGN_DIGEST_TYPE_SHA256 plainString:_TextFiledB.text];
    _labelB.text = signString;
}

- (IBAction)deSignB:(id)sender {
    //加载公私钥
    [self opensslRSALoadKey];
    BOOL aBool = [[ZWOpenSSLRSA sharedInstance] verifyWithPublicKeyUsingDigest:RSA_SIGN_DIGEST_TYPE_SHA256 signString:_labelB.text plainString:_TextFiledB.text];
    if (aBool) {
        _labelB.text = @"恭喜你签名效验通过";
        NSLog(@"恭喜你签名效验通过");
    }else{
        NSLog(@"效验未通过");
    }
}

#pragma mark - private
-(void)rsaLoadKey{
    NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"cert" ofType:@"der"];
    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"pkcs" ofType:@"p12"];

    [[ZWRSA sharedInstance] loadPublicKeyFromCertificateFile:publicKeyPath];
    [[ZWRSA sharedInstance] loadEveryThingFromPKCS12File:privateKeyPath passphrase:@"123456"];
    
}

-(void)opensslRSALoadKey{
    ZWOpenSSLRSA *rsa = [ZWOpenSSLRSA sharedInstance];
    [rsa importRSAPublicKeyPEMFilePath:[[NSBundle mainBundle] pathForResource:@"rsa_public_key" ofType:@"pem"]];
    [rsa importRSAPrivateKeyPEMFilePath:[[NSBundle mainBundle] pathForResource:@"rsa_private_key" ofType:@"pem"]];
    
}

@end
