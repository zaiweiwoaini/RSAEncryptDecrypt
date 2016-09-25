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
- (IBAction)encryptA:(UIButton *)sender {
    [self rsaLoadKey];
    _labelA.text = [[ZWRSA sharedInstance] encryptStringWithSourceString:_textFiledA.text];
    NSLog(@"加密结果为:%@",_labelA.text);
}

- (IBAction)decryptA:(UIButton *)sender {
    _labelA.text = [[ZWRSA sharedInstance] decryptStringWithSourceString:_labelA.text];
    NSLog(@"解密结果为:%@",_labelA.text);
}

- (IBAction)encryptB:(UIButton *)sender {

    
    [self opensslRSALoadKey];

    
    
    
    ZWOpenSSLRSA *rsa = [ZWOpenSSLRSA sharedInstance];

    NSString *str1 = [rsa encryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainString:_TextFiledB.text];
    NSString *str2 = [rsa encryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainString:_TextFiledB.text];
    _labelB.text = str1;
    NSLog(@"encrypt-%@,%@",str1,str2);

}

- (IBAction)decryptB:(UIButton *)sender {
    [self opensslRSALoadKey];

    ZWOpenSSLRSA *rsa = [ZWOpenSSLRSA sharedInstance];
    NSString *str1 = [rsa decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherString:_labelB.text];
//    NSString *str2 = [rsa decryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherString:_labelB.text];
    _labelB.text = str1;
}


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
