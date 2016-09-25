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
    
}

- (IBAction)decryptB:(UIButton *)sender {
    
}


-(void)rsaLoadKey{
    NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"cert" ofType:@"der"];
    [[ZWRSA sharedInstance] loadPublicKeyFromCertificateFile:publicKeyPath];
    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"pkcs" ofType:@"p12"];
    [[ZWRSA sharedInstance] loadEveryThingFromPKCS12File:privateKeyPath passphrase:@"123456"];
    
    
}


@end
