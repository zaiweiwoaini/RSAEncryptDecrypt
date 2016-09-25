//
//  ViewController.h
//  RSAEncryptDecrypt
//
//  Created by zaiwei on 16/9/25.
//  Copyright © 2016年 zaiwei. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
@property (weak, nonatomic) IBOutlet UITextField *textFiledA;
@property (weak, nonatomic) IBOutlet UILabel *labelA;
@property (weak, nonatomic) IBOutlet UITextField *TextFiledB;
@property (weak, nonatomic) IBOutlet UILabel *labelB;

- (IBAction)encryptA:(UIButton *)sender;
- (IBAction)decryptA:(UIButton *)sender;
- (IBAction)encryptB:(UIButton *)sender;
- (IBAction)decryptB:(UIButton *)sender;

@end

