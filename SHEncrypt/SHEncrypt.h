//
//  SHEncrypt.h
//  SHEncrypt
//
//  Created by my on 16/3/17.
//  Copyright © 2016年 chenlaifang. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

typedef enum {
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
}RSA_PADDING_TYPE;


@interface SHEncrypt : NSObject


+ (SHEncrypt*)sharedInstance;
/**
 *  保存从服务器端返回来的base64的公钥
 *
 *  @param pubKey 公钥
 */
- (void)saveRSAKeyPair:(NSString*)pubKey;
/**
 *  字符串加密操作
 *
 *  @param text　需要加密的字符串
 *
 *  @return 返回经过RSA加密过的字符串
 */
- (NSString *)encryptUsingServerPublicKeyWithText:(NSString*)text;
/**
 *  解密从服务器商返回的字符串
 *
 *  @param text 需要解密的字符串
 *
 *  @return 返加解密后的字符串
 */
- (NSString *)decryptUsingServerPublicKeyWithText:(NSString *)text;

@end
