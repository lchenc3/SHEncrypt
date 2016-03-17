//
//  SHEncrypt.m
//  SHEncrypt
//
//  Created by my on 16/3/17.
//  Copyright © 2016年 chenlaifang. All rights reserved.
//

#import "SHEncrypt.h"
#import "NSString+Base64.h"
#import "NSData+Base64.h"

#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@".openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"publicKey"]

@implementation SHEncrypt

+ (SHEncrypt*)sharedInstance {
    
    static SHEncrypt *_rsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _rsa = [[self alloc] init];
    });
    return _rsa;
}

- (void)saveRSAKeyPair:(NSString*)pubKey {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:OpenSSLRSAPublicKeyFile])
    {
        [fm removeItemAtPath:OpenSSLRSAPublicKeyFile error:nil];
    }
    
    NSString *rsaPubKey = [self formatPublicKey:pubKey];
    [rsaPubKey writeToFile:OpenSSLRSAPublicKeyFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
/*
- (RSA *)getRSAfromfile {
    
    RSA *_rsa = NULL;
    BIO *bio_private = NULL;
    bio_private = BIO_new(BIO_s_file());
    NSString *filePath = OpenSSLRSAPublicKeyFile;
    char *private_key_file_path = (char *)[filePath UTF8String];
    BIO_read_filename(bio_private, private_key_file_path);
    _rsa = PEM_read_bio_RSA_PUBKEY(bio_private, NULL, NULL, NULL);
    
    if (_rsa == nil)
    {
        NSLog(@"rsa_public read error : private key is NULL");
    }
    return _rsa
    
}
*/

/**
 *  加密操作
 *
 *  @param text
 *
 *  @return
 */
- (NSString *)encryptUsingServerPublicKeyWithText:(NSString*)text {
    if (text && [text length])
    {
        RSA *_rsa = NULL;
        BIO *bio_private = NULL;
        bio_private = BIO_new(BIO_s_file());
        NSString *filePath = OpenSSLRSAPublicKeyFile;
        char *private_key_file_path = (char *)[filePath UTF8String];
        BIO_read_filename(bio_private, private_key_file_path);
        _rsa = PEM_read_bio_RSA_PUBKEY(bio_private, NULL, NULL, NULL);
        
        if (_rsa == nil)
        {
            NSLog(@"rsa_private read error : private key is NULL");
        }
        
        const char *message = [text UTF8String];
        int messageLength = (int)strlen(message);
        int key_size = RSA_size(_rsa);
        unsigned char *encrypted = (unsigned char*)malloc(key_size);
        
        int bufSize = RSA_public_encrypt(messageLength, (unsigned char*)message, encrypted, _rsa, RSA_PADDING_TYPE_PKCS1);
        if (bufSize == -1)
        {
            RSA_free(_rsa);
            return nil;
        }
        NSString * base64String = base64StringFData([NSData dataWithBytes:encrypted length:bufSize]);
        BIO_free_all(bio_private);
        free(encrypted);
        RSA_free(_rsa);
        return base64String;
    }
    return  nil;

}
/**
 *  解密　使用分段解密
 *
 *  @param sData
 *
 *  @return　返加解密后的字符串
 */

- (NSString *)decryptUsingServerPublicKeyWithText:(NSString *)text {
    if (text && [text length])
    {
        // RSA 分段解密
        NSData *sData = [text base64DecodedData]; //dataFBase64String(data);
        
        NSUInteger dataLength = sData.length;
        NSInteger splitCount = dataLength % 256 > 0 ? dataLength/256 + 1 : dataLength/256;
        
        NSMutableString *returnString = [[NSMutableString alloc] init];
        for (int i = 0; i < splitCount; i ++) {
            NSData *splitData = [sData subdataWithRange:NSMakeRange(i*256, 256)];
            [returnString appendString:[self decryptBase64Data:splitData]];
        }
        return returnString;
    }
    return nil;
}

- (NSString*)decryptBase64Data:(NSData*)sData {
    
    unsigned char* message = (unsigned char*)[sData bytes];
    RSA *_rsa = NULL;
    BIO *bio_private = NULL;
    bio_private = BIO_new(BIO_s_file());
    NSString *filePath = OpenSSLRSAPublicKeyFile;
    char *private_key_file_path = (char *)[filePath UTF8String];
    BIO_read_filename(bio_private, private_key_file_path);
    _rsa = PEM_read_bio_RSA_PUBKEY(bio_private, NULL, NULL, NULL);
    
    if (_rsa == nil)
    {
        NSLog(@"rsa_private read error : private key is NULL");
        return @"";
    }
    int key_size = RSA_size(_rsa);
    
    char *ptext = (char*)malloc(key_size);
    bzero(ptext, key_size);
    //RSA_PKCS1_PADDING
    int outlen = RSA_public_decrypt(key_size, (const unsigned char*)message, (unsigned char*)ptext, _rsa, RSA_PKCS1_PADDING);
    if (outlen < 0)
    {
        return nil;
    }
    
    NSMutableString *decryptString = [[NSMutableString alloc] initWithBytes:ptext length:strlen(ptext) encoding:NSASCIIStringEncoding];
    // TODO: memory free
    free(ptext);
    ptext = NULL;
    RSA_free(_rsa);
    BIO_free_all(bio_private);
    return decryptString;
    
}

#pragma mark - private methods

/**
 *  格式发公钥
 *
 *  @param publicKey
 *
 *  @return
 */
- (NSString *)formatPublicKey:(NSString *)publicKey {
    
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 65) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----\n"];
    return result;
}

NSString *base64StringFData(NSData *signature)
{
    NSUInteger signatureLength = [signature length];
    unsigned char *outputBuffer = (unsigned char *)malloc(2 * 4 * (signatureLength / 3 + 1));
    int outputLength = EVP_EncodeBlock(outputBuffer, [signature bytes], (int)signatureLength);
    outputBuffer[outputLength] = '\0';
    NSString *base64String = [NSString stringWithCString:(char *)outputBuffer encoding:NSASCIIStringEncoding];
    free(outputBuffer);
    return base64String;
}

NSData *dataFBase64String(NSString *base64String)
{
    NSUInteger stringLength = [base64String length];
    const unsigned char *strBuffer = (const unsigned char *)[base64String UTF8String];
    unsigned char *outputBuffer = (unsigned char *)malloc(2 * 3 * (stringLength / 4 + 1));
    int outputLength = EVP_DecodeBlock(outputBuffer, strBuffer, (int)stringLength);
    
    int zeroByteCounter = 0;
    for (int i = (int)stringLength - 1; i >= 0; i--)
    {
        if (strBuffer[i] == '=')
        {
            zeroByteCounter++;
        }
        else
        {
            break;
        }
    }
    
    NSData *data = [[NSData alloc] initWithBytes:outputBuffer length:outputLength - zeroByteCounter];
    free(outputBuffer);
    return data;
}

@end
