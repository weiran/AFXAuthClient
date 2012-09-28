//
//  FRHashSHA256.h
//  Instaforms
//
//  Created by Weiran Zhang on 03/07/2012.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

@interface FRHashSHA : NSObject
+ (NSString *)SHA1HashString:(NSString *)data withKey:(NSString *)key;
+ (NSString *)SHA256HashString:(NSString *)data withKey:(NSString *)key;
@end
