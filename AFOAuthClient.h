// AFOAuth2Client.h
//
// Copyright (c) 2011 Mattt Thompson (http://mattt.me/)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <Foundation/Foundation.h>
#import "AFHTTPClient.h"

@class AFXAuthAccountCredential;

extern NSString * const kAFXAuthMode;

@class AFOAuthAccount;

@interface AFOAuthClient : AFHTTPClient

@property (readonly, nonatomic, copy) NSString *serviceProviderIdentifier;
@property (readonly, nonatomic, copy) NSString *consumerKey;
@property (readonly, nonatomic, copy) NSString *consumerSecret;
@property (readonly, nonatomic, copy) NSString *token;
@property (readonly, nonatomic, copy) NSString *tokenSecret;

- (id)initWithBaseURL:(NSURL *)url
          consumerKey:(NSString *)consumerKey
       consumerSecret:(NSString *)consumerSecret;

- (id)initWithBaseUrl:(NSURL *)url
          consumerKey:(NSString *)consumerKey
       consumerSecret:(NSString *)consumerSecret
                token:(NSString *)token
          tokenSecret:(NSString *)tokenSecret;

- (void)authenticateUsingXAuthWithPath:(NSString *)path
                              username:(NSString *)username
                              password:(NSString *)password
                           consumerKey:(NSString *)consumerKey
                        consumerSecret:(NSString *)consumerSecret
                               success:(void (^)(AFXAuthAccountCredential *credentials))success 
                               failure:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error))failure;

- (void)JSONRequestOperationWithUrl:(NSString *)path
                         parameters:(NSDictionary *)parameters
                            success:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, id JSON))success 
                            failure:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error, id JSON))failure;

- (void)enqueuePostRequestOperaionWithURL:(NSString *)path
                               parameters:(NSDictionary *)parameters;

- (void)postQueueWithCompletion:(void (^)(NSArray *operations))completion;

- (void)setToken:(NSString *)token tokenSecret:(NSString *)tokenSecret;

@end

#pragma mark -

@interface AFXAuthAccountCredential : NSObject <NSCoding>

@property (readonly, nonatomic, strong) NSString *token;
@property (readonly, nonatomic, strong) NSString *tokenSecret;

+ (id)credentialWithOAuthToken:(NSString *)token tokenSecret:(NSString *)secret;
- (id)initWithOAuthToken:(NSString *)token tokenSecret:(NSString *)secret;

@end