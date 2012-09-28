#import "AFOAuthClient.h"
#import "FRHashSHA.h"
#import "NSDictionary+UrlEncoding.h"
#import "FROrderedDictionary.h"
#import "NSDictionary+QLineData.h"
#import "AFJSONRequestOperation.h"
#import "NSData+Base64String.h"

NSString * const kAFXAuthMode = @"client_auth";

@interface AFOAuthClient () {
    NSMutableArray *_requestQueue;
}

@property (readwrite, nonatomic, copy) NSString *serviceProviderIdentifier;

@end

@implementation AFOAuthClient

@synthesize serviceProviderIdentifier = _serviceProviderIdentifier;
@synthesize consumerKey = _consumerKey;
@synthesize consumerSecret = _consumerSecret;
@synthesize token = _token;
@synthesize tokenSecret = _tokenSecret;

- (id)initWithBaseURL:(NSURL *)url {
    self = [super initWithBaseURL:url];
    
    if (!self) {
        return nil;
    }
    
    self.serviceProviderIdentifier = [self.baseURL host];
    _requestQueue = [NSMutableArray array];
    
    return self;
}

- (id)initWithBaseURL:(NSURL *)url
          consumerKey:(NSString *)consumerKey
       consumerSecret:(NSString *)consumerSecret
{
    self = [super initWithBaseURL:url];
    
    if (self) {
        _serviceProviderIdentifier = [url host];
        _consumerKey = consumerKey;
        _consumerSecret = consumerSecret;
        _requestQueue = [NSMutableArray array];
    }
    
    return self;
}

- (id)initWithBaseUrl:(NSURL *)url
          consumerKey:(NSString *)consumerKey
       consumerSecret:(NSString *)consumerSecret
                token:(NSString *)token
          tokenSecret:(NSString *)tokenSecret
{
    self = [super initWithBaseURL:url];
    
    if (self) {
        _serviceProviderIdentifier = [url host];
        _consumerKey = consumerKey;
        _consumerSecret = consumerSecret;
        _token = token;
        _tokenSecret = tokenSecret;
        _requestQueue = [NSMutableArray array];
    }
    
    return self;
}

- (void)setToken:(NSString *)token tokenSecret:(NSString *)tokenSecret {
    _token = token;
    _tokenSecret = tokenSecret;
}

- (void)authenticateUsingXAuthWithPath:(NSString *)path
                              username:(NSString *)username
                              password:(NSString *)password
                           consumerKey:(NSString *)consumerKey
                        consumerSecret:(NSString *)consumerSecret
                               success:(void (^)(AFXAuthAccountCredential *credentials))success 
                               failure:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error))failure {
    // sanatise username and password
    if (!username) username = @"";
    if (!password) password = @"";
    
    NSMutableDictionary *authParameters = [NSMutableDictionary dictionary];
    [authParameters setObject:kAFXAuthMode forKey:@"x_auth_mode"];
    [authParameters setObject:username forKey:@"x_auth_username"];
    [authParameters setObject:password forKey:@"x_auth_password"];
    
    [self authenticateUsingOAuthWithPath:path
                          authParameters:authParameters
                                 success:^(AFXAuthAccountCredential *credentials) {
                                     if (success)
                                         success(credentials);
                                 } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
                                     if (failure)
                                         failure(operation.request, operation.response, error);
                                 }];
}

- (void)authenticateUsingOAuthWithPath:(NSString *)path
                        authParameters:(NSDictionary *)authParameters
                               success:(void (^)(AFXAuthAccountCredential *credentials))success
                               failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure
{
    // create authrization header parameters
    NSMutableDictionary *authHeaderParameters = [NSMutableDictionary dictionaryWithDictionary:[self authorizationHeader]];
    
    NSString *signature = [self getHMACSHA1SignitureWithURL:path
                                             authParameters:authHeaderParameters
                                                 parameters:authParameters
                                             consumerSecret:_consumerSecret
                                                tokenSecret:nil
                                             stringEncoding:self.stringEncoding
                                                 httpMethod:@"POST"];
    self.parameterEncoding = AFFormURLParameterEncoding;
    [authHeaderParameters setValue:signature forKey:@"oauth_signature"];
    
    NSString *oauthHeader = [self buildAuthoizationHeader:authHeaderParameters];
    
    [self clearAuthorizationHeader];
    [self setDefaultHeader:@"Authorization" value:oauthHeader];
    
    [self postPath:path
        parameters:authParameters
           success:^(AFHTTPRequestOperation *operation, id responseObject) {
               // parse response string (query format) into 
               NSMutableString *responseString = [[NSMutableString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
               [responseString replaceOccurrencesOfString:@"\"" withString:@"" options:NSCaseInsensitiveSearch range:NSMakeRange(0, responseString.length)];
               
               NSDictionary *responseDictionary = [NSDictionary dictionaryWithQueryLineString:responseString];
                              
               AFXAuthAccountCredential *credential = 
                   [AFXAuthAccountCredential credentialWithOAuthToken:[responseDictionary valueForKey:@"oauth_token"]
                                                          tokenSecret:[responseDictionary valueForKey:@"oauth_token_secret"]];
               if (success) {
                   success(credential);
               }
           } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning change method signature to return proper response string as below
               //NSString *responseString = [[NSString alloc] initWithData:operation.responseData encoding:NSUTF8StringEncoding];
               if (failure) {
                   failure(operation, error);
               }
           }
     ];
}

- (void)JSONRequestOperationWithUrl:(NSString *)path
                         parameters:(NSDictionary *)parameters
                            success:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, id JSON))success 
                            failure:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error, id JSON))failure
{
    NSMutableDictionary *authHeaderParameters = [NSMutableDictionary dictionaryWithDictionary:[self authorizationHeader]];
    if (_token) {
        [authHeaderParameters setObject:_token forKey:@"oauth_token"];
    }
    
    NSString *signature = [self getHMACSHA1SignitureWithURL:path
                                             authParameters:authHeaderParameters
                                                 parameters:parameters
                                             consumerSecret:_consumerSecret
                                                tokenSecret:_tokenSecret
                                             stringEncoding:self.stringEncoding
                                                 httpMethod:@"GET"];
    
    [authHeaderParameters setValue:signature forKey:@"oauth_signature"];
    
    NSString *oauthHeader = [self buildAuthoizationHeader:authHeaderParameters];
    
    [self clearAuthorizationHeader];
    [self setDefaultHeader:@"Authorization" value:oauthHeader];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
        
    [self getPath:path parameters:parameters
    success:^(AFHTTPRequestOperation *operation, id responseObject) {
       if (success && responseObject) {
           //NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:self.stringEncoding];
           NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:responseObject options:NSJSONWritingPrettyPrinted error:nil];
           success(operation.request, operation.response, dictionary);
       } else {
           NSLog(@"WTF");
       }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
       if (failure) {
           NSString *responseString = [[NSString alloc] initWithData:operation.responseData encoding:self.stringEncoding];
           failure(operation.request, operation.response, error, responseString);
       }
    }];
}

- (void)enqueuePostRequestOperaionWithURL:(NSString *)path parameters:(NSDictionary *)parameters {
    NSMutableDictionary *authHeaderParameters = [NSMutableDictionary dictionaryWithDictionary:[self authorizationHeader]];
    [authHeaderParameters setObject:_token forKey:@"oauth_token"];
    
    path = [NSString stringWithFormat:@"%@?database=%@", path, [parameters objectForKey:@"database"]];
    
    NSString *signature = [self getHMACSHA1SignitureWithURL:path
                                             authParameters:authHeaderParameters
                                                 parameters:nil // nil parameters for a post
                                             consumerSecret:_consumerSecret
                                                tokenSecret:_tokenSecret
                                             stringEncoding:self.stringEncoding
                                                 httpMethod:@"POST"];
    
    [authHeaderParameters setValue:signature forKey:@"oauth_signature"];
    
    NSString *oauthHeader = [self buildAuthoizationHeader:authHeaderParameters];
    
    [self clearAuthorizationHeader];
    [self setDefaultHeader:@"Authorization" value:oauthHeader];
    [self setDefaultHeader:@"Accept" value:@"application/json"];
    
    self.parameterEncoding = AFJSONParameterEncoding;
    
    NSURLRequest *request = [self requestWithMethod:@"POST" path:path parameters:parameters];
    
    [_requestQueue addObject:request];
}

- (void)postQueueWithCompletion:(void (^)(NSArray *operations))completion {
    [self enqueueBatchOfHTTPRequestOperationsWithRequests:_requestQueue
                                            progressBlock:^(NSUInteger numberOfCompletedOperations, NSUInteger totalNumberOfOperations) {
                                                NSLog(@"Progress: %d, %d", numberOfCompletedOperations, totalNumberOfOperations);
                                            } completionBlock:^(NSArray *operations) {
                                                if (completion)
                                                    completion(operations);
                                            }];
}

#pragma mark - 

- (NSString *)buildAuthoizationHeader:(NSDictionary *)parameters {
    NSMutableString *header = [NSMutableString stringWithString:@"OAuth "];
    for (NSString *key in [parameters allKeys]) {
        [header appendFormat:@"%@=\"%@\",", key, [parameters valueForKey:key]];
    }
    // clip last comma
    NSString *authHeader = [header substringToIndex:(header.length - 1)];
    return authHeader;
}

- (NSDictionary *)getOAuthRequestParametersWithKey:(NSString *)key
                                            secret:(NSString *)secret
                                    bodyParameters:(NSDictionary *)bodyParameters
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    [parameters setValue:@"HMAC-SHA1" forKey:@"oauth_signature_method"];
    [parameters setValue:@"somenonce" forKey:@"oauth_nonce"];
    [parameters setValue:key forKey:@"oauth_consumer_key"];
    [parameters setValue:[NSNumber numberWithInt:floorf([NSDate.date timeIntervalSince1970])] 
                  forKey:@"oauth_timestamp"];
    [parameters setValue:@"1.0" forKey:@"oauth_version"];
    
    return parameters;
}

- (NSString *)getHMACSHA1SignitureWithURL:(NSString *)url
                           authParameters:(NSDictionary *)authParameters
                               parameters:(NSDictionary *)parameters
                           consumerSecret:(NSString *)consumerSecret 
                              tokenSecret:(NSString *)tokenSecret 
                           stringEncoding:(NSStringEncoding)stringEncoding
                               httpMethod:(NSString *)httpMethod
{
    NSString *hashKey = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
    
    NSString *requestURL = AFURLEncodedStringFromStringWithEncoding([NSString stringWithFormat:@"%@%@", self.baseURL.absoluteString, url], stringEncoding);
    FROrderedDictionary *signatureParameters = [[FROrderedDictionary alloc] initWithDictionary:authParameters];
    
    if (httpMethod == @"GET") {
        NSString *requestParameters = [NSString stringWithFormat:@"?%@", AFQueryStringFromParametersWithEncoding(parameters, stringEncoding)];
        requestURL = [requestURL stringByAppendingFormat:@"%@", AFURLEncodedStringFromStringWithEncoding(requestParameters, stringEncoding)];
    } else {
        [signatureParameters addEntriesFromDictionary:parameters];   
    }
    
    NSString *signatureBase = 
        [NSString stringWithFormat:@"%@&%@&%@", @"POST", requestURL, AFURLEncodedStringFromStringWithEncoding([signatureParameters sortedString], stringEncoding)];
    
    NSString *signature = [FRHashSHA SHA1HashString:signatureBase withKey:hashKey];
    
    NSLog(@"Signature base: %@ \nHashed value: %@", signatureBase, signature);
    
    return signature;
}

NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

- (NSString *)randomString:(int)length 
{    
    NSMutableString *randomString = [NSMutableString stringWithCapacity:length];    
    for (int i = 0; i < length; i++) {
        [randomString appendFormat:@"%C", [letters characterAtIndex:arc4random() % letters.length]];
    }
    
    return randomString;
}

- (NSDictionary *)authorizationHeader
{
    NSMutableDictionary *authHeaderParameters = [NSMutableDictionary dictionary];
    [authHeaderParameters setValue:_consumerKey forKey:@"oauth_consumer_key"];
    [authHeaderParameters setValue:[self randomString:12] forKey:@"oauth_nonce"];
    [authHeaderParameters setValue:@"HMAC-SHA1" forKey:@"oauth_signature_method"];
    [authHeaderParameters setValue:[NSNumber numberWithInt:floorf([NSDate.date timeIntervalSince1970])] 
                            forKey:@"oauth_timestamp"];
    [authHeaderParameters setValue:@"1.0" forKey:@"oauth_version"];
    
    if (_token) {
        [authHeaderParameters setValue:_token forKey:@"oauth_token"];
    }
    
    return authHeaderParameters;
}

@end

#pragma mark -

@interface AFXAuthAccountCredential()
@property (nonatomic, strong) NSString *token;
@property (nonatomic, strong) NSString *tokenSecret;
@end

@implementation AFXAuthAccountCredential
@synthesize token = _token;
@synthesize tokenSecret = _tokenSecret;

+ (id)credentialWithOAuthToken:(NSString *)token tokenSecret:(NSString *)secret {
    return [[self alloc] initWithOAuthToken:token tokenSecret:secret];
}

- (id)initWithOAuthToken:(NSString *)token tokenSecret:(NSString *)secret {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    _token = token;
    _tokenSecret = secret;
    
    return self;
}


- (NSString *)description {
    return [NSString stringWithFormat:@"<%@ token:\"%@\" tokenSecret:\"%@\">", [self class], self.token, self.tokenSecret];
}


#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
    self = [super init];
    _token = [decoder decodeObjectForKey:@"token"];
    _tokenSecret = [decoder decodeObjectForKey:@"tokenSecret"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
    [encoder encodeObject:_token forKey:@"token"];
    [encoder encodeObject:_tokenSecret forKey:@"tokenSecret"];
}

@end
