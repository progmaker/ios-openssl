//
//  SSLConnection.h
//  ios-openssl
//
//  Created by Дмитрий on 10.05.13.
//  Copyright (c) 2013 Dmitriy. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class SSLConnection;
@protocol SSLConnectionDelegate <NSObject>
    - (void)SSLConnection:(SSLConnection*)_sslConnection didReceiveString:(NSString*)string;
@end

@interface SSLConnection : NSObject<NSURLConnectionDataDelegate>{
    NSURL* url;
    NSString* format;
    id<SSLConnectionDelegate> delegate;
}

@property SSLConnection* Instance;
@property NSArray* currentCookies;

+ (SSLConnection*) Instance;
- (void) initWithUrl:(NSString*)_url withDelegate:(id)_delegate withFormat:(NSString*) _format;
- (void) sendPostAsync:(NSString *) requestData;




@end
