//
//  SSLConnection.m
//  ios-openssl
//
//  Created by Дмитрий on 10.05.13.
//  Copyright (c) 2013 Dmitriy. All rights reserved.
//

#import "SSLConnection.h"

@implementation SSLConnection


static SSLConnection* _instance;
+ (SSLConnection*) Instance
{
    @synchronized(self) {
        if(_instance == nil) {
            _instance = [[[self class]alloc] init];
        }
    }
    return _instance;
}


- (void) initWithUrl:(NSString*)_url withDelegate:(id)_delegate withFormat:(NSString*) _format
{
    delegate = _delegate;
    url = [NSURL URLWithString:_url];
    format = _format;
}

- (void) sendPostAsync:(NSString *) requestData
{
    @try {
        NSLog(@"start post");
        unsigned int len = [requestData length] ;
        NSString *postLength = [NSString stringWithFormat:@"%ui", len];
        NSData *postData = [requestData dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
        NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10.0];
        [request setHTTPMethod:@"POST"];
        [request setValue:postLength forHTTPHeaderField:@"Content-Length"];
        [request setValue:format forHTTPHeaderField:@"Content-Type"];
        [request setHTTPBody: postData];
        
        NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest:request delegate:self];
        [connection start];
    
    } @catch(NSException *e) {
        
    } @finally {
        
    }
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"error");
}


- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)connection
{
    NSLog(@"connectionShouldUseCredentialStorage");
    return YES;
    
}


- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    NSLog(@"canAuthenticateAgainstProtectionSpace");
    NSString * challenge = [protectionSpace authenticationMethod];
    NSLog(@"canAuthenticateAgainstProtectionSpace challenge %@ isServerTrust=%d", challenge, [challenge isEqualToString:NSURLAuthenticationMethodServerTrust]);
    if ([challenge isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        return YES;
    }
    
    return NO;
}


- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    @try {
        NSLog(@"Authentication challenge");
        if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            NSURLCredential* credentials = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                //if ([trustedHosts containsObject:challenge.protectionSpace.host]){}
            [challenge.sender useCredential:credentials forAuthenticationChallenge:challenge];
            [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
        }
    } @catch(NSException *e) {
        
    } @finally {
        
    }
    
}


- (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
        NSLog(@"didCancelAuthenticationChallenge");
}


- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
        NSLog(@"didReceiveResponse");
}


- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    if(delegate && [delegate respondsToSelector:@selector(SSLConnection:didReceiveString:)]) {
        NSString* response = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        [delegate SSLConnection:self didReceiveString:response];
    }
    
}


- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
        NSLog(@"connectionDidFinishLoading");
}


@end
