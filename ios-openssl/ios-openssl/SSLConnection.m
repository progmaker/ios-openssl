//
//  SSLConnection.m
//  ios-openssl
//
//  Created by Дмитрий on 10.05.13.
//  Copyright (c) 2013 Dmitriy. All rights reserved.
//

#import "SSLConnection.h"
#import <openssl/x509.h>
#import <openssl/bio.h>
#import <openssl/err.h>

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
        
        if ([challenge previousFailureCount] > 0) {
            //this will cause an authentication failure
            [[challenge sender] cancelAuthenticationChallenge:challenge];
            NSLog(@"Bad Username Or Password");
            return;
        }
        
        if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            NSURLCredential* credentials = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            SecTrustResultType result;
            SecTrustEvaluate(challenge.protectionSpace.serverTrust, &result);
            
            if(result == kSecTrustResultProceed || result == kSecTrustResultConfirm ||  result == kSecTrustResultUnspecified) {
                
                //print server certificate in console
                printCertificate(extractCertificate(challenge));

                //if ([trustedHosts containsObject:challenge.protectionSpace.host]){}
                [challenge.sender useCredential:credentials forAuthenticationChallenge:challenge];
                [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
                
            }
        }
        else if ([[challenge protectionSpace] authenticationMethod] == NSURLAuthenticationMethodClientCertificate) {
             NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"CertificateName" ofType:@"p12"];
            NSData *p12Data = [[NSData alloc] initWithContentsOfFile:p12Path];
            
            CFStringRef password = CFSTR("PASSWORD");
            const void *keys[] = { kSecImportExportPassphrase };
            const void *values[] = { password };
            CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
            CFArrayRef p12Items;
            
            OSStatus result = SecPKCS12Import((__bridge CFDataRef)p12Data, optionsDictionary, &p12Items);
            
            if(result == noErr) {
                CFDictionaryRef identityDict = CFArrayGetValueAtIndex(p12Items, 0);
                SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
                
                SecCertificateRef certRef;
                SecIdentityCopyCertificate(identityApp, &certRef);
                
                SecCertificateRef certArray[1] = { certRef };
                CFArrayRef myCerts = CFArrayCreate(NULL, (void *)certArray, 1, NULL);
                CFRelease(certRef);
                
                NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identityApp certificates:(__bridge NSArray *)myCerts persistence:NSURLCredentialPersistencePermanent];
                CFRelease(myCerts);
                
                [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
            }
        } else if ([[challenge protectionSpace] authenticationMethod] == NSURLAuthenticationMethodDefault || [[challenge protectionSpace] authenticationMethod] == NSURLAuthenticationMethodNTLM) {
            // For normal authentication based on username and password. This could be NTLM or Default.
            
            NSURLCredential *credential = [NSURLCredential credentialWithUser:@"username" password:@"password" persistence:NSURLCredentialPersistenceForSession];
            [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
        } else {
            //If everything fails, we cancel the challenge.
            [[challenge sender] cancelAuthenticationChallenge:challenge];
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


SecCertificateRef extractCertificate(NSURLAuthenticationChallenge* challenge)
{
    SecTrustResultType trustResult;
    SecTrustRef currentServerTrust = challenge.protectionSpace.serverTrust;
    SecTrustEvaluate(currentServerTrust, &trustResult);
    CFIndex certificateCount = SecTrustGetCertificateCount(currentServerTrust);
    SecCertificateRef certRef = SecTrustGetCertificateAtIndex(currentServerTrust, (certificateCount - 1));
    return certRef;
}

void printCertificate(SecCertificateRef certRef)
{
    CFDataRef data = SecCertificateCopyData(certRef);
    X509 *x509cert = NULL;
    if (data) {
        BIO *mem = BIO_new_mem_buf((void *)CFDataGetBytePtr(data), CFDataGetLength(data));
        
        x509cert = d2i_X509_bio(mem, NULL);
        
        X509_print_fp(stdout,x509cert);
        BIO_free(mem);
        CFRelease(data);
        
        if (!x509cert) {
            NSLog(@"couldn't parse X509 Certificate");
            
        }
    } else {
        NSLog(@"Failed  data from CertificateRef");
    }
}


OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = CFSTR("PASSWORD");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}


@end
