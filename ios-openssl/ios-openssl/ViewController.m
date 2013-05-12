//
//  ViewController.m
//  ios-openssl
//
//  Created by Дмитрий on 10.05.13.
//  Copyright (c) 2013 Dmitriy. All rights reserved.
//

#import "ViewController.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	[[SSLConnection Instance] initWithUrl:@"https://paypal.com" withDelegate:self withFormat:@"application/json"];
    [[SSLConnection Instance] sendPostAsync:@""];
}

- (void) SSLConnection:(SSLConnection *)_sslConnection didReceiveString:(NSString *)string
{
    NSLog(@"response: %@", string);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
