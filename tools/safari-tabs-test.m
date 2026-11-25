#import <Foundation/Foundation.h>
#include <assert.h>
@interface CloudTabDevice : NSObject {
    NSDictionary *_dictionary;NSString *_uuid;
}
@property(readonly) NSDictionary *dictionary;
@property(readonly) NSString *uuid;
- (id)initWithDictionary:(id)dictionary uuid:(id)uuid;
@end
@implementation CloudTabDevice
@synthesize dictionary=_dictionary,uuid=_uuid;
- (id)initWithDictionary:(id)dictionary uuid:(id)uuid {if((self=[super init])) {_dictionary=[dictionary copy];_uuid=[uuid copy];}return self;}
- (void)dealloc {[_dictionary release];[_uuid release];[super dealloc];}
@end
#include "../src/mac/cloudtabs/AQSafariTabs.m"
int main(void) { @autoreleasepool {
    NSDictionary *tab=@{@"Title":@"Fixture",@"URL":@"https://example.invalid/"};
    NSMutableDictionary *device=[NSMutableDictionary dictionaryWithDictionary:@{@"DeviceName":@"Fixture phone",@"LastModified":[NSDate date],@"Tabs":@[tab]}];
    NSMutableDictionary *cache=[NSMutableDictionary dictionaryWithDictionary:@{@"Version":@1,@"Account":@"fixture-account",@"Devices":@{@"fixture-device":device}}];
    NSArray *devices=AQDecodeDevices(cache,@"fixture-account");assert(devices.count==1);
    assert([[[[devices objectAtIndex:0] dictionary] objectForKey:@"Tabs"] count]==1);
    assert(!AQDecodeDevices(cache,@"different-account"));assert(!AQDecodeDevices(cache,nil));assert(!AQDecodeDevices(@[],@"fixture-account"));
    [device setObject:@[@{@"Title":@"Bad scheme",@"URL":@"javascript:alert(1)"}] forKey:@"Tabs"];
    assert(!AQDecodeDevices(cache,@"fixture-account"));
    [device setObject:@[@{@"Title":@1,@"URL":@"https://example.invalid/"}] forKey:@"Tabs"];
    assert(!AQDecodeDevices(cache,@"fixture-account"));
    [device setObject:@[tab] forKey:@"Tabs"];
    [device setObject:@"not a date" forKey:@"LastModified"];assert(!AQDecodeDevices(cache,@"fixture-account"));
    [device setObject:[NSDate date] forKey:@"LastModified"];
    NSMutableArray *tooMany=[NSMutableArray array];for(unsigned i=0;i<10001;i++)[tooMany addObject:tab];
    [device setObject:tooMany forKey:@"Tabs"];assert(!AQDecodeDevices(cache,@"fixture-account"));
    [device setObject:@[] forKey:@"Tabs"];assert(AQDecodeDevices(cache,@"fixture-account").count==0);
    puts("PASS: Safari native device conversion, account isolation, URL/type validation and bounds");
} return 0; }
