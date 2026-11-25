#import <Foundation/Foundation.h>
#include <assert.h>
int tf_flag(const char *name){(void)name;return 0;}
#include "../src/mac/cloudtabs/AQSafariTabs.m"
int main(int argc,char **argv){@autoreleasepool {
    assert(argc==3);NSData *source=[NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
    NSDictionary *plan=[NSDictionary dictionaryWithContentsOfFile:[NSString stringWithUTF8String:argv[2]]];NSArray *items=[plan objectForKey:@"Items"];
    NSDictionary *desired=AQBookIndex(items);id current=[NSPropertyListSerialization propertyListWithData:source options:0 format:NULL error:NULL];
    NSMutableDictionary *existing=[NSMutableDictionary dictionary];BOOL collected=AQBookCollectDictionaries(current,existing,[NSMutableSet set],0);NSString *rootID=nil;
    for(NSString *identifier in desired)if([[[desired objectForKey:identifier] objectForKey:@"Role"] isEqual:@"Root"]){rootID=identifier;break;}
    NSDictionary *candidate=rootID?AQBookBuildDictionary(rootID,desired,existing,0):nil;
    NSMutableArray *candidateItems=[NSMutableArray array];NSMutableDictionary *candidateRoles=[NSMutableDictionary dictionary];
    for(NSString *identifier in desired)if([[desired objectForKey:identifier] objectForKey:@"Role"])[candidateRoles setObject:[[desired objectForKey:identifier] objectForKey:@"Role"] forKey:identifier];
    BOOL candidateFlattened=candidate&&AQBookFlatten(candidate,@"",0,candidateRoles,candidateItems,[NSMutableSet set],0);BOOL indexed=candidateFlattened&&AQBookIndex(candidateItems)!=nil;
    printf("preflight desired=%d collected=%d existing=%lu root=%d root-match=%d candidate=%d flattened=%d indexed=%d candidate-items=%lu\n",desired!=nil,collected,(unsigned long)existing.count,rootID!=nil,rootID&&[[current objectForKey:@"WebBookmarkUUID"] isEqual:rootID],candidate!=nil,candidateFlattened,indexed,(unsigned long)candidateItems.count);
    NSData *output=AQBookBuildFile(source,items);assert(output && ![output isEqual:source]);
    NSDictionary *root=[NSPropertyListSerialization propertyListWithData:output options:0 format:NULL error:NULL];NSMutableDictionary *index=[NSMutableDictionary dictionary];
    assert(AQBookCollectDictionaries(root,index,[NSMutableSet set],0));assert(index.count==items.count);
    NSMutableArray *flattened=[NSMutableArray array];NSMutableDictionary *roles=[NSMutableDictionary dictionary];
    NSArray *aliased=AQBookItemsByAliasingRoot(items,[root objectForKey:@"WebBookmarkUUID"]);
    for(NSDictionary *item in aliased)if([item objectForKey:@"Role"])[roles setObject:[item objectForKey:@"Role"] forKey:[item objectForKey:@"ID"]];
    assert(AQBookFlatten(root,@"",0,roles,flattened,[NSMutableSet set],0));NSDictionary *actual=AQBookIndex(flattened),*expected=AQBookIndex(aliased);assert(actual && expected);
    assert(!AQBookPlanMismatch(actual,expected,@{}));
    printf("PASS: real non-deleting bookmark plan builds and round-trips %lu managed items without touching Safari\n",(unsigned long)items.count);
}return 0;}
