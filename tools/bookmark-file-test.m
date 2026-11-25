#import <Foundation/Foundation.h>
#include <assert.h>
int tf_flag(const char *name){(void)name;return 0;}
#include "../src/mac/cloudtabs/AQSafariTabs.m"
static NSDictionary *native(NSString *identifier,NSString *type,NSString *title,NSArray *children) {
    NSMutableDictionary *value=[NSMutableDictionary dictionaryWithDictionary:@{@"WebBookmarkUUID":identifier,@"WebBookmarkType":type}];
    if([type isEqual:@"WebBookmarkTypeList"]){[value setObject:title forKey:@"Title"];[value setObject:children?:@[] forKey:@"Children"];}else{[value setObject:@{@"title":title} forKey:@"URIDictionary"];[value setObject:[@"https://example.invalid/" stringByAppendingString:identifier] forKey:@"URLString"];}
    return value;
}
static NSDictionary *item(NSString *identifier,NSString *parent,NSString *kind,NSString *title,NSUInteger index,NSString *role) {
    NSMutableDictionary *value=[NSMutableDictionary dictionaryWithDictionary:@{@"ID":identifier,@"Parent":parent,@"Kind":kind,@"Title":title,@"Index":@(index)}];
    if(role)[value setObject:role forKey:@"Role"];
    if([kind isEqual:@"leaf"])[value setObject:[@"https://example.invalid/" stringByAppendingString:identifier] forKey:@"URL"];
    return value;
}
int main(void){@autoreleasepool {
    NSDictionary *localReading=native(@"local-reading",@"WebBookmarkTypeLeaf",@"Local",nil);
    NSMutableDictionary *localReadingMutable=[[localReading mutableCopy] autorelease];
    [localReadingMutable setObject:@{@"DateAdded":[NSDate dateWithTimeIntervalSinceReferenceDate:10],@"DateLastViewed":[NSDate dateWithTimeIntervalSinceReferenceDate:20],@"PreviewText":@"Old"} forKey:@"ReadingList"];
    NSDictionary *bar=native(@"bar",@"WebBookmarkTypeList",@"BookmarksBar",@[]),*menu=native(@"menu",@"WebBookmarkTypeList",@"BookmarksMenu",@[]),*reading=native(@"reading",@"WebBookmarkTypeList",@"com.apple.ReadingList",@[localReadingMutable]);
    NSDictionary *proxy=@{@"WebBookmarkType":@"WebBookmarkTypeProxy",@"WebBookmarkUUID":@"history",@"Title":@"History"};
    NSDictionary *root=native(@"root",@"WebBookmarkTypeList",@"",@[bar,proxy,menu,reading]);
    NSData *source=[NSPropertyListSerialization dataWithPropertyList:root format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    NSArray *plan=@[item(@"root",@"",@"folder",@"Root",0,@"Root"),item(@"bar",@"root",@"folder",@"BookmarksBar",0,@"BookmarksBar"),item(@"menu",@"root",@"folder",@"BookmarksMenu",1,@"BookmarksMenu"),item(@"reading",@"root",@"folder",@"ReadingList",2,@"ReadingList"),item(@"folder",@"root",@"folder",@"Cloud Folder",3,nil),item(@"cloud",@"folder",@"leaf",@"Cloud",0,nil),@{@"ID":@"local-reading",@"Parent":@"reading",@"Kind":@"leaf",@"Title":@"Local updated",@"URL":@"https://example.invalid/local-reading",@"Index":@0,@"DateAdded":@10.0,@"PreviewText":@"Updated"}];
    NSData *output=AQBookBuildFile(source,plan);assert(output && ![output isEqual:source]);
    NSDictionary *built=[NSPropertyListSerialization propertyListWithData:output options:0 format:NULL error:NULL];assert([[[built objectForKey:@"Children"] objectAtIndex:1] isEqual:proxy]);
    NSMutableDictionary *index=[NSMutableDictionary dictionary];assert(AQBookCollectDictionaries(built,index,[NSMutableSet set],0));
    assert(index.count==plan.count && [index objectForKey:@"cloud"] && [index objectForKey:@"folder"]);
    NSDictionary *updated=[index objectForKey:@"local-reading"],*attributes=[updated objectForKey:@"ReadingList"];
    assert([[[updated objectForKey:@"URIDictionary"] objectForKey:@"title"] isEqual:@"Local updated"]);
    assert([attributes objectForKey:@"DateAdded"] && ![attributes objectForKey:@"DateLastViewed"] && [[attributes objectForKey:@"PreviewText"] isEqual:@"Updated"]);
    assert([[NSPropertyListSerialization propertyListWithData:source options:0 format:NULL error:NULL] isEqual:root]);
    NSMutableArray *bad=[plan mutableCopy];NSMutableDictionary *badRoot=[[[bad objectAtIndex:0] mutableCopy] autorelease];[badRoot setObject:@"bar" forKey:@"ID"];[bad replaceObjectAtIndex:0 withObject:badRoot];assert(!AQBookBuildFile(source,bad));[bad release];
    puts("PASS: complete bookmark-file merge, proxy preservation, Reading List fields, source immutability and root validation");
}return 0;}
