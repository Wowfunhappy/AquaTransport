#import <Foundation/Foundation.h>
@interface CloudTabStore : NSObject
- (NSArray *)syncedCloudTabDevices;
- (BOOL)cloudTabsSupported;
@end
@interface CloudTabKeyValueStore : NSObject
- (void)setDictionary:(id)value forKey:(id)key;
- (void)removeObjectForKey:(id)key;
@end
@implementation CloudTabKeyValueStore
- (void)setDictionary:(id)value forKey:(id)key {(void)value;(void)key;}
- (void)removeObjectForKey:(id)key {(void)key;}
@end
@implementation CloudTabStore
- (NSArray *)syncedCloudTabDevices {return @[@"native fixture"];} 
- (BOOL)cloudTabsSupported {return NO;}
@end
