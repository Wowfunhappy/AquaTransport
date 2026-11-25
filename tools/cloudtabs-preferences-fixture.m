#import <Foundation/Foundation.h>
@interface MMService : NSObject
- (BOOL)isEnabled;
- (void)_setEnabled:(BOOL)enabled;
@end
@implementation MMService
- (BOOL)isEnabled {return YES;}
- (void)_setEnabled:(BOOL)enabled {(void)enabled;}
@end
@interface MMBookmarksService : MMService
- (void)setEnabled:(BOOL)enabled creating:(BOOL)creating withWindow:(id)window;
@end
@implementation MMBookmarksService
- (void)setEnabled:(BOOL)enabled creating:(BOOL)creating withWindow:(id)window {(void)creating;(void)window;[self _setEnabled:enabled];}
@end
