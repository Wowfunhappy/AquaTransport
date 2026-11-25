#define main AQCloudTabsAuthMain
#include "../src/mac/cloudtabs/authorize.m"
#undef main
#include <assert.h>
@interface AQTransportFixture : NSURLProtocol @end
@implementation AQTransportFixture
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {(void)request;return YES;}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {return request;}
- (void)stopLoading {}
- (void)startLoading {
    assert([self.request.HTTPMethod isEqual:@"POST"]);
    NSHTTPURLResponse *response=[[[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:self.request.HTTPBody?:[NSData data]];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end
int main(int argc,char **argv) { @autoreleasepool {
    NSURL *url=[NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2"];
    NSHTTPURLResponse *ok=[[[NSHTTPURLResponse alloc] initWithURL:url statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    NSHTTPURLResponse *unavailable=[[[NSHTTPURLResponse alloc] initWithURL:url statusCode:503 HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    for(NSNumber *code in @[@(-20101),@(-22406),@(-49999)]) {AQObserveLoginFailure(ok,@{@"ec":code});assert(AQIncorrectCredentials);}
    AQObserveLoginFailure(ok,@{@"ec":@(-22421),@"hsc":@434});assert(!AQIncorrectCredentials);
    AQObserveLoginFailure(ok,@{@"ec":@(-22421),@"hsc":@401});assert(AQIncorrectCredentials);
    AQObserveLoginFailure(unavailable,@{});assert(!AQIncorrectCredentials);
    [NSURLProtocol registerClass:[AQTransportFixture class]];
    return AQCloudTabsAuthMain(argc,argv);
} }
