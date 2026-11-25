/* Private inherited socketpair: prompts and answers never enter argv or files. */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#define AQ_PROMPT_FD 198
#define AQ_PROMPT_LIMIT 65536
static BOOL AQPromptTransfer(int fd,void *bytes,size_t length,BOOL writing) {
    char *p=bytes;
    while(length) {
        ssize_t n=writing?write(fd,p,length):read(fd,p,length);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return NO;p+=n;length-=(size_t)n;
    }
    return YES;
}
static NSDictionary *AQPromptRead(int fd) {
    uint32_t size;
    if(!AQPromptTransfer(fd,&size,sizeof size,NO)) return nil;
    size=ntohl(size);if(!size || size>AQ_PROMPT_LIMIT) return nil;
    NSMutableData *data=[NSMutableData dataWithLength:size];
    if(!AQPromptTransfer(fd,data.mutableBytes,size,NO)) return nil;
    id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    memset(data.mutableBytes,0,data.length);
    return [value isKindOfClass:[NSDictionary class]]?value:nil;
}
static BOOL AQPromptWrite(int fd,NSDictionary *value) {
    NSMutableData *data=[[[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL] mutableCopy] autorelease];
    if(!data.length || data.length>AQ_PROMPT_LIMIT) return NO;
    uint32_t size=htonl((uint32_t)data.length);
    BOOL ok=AQPromptTransfer(fd,&size,sizeof size,YES) && AQPromptTransfer(fd,data.mutableBytes,data.length,YES);
    memset(data.mutableBytes,0,data.length);return ok;
}
