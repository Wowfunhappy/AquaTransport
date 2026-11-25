/* Reuse AquaTransport's bounded native HTTP transport, including CFNetwork's
 * address-family fallback. The pipe never places credentials in argv or files. */
static NSData *AQTransportInput(void) {
 NSMutableData *input=[NSMutableData data];unsigned char buffer[8192];
 for(;;) {ssize_t n=read(STDIN_FILENO,buffer,sizeof buffer);if(n<0 && errno==EINTR) continue;
  if(n<0 || input.length+(NSUInteger)MAX(n,0)>5*1024*1024) return nil;
  if(!n) return input;[input appendBytes:buffer length:(NSUInteger)n];}
}
static BOOL AQTransportURL(NSURL *url) {
 if(![[[url scheme] lowercaseString] isEqual:@"https"] || [url user] || [url password] || [url fragment] || ([url port] && [[url port] intValue]!=443)) return NO;
 NSString *host=[[url host] lowercaseString],*path=[url path];
 if([host isEqual:@"gateway.icloud.com"]) return [path hasPrefix:@"/setup/setup/ck/"] || [path hasPrefix:@"/ckdatabase/api/client/"] || [path hasPrefix:@"/ckcoderouter/api/client/"];
 if([host isEqual:@"setup.icloud.com"]) return [path isEqual:@"/setup/get_account_settings"];
 NSRegularExpression *escrow=[NSRegularExpression regularExpressionWithPattern:@"^(p[0-9]+-)?escrowproxy\\.icloud\\.com$" options:0 error:NULL];
 return [escrow numberOfMatchesInString:host?:@"" options:0 range:NSMakeRange(0,host.length)]==1 &&
  [@[@"/escrowproxy/api/get_records",@"/escrowproxy/api/srp_init",@"/escrowproxy/api/recover"] containsObject:path];
}
static int AQTransport(void) {
 NSDictionary *input=aq_plist(AQTransportInput());NSURL *url=[NSURL URLWithString:aq_string([input objectForKey:@"url"])?:@""];
 NSDictionary *headers=aq_dict([input objectForKey:@"headers"]);NSData *body=aq_data([input objectForKey:@"body"]);
 if(!AQTransportURL(url) || !headers || headers.count>128 || !body || body.length>4*1024*1024) return 2;
 NSMutableURLRequest *request=[NSMutableURLRequest requestWithURL:url];[request setHTTPMethod:@"POST"];if(body.length)[request setHTTPBody:body];
 for(id key in headers) {
  NSString *name=aq_device_field(key),*value=aq_device_field([headers objectForKey:key]);
  if(!name || !value || [name rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"] invertedSet]].location!=NSNotFound) return 2;
  [request setValue:value forHTTPHeaderField:name];
 }
 NSHTTPURLResponse *response=nil;NSError *error=nil;
 NSData *data=aq_send(nil,request,&response,&error);
 NSDictionary *result=data?@{@"status":@([response statusCode]),@"body":data}:@{@"error":@([error code])};
 NSData *encoded=[NSPropertyListSerialization dataWithPropertyList:result format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
 if(!encoded) return 3;
 const char *bytes=encoded.bytes;size_t left=encoded.length;
 while(left) {ssize_t n=write(STDOUT_FILENO,bytes,left);if(n<0 && errno==EINTR) continue;if(n<=0)return 3;bytes+=n;left-=n;}
 return 0;
}
