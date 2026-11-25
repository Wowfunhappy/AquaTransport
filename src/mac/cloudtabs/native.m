/* Python's system interpreter needs no third-party modules. This narrow ABI
 * uses the project's pinned OpenSSL and Foundation's native plist codec. */
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>

extern CFTypeID _CFKeyedArchiverUIDGetTypeID(void);
extern CFTypeRef _CFKeyedArchiverUIDCreate(CFAllocatorRef,uint32_t);
extern uint32_t _CFKeyedArchiverUIDGetValue(CFTypeRef);
#define AQ_LIMIT (4*1024*1024)
static NSString *string(id v) {return [v isKindOfClass:[NSString class]]?v:nil;}
static NSData *decode(id value) {
 NSString *s=string(value);NSData *ascii=[s dataUsingEncoding:NSASCIIStringEncoding];NSUInteger n=ascii.length;
 if(!s || !ascii || n%4 || n>8*1024*1024) return nil;
 if(!n)return [NSData data];
 const unsigned char *p=ascii.bytes;unsigned padding=0;
 if(p[n-1]=='=')padding++;if(n>1 && p[n-2]=='=')padding++;
 for(NSUInteger i=0;i<n-padding;i++) if(!((p[i]>='A'&&p[i]<='Z')||(p[i]>='a'&&p[i]<='z')||(p[i]>='0'&&p[i]<='9')||p[i]=='+'||p[i]=='/'))return nil;
 NSMutableData *out=[NSMutableData dataWithLength:n];int size=EVP_DecodeBlock(out.mutableBytes,p,(int)n);
 if(size<0 || (NSUInteger)size<padding || size-(int)padding>AQ_LIMIT)return nil;
 [out setLength:size-padding];return out;
}
static NSString *encode(NSData *data) {
 if(!data || data.length>AQ_LIMIT)return nil;
 NSMutableData *encoded=[NSMutableData dataWithLength:4*((data.length+2)/3)+1];
 int size=EVP_EncodeBlock(encoded.mutableBytes,data.bytes,(int)data.length);
 return [[[NSString alloc] initWithBytes:encoded.bytes length:size encoding:NSASCIIStringEncoding] autorelease];
}
static id blob(NSData *data) {NSString *s=encode(data);return s?@{@"data":s}:nil;}
static const EVP_MD *digest(NSString *name) {
 if([name isEqual:@"sha256"])return EVP_sha256();if([name isEqual:@"sha384"])return EVP_sha384();if([name isEqual:@"sha512"])return EVP_sha512();return NULL;
}
static int curve(NSNumber *bits) {return bits.intValue==256?NID_X9_62_prime256v1:bits.intValue==384?NID_secp384r1:0;}
static EVP_PKEY *readKey(NSData *data,BOOL privateKey) {
 if(!data.length || data.length>16384)return NULL;
 const unsigned char *p=data.bytes;EVP_PKEY *key=privateKey?d2i_AutoPrivateKey(NULL,&p,(long)data.length):d2i_PUBKEY(NULL,&p,(long)data.length);
 if(!key || p!=(const unsigned char *)data.bytes+data.length || EVP_PKEY_base_id(key)!=EVP_PKEY_EC){EVP_PKEY_free(key);return NULL;}
 const EC_KEY *ec=EVP_PKEY_get0_EC_KEY(key);int nid=ec?EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)):0;
 if((nid!=NID_X9_62_prime256v1 && nid!=NID_secp384r1) || EC_KEY_check_key(ec)!=1){EVP_PKEY_free(key);return NULL;}
 return key;
}
static id keyInfo(EVP_PKEY *key,BOOL privateKey) {
 const EC_KEY *ec=EVP_PKEY_get0_EC_KEY(key);if(!ec)return nil;
 const EC_GROUP *group=EC_KEY_get0_group(ec);const EC_POINT *point=EC_KEY_get0_public_key(ec);
 int bits=EC_GROUP_get_degree(group);unsigned char buffer[97];
 size_t size=EC_POINT_point2oct(group,point,POINT_CONVERSION_UNCOMPRESSED,buffer,sizeof buffer,NULL);
 if(size!=(size_t)(1+2*((bits+7)/8)))return nil;
 unsigned char *der=NULL;int n=i2d_PUBKEY(key,&der);if(n<=0)return nil;
 NSString *publicData=encode([NSData dataWithBytes:der length:n]);OPENSSL_free(der);
 NSMutableDictionary *result=[NSMutableDictionary dictionaryWithDictionary:@{@"bits":@(bits),@"public":publicData,@"point":encode([NSData dataWithBytes:buffer length:size])}];
 if(privateKey) {
  PKCS8_PRIV_KEY_INFO *info=EVP_PKEY2PKCS8(key);if(!info)return nil;
  der=NULL;n=i2d_PKCS8_PRIV_KEY_INFO(info,&der);PKCS8_PRIV_KEY_INFO_free(info);if(n<=0)return nil;
  [result setObject:encode([NSData dataWithBytes:der length:n]) forKey:@"private"];OPENSSL_clear_free(der,n);
 }
 return result;
}
static NSData *cipher(NSDictionary *r,NSString *operation) {
 NSData *key=decode(r[@"key"]),*input=decode(r[@"input"]),*iv=decode(r[@"iv"]?:@"");
 if(!key || !input || !iv || input.length>AQ_LIMIT)return nil;
 const EVP_CIPHER *algorithm=NULL;BOOL gcm=[operation isEqual:@"gcm"],wrap=[operation isEqual:@"unwrap"];
 if(gcm) {if(key.length==16)algorithm=EVP_aes_128_gcm();if(key.length==32)algorithm=EVP_aes_256_gcm();}
 else if([operation isEqual:@"cbc"]) {if(key.length==16)algorithm=EVP_aes_128_cbc();if(key.length==32)algorithm=EVP_aes_256_cbc();}
 else if([operation isEqual:@"ctr"]) {if(key.length==16)algorithm=EVP_aes_128_ctr();if(key.length==24)algorithm=EVP_aes_192_ctr();if(key.length==32)algorithm=EVP_aes_256_ctr();}
 else if(wrap) {if(key.length==16)algorithm=EVP_aes_128_wrap();if(key.length==32)algorithm=EVP_aes_256_wrap();}
 if(!algorithm || (!gcm&&!wrap&&iv.length!=16))return nil;
 NSData *aad=gcm?decode(r[@"aad"]):nil,*tag=gcm?decode(r[@"tag"]):nil;
 if(gcm && (!aad || !tag || (tag.length!=12&&tag.length!=16) || iv.length<8 || iv.length>128))return nil;
 EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();NSMutableData *out=[NSMutableData dataWithLength:input.length+32];int a=0,b=0,ignored=0,ok=ctx!=NULL;
 if(wrap&&ctx)EVP_CIPHER_CTX_set_flags(ctx,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 if(ok)ok=EVP_DecryptInit_ex(ctx,algorithm,NULL,NULL,NULL)==1;
 if(ok&&gcm)ok=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,(int)iv.length,NULL)==1;
 if(ok)ok=EVP_DecryptInit_ex(ctx,NULL,NULL,key.bytes,iv.length?iv.bytes:NULL)==1;
 if(ok&&gcm&&aad.length)ok=EVP_DecryptUpdate(ctx,NULL,&ignored,aad.bytes,(int)aad.length)==1;
 if(ok)ok=EVP_DecryptUpdate(ctx,out.mutableBytes,&a,input.bytes,(int)input.length)==1;
 if(ok&&gcm)ok=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,(int)tag.length,(void *)tag.bytes)==1;
 if(ok)ok=EVP_DecryptFinal_ex(ctx,(unsigned char *)out.mutableBytes+a,&b)==1;
 EVP_CIPHER_CTX_free(ctx);
 NSData *result=ok?[NSData dataWithBytes:out.bytes length:a+b]:nil;OPENSSL_cleanse(out.mutableBytes,out.length);return result;
}
static NSData *encryptGCM(NSDictionary *r) {
 NSData *key=decode(r[@"key"]),*iv=decode(r[@"iv"]),*input=decode(r[@"input"]),*aad=decode(r[@"aad"]);
 NSUInteger tagLength=[r[@"tagLength"] unsignedIntegerValue];
 const EVP_CIPHER *algorithm=key.length==16?EVP_aes_128_gcm():key.length==32?EVP_aes_256_gcm():NULL;
 if(!algorithm || !iv || iv.length!=12 || !input || input.length>AQ_LIMIT || !aad || aad.length>AQ_LIMIT || (tagLength!=12 && tagLength!=16))return nil;
 EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();NSMutableData *out=[NSMutableData dataWithLength:tagLength+input.length+16];
 int a=0,b=0,ignored=0;BOOL ok=ctx && EVP_EncryptInit_ex(ctx,algorithm,NULL,key.bytes,iv.bytes)==1;
 if(ok && aad.length)ok=EVP_EncryptUpdate(ctx,NULL,&ignored,aad.bytes,(int)aad.length)==1;
 if(ok)ok=EVP_EncryptUpdate(ctx,(unsigned char *)out.mutableBytes+tagLength,&a,input.bytes,(int)input.length)==1;
 if(ok)ok=EVP_EncryptFinal_ex(ctx,(unsigned char *)out.mutableBytes+tagLength+a,&b)==1;
 if(ok)ok=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,(int)tagLength,out.mutableBytes)==1;
 EVP_CIPHER_CTX_free(ctx);
 NSData *result=ok?[NSData dataWithBytes:out.bytes length:tagLength+a+b]:nil;OPENSSL_cleanse(out.mutableBytes,out.length);return result;
}
static NSData *wrapKey(NSDictionary *r) {
 NSData *key=decode(r[@"key"]),*input=decode(r[@"input"]);
 const EVP_CIPHER *algorithm=key.length==16?EVP_aes_128_wrap():key.length==32?EVP_aes_256_wrap():NULL;
 if(!algorithm || !input || input.length<16 || input.length>AQ_LIMIT || input.length%8)return nil;
 EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();if(!ctx)return nil;
 EVP_CIPHER_CTX_set_flags(ctx,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 NSMutableData *out=[NSMutableData dataWithLength:input.length+16];int a=0,b=0;
 BOOL ok=EVP_EncryptInit_ex(ctx,algorithm,NULL,key.bytes,NULL)==1 && EVP_EncryptUpdate(ctx,out.mutableBytes,&a,input.bytes,(int)input.length)==1 && EVP_EncryptFinal_ex(ctx,(unsigned char *)out.mutableBytes+a,&b)==1;
 EVP_CIPHER_CTX_free(ctx);NSData *result=ok?[NSData dataWithBytes:out.bytes length:a+b]:nil;OPENSSL_cleanse(out.mutableBytes,out.length);return result;
}
static id plistTree(id value,unsigned depth,unsigned *count) {
 if(depth>64 || ++*count>100000)return nil;
 if([value isKindOfClass:[NSString class]])return @[@"str",value];
 if([value isKindOfClass:[NSData class]])return @[@"data",encode(value)];
 if([value isKindOfClass:[NSDate class]]) {double t=[value timeIntervalSince1970];return isfinite(t)?@[@"date",@(t)]:nil;}
 CFTypeID type=CFGetTypeID((CFTypeRef)value);
 if(type==_CFKeyedArchiverUIDGetTypeID())return @[@"uid",@(_CFKeyedArchiverUIDGetValue((CFTypeRef)value))];
 if([value isKindOfClass:[NSNumber class]]) {
  if(type==CFBooleanGetTypeID())return @[@"bool",value];
  const char *kind=[value objCType];if(!strcmp(kind,"d")||!strcmp(kind,"f"))return isfinite([value doubleValue])?@[@"real",value]:nil;
  return @[@"int",[value stringValue]];
 }
 if([value isKindOfClass:[NSArray class]]) {NSMutableArray *items=[NSMutableArray array];for(id item in value){id v=plistTree(item,depth+1,count);if(!v)return nil;[items addObject:v];}return @[@"array",items];}
 if([value isKindOfClass:[NSDictionary class]]) {NSMutableArray *items=[NSMutableArray array];for(id key in value){if(!string(key))return nil;id v=plistTree([value objectForKey:key],depth+1,count);if(!v)return nil;[items addObject:@[key,v]];}return @[@"dict",items];}
 return nil;
}
static id plistValue(id node,unsigned depth,unsigned *count) {
 if(depth>64 || ++*count>100000 || ![node isKindOfClass:[NSArray class]] || [node count]!=2)return nil;
 NSString *tag=string(node[0]);id v=node[1];
 if([tag isEqual:@"str"])return string(v);
 if([tag isEqual:@"data"])return decode(v);
 if([tag isEqual:@"int"]) {
  NSString *s=string(v);if(!s.length || s.length>21)return nil;const char *p=s.UTF8String;char *end=NULL;errno=0;
  if(*p=='-'){long long n=strtoll(p,&end,10);return !errno&&end&&!*end&&end!=p?@(n):nil;}
  unsigned long long n=strtoull(p,&end,10);return !errno&&end&&!*end&&end!=p?@(n):nil;
 }
 if([tag isEqual:@"bool"])return [v isKindOfClass:[NSNumber class]]?@([v boolValue]):nil;
 if([tag isEqual:@"real"] || [tag isEqual:@"date"]) {if(![v isKindOfClass:[NSNumber class]] || !isfinite([v doubleValue]))return nil;return [tag isEqual:@"date"]?[NSDate dateWithTimeIntervalSince1970:[v doubleValue]]:v;}
 if([tag isEqual:@"uid"]) {if(![v isKindOfClass:[NSNumber class]] || [v longLongValue]<0 || [v unsignedLongLongValue]>UINT32_MAX)return nil;CFTypeRef uid=_CFKeyedArchiverUIDCreate(NULL,[v unsignedIntValue]);return [(id)uid autorelease];}
 if(![v isKindOfClass:[NSArray class]])return nil;
 if([tag isEqual:@"array"]) {NSMutableArray *a=[NSMutableArray array];for(id item in v){id value=plistValue(item,depth+1,count);if(!value)return nil;[a addObject:value];}return a;}
 if([tag isEqual:@"dict"]) {NSMutableDictionary *d=[NSMutableDictionary dictionary];for(id item in v){if(![item isKindOfClass:[NSArray class]]||[item count]!=2||!string(item[0])||d[item[0]])return nil;id value=plistValue(item[1],depth+1,count);if(!value)return nil;d[item[0]]=value;}return d;}
 return nil;
}
static id operation(NSDictionary *r) {
 NSString *op=string(r[@"op"]);if(!op)return nil;
 if([@[@"cbc",@"gcm",@"ctr",@"unwrap"] containsObject:op])return blob(cipher(r,op));
 if([op isEqual:@"gcm-encrypt"])return blob(encryptGCM(r));
 if([op isEqual:@"wrap"])return blob(wrapKey(r));
 if([op isEqual:@"equal"]) {NSData *a=decode(r[@"a"]),*b=decode(r[@"b"]);if(!a||!b)return nil;return @{@"valid":@(a.length==b.length && !CRYPTO_memcmp(a.bytes,b.bytes,a.length))};}
 if([op isEqual:@"pbkdf2"]) {
  NSData *password=decode(r[@"password"]),*salt=decode(r[@"salt"]);const EVP_MD *md=digest(string(r[@"digest"]));
  int rounds=[r[@"rounds"] intValue],length=[r[@"length"] intValue];if(!password||!salt||!md||rounds<1||rounds>1000000||length<1||length>4096)return nil;
  NSMutableData *out=[NSMutableData dataWithLength:length];int ok=PKCS5_PBKDF2_HMAC(password.bytes,(int)password.length,salt.bytes,(int)salt.length,rounds,md,length,out.mutableBytes);
  id result=ok?blob(out):nil;OPENSSL_cleanse(out.mutableBytes,out.length);return result;
 }
 if([op isEqual:@"cmac"]) {
  NSData *key=decode(r[@"key"]),*data=decode(r[@"input"]);const char *name=key.length==16?"AES-128-CBC":key.length==24?"AES-192-CBC":key.length==32?"AES-256-CBC":NULL;
  if(!key||!data||!name)return nil;EVP_MAC *mac=EVP_MAC_fetch(NULL,"CMAC",NULL);EVP_MAC_CTX *ctx=mac?EVP_MAC_CTX_new(mac):NULL;
  OSSL_PARAM params[]={OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,(char *)name,0),OSSL_PARAM_construct_end()};
  unsigned char out[16];size_t length=0;int ok=ctx && EVP_MAC_init(ctx,key.bytes,key.length,params)==1 && EVP_MAC_update(ctx,data.bytes,data.length)==1 && EVP_MAC_final(ctx,out,&length,sizeof out)==1;
  EVP_MAC_CTX_free(ctx);EVP_MAC_free(mac);return ok&&length==16?blob([NSData dataWithBytes:out length:length]):nil;
 }
 if([op isEqual:@"ec-derive"] || [op isEqual:@"ec-point"]) {
  int nid=curve(r[@"bits"]);NSData *data=decode(r[@"input"]);if(!nid||!data)return nil;
  EC_KEY *ec=EC_KEY_new_by_curve_name(nid);const EC_GROUP *group=ec?EC_KEY_get0_group(ec):NULL;EC_POINT *point=group?EC_POINT_new(group):NULL;
  BN_CTX *ctx=BN_CTX_new();BIGNUM *n=NULL,*order=BN_new();BOOL priv=[op isEqual:@"ec-derive"];int ok=ec&&point&&ctx&&order;
  if(ok&&priv) {n=BN_bin2bn(data.bytes,(int)data.length,NULL);if(n)BN_set_flags(n,BN_FLG_CONSTTIME);ok=n&&!BN_is_zero(n)&&EC_GROUP_get_order(group,order,ctx)==1&&BN_cmp(n,order)<0&&EC_POINT_mul(group,point,n,NULL,NULL,ctx)==1&&EC_KEY_set_private_key(ec,n)==1;}
  if(ok&&!priv)ok=EC_POINT_oct2point(group,point,data.bytes,data.length,ctx)==1;
  if(ok)ok=EC_KEY_set_public_key(ec,point)==1&&EC_KEY_check_key(ec)==1;
  EVP_PKEY *key=ok?EVP_PKEY_new():NULL;if(key)ok=EVP_PKEY_set1_EC_KEY(key,ec)==1;else ok=0;
  id result=ok?keyInfo(key,priv):nil;EVP_PKEY_free(key);BN_clear_free(n);BN_free(order);BN_CTX_free(ctx);EC_POINT_free(point);EC_KEY_free(ec);return result;
 }
 if([op isEqual:@"ec-load"] || [op isEqual:@"ec-verify"] || [op isEqual:@"ec-sign"] || [op isEqual:@"ec-exchange"] || [op isEqual:@"ec-scalar"]) {
  BOOL priv=[op isEqual:@"ec-exchange"]||[op isEqual:@"ec-sign"]||[op isEqual:@"ec-scalar"]||[r[@"private"] boolValue];
  EVP_PKEY *key=readKey(decode(r[@"key"]),priv);if(!key)return nil;id result=nil;
  if([op isEqual:@"ec-load"])result=keyInfo(key,priv);
  if([op isEqual:@"ec-scalar"]) {const EC_KEY *ec=EVP_PKEY_get0_EC_KEY(key);int size=(EC_GROUP_get_degree(EC_KEY_get0_group(ec))+7)/8;unsigned char out[48];if(BN_bn2binpad(EC_KEY_get0_private_key(ec),out,size)==size)result=blob([NSData dataWithBytes:out length:size]);OPENSSL_cleanse(out,sizeof out);}
  if([op isEqual:@"ec-verify"]) {NSData *data=decode(r[@"input"]),*sig=decode(r[@"signature"]);const EVP_MD *md=digest(string(r[@"digest"]));EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(data&&sig&&md&&ctx&&EVP_DigestVerifyInit(ctx,NULL,md,NULL,key)==1)result=@{@"valid":@(EVP_DigestVerify(ctx,sig.bytes,sig.length,data.bytes,data.length)==1)};EVP_MD_CTX_free(ctx);}
  if([op isEqual:@"ec-sign"]) {NSData *data=decode(r[@"input"]);const EVP_MD *md=digest(string(r[@"digest"]));EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned char signature[144];size_t length=sizeof signature;if(data&&md&&ctx&&EVP_DigestSignInit(ctx,NULL,md,NULL,key)==1&&EVP_DigestSign(ctx,signature,&length,data.bytes,data.length)==1&&length<=sizeof signature)result=blob([NSData dataWithBytes:signature length:length]);OPENSSL_cleanse(signature,sizeof signature);EVP_MD_CTX_free(ctx);}
  if([op isEqual:@"ec-exchange"]) {EVP_PKEY *peer=readKey(decode(r[@"peer"]),NO);EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(key,NULL);size_t length=0;unsigned char out[48];if(peer&&ctx&&EVP_PKEY_derive_init(ctx)==1&&EVP_PKEY_derive_set_peer(ctx,peer)==1&&EVP_PKEY_derive(ctx,NULL,&length)==1&&length<=sizeof out&&EVP_PKEY_derive(ctx,out,&length)==1)result=blob([NSData dataWithBytes:out length:length]);OPENSSL_cleanse(out,sizeof out);EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(peer);}
  EVP_PKEY_free(key);return result;
 }
 if([op isEqual:@"plist-decode"]) {NSData *data=decode(r[@"input"]);if(!data.length)return nil;id value=[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];unsigned count=0;id tree=value?plistTree(value,0,&count):nil;return tree?@{@"tree":tree}:nil;}
 if([op isEqual:@"plist-encode"]) {unsigned count=0;id value=plistValue(r[@"tree"],0,&count);if(!value)return nil;NSData *data=[NSPropertyListSerialization dataWithPropertyList:value format:[r[@"xml"] boolValue]?NSPropertyListXMLFormat_v1_0:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];return blob(data);}
 return nil;
}
__attribute__((visibility("default"))) int AQCloudTabsNativeCall(const void *input,size_t length,void **output,size_t *outputLength) {
 if(!output||!outputLength)return 0;*output=NULL;*outputLength=0;if(!input||!length||length>8*1024*1024)return 0;
 @autoreleasepool { @try {
  id request=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:input length:length] options:0 error:NULL];
  id result=[request isKindOfClass:[NSDictionary class]]?operation(request):nil;
  NSData *data=[NSJSONSerialization dataWithJSONObject:result?:@{@"error":@"Native operation failed"} options:0 error:NULL];
  if(!data || data.length>16*1024*1024)return 0;void *bytes=malloc(data.length);if(!bytes)return 0;
  memcpy(bytes,data.bytes,data.length);*output=bytes;*outputLength=data.length;return 1;
 } @catch(NSException *exception) {return 0;} }
}
__attribute__((visibility("default"))) void AQCloudTabsNativeFree(void *data,size_t length) {if(data){OPENSSL_cleanse(data,length);free(data);}}
