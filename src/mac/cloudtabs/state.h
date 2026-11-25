#ifndef AQ_CLOUDTABS_STATE_H
#define AQ_CLOUDTABS_STATE_H
#ifndef AQ_CLOUDTABS_STATE_DIRECTORY
#define AQ_CLOUDTABS_STATE_DIRECTORY ([NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/AquaTransport/CloudTabs"])
#endif
static NSString *AQCloudTabsStateDirectory(void) {return AQ_CLOUDTABS_STATE_DIRECTORY;}
#endif
