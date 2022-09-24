#import <React/RCTBridgeModule.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

@interface TouchID : NSObject <RCTBridgeModule>
    - (NSString *_Nonnull)getBiometryType:(LAContext *_Nonnull)context;
@end
