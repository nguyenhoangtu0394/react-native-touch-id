#import "TouchID.h"
#import <React/RCTUtils.h>
#import "React/RCTConvert.h"

// todo link fix passcodefallback
// https://medium.com/@pawankhadpe/support-passcode-fallback-along-with-touchid-a0cfa1cc8a8c
@implementation TouchID

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(isSupported: (NSDictionary *)options
                  callback: (RCTResponseSenderBlock)callback)
{
    LAContext *context = [[LAContext alloc] init];
    NSError *error;
    
    // Check to see if we have a passcode fallback
    // NSNumber *passcodeFallback = [NSNumber numberWithBool:true];
    Boolean passcodeFallback = false;
    if (RCTNilIfNull([options objectForKey:@"passcodeFallback"]) != nil) {
        // passcodeFallback = [RCTConvert NSNumber:options[@"passcodeFallback"]];
        passcodeFallback = [[RCTConvert NSNumber:options[@"passcodeFallback"]] boolValue];
    }
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        
        // No error found, proceed
        callback(@[[NSNull null], [self getBiometryType:context]]);
    }
//    else if ([passcodeFallback boolValue] && [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
    else if (passcodeFallback && [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
   
        // No error
        callback(@[[NSNull null], [self getBiometryType:context]]);
    }
    // Device does not support FaceID / TouchID / Pin OR there was an error!
    else {
        if (error) {
            NSString *errorReason = [self getErrorReason:error];
            NSLog(@"Authentication failed: %@", errorReason);
            
            callback(@[RCTMakeError(errorReason, nil, nil), [self getBiometryType:context]]);
            return;
        }
        
        callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
        return;
    }
}

RCT_EXPORT_METHOD(authenticate: (NSString *)reason
                  options:(NSDictionary *)options
                  callback: (RCTResponseSenderBlock)callback)
{
    NSString *keyBiometric = @"react-native-touch-id-biometric";
    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
                                                                 nil,
                                                                 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                 kSecAccessControlUserPresence,
                                                                 &error);

    if (access == NULL || error != NULL) {
      callback(@[RCTMakeError(@"RCTTouchIDNotSupported", nil, nil)]);
      return;
    }
    
    LAContext* context = [[LAContext alloc] init];
    NSDictionary *query = @{
      (id)kSecClass: (id)kSecClassGenericPassword,
      (id)kSecAttrAccount: keyBiometric,
      (id)kSecAttrAccessControl: (__bridge_transfer id)access,
      (id)kSecUseAuthenticationContext: context,
      (id)kSecValueData: [@"true" dataUsingEncoding:NSUTF8StringEncoding]
    };

    // Deletes the existing item prior to inserting the new one
    SecItemDelete((CFDictionaryRef)query);
    
    OSStatus insertStatus = SecItemAdd((CFDictionaryRef)query, nil);
    if (insertStatus == errSecSuccess) {
        NSDictionary* getQuery = @{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrAccount: keyBiometric,
        (id)kSecMatchLimit: (id)kSecMatchLimitOne,
        (id)kSecUseAuthenticationContext: context,
        (id)kSecReturnData: (id)kCFBooleanTrue
        };
        OSStatus getStatus = SecItemCopyMatching((CFDictionaryRef)getQuery, nil);
        if (getStatus == errSecSuccess) {
            callback(@[[NSNull null], @"Authenticated with Touch ID."]);
        } else {
            callback(@[RCTMakeError(@"LAErrorAuthenticationFailed", nil, nil)]);
        }
    } else {
        callback(@[RCTMakeError(@"LAErrorSystemCancel", nil, nil)]);
    }
}

- (void)handleAttemptToUseDeviceIDWithSuccess:(BOOL)success error:(NSError *)error callback:(RCTResponseSenderBlock)callback {
    if (success) { // Authentication Successful
        callback(@[[NSNull null], @"Authenticated with Touch ID."]);
    } else if (error) { // Authentication Error
        NSString *errorReason = [self getErrorReason:error];
        NSLog(@"Authentication failed: %@", errorReason);
        callback(@[RCTMakeError(errorReason, nil, nil)]);
    } else { // Authentication Failure
        callback(@[RCTMakeError(@"LAErrorAuthenticationFailed", nil, nil)]);
    }
}

- (NSString *)getErrorReason:(NSError *)error
{
    NSString *errorReason;
    
    switch (error.code) {
        case LAErrorAuthenticationFailed:
            errorReason = @"LAErrorAuthenticationFailed";
            break;
            
        case LAErrorUserCancel:
            errorReason = @"LAErrorUserCancel";
            break;
            
        case LAErrorUserFallback:
            errorReason = @"LAErrorUserFallback";
            break;
            
        case LAErrorSystemCancel:
            errorReason = @"LAErrorSystemCancel";
            break;
            
        case LAErrorPasscodeNotSet:
            errorReason = @"LAErrorPasscodeNotSet";
            break;
            
        case LAErrorTouchIDNotAvailable:
            errorReason = @"LAErrorTouchIDNotAvailable";
            break;
            
        case LAErrorTouchIDNotEnrolled:
            errorReason = @"LAErrorTouchIDNotEnrolled";
            break;
            
         case LAErrorTouchIDLockout:
            errorReason = @"LAErrorTouchIDLockout";
            break;
               
        default:
            errorReason = @"RCTTouchIDUnknownError";
            break;
    }
    
    return errorReason;
}

- (NSString *)getBiometryType:(LAContext *)context
{
    if (@available(iOS 11, *)) {
        if (context.biometryType == LABiometryTypeFaceID) {
            return @"FaceID";
        }
        else if (context.biometryType == LABiometryTypeTouchID) {
            return @"TouchID";
        }
        else if (context.biometryType == LABiometryNone) {
            return @"None";
        }
    }

    return @"TouchID";
}

@end
