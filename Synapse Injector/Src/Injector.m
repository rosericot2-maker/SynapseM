//
//
//	SYNAPSE-PHOENIX (working title)
//	File.:	Injector.m
//	Desc.:	Synapse DLL injector for UI.
//
//

#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <unistd.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <ifaddrs.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <IOKit/IOKit.h>
#import <IOKit/storage/IOStorageAttributes.h>
#import <IOKit/IOBSD.h>

// Import local headers if available
// #import "ObfuscatedString.h"
// #import "sha512.h"
// #import "WinReg.h" // Adapted for CoreFoundation/Preferences

// Placeholder for external libraries if needed (e.g., CryptoKit, CommonCrypto)
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SystemFingerprint : NSObject

@property (nonatomic, assign) NSUInteger FingerprintSize;
@property (nonatomic, strong) NSMutableData *UniqueFingerprint;

- (instancetype)init;
- (void)initializeFingerprint;
- (NSString *)toString;
+ (NSString *)pad4Byte:(NSString *)str;
- (void)interleave:(NSUInteger)data;

@end

@implementation SystemFingerprint

- (instancetype)init {
    self = [super init];
    if (self) {
        self.FingerprintSize = 16;
        self.UniqueFingerprint = [NSMutableData dataWithLength:16];
    }
    return self;
}

- (void)initializeFingerprint {
    uint8_t *bytes = (uint8_t *)self.UniqueFingerprint.mutableBytes;
    for (NSUInteger i = 0; i < self.FingerprintSize - 1; i++) {
        bytes[i] = (uint8_t)(~i & 255);
    }
}

- (NSString *)toString {
    NSMutableString *outString = [NSMutableString string];
    uint8_t *bytes = (uint8_t *)self.UniqueFingerprint.bytes;
    
    for (NSUInteger i = 0; i < self.FingerprintSize - 1; i++) {
        // Convert each byte to a hex string
        char hex[3] = {0};
        snprintf(hex, sizeof(hex), "%02X", bytes[i]);
        [outString appendString:[NSString stringWithUTF8String:hex]];
    }
    return outString;
}

+ (NSString *)pad4Byte:(NSString *)str {
    NSUInteger len = str.length;
    NSUInteger remainder = len % 4;
    if (remainder != 0) {
        NSUInteger padding = 4 - remainder;
        NSMutableString *mutableStr = [str mutableCopy];
        for (NSUInteger i = 0; i < padding; i++) {
            [mutableStr appendString:@" "];
        }
        return mutableStr;
    }
    return str;
}

- (void)interleave:(NSUInteger)data {
    uint32_t *ptr = (uint32_t *)self.UniqueFingerprint.mutableBytes;
    
    // XOR with data + constants
    ptr[0] ^= data + 0x2EF35C3D;
    ptr[1] ^= data + 0x6E50D365;
    ptr[2] ^= data + 0x73B3E4F9;
    ptr[3] ^= data + 0x1A044581;
    
    /* assure no reversal */
    uint32_t originalValue = ptr[0];
    ptr[0] ^= ptr[3];
    ptr[3] ^= originalValue * 0x3D05F7D1 + ptr[0];
    
    uint8_t *bytes = (uint8_t *)self.UniqueFingerprint.mutableBytes;
    bytes[0] = bytes[15] + bytes[14];
    bytes[14] = bytes[0] + bytes[15];
}

+ (BOOL)isNumber:(NSString *)s {
    if (s.length == 0) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:s];
    return [scanner scanUnsignedLongLong:NULL] && scanner.atEnd;
}

+ (NSString *)getPhysicalDriveId:(NSUInteger)Id {
    // In macOS, getting the physical serial ID usually involves IOKit
    // This is a simplified placeholder similar to the Windows CreateFile logic
    
    io_service_t driveService = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOBSDNameMatching(kIOMasterPortDefault, 0, [NSString stringWithFormat:@"disk%d", Id]));
    
    if (driveService == MACH_PORT_NULL) {
        return @"Unknow";
    }
    
    CFStringRef serial = (CFStringRef)IORegistryEntryCreateCFProperty(driveService,
        CFSTR("IOBSDName"), kCFAllocatorDefault, 0);
    
    // Try to get the actual serial number
    CFStringRef serialNumber = (CFStringRef)IORegistryEntryCreateCFProperty(driveService,
        CFSTR("IOPropertyString"), kCFAllocatorDefault, 0);
        
    if (serialNumber) {
        NSString *str = (__bridge NSString *)serialNumber;
        CFRelease(serialNumber);
        IOObjectRelease(driveService);
        return str;
    }
    
    // Fallback
    IOObjectRelease(driveService);
    return @"Unknow";
}

// Helper to get MAC address for fingerprinting
+ (NSString *)getMACAddress {
    struct ifaddrs *addrs;
    const struct ifaddrs *cursor;
    NSString *foundMAC = nil;

    if (getifaddrs(&addrs) != 0)
        return nil;

    cursor = addrs;
    while (cursor != NULL) {
        // Skip loopback, tunnel, and non-ethernet interfaces
        if (cursor->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sd = (struct sockaddr_dl *)cursor->ifa_addr;
            if (sd && (sd->sdl_nlen > 0) && (strncmp(cursor->ifa_name, "en", 2) == 0)) {
                u_char *mac = (u_char *)LLADDR(sd);
                foundMAC = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
                break;
            }
        }
        cursor = cursor->ifa_next;
    }
    freeifaddrs(addrs);
    return foundMAC;
}

// Helper to get CPU Type
+ (NSString *)getCPUArch {
    int name[2] = {CTL_HW, HW_MACHINE};
    char machine[256];
    size_t len = sizeof(machine);
    sysctl(name, 2, &machine, &len, NULL, 0);
    return [NSString stringWithUTF8String:machine];
}

@end

NS_ASSUME_NONNULL_END
