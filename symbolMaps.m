#import "symbolMaps.h"

#import "RegexKitLite.h"
#include "common.h"

NSDictionary *parseMapFile(NSString *mapFile) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    NSData *data = [[NSData alloc] initWithContentsOfFile:mapFile];
    NSString *content = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
    [data release];

    if (content != nil) {
        BOOL foundSymbols = NO;
        for (NSString *line in [content componentsSeparatedByString:@"\n"]) {
            if (!foundSymbols) {
                foundSymbols = [line hasPrefix:@"# Symbols:"];
            } else {
                if ([line length] > 0) {
                    NSArray *array = [line captureComponentsMatchedByRegex:@"^0x([0-9a-fA-F]+)\\s+0x[0-9a-fA-F]+\\s+\\[\\s*\\d+\\] (.*)$"];
                    if ([array count] == 3) {
                        NSString *matches[2];
                        [array getObjects:matches range:NSMakeRange(1, 2)];
                        if (!(
                            [matches[1] isEqualToString:@"anon"] ||
                            [matches[1] isEqualToString:@"CFString"] ||
                            [matches[1] hasPrefix:@"literal string:"] ||
                            [matches[1] rangeOfString:@"-"].location != NSNotFound
                            )) {
                            unsigned long long address = convertHexStringToLongLong([matches[0] UTF8String], [matches[0] length]);
                            NSNumber *number = [[NSNumber alloc] initWithUnsignedLongLong:address];
                            [result setObject:matches[1] forKey:number];
                            [number release];
                        }
                    }
                }
            }
        }
        [content release];
    }

    return result;
}

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
