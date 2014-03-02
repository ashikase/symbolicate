#import <Foundation/Foundation.h>

#include "Headers.h"

@interface BinaryInfo : NSObject {
    @package
        // slide = text address - actual address
        uint64_t address;
        int64_t slide;
        VMUSymbolOwner *owner;
        NSArray *symbolAddresses;
        NSUInteger line;
        BOOL encrypted;
        BOOL executable;
        BOOL blamable;
}
@property(nonatomic, readonly) VMUMachOHeader *header;
@property(nonatomic, readonly) NSArray *methods;
@property(nonatomic, readonly) NSString *path;
- (id)initWithPath:(NSString *)path;
@end

CFComparisonResult reversedCompareNSNumber(NSNumber *a, NSNumber *b);

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
