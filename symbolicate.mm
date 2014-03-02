/*

symbolicate.m ... Symbolicate a crash log.
Copyright (C) 2009  KennyTM~ <kennytm@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#import "symbolicate.h"

#import <Foundation/Foundation.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <notify.h>
#include "Headers.h"
#import "RegexKitLite.h"
#include "common.h"
#include "demangle.h"
#include "localSymbols.h"

enum SymbolicationMode {
    SM_CheckingMode,
    SM_ExceptionMode,
    SM_BacktraceMode,
    SM_BinaryImageMode,
};

@interface SymbolInfo : NSObject
@property(nonatomic, copy) NSString *name;
@property(nonatomic) uint64_t offset;
@property(nonatomic, copy) NSString *sourcePath;
@property(nonatomic) NSUInteger sourceLineNumber;
@end
@implementation SymbolInfo
- (void)dealloc {
    [_name release];
    [_sourcePath release];
    [super dealloc];
}
@end

@interface BacktraceInfo : NSObject {
    @package
        NSUInteger depth;
        uint64_t imageAddress;
        uint64_t address;
}
@property(nonatomic, retain) SymbolInfo *symbolInfo;
@end
@implementation BacktraceInfo
- (void)dealloc {
    [_symbolInfo release];
    [super dealloc];
}
@end

@interface BinaryInfo : NSObject {
    @package
        // slide = text address - actual address
        uint64_t address;
        int64_t slide;
        VMUSymbolOwner *owner;
        VMUMachOHeader *header;
        NSArray *symbolAddresses;
        NSArray *methods;
        NSString *path;
        NSUInteger line;
        BOOL encrypted;
        BOOL executable;
        BOOL blamable;
}
@end
@implementation BinaryInfo @end

@interface MethodInfo : NSObject {
    @package
        uint64_t address;
        NSString *name;
}
@end
@implementation MethodInfo @end

static uint64_t uint64FromHexString(NSString *string) {
    return (uint64_t)unsignedLongLongFromHexString([string UTF8String], [string length]);
}

static uint64_t linkCommandOffsetForHeader(VMUMachOHeader *header, uint64_t linkCommand) {
    uint64_t cmdsize = 0;
    Ivar ivar = class_getInstanceVariable([VMULoadCommand class], "_command");
    for (VMULoadCommand *lc in [header loadCommands]) {
        uint32_t cmd = (uint32_t)object_getIvar(lc, ivar);
        if (cmd == linkCommand) {
            return [header isMachO64] ?
                sizeof(mach_header_64) + cmdsize :
                sizeof(mach_header) + cmdsize;
        }
        cmdsize += [lc cmdSize];
    }
    return 0;
}

static BOOL isEncrypted(VMUMachOHeader *header) {
    BOOL isEncrypted = NO;

    uint64_t offset = linkCommandOffsetForHeader(header, LC_ENCRYPTION_INFO);
    if (offset != 0) {
        id<VMUMemoryView> view = (id<VMUMemoryView>)[[header memory] view];
        @try {
            [view setCursor:[header address] + offset + 16];
            isEncrypted = ([view uint32] > 0);
        } @catch (NSException *exception) {
            fprintf(stderr, "WARNING: Exception '%s' generated when determining encryption status for %s.\n",
                    [[exception reason] UTF8String], [[header path] UTF8String]);
        }
    }

    return isEncrypted;
}

static CFComparisonResult ReversedCompareNSNumber(NSNumber *a, NSNumber *b) {
    return [b compare:a];
}

static NSArray *symbolAddressesForImageWithHeader(VMUMachOHeader *header) {
    NSMutableArray *addresses = [NSMutableArray array];

    uint64_t offset = linkCommandOffsetForHeader(header, LC_FUNCTION_STARTS);
    if (offset != 0) {
        id<VMUMemoryView> view = (id<VMUMemoryView>)[[header memory] view];
        @try {
            [view setCursor:[header address] + offset + 8];
            uint32_t dataoff = [view uint32];
            [view setCursor:dataoff];
            uint64_t offset;
            uint64_t symbolAddress = [[header segmentNamed:@"__TEXT"] vmaddr];
            while ((offset = [view ULEB128])) {
                symbolAddress += offset;
                [addresses addObject:[NSNumber numberWithUnsignedLongLong:symbolAddress]];
            }
        } @catch (NSException *exception) {
            fprintf(stderr, "WARNING: Exception '%s' generated when extracting symbol addresses for %s.\n",
                    [[exception reason] UTF8String], [[header path] UTF8String]);
        }
    }

    [addresses sortUsingFunction:(NSInteger (*)(id, id, void *))ReversedCompareNSNumber context:NULL];
    return addresses;
}

static CFComparisonResult ReversedCompareMethodInfos(MethodInfo *a, MethodInfo *b) {
    return (a->address > b->address) ? kCFCompareLessThan : (a->address < b->address) ? kCFCompareGreaterThan : kCFCompareEqualTo;
}

#define RO_META     (1 << 0)
#define RW_REALIZED (1 << 31)

NSArray *methodsForImageWithHeader(VMUMachOHeader *header) {
    NSMutableArray *methods = [NSMutableArray array];

    const BOOL isFromSharedCache = [header respondsToSelector:@selector(isFromSharedCache)] && [header isFromSharedCache];
    const BOOL is64Bit = [header isMachO64];

    VMUSegmentLoadCommand *textSeg = [header segmentNamed:@"__TEXT"];
    int64_t vmdiff_text = [textSeg fileoff] - [textSeg vmaddr];

    VMUSegmentLoadCommand *dataSeg = [header segmentNamed:@"__DATA"];
    int64_t vmdiff_data = [dataSeg fileoff] - [dataSeg vmaddr];

    id<VMUMemoryView> view = (id<VMUMemoryView>)[[header memory] view];
    VMUSection *clsListSect = [dataSeg sectionNamed:@"__objc_classlist"];
    @try {
        [view setCursor:[clsListSect offset]];
        const uint64_t numClasses = [clsListSect size] / (is64Bit ? sizeof(uint64_t) : sizeof(uint32_t));
        for (uint64_t i = 0; i < numClasses; ++i) {
            uint64_t class_t_address = is64Bit ? [view uint64] : [view uint32];
            uint64_t next_class_t = [view cursor];

            if (i == 0 && isFromSharedCache) {
                // FIXME: Determine what this offset is and how to properly obtain it.
                VMUSection *sect = [dataSeg sectionNamed:@"__objc_data"];
                vmdiff_data -= (class_t_address - [sect addr]) / 0x1000 * 0x1000;
            }
            [view setCursor:vmdiff_data + class_t_address];

process_class:
            // Get address for meta class.
            // NOTE: This is needed for retrieving class (non-instance) methods.
            uint64_t isa;
            if (is64Bit) {
                isa = [view uint64];
                [view advanceCursor:24];
            } else {
                isa = [view uint32];
            [view advanceCursor:12];
            }

            // Confirm struct is actually class_ro_t (and not class_rw_t).
            const uint64_t class_ro_t_address = is64Bit ? [view uint64] : [view uint32];
            [view setCursor:vmdiff_data + class_ro_t_address];
            const uint32_t flags = [view uint32];
            if (!(flags & RW_REALIZED)) {
                const char methodType = (flags & 1) ? '+' : '-';

                uint64_t class_ro_t_name;
                if (is64Bit) {
                    [view advanceCursor:20];
                    class_ro_t_name = [view uint64];
                } else {
                [view advanceCursor:12];
                    class_ro_t_name = [view uint32];
                }
                if (i == 0 && isFromSharedCache && !(flags & RO_META)) {
                    // FIXME: Determine what this offset is and how to properly obtain it.
                    VMUSection *sect = [textSeg sectionNamed:@"__objc_classname"];
                    vmdiff_text -= (class_ro_t_name - [sect addr]) / 0x1000 * 0x1000;
                }
                [view setCursor:[header address] + vmdiff_text + class_ro_t_name];
                NSString *className = [view stringWithEncoding:NSUTF8StringEncoding];

                uint64_t baseMethods;
                if (is64Bit) {
                    [view setCursor:vmdiff_data + class_ro_t_address + 40];
                    baseMethods = [view uint64];
                } else {
                [view setCursor:vmdiff_data + class_ro_t_address + 20];
                    baseMethods = [view uint32];
                }
                if (baseMethods != 0) {
                    [view setCursor:vmdiff_data + baseMethods];
                    const uint32_t entsize = [view uint32];
                    if (entsize == 12 || entsize == 15) {
                        uint32_t count = [view uint32];
                        for (uint32_t j = 0; j < count; ++j) {
                            MethodInfo *mi = [[MethodInfo alloc] init];
                            const uint64_t sel = is64Bit ? [view uint64] : [view uint32];
                            NSString *methodName = nil;
                            if (entsize == 15) {
                                // Pre-optimized selector
                                methodName = [[NSString alloc] initWithCString:(const char *)sel encoding:NSUTF8StringEncoding];
                            } else {
                                const uint64_t loc = [view cursor];
                                [view setCursor:[header address] + vmdiff_text + sel];
                                methodName = [[view stringWithEncoding:NSUTF8StringEncoding] retain];
                                [view setCursor:loc];
                            }
                            mi->name = [NSString stringWithFormat:@"%c[%@ %@]", methodType, className, methodName];
                            [methodName release];
                            if (is64Bit) {
                                [view uint64]; // Skip 'types'
                                mi->address = [view uint64];
                            } else {
                                [view uint32]; // Skip 'types'
                            mi->address = [view uint32];
                            }
                            [methods addObject:mi];
                            [mi release];
                        }
                    }
                }
            }
            if (!(flags & RO_META)) {
                [view setCursor:vmdiff_data + isa];
                goto process_class;
            } else {
                [view setCursor:next_class_t];
            }
        }
    } @catch (NSException *exception) {
        fprintf(stderr, "WARNING: Exception '%s' generated when extracting methods for %s.\n",
                [[exception reason] UTF8String], [[header path] UTF8String]);
    }

    [methods sortUsingFunction:(NSInteger (*)(id, id, void *))ReversedCompareMethodInfos context:NULL];
    return methods;
}

static BacktraceInfo *extractBacktraceInfo(NSString *line) {
    BacktraceInfo *bti = nil;

    NSArray *array = [line captureComponentsMatchedByRegex:@"^(\\d+)\\s+.*\\S\\s+0x([0-9a-f]+) 0x([0-9a-f]+) \\+ (?:0x)?\\d+"];
    if ([array count] == 4) {
        NSString *matches[] = {[array objectAtIndex:1], [array objectAtIndex:2], [array objectAtIndex:3]};
        bti = [[BacktraceInfo alloc] init];
        bti->depth = [matches[0] intValue];
        bti->address = uint64FromHexString(matches[1]);
        bti->imageAddress = uint64FromHexString(matches[2]);
    }

    return [bti autorelease];
}

NSString *symbolicate(NSString *content, NSDictionary *symbolMaps, unsigned progressStepping, NSArray **blameInfo) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    //BOOL alreadySymbolicated = [content isMatchedByRegex:@"<key>symbolicated</key>[\\n\\s]+<true\\s*/>"];
    //if (alreadySymbolicated && [symbolMaps count] == 0) {
    //    fprintf(stderr, "WARNING: File has already been symbolicated, and no symbol maps were provided for reprocessing.\n");
    //    return nil;
    //}

    NSArray *inputLines = [[content stringByReplacingOccurrencesOfString:@"\r" withString:@""] componentsSeparatedByString:@"\n"];
    NSMutableArray *outputLines = [[NSMutableArray alloc] init];
    BOOL shouldNotifyOfProgress = (progressStepping > 0 && progressStepping < 100);

    enum SymbolicationMode mode = SM_CheckingMode;
    NSMutableArray *extraInfoArray = [[NSMutableArray alloc] init];
    NSMutableDictionary *binaryImages = [[NSMutableDictionary alloc] init];
    BOOL hasLastExceptionBacktrace = NO;
    NSString *exceptionType = nil;

    for (NSString *line in inputLines) {
        // extraInfo:
        //   - true = start of crashing thread.
        //   - false = start of non-crashing thread.
        //   - BacktraceInfo = backtrace info :)
        //   - null = irrelevant.
        id extraInfo = [NSNull null];

        switch (mode) {
            case SM_CheckingMode:
                if ([line hasPrefix:@"Exception Type:"]) {
                    NSUInteger lastCloseParenthesis = [line rangeOfString:@")" options:NSBackwardsSearch].location;
                    if (lastCloseParenthesis != NSNotFound) {
                        NSRange range = NSMakeRange(0, lastCloseParenthesis);
                        NSUInteger lastOpenParenthesis = [line rangeOfString:@"(" options:NSBackwardsSearch range:range].location;
                        if (lastOpenParenthesis < lastCloseParenthesis) {
                            range = NSMakeRange(lastOpenParenthesis + 1, lastCloseParenthesis - lastOpenParenthesis - 1);
                            exceptionType = [line substringWithRange:range];
                        }
                    }
                    break;
                } else if ([line hasPrefix:@"Last Exception Backtrace:"]) {
                    hasLastExceptionBacktrace = YES;
                    //mode = alreadySymbolicated ? SM_BacktraceMode : SM_ExceptionMode;
                    mode = SM_ExceptionMode;
                    break;
                } else if (![line hasPrefix:@"Thread 0"]) {
                    break;
                } else {
                    // Start of thread 0; fall-through to next case.
                    mode = SM_BacktraceMode;
                }

            case SM_BacktraceMode:
                if ([line isEqualToString:@"Binary Images:"]) {
                    mode = SM_BinaryImageMode;
                } else if ([line length] > 0) {
                    if ([line hasSuffix:@":"]) {
                        extraInfo = ([line rangeOfString:@"Crashed"].location != NSNotFound) ? (id)kCFBooleanTrue : (id)kCFBooleanFalse;
                    } else {
                        BacktraceInfo *bti = extractBacktraceInfo(line);
                        if (bti != nil) {
                            extraInfo = bti;
                        }
                    }
                }
                break;

            case SM_ExceptionMode: {
                mode = SM_CheckingMode;

                NSUInteger lastCloseParenthesis = [line rangeOfString:@")" options:NSBackwardsSearch].location;
                if (lastCloseParenthesis != NSNotFound) {
                    NSRange range = NSMakeRange(0, lastCloseParenthesis);
                    NSUInteger firstOpenParenthesis = [line rangeOfString:@"(" options:0 range:range].location;
                    if (firstOpenParenthesis < lastCloseParenthesis) {
                        NSUInteger depth = 0;
                        range = NSMakeRange(firstOpenParenthesis + 1, lastCloseParenthesis - firstOpenParenthesis - 1);
                        NSArray *array = [[line substringWithRange:range] componentsSeparatedByString:@" "];
                        for (NSString *address in array) {
                            BacktraceInfo *bti = [[BacktraceInfo alloc] init];
                            bti->depth = depth;
                            bti->address = uint64FromHexString(address);
                            bti->imageAddress = 0;
                            [extraInfoArray addObject:bti];
                            [bti release];
                            ++depth;

                            [outputLines addObject:[NSNull null]];
                        }
                        continue;
                    }
                }
                break;
            }

            case SM_BinaryImageMode: {
                NSArray *array = [line captureComponentsMatchedByRegex:@"^ *0x([0-9a-f]+) - *[0-9a-fx]+ [ +]?(.+?) arm\\w*  (?:<[0-9a-f]{32}> )?(.+)$"];
                if ([array count] == 4) {
                    NSString *match = [array objectAtIndex:1];
                    uint64_t address = uint64FromHexString(match);
                    [binaryImages setObject:array forKey:[NSNumber numberWithUnsignedLongLong:address]];
                } else {
                    mode = SM_CheckingMode;
                }
                break;
            }
        }

        [outputLines addObject:line];
        [extraInfoArray addObject:extraInfo];
    }

    NSUInteger i = 0;
    BOOL isCrashing = NO;
    BOOL hasHeaderFromSharedCacheWithPath = [VMUMemory_File respondsToSelector:@selector(headerFromSharedCacheWithPath:)];
    Class $BinaryInfo = [BinaryInfo class];
    NSUInteger total_lines = [extraInfoArray count];
    NSUInteger last_percent = 0;

    // Prepare array of image start addresses for determining symbols of exception.
    NSArray *imageAddresses = nil;
    if (hasLastExceptionBacktrace) {
        imageAddresses = [[binaryImages allKeys] sortedArrayUsingSelector:@selector(compare:)];
    }

    for (BacktraceInfo *bti in extraInfoArray) {
         if (shouldNotifyOfProgress) {
             NSUInteger this_percent = MIN((NSUInteger)100, 200 * i / total_lines);
             if (this_percent - last_percent >= progressStepping) {
                 last_percent = this_percent;
                 int token;
                 notify_register_check(PKG_ID".progress", &token);
                 notify_set_state(token, this_percent);
                 notify_post(PKG_ID".progress");
             }
         }

        if (bti == (id)kCFBooleanTrue) {
            isCrashing = YES;
        } else if (bti == (id)kCFBooleanFalse) {
            isCrashing = NO;
        } else if (bti != (id)kCFNull) {
            // Determine start address for this backtrace line.
            if (bti->imageAddress == 0) {
                for (NSNumber *number in [imageAddresses reverseObjectEnumerator]) {
                    uint64_t imageAddress = [number unsignedLongLongValue];
                    if (bti->address > imageAddress) {
                        bti->imageAddress = imageAddress;
                        break;
                    }
                }
            }

            // Retrieve info for related binary image.
            NSNumber *imageAddress = [NSNumber numberWithUnsignedLongLong:bti->imageAddress];
            BinaryInfo *bi = [binaryImages objectForKey:imageAddress];
            if (bi != nil) {
                // NOTE: If image has not been processed yet, type will be NSArray.
                if (![bi isKindOfClass:$BinaryInfo]) {
                    // NOTE: Binary images are only processed as needed. Most
                    //       likely only a small number of images were being
                    //       called into at the time of the crash.

                    // Create a BinaryInfo object for the image
                    NSArray *array = (NSArray *)bi;
                    NSString *matches[] = {[array objectAtIndex:1], [array objectAtIndex:2], [array objectAtIndex:3]};
                    bi = [[BinaryInfo alloc] init];
                    bi->address = uint64FromHexString(matches[0]);
                    bi->path = matches[2];
                    bi->blamable = YES;

                    // Get Mach-O header for the image
                    VMUMachOHeader *header = nil;
                    if (hasHeaderFromSharedCacheWithPath) {
                        header = [VMUMemory_File headerFromSharedCacheWithPath:matches[2]];
                    }
                    if (header == nil) {
                        header = [VMUMemory_File headerWithPath:matches[2]];
                    }
                    if (![header isKindOfClass:[VMUMachOHeader class]]) {
                        header = [[VMUHeader extractMachOHeadersFromHeader:header matchingArchitecture:[VMUArchitecture currentArchitecture] considerArchives:NO] lastObject];
                    }
                    if (header != nil) {
                        uint64_t textStart = [[header segmentNamed:@"__TEXT"] vmaddr];
                        bi->slide = textStart - bi->address;
                        bi->owner = [VMUSymbolExtractor extractSymbolOwnerFromHeader:header];
                        bi->header = header;
                        bi->encrypted = isEncrypted(bi->header);
                        bi->executable = ([header fileType] == MH_EXECUTE);
                        bi->symbolAddresses = symbolAddressesForImageWithHeader(header);
                    }

                    [binaryImages setObject:bi forKey:imageAddress];
                    [bi release];
                }

                // Add source/symbol information to the end of the output line.
                SymbolInfo *symbolInfo = nil;
                if (bi->header != nil) {
                    uint64_t address = bti->address + bi->slide;
                    VMUSourceInfo *srcInfo = [bi->owner sourceInfoForAddress:address];
                    if (srcInfo != nil) {
                        // Store source file name and line number.
                        symbolInfo = [SymbolInfo new];
                        [symbolInfo setSourcePath:[srcInfo path]];
                        [symbolInfo setSourceLineNumber:[srcInfo lineNumber]];
                    } else {
                        // Determine symbol address.
                        // NOTE: Only possible if LC_FUNCTION_STARTS exists in the binary.
                        uint64_t symbolAddress = 0;
                        NSUInteger count = [bi->symbolAddresses count];
                        if (count != 0) {
                            NSNumber *targetAddress = [[NSNumber alloc] initWithUnsignedLongLong:address];
                            CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)bi->symbolAddresses, CFRangeMake(0, count), targetAddress, (CFComparatorFunction)ReversedCompareNSNumber, NULL);
                            [targetAddress release];
                            if (matchIndex < (CFIndex)count) {
                                symbolAddress = [[bi->symbolAddresses objectAtIndex:matchIndex] unsignedLongLongValue];
                            }
                        }

                        // Attempt to retrieve symbol name and hex offset.
                        NSString *name = nil;
                        uint64_t offset = 0;
                        VMUSymbol *symbol = [bi->owner symbolForAddress:address];
                        if (symbol != nil && ([symbol addressRange].location == (symbolAddress & ~1) || symbolAddress == 0)) {
                            //if (alreadySymbolicated) {
                            //    goto skip_this_line;
                            //}
                            name = [symbol name];
                            if ([name isEqualToString:@"<redacted>"] && hasHeaderFromSharedCacheWithPath) {
                                NSString *localName = nameForLocalSymbol([bi->header address], [symbol addressRange].location);
                                if (localName != nil) {
                                    name = localName;
                                } else {
                                    fprintf(stderr, "Unable to determine name for: %s, 0x%08llx\n", [bi->path UTF8String], [symbol addressRange].location);
                                }
                            }
                            // Attempt to demangle name
                            // NOTE: It seems that Apple's demangler fails for some
                            //       names, so we attempt to do it ourselves.
                            name = demangle(name);
                            offset = address - [symbol addressRange].location;
                        } else if (NSDictionary *map = [symbolMaps objectForKey:bi->path]) {
                            for (NSNumber *number in [[[map allKeys] sortedArrayUsingSelector:@selector(compare:)] reverseObjectEnumerator]) {
                                uint64_t mapSymbolAddress = [number unsignedLongLongValue];
                                if (address > mapSymbolAddress) {
                                    name = demangle([map objectForKey:number]);
                                    offset = address - mapSymbolAddress;
                                    break;
                                }
                            }
                        } else if (!bi->encrypted) {
                            // Determine methods, attempt to match with symbol address.
                            if (symbolAddress != 0) {
                                MethodInfo *method = nil;
                                if (bi->methods == nil) {
                                    bi->methods = methodsForImageWithHeader(bi->header);
                                }
                                count = [bi->methods count];
                                if (count != 0) {
                                    MethodInfo *targetMethod = [[MethodInfo alloc] init];
                                    targetMethod->address = address;
                                    CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)bi->methods, CFRangeMake(0, count), targetMethod, (CFComparatorFunction)ReversedCompareMethodInfos, NULL);
                                    [targetMethod release];

                                    if (matchIndex < (CFIndex)count) {
                                        method = [bi->methods objectAtIndex:matchIndex];
                                    }
                                }

                                if (method != nil && method->address >= symbolAddress) {
                                    name = method->name;
                                    offset = address - method->address;
                                } else {
                                    uint64_t textStart = [[bi->header segmentNamed:@"__TEXT"] vmaddr];
                                    name = [NSString stringWithFormat:@"0x%08llx", (symbolAddress - textStart)];
                                    offset = address - symbolAddress;
                                }
                            }
                        }

                        if (name != nil) {
                            symbolInfo = [SymbolInfo new];
                            [symbolInfo setName:name];
                            [symbolInfo setOffset:offset];
                        }
                    }
                }

                NSString *lineComment = nil;
                if (symbolInfo != nil) {
                    NSString *sourcePath = [symbolInfo sourcePath];
                    if (sourcePath != nil) {
                        lineComment = [NSString stringWithFormat:@"\t// %@:%u", sourcePath, [symbolInfo sourceLineNumber]];
                    } else {
                        NSString *name = [symbolInfo name];
                        if (name != nil) {
                            lineComment = [NSString stringWithFormat:@"\t// %@ + 0x%llx", name, [symbolInfo offset]];
                        }
                    }

                    [bti setSymbolInfo:symbolInfo];
                    [symbolInfo release];
                }

                // Write out line of backtrace.
                NSString *addressString = [[NSString alloc] initWithFormat:@"0x%08llx 0x%08llx + 0x%llx",
                         bti->address, bi->address, bti->address - bi->address];
                NSString *newLine = [[NSString alloc] initWithFormat:@"%-6u%s%-30s\t%-32s%@",
                         bti->depth, bi->blamable ? "+ " : "  ",
                         [[[bi->path lastPathComponent] stringByAppendingString:(bi->executable ? @" (*)" : @"")] UTF8String],
                         [addressString UTF8String], lineComment ?: @""];
                [addressString release];
                [outputLines replaceObjectAtIndex:i withObject:newLine];
                [newLine release];

            }
        }

skip_this_line:
        ++i;
    }

    if (blameInfo != NULL) {
        *blameInfo = [blame(exceptionType, binaryImages, extraInfoArray) retain];
    }
    [binaryImages release];

    [pool drain];

    if (blameInfo != NULL) {
        [*blameInfo autorelease];
    }

    [outputLines autorelease];
    return [outputLines componentsJoinedByString:@"\n"];
}

NSArray *blame(NSString *exceptionType, NSDictionary *binaryImages, NSArray *backtraceLines) {
    NSMutableArray *result = nil;

    // Load blame filters.
    NSDictionary *whiteListFile = [[NSDictionary alloc] initWithContentsOfFile:@"/etc/symbolicate/whitelist.plist"];
    NSSet *filters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"Filters"]];
    NSSet *functionFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"FunctionFilters"]];
    NSSet *prefixFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"PrefixFilters"]];
    NSSet *reverseFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"ReverseFunctionFilters"]];
    NSSet *signalFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"SignalFilters"]];
    [whiteListFile release];

    // If exception type is not whitelisted, process blame.
    if (![signalFilters containsObject:exceptionType]) {
        // Mark which binary images are unblamable.
        Class $BinaryInfo = [BinaryInfo class];
        BOOL hasHeaderFromSharedCacheWithPath = [VMUMemory_File respondsToSelector:@selector(headerFromSharedCacheWithPath:)];
        for (BinaryInfo *bi in binaryImages) {
            if ([bi isKindOfClass:$BinaryInfo]) {
                // Determine if binary image should not be blamed.
                if (hasHeaderFromSharedCacheWithPath && [bi->header isFromSharedCache]) {
                    // Don't blame anything from the shared cache.
                    bi->blamable = NO;
                } else {
                    // Don't blame white-listed libraries.
                    if ([filters containsObject:bi->path]) {
                        bi->blamable = NO;
                    } else {
                        // Don't blame white-listed folders.
                        for (NSString *prefix in prefixFilters) {
                            if ([bi->path hasPrefix:prefix]) {
                                bi->blamable = NO;
                                break;
                            }
                        }
                    }
                }
            }
        }

        NSUInteger i = 0;
        BOOL isCrashing = NO;
        for (BacktraceInfo *bti in backtraceLines) {
            if (bti == (id)kCFBooleanTrue) {
                isCrashing = YES;
            } else if (bti == (id)kCFBooleanFalse) {
                isCrashing = NO;
            } else if (bti != (id)kCFNull) {
                // Retrieve info for related binary image.
                NSNumber *imageAddress = [NSNumber numberWithUnsignedLongLong:bti->imageAddress];
                BinaryInfo *bi = [binaryImages objectForKey:imageAddress];
                if (bi != nil) {
                    // Determine if binary image should be blamed.
                    if (bi->blamable && (bi->line == 0 || ((bi->line & 0x80000000) && isCrashing))) {
                        // Blame.
                        bi->line = i;
                        // Make it a secondary suspect if it isn't in the crashing thread.
                        if (!isCrashing) {
                            bi->line |= 0x80000000;
                        }
                    }

                    // Check symbol name of system functions against blame filters.
                    if ([bi->path isEqualToString:@"/usr/lib/libSystem.B.dylib"]) {
                        SymbolInfo *symbolInfo = [bti symbolInfo];
                        if (symbolInfo != nil) {
                            NSString *name = [symbolInfo name];
                            if (name != nil) {
                                if (isCrashing) {
                                    // Check if this function should never cause crash (only hang).
                                    if ([functionFilters containsObject:name]) {
                                        isCrashing = NO;
                                    }
                                } else {
                                    // Check if this function is actually causing crash.
                                    if ([reverseFilters containsObject:name]) {
                                        isCrashing = YES;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            ++i;
        }

        // Output blame info.
        result = [NSMutableArray array];
        for (NSNumber *key in binaryImages) {
            BinaryInfo *bi = [binaryImages objectForKey:key];
            if ([bi isKindOfClass:$BinaryInfo] && bi->blamable) {
                NSArray *array = [[NSArray alloc] initWithObjects:bi->path, [NSNumber numberWithUnsignedInteger:bi->line], nil];
                [result addObject:array];
                [array release];
            }
        }
    }

    [filters release];
    [functionFilters release];
    [prefixFilters release];
    [reverseFilters release];
    [signalFilters release];

    return result;
}

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
