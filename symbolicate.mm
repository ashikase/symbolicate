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
#import "RegexKitLite.h"
#include "common.h"

#include "Headers.h"
#include "localSymbols.h"

enum SymbolicationMode {
    SM_CheckingMode,
    SM_ExceptionMode,
    SM_BacktraceMode,
    SM_BinaryImageMode,
};

@interface BacktraceInfo : NSObject {
    @package
        NSUInteger depth;
        unsigned long long imageAddress;
        unsigned long long address;
}
@end
@implementation BacktraceInfo @end

@interface BinaryInfo : NSObject {
    @package
        // slide = text address - actual address
        unsigned long long address;
        long long slide;
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
        unsigned long long impAddr;
        NSString *name;
}
@end
@implementation MethodInfo @end

static uint64_t read_uleb128(const uint8_t **buf, const uint8_t *buf_end) {
    uint64_t result = 0;

    const uint8_t *p = *buf;
    uint8_t byte;
    unsigned shift = 0;
    do {
        if (p >= buf_end) {
            fprintf(stderr, "WARNING: Bounds failure in read_uleb128().\n");
            return 0;
        }

        byte = *p++;
        if (shift >= 64 || (byte << shift >> shift) != byte) {
            fprintf(stderr, "WARNING: Read value larger than 64-bits in read_uleb128().\n");
            return 0;
        } else {
            result |= (byte & 0x7f) << shift;
            shift += 7;
        }
    } while ((byte & 0x80) != 0);
    *buf = p;
    return result;
}

static CFComparisonResult ReversedCompareNSNumber(NSNumber *a, NSNumber *b) {
    return [b compare:a];
}

static NSArray *symbolAddressesForImageWithHeader(VMUMachOHeader *header) {
    NSMutableArray *addresses = [NSMutableArray array];

    VMUMemory_Handle *memory = [header memory];
    Ivar ivar = class_getInstanceVariable([VMUMemory_Handle class], "_data");
    const uint8_t *data = reinterpret_cast<const uint8_t *>(object_getIvar(memory, ivar));
    if (data != NULL) {
        const mach_header *mh = reinterpret_cast<const mach_header *>(data);
        if (mh->magic == MH_MAGIC) {
            const load_command *cmd = reinterpret_cast<const load_command *>(data + sizeof(mach_header));
            for (uint32_t j = 0; j < mh->ncmds; ++j) {
                if (cmd->cmd == LC_FUNCTION_STARTS) {
                    const linkedit_data_command *functionStarts = reinterpret_cast<const linkedit_data_command *>(cmd);
                const uint64_t textStart = [[header segmentNamed:@"__TEXT"] vmaddr];
                    const uint8_t *start = data + textStart + functionStarts->dataoff;
                    const uint8_t *end = start + functionStarts->datasize;
                uint64_t offset;
                uint64_t symbolAddress = 0;
                    while ((offset = read_uleb128(&start, end))) {
                    symbolAddress += offset;
                    [addresses addObject:[NSNumber numberWithUnsignedLongLong:symbolAddress]];
                }
                    break;
                }
                cmd = reinterpret_cast<const load_command *>((uint8_t *)cmd + cmd->cmdsize);
            }
        }
    }

    [addresses sortUsingFunction:(NSInteger (*)(id, id, void *))ReversedCompareNSNumber context:NULL];
    return addresses;
}

static CFComparisonResult ReversedCompareMethodInfos(MethodInfo *a, MethodInfo *b) {
    return (a->impAddr > b->impAddr) ? kCFCompareLessThan : (a->impAddr < b->impAddr) ? kCFCompareGreaterThan : kCFCompareEqualTo;
}

#define RO_META     (1 << 0)
#define RW_REALIZED (1 << 31)

NSArray *methodsForImageWithHeader(VMUMachOHeader *header) {
    NSMutableArray *methods = [NSMutableArray array];

    VMUSegmentLoadCommand *dataSeg = [header segmentNamed:@"__DATA"];
    long long vmdiff_data = [dataSeg fileoff] - [dataSeg vmaddr];

    VMUSegmentLoadCommand *textSeg = [header segmentNamed:@"__TEXT"];
    long long vmdiff_text = [textSeg fileoff] - [textSeg vmaddr];

    id<VMUMemoryView> view = (id<VMUMemoryView>)[[header memory] view];
    VMUSection *clsListSect = [dataSeg sectionNamed:@"__objc_classlist"];
    @try {
        [view setCursor:[clsListSect offset]];
        uint64_t numClasses = [clsListSect size] / sizeof(uint32_t);
        for (uint64_t i = 0; i < numClasses; ++i) {
            uint32_t class_t_address = [view uint32];
            uint64_t next_class_t = [view cursor];
            [view setCursor:vmdiff_data + class_t_address];

process_class:
            // Get address for meta class.
            // NOTE: This is needed for retrieving class (non-instance) methods.
            uint32_t isa = [view uint32];
            [view advanceCursor:12];

            // Confirm struct is actually class_ro_t (and not class_rw_t).
            uint32_t class_ro_t_address = [view uint32];
            [view setCursor:vmdiff_data + class_ro_t_address];
            uint32_t flags = [view uint32];
            if (!(flags & RW_REALIZED)) {
                char methodType = (flags & 1) ? '+' : '-';

                [view advanceCursor:12];
                [view setCursor:vmdiff_text + [view uint32]];
                NSString *className = [view stringWithEncoding:NSUTF8StringEncoding];

                [view setCursor:vmdiff_data + class_ro_t_address + 20];
                uint32_t baseMethods = [view uint32];
                if (baseMethods != 0) {
                    [view setCursor:vmdiff_data + baseMethods];
                    uint32_t entsize = [view uint32];
                    if (entsize == 12) {
                        uint32_t count = [view uint32];
                        for (uint32_t j = 0; j < count; ++j) {
                            MethodInfo *mi = [[MethodInfo alloc] init];
                            uint32_t sel = [view uint32];
                            uint64_t loc = [view cursor];
                            [view setCursor:vmdiff_text + sel];
                            NSString *methodName = [view stringWithEncoding:NSUTF8StringEncoding];
                            mi->name = [NSString stringWithFormat:@"%c[%@ %@]", methodType, className, methodName];
                            [view setCursor:loc];
                            [view uint32];
                            mi->impAddr = [view uint32] & ~1;
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

static NSString *escapeHTML(NSString *x, NSCharacterSet *escSet) {
    // Do not copy unless we're sure the string contains the characters we want to escape.
    if ([x rangeOfCharacterFromSet:escSet].location != NSNotFound) {
        NSMutableString *rx = [NSMutableString stringWithString:x];
        [rx replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0 range:NSMakeRange(0, [rx length])];
        [rx replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0 range:NSMakeRange(0, [rx length])];
        [rx replaceOccurrencesOfString:@">" withString:@"&gt;" options:0 range:NSMakeRange(0, [rx length])];
        return rx;
    } else {
        return x;
    }
}

NSString *symbolicate(NSString *content, NSDictionary *symbolMaps, unsigned progressStepping) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    BOOL alreadySymbolicated = [content isMatchedByRegex:@"<key>symbolicated</key>[\\n\\s]+<true\\s*/>"];
    if (alreadySymbolicated && [symbolMaps count] == 0) {
        fprintf(stderr, "WARNING: File has already been symbolicated, and no symbol maps were provided for reprocessing.\n");
        return nil;
    }

    NSArray *inputLines = [content componentsSeparatedByString:@"\n"];
    NSMutableArray *outputLines = [[NSMutableArray alloc] init];
    BOOL shouldNotifyOfProgress = (progressStepping > 0 && progressStepping < 100);

    NSDictionary *whiteListFile = [[NSDictionary alloc] initWithContentsOfFile:@"/etc/symbolicate/whitelist.plist"];
    NSSet *filters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"Filters"]];
    NSSet *functionFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"FunctionFilters"]];
    NSArray *prefixFilters = [[whiteListFile objectForKey:@"PrefixFilters"] retain];
    NSSet *reverseFilters = [[NSSet alloc] initWithArray:[whiteListFile objectForKey:@"ReverseFunctionFilters"]];
    NSArray *signalFilters = [[whiteListFile objectForKey:@"SignalFilters"] retain];
    [whiteListFile release];

    enum SymbolicationMode mode = SM_CheckingMode;
    NSMutableArray *extraInfoArray = [[NSMutableArray alloc] init];
    NSMutableDictionary *binaryImages = [[NSMutableDictionary alloc] init];
    BOOL hasLastExceptionBacktrace = NO;
    BOOL isFilteredSignal = YES;
    NSUInteger depth = 0;

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
                            NSString *signalStr = [line substringWithRange:range];
                            isFilteredSignal = isFilteredSignal && ![signalFilters containsObject:signalStr];
                        }
                    }
                    break;
                } else if ([line hasPrefix:@"Last Exception Backtrace:"]) {
                    hasLastExceptionBacktrace = YES;
                    mode = alreadySymbolicated ? SM_BacktraceMode : SM_ExceptionMode;
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
                        depth = 0;
                    } else {
                        NSArray *array = [line captureComponentsMatchedByRegex:@"^\\d+\\s+.*\\S\\s+0x([0-9a-f]+) 0x([0-9a-f]+) \\+ (?:0x)?\\d+"];
                        if ([array count] == 3) {
                            NSString *matches[2];
                            [array getObjects:matches range:NSMakeRange(1, 2)];

                            BacktraceInfo *bti = [[[BacktraceInfo alloc] init] autorelease];
                            bti->depth = depth;
                            bti->imageAddress = unsignedLongLongFromHexString([matches[1] UTF8String], [matches[1] length]);
                            bti->address = unsignedLongLongFromHexString([matches[0] UTF8String], [matches[0] length]);
                            extraInfo = bti;
                            ++depth;
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
                        range = NSMakeRange(firstOpenParenthesis + 1, lastCloseParenthesis - firstOpenParenthesis - 1);
                        NSArray *array = [[line substringWithRange:range] componentsSeparatedByString:@" "];
                        for (NSString *address in array) {
                            BacktraceInfo *bti = [[BacktraceInfo alloc] init];
                            bti->depth = depth;
                            bti->imageAddress = 0;
                            bti->address = unsignedLongLongFromHexString([address UTF8String], [address length]);
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
                NSArray *array = [line captureComponentsMatchedByRegex:@"^ *0x([0-9a-f]+) - *[0-9a-fx]+ [ +](.+?) arm\\w*  (?:&lt;[0-9a-f]{32}&gt; )?(.+)$"];
                if ([array count] == 4) {
                    NSString *match = [array objectAtIndex:1];
                    unsigned long long address = unsignedLongLongFromHexString([match UTF8String], [match length]);
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

    NSCharacterSet *escSet = [NSCharacterSet characterSetWithCharactersInString:@"<>&"];

    NSUInteger i = 0;
    BOOL isCrashing = NO;
    BOOL hasHeaderFromSharedCacheWithPath = [VMUMemory_File respondsToSelector:@selector(headerFromSharedCacheWithPath:)];
    Class $BinaryInfo = [BinaryInfo class];
    NSUInteger total_lines = [extraInfoArray count];
    int last_percent = 0;

    Ivar _command_ivar = class_getInstanceVariable([VMULoadCommand class], "_command");

    // Prepare array of image start addresses for determining symbols of exception.
    NSArray *imageAddresses = nil;
    if (hasLastExceptionBacktrace) {
        imageAddresses = [[binaryImages allKeys] sortedArrayUsingSelector:@selector(compare:)];
    }

    for (BacktraceInfo *bti in extraInfoArray) {
         if (shouldNotifyOfProgress) {
             int this_percent = MIN(100, 200 * i / total_lines);
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
                    unsigned long long imageAddress = [number unsignedLongLongValue];
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
                    NSString *matches[3];
                    [(NSArray *)bi getObjects:matches range:NSMakeRange(1, 3)];

                    // Create a BinaryInfo object for the image
                    bi = [[BinaryInfo alloc] init];
                    bi->address = unsignedLongLongFromHexString([matches[0] UTF8String], [matches[0] length]);
                    bi->path = matches[2];
                    bi->line = 0;
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
                        unsigned long long textStart = [[header segmentNamed:@"__TEXT"] vmaddr];
                        bi->slide = textStart - bi->address;
                        bi->owner = [VMUSymbolExtractor extractSymbolOwnerFromHeader:header];
                        bi->header = header;
                        for (VMULoadCommand *lc in [header loadCommands]) {
                            if ((int)object_getIvar(lc, _command_ivar) == LC_ENCRYPTION_INFO) {
                                bi->encrypted = YES;
                                break;
                            }
                        }
                        bi->executable = ([header fileType] == MH_EXECUTE);
                    }

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

                    [binaryImages setObject:bi forKey:imageAddress];
                    [bi release];
                }

                // Determine if binary image should be blamed.
                if (bi->blamable && (bi->line == 0 || ((bi->line & 0x80000000) && isCrashing))) {
                    // Blame.
                    bi->line = i;
                    // Make it a secondary suspect if it isn't in the crashing thread.
                    if (!isCrashing) {
                        bi->line |= 0x80000000;
                    }
                }

                // Add source/symbol information to the end of the output line.
                NSString *lineComment = nil;
                if (bi->header != nil) {
                    unsigned long long address = bti->address + bi->slide;
                    VMUSourceInfo *srcInfo = [bi->owner sourceInfoForAddress:address];
                    if (srcInfo != nil) {
                        // Add source file name and line number.
                        lineComment = [NSString stringWithFormat:@"\t// %@:%u", escapeHTML([srcInfo path], escSet), [srcInfo lineNumber]];
                    } else {
                        NSString *name = nil;
                        unsigned long long offset = 0;

                        // Attempt to add symbol name and hex offset.
                        VMUSymbol *symbol = [bi->owner symbolForAddress:address];
                        if (symbol != nil) {
                            if (alreadySymbolicated) {
                                goto skip_this_line;
                            }
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

                            // FIXME: Where does this actually belong?
                            if (isCrashing) {
                                // Check if this function should never cause crash (only hang).
                                if ([bi->path isEqualToString:@"/usr/lib/libSystem.B.dylib"] && [functionFilters containsObject:name]) {
                                    isCrashing = NO;
                                }
                            } else if (!isCrashing) {
                                // Check if this function is actually causing crash.
                                if ([bi->path isEqualToString:@"/usr/lib/libSystem.B.dylib"] && [reverseFilters containsObject:name]) {
                                    isCrashing = YES;
                                }
                            }
                            offset = address - [symbol addressRange].location;
                        } else if (NSDictionary *map = [symbolMaps objectForKey:bi->path]) {
                            for (NSNumber *number in [[[map allKeys] sortedArrayUsingSelector:@selector(compare:)] reverseObjectEnumerator]) {
                                unsigned long long symbolAddress = [number unsignedLongLongValue];
                                if (address > symbolAddress) {
                                    name = demangle([map objectForKey:number]);
                                    offset = address - symbolAddress;
                                    break;
                                }
                            }
                        } else if (!bi->encrypted) {
                            // Determine symbol addresses and attempt to match with Objective-C methods
                            unsigned long long pageZeroOffset = bi->executable ? [[bi->header segmentNamed:@"__TEXT"] vmaddr] : 0;

                            unsigned long long symbolAddress = 0;
                            if (bi->symbolAddresses == nil) {
                                bi->symbolAddresses = symbolAddressesForImageWithHeader(bi->header);
                            }
                            NSUInteger count = [bi->symbolAddresses count];
                            if (count != 0) {
                                NSNumber *targetAddress = [[NSNumber alloc] initWithUnsignedLongLong:(address - pageZeroOffset)];
                                CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)bi->symbolAddresses, CFRangeMake(0, count), targetAddress, (CFComparatorFunction)ReversedCompareNSNumber, NULL);
                                [targetAddress release];

                                if (matchIndex < count) {
                                    symbolAddress = [[bi->symbolAddresses objectAtIndex:matchIndex] unsignedLongLongValue] + pageZeroOffset;
                                }
                            }

                            MethodInfo *method = nil;
                            if (bi->methods == nil) {
                                bi->methods = methodsForImageWithHeader(bi->header);
                            }
                            count = [bi->methods count];
                            if (count != 0) {
                                MethodInfo *targetMethod = [[MethodInfo alloc] init];
                                targetMethod->impAddr = address;
                                CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)bi->methods, CFRangeMake(0, count), targetMethod, (CFComparatorFunction)ReversedCompareMethodInfos, NULL);
                                [targetMethod release];

                                if (matchIndex < count) {
                                    method = [bi->methods objectAtIndex:matchIndex];
                                }
                            }

                            if (symbolAddress != 0) {
                                if (method != nil && method->impAddr >= symbolAddress) {
                                    name = method->name;
                                    offset = address - method->impAddr;
                                } else {
                                    name = [NSString stringWithFormat:@"0x%08llx", (symbolAddress - pageZeroOffset)];
                                    offset = address - symbolAddress;
                                }
                            }
                        }

                        if (name != nil) {
                            lineComment = [NSString stringWithFormat:@"\t// %@ + 0x%llx", escapeHTML(name, escSet), offset];
                        }
                    }
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
    [extraInfoArray release];
    [filters release];
    [functionFilters release];
    [prefixFilters release];
    [reverseFilters release];
    [signalFilters release];

    /*
    if (isFilteredSignal) {
        for (NSString *name in binaryImages) {
            BinaryInfo *bi = [binaryImages objectForKey:name];
            if ([bi isKindOfClass:$BinaryInfo] && (bi->line & 0x80000000)) {
                isFilteredSignal = NO;
                break;
            }
        }
    }
    */

    if (!alreadySymbolicated) {
        // Write down blame info.
        NSMutableString *blameInfo = [NSMutableString stringWithString:@"\t<key>blame</key>\n\t<array>\n"];
        if (isFilteredSignal) {
            for (NSNumber *key in binaryImages) {
                BinaryInfo *bi = [binaryImages objectForKey:key];
                if ([bi isKindOfClass:$BinaryInfo] && bi->blamable) {
                    [blameInfo appendFormat:@"\t\t<array><string>%@</string><integer>%d</integer></array>\n", escapeHTML(bi->path, escSet), bi->line];
                }
            }
        }
        [blameInfo appendString:@"\t</array>"];
        [outputLines insertObject:blameInfo atIndex:[outputLines count] - 3];
        [binaryImages release];

        // Mark that this file has been symbolicated.
        [outputLines insertObject:@"\t<key>symbolicated</key>\n\t<true />" atIndex:[outputLines count] - 3];
    }

    [pool drain];

    [outputLines autorelease];
    return [outputLines componentsJoinedByString:@"\n"];
}

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
