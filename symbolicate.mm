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

#import "BacktraceInfo.h"
#import "BinaryInfo.h"
#import "MethodInfo.h"
#import "SymbolInfo.h"

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

static uint64_t uint64FromHexString(NSString *string) {
    return (uint64_t)unsignedLongLongFromHexString([string UTF8String], [string length]);
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

SymbolInfo *fetchSymbolInfo(BinaryInfo *bi, uint64_t address, NSDictionary *symbolMap) {
    SymbolInfo *symbolInfo = nil;

    VMUMachOHeader *header = [bi header];
    if (header != nil) {
        address += [bi slide];
        VMUSymbolOwner *owner = [bi owner];
        VMUSourceInfo *srcInfo = [owner sourceInfoForAddress:address];
        if (srcInfo != nil) {
            // Store source file name and line number.
            symbolInfo = [SymbolInfo new];
            [symbolInfo setSourcePath:[srcInfo path]];
            [symbolInfo setSourceLineNumber:[srcInfo lineNumber]];
        } else {
            // Determine symbol address.
            // NOTE: Only possible if LC_FUNCTION_STARTS exists in the binary.
            uint64_t symbolAddress = 0;
            NSArray *symbolAddresses = [bi symbolAddresses];
            NSUInteger count = [symbolAddresses count];
            if (count != 0) {
                NSNumber *targetAddress = [[NSNumber alloc] initWithUnsignedLongLong:address];
                CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)symbolAddresses, CFRangeMake(0, count), targetAddress, (CFComparatorFunction)reversedCompareNSNumber, NULL);
                [targetAddress release];
                if (matchIndex < (CFIndex)count) {
                    symbolAddress = [[symbolAddresses objectAtIndex:matchIndex] unsignedLongLongValue];
                }
            }

            // Attempt to retrieve symbol name and hex offset.
            NSString *name = nil;
            uint64_t offset = 0;
            VMUSymbol *symbol = [owner symbolForAddress:address];
            if (symbol != nil && ([symbol addressRange].location == (symbolAddress & ~1) || symbolAddress == 0)) {
                name = [symbol name];
                if ([name isEqualToString:@"<redacted>"]) {
                    BOOL hasHeaderFromSharedCacheWithPath = [VMUMemory_File respondsToSelector:@selector(headerFromSharedCacheWithPath:)];
                    if (hasHeaderFromSharedCacheWithPath) {
                        NSString *localName = nameForLocalSymbol([header address], [symbol addressRange].location);
                        if (localName != nil) {
                            name = localName;
                        } else {
                            fprintf(stderr, "Unable to determine name for: %s, 0x%08llx\n", [[bi path] UTF8String], [symbol addressRange].location);
                        }
                    }
                }
                // Attempt to demangle name
                // NOTE: It seems that Apple's demangler fails for some
                //       names, so we attempt to do it ourselves.
                name = demangle(name);
                offset = address - [symbol addressRange].location;
            } else if (symbolMap != nil) {
                for (NSNumber *number in [[[symbolMap allKeys] sortedArrayUsingSelector:@selector(compare:)] reverseObjectEnumerator]) {
                    uint64_t mapSymbolAddress = [number unsignedLongLongValue];
                    if (address > mapSymbolAddress) {
                        name = demangle([symbolMap objectForKey:number]);
                        offset = address - mapSymbolAddress;
                        break;
                    }
                }
            } else if (![bi isEncrypted]) {
                // Determine methods, attempt to match with symbol address.
                if (symbolAddress != 0) {
                    MethodInfo *method = nil;
                    NSArray *methods = [bi methods];
                    count = [methods count];
                    if (count != 0) {
                        MethodInfo *targetMethod = [[MethodInfo alloc] init];
                        targetMethod->address = address;
                        CFIndex matchIndex = CFArrayBSearchValues((CFArrayRef)methods, CFRangeMake(0, count), targetMethod, (CFComparatorFunction)reversedCompareMethodInfos, NULL);
                        [targetMethod release];

                        if (matchIndex < (CFIndex)count) {
                            method = [methods objectAtIndex:matchIndex];
                        }
                    }

                    if (method != nil && method->address >= symbolAddress) {
                        name = method->name;
                        offset = address - method->address;
                    } else {
                        uint64_t textStart = [[header segmentNamed:@"__TEXT"] vmaddr];
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

    return symbolInfo;
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
                    bi = [[BinaryInfo alloc] initWithPath:matches[2] address:uint64FromHexString(matches[0])];
                    [bi setBlamable:YES];
                    [binaryImages setObject:bi forKey:imageAddress];
                    [bi release];
                }

                NSString *lineComment = nil;
                NSDictionary *symbolMap = [symbolMaps objectForKey:[bi path]];
                SymbolInfo *symbolInfo = fetchSymbolInfo(bi, bti->address, symbolMap);
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
                         bti->address, bti->imageAddress, bti->address - bti->imageAddress];
                NSString *newLine = [[NSString alloc] initWithFormat:@"%-6u%s%-30s\t%-32s%@",
                         bti->depth, [bi isBlamable] ? "+ " : "  ",
                         [[[[bi path] lastPathComponent] stringByAppendingString:([bi isExecutable] ? @" (*)" : @"")] UTF8String],
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
                BOOL blamable = YES;
                if (hasHeaderFromSharedCacheWithPath && [[bi header] isFromSharedCache]) {
                    // Don't blame anything from the shared cache.
                    blamable = NO;
                } else {
                    // Don't blame white-listed libraries.
                    NSString *path = [bi path];
                    if ([filters containsObject:path]) {
                        blamable = NO;
                    } else {
                        // Don't blame white-listed folders.
                        for (NSString *prefix in prefixFilters) {
                            if ([path hasPrefix:prefix]) {
                                blamable = NO;
                                break;
                            }
                        }
                    }
                }
                if (!blamable) {
                    [bi setBlamable:NO];
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
                    NSInteger line = [bi line];
                    if ([bi isBlamable] && (line == 0 || ((line & 0x80000000) && isCrashing))) {
                        // Blame.
                        line = i;
                        // Make it a secondary suspect if it isn't in the crashing thread.
                        if (!isCrashing) {
                            line |= 0x80000000;
                        }
                        [bi setLine:line];
                    }

                    // Check symbol name of system functions against blame filters.
                    if ([[bi path] isEqualToString:@"/usr/lib/libSystem.B.dylib"]) {
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
            if ([bi isKindOfClass:$BinaryInfo] && [bi isBlamable]) {
                NSArray *array = [[NSArray alloc] initWithObjects:[bi path], [NSNumber numberWithUnsignedInteger:[bi line]], nil];
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
