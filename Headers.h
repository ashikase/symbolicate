#ifndef SYMBOLICATE_HEADERS_H_
#define SYMBOLICATE_HEADERS_H_

typedef struct _VMURange {
    unsigned long long location;
    unsigned long long length;
} VMURange;

@interface VMUSymbolicator : NSObject @end

@interface VMUAddressRange : NSObject <NSCoding> @end
@interface VMUArchitecture : NSObject <NSCoding, NSCopying>
+ (id)architectureWithCpuType:(int)cpuType cpuSubtype:(int)subtype;
+ (id)currentArchitecture;
@end
@interface VMUDyld : NSObject
+ (id)nativeSharedCachePath;
@end
@interface VMUHeader : NSObject
+ (id)extractMachOHeadersFromHeader:(id)header matchingArchitecture:(id)architecture considerArchives:(BOOL)archives;
@end
@interface VMULoadCommand : NSObject @end
@interface VMUMachOHeader : VMUHeader
- (unsigned long long)address;
- (BOOL)isFromSharedCache;
- (id)loadCommands;
- (id)memory;
- (id)path;
- (id)segmentNamed:(id)named;
@end
@protocol VMUMemory <NSObject>
- (id)view;
@end
@protocol VMUMemoryView <NSObject>
- (void)advanceCursor:(unsigned long long)cursor;
- (unsigned long long)cursor;
- (void)setCursor:(unsigned long long)cursor;
- (id)stringWithEncoding:(unsigned)encoding;
- (unsigned)uint32;
@end
@interface VMUMemory_Base : NSObject @end
@interface VMUMemory_File : VMUMemory_Base <VMUMemory>
+ (id)headerFromSharedCacheWithPath:(id)path;
+ (id)headerWithPath:(id)path;
- (VMURange)addressRange;
- (void)buildSharedCacheMap;
- (id)initWithPath:(id)path fileRange:(VMURange)range mapToAddress:(unsigned long long)address architecture:(id)architecture;
@end
@interface VMUMemory_Handle : VMUMemory_Base <VMUMemory> @end
@interface VMUSourceInfo : VMUAddressRange <NSCopying>
- (unsigned)lineNumber;
- (id)path;
@end
@interface VMUSection : NSObject
- (unsigned)offset;
- (unsigned long long)size;
@end
@interface VMUSegmentLoadCommand : VMULoadCommand
- (unsigned long long)fileoff;
- (id)sectionNamed:(id)named;
- (unsigned long long)vmaddr;
@end
@interface VMUSymbol : VMUAddressRange <NSCopying>
- (VMURange)addressRange;
- (id)name;
@end
@interface VMUSymbolExtractor : NSObject
+ (id)extractSymbolOwnerFromHeader:(id)header;
@end
@interface VMUSymbolOwner : NSObject <NSCopying>
- (id)sourceInfoForAddress:(unsigned long long)address;
- (id)symbolForAddress:(unsigned long long)address;
@end

#endif // SYMBOLICATE_HEADERS_H_

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
