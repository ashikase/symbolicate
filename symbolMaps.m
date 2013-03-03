#import "symbolMaps.h"

#import "RegexKitLite.h"
#include "common.h"

// NOTE: It seems that older SDKs (iOS 3.0 and earlier?) do not include bzlib.h.
//#include <bzlib.h>
#define BZ_OK 0
#define BZ_STREAM_END 4

typedef struct {
    char *next_in;
    unsigned int avail_in;
    unsigned int total_in_lo32;
    unsigned int total_in_hi32;
    char *next_out;
    unsigned int avail_out;
    unsigned int total_out_lo32;
    unsigned int total_out_hi32;
    void *state;
    void *(*bzalloc)(void *,int,int);
    void (*bzfree)(void *,void *);
    void *opaque;
} bz_stream;

extern int BZ2_bzDecompressInit(bz_stream *strm, int verbosity, int small);
extern int BZ2_bzDecompress(bz_stream* strm);
extern int BZ2_bzDecompressEnd(bz_stream *strm);

static NSData *bunzip2(NSData *inputData) {
    NSMutableData *outputData = [NSMutableData data];

    const int bufSize = 4096;
    NSMutableData *buf = [NSMutableData dataWithLength:bufSize];
    bz_stream stream = {0};
    stream.next_in = (char *)[inputData bytes];
    stream.avail_in = [inputData length];

    BZ2_bzDecompressInit(&stream, 0, 0);
    int ret;
    do {
        stream.next_out = [buf mutableBytes];
        stream.avail_out = bufSize;
        ret = BZ2_bzDecompress(&stream);
        if (ret != BZ_OK && ret != BZ_STREAM_END) {
            break;
        }
        [outputData appendBytes:[buf bytes] length:(bufSize - stream.avail_out)];
    } while (ret != BZ_STREAM_END);
    BZ2_bzDecompressEnd(&stream);

    return outputData;
}

NSDictionary *parseMapFile(NSString *mapFile) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    if (![[NSFileManager defaultManager] fileExistsAtPath:mapFile]) {
        return nil;
    }

    NSString *content = nil;
    if ([[mapFile pathExtension] isEqualToString:@"bz2"]) {
        NSData *data = [[NSData alloc] initWithContentsOfFile:mapFile];
        content = [[NSString alloc] initWithData:bunzip2(data) encoding:NSASCIIStringEncoding];
        [data release];
    } else {
        content = [[NSString alloc] initWithContentsOfFile:mapFile encoding:NSASCIIStringEncoding error:NULL];
    }

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
                            unsigned long long address = unsignedLongLongFromHexString([matches[0] UTF8String], [matches[0] length]);
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
