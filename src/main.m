/**
 * Name: symbolicate
 * Type: iOS/OS X shared command line tool
 * Desc: Tool for parsing and symbolicating iOS crash log files.
 *
 * Author: Lance Fetters (aka. ashikase)
 * License: GPL v3 (See LICENSE file for details)
 */

#include <getopt.h>
#include <notify.h>
#include <string.h>

#import <libcrashreport/libcrashreport.h>
#import "symbolMaps.h"

static void print_usage() {
    fprintf(stderr,
            "Usage: symbolicate [<options>] <file>\n"
            "\n"
            "Options:\n"
            "    --blame-only      Process blame without symbolicating.\n"
            "                      Note that function filters will not work in this case.\n"
            "    -m <path,file>    Provide symbol map file for specified binary image path.\n"
            "                      If file ends with \".bz2\", bzip2 compression is assumed.\n"
            "    -o <file>         Write output to file instead of to stdout.\n"
            "    --print-blame     Print just list of suspects, from most to least likely.\n"
            "    --sysroot=<path>  Use 'path' as the root path when loading binaries and shared caches.\n"
            "                      (e.g. <sysroot>/System/Library/Caches/com.apple.dyld/dyld...)\n"
            "\n"
           );
}

int main(int argc, char *argv[]) {
    int ret = 1;

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if (argc == 1) {
        print_usage();
    } else {
        const char *outputFile = NULL;
        const char *sysroot = NULL;
        NSMutableDictionary *mapFiles = [NSMutableDictionary new];
        BOOL shouldSymbolicate = YES;
        BOOL shouldPrintBlame = NO;

        int blameOnlyFlag = 0;
        int printBlameFlag = 0;
        struct option longopts[] = {
            { "blame-only", no_argument, &blameOnlyFlag, 1 },
            { "print-blame", no_argument, &printBlameFlag, 1 },
            { "sysroot", required_argument, NULL, '/' },
            { NULL, 0, NULL, 0 }
        };

        int c;
        while ((c = getopt_long(argc, argv, "m:n:o:", longopts, NULL)) != -1) {
            switch (c) {
                case 'm': {
                    char *path = strtok(optarg, ",");
                    char *file = strtok(NULL, ",");
                    if (path != NULL && file != NULL) {
                        [mapFiles setObject:[NSString stringWithCString:file encoding:NSUTF8StringEncoding]
                            forKey:[NSString stringWithCString:path encoding:NSUTF8StringEncoding]];
                    }
                    break;
                }
                case 'n':
                    break;
                case 'o':
                    outputFile = optarg;
                    break;
                case '/':
                    sysroot = optarg;
                    break;
                case 0:
                    shouldSymbolicate = (blameOnlyFlag == 0);
                    shouldPrintBlame = (printBlameFlag == 1);
                    break;
                default:
                    print_usage();
                    goto exit;
            }
        }

        const char *inputFile = (optind < argc) ? argv[optind] : NULL;
        if (inputFile == NULL) {
            print_usage();
        } else {
            // Parse the log file.
            NSString *inputFileString = [[NSString alloc] initWithUTF8String:inputFile];
            CRCrashReport *report = [CRCrashReport crashReportWithFile:inputFileString];
            [inputFileString release];
            if (report == nil) {
                goto exit;
            }

            if (shouldSymbolicate) {
                // Parse map files (optional).
                NSMutableDictionary *symbolMaps = [NSMutableDictionary new];
                for (NSString *imagePath in mapFiles) {
                    NSString *mapFile = [mapFiles objectForKey:imagePath];
                    NSDictionary *result = parseMapFile(mapFile);
                    if (result != nil) {
                        [symbolMaps setObject:result forKey:imagePath];
                    } else {
                        fprintf(stderr, "WARNING: Unable to read map file \"%s\".\n", [mapFile UTF8String]);
                    }
                }
                [mapFiles release];

                // Set system root to use.
                NSString *systemRoot = nil;
                if (sysroot != NULL) {
                    systemRoot = [[NSString alloc] initWithFormat:@"%s", sysroot];
                }

                // Symbolicate threads in the report.
                if (![report symbolicateUsingSystemRoot:systemRoot symbolMaps:symbolMaps]) {
                    fprintf(stderr, "WARNING: Failed to symbolicate.\n");
                }
                [systemRoot release];
                [symbolMaps release];
            }

            // Load blame filters.
            NSDictionary *filters = [[NSDictionary alloc] initWithContentsOfFile:@"/etc/symbolicate/blame_filters.plist"];

            // Process blame.
            if (![report blameUsingFilters:filters]) {
                fprintf(stderr, "WARNING: Failed to process blame.\n");
            }
            [filters release];

            // Determine what to output.
            NSString *outputString = nil;
            if (shouldPrintBlame) {
                // Output the blame.
                NSMutableString *string = [NSMutableString string];
                NSArray *blame = [[report properties] objectForKey:kCrashReportBlame];
                for (NSString *suspect in blame) {
                    [string appendString:suspect];
                    [string appendString:@"\n"];
                }
                outputString = string;
            } else {
                // Output the log file.
                outputString = [report stringRepresentation];
            }

            // Write out the output.
            NSString *filepath = (outputFile != NULL) ? [[NSString alloc] initWithUTF8String:outputFile] : nil;
            if (filepath != nil) {
                // Write to file.
                NSError *error = nil;
                if ([outputString writeToFile:filepath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
                    fprintf(stderr, "INFO: Result written to %s.\n", [filepath UTF8String]);
                } else {
                    fprintf(stderr, "ERROR: Unable to write to file: %s.\n", [[error localizedDescription] UTF8String]);
                }
                [filepath release];
            } else {
                // Print to screen.
                printf("%s", [outputString UTF8String]);
            }

            // Send notification of completion.
            // NOTE: This is for backwards-compatibility. Some packages that
            //       call symbolicate expect to be notified with status updates.
            int token;
            notify_register_check(PKG_ID".progress", &token);
            notify_set_state(token, 100);
            notify_post(PKG_ID".progress");

            ret = 0;
        }
    }

exit:
    // FIXME: Is it actually necessary to drain the pool on exit?
    //        Draining the pool is actually quite slow.
    [pool drain];
    return ret;
}

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
