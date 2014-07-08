/*

main.m ... Main for CrashReporter
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

#include <getopt.h>
#include <string.h>

#import <libsymbolicate/CRCrashReport.h>
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
        NSMutableDictionary *mapFiles = [NSMutableDictionary new];
        BOOL shouldSymbolicate = YES;

        int blameOnlyFlag = 0;
        struct option longopts[] = {
            { "blame-only", no_argument, &blameOnlyFlag, 1 },
            { NULL, 0, NULL, 0 }
        };

        int c;
        while ((c = getopt_long(argc, argv, "m:o:", longopts, NULL)) != -1) {
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
                case 'o':
                    outputFile = optarg;
                    break;
                case 0:
                    shouldSymbolicate = (blameOnlyFlag == 0);
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

                // Symbolicate threads in the report.
                if (![report symbolicateUsingSymbolMaps:symbolMaps]) {
                    fprintf(stderr, "WARNING: Failed to symbolicate.");
                }
                [symbolMaps release];
            }

            // Load blame filters.
            NSDictionary *filters = [[NSDictionary alloc] initWithContentsOfFile:@"/etc/symbolicate/whitelist.plist"];

            // Process blame.
            if (![report blameUsingFilters:filters]) {
                fprintf(stderr, "WARNING: Failed to process blame.");
            }
            [filters release];

            // Write out the log file.
            NSString *filepath = (outputFile != NULL) ? [[NSString alloc] initWithUTF8String:outputFile] : nil;
            [report writeToFile:filepath forcePropertyList:NO];
            [filepath release];
        }
    }

exit:
    [pool drain];
    return ret;
}

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
