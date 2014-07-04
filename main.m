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

#import "crashreport.h"
#import "symbolMaps.h"

static void print_usage() {
    fprintf(stderr,
            "Usage: symbolicate [<options>] <file>\n"
            "\n"
            "Options:\n"
            "    -m <path,file>    Provide symbol map file for specified binary image path.\n"
            "                      If file ends with \".bz2\", bzip2 compression is assumed.\n"
            "    -n <step>         Send notifications of progress via notify_post().\n"
            "                      The notification name is \""PKG_ID".progress\".\n"
            "                      Progress percentage is obtainable via notify_get_state().\n"
            "                      Step value can be any integer 1-100.\n"
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
        NSMutableDictionary *mapFiles = [NSMutableDictionary dictionary];
        unsigned progressStepping = 0;

        int c;
        while ((c = getopt (argc, argv, "m:n:o:")) != -1) {
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
                    progressStepping = atoi(optarg);
                    break;
                case 'o':
                    outputFile = optarg;
                    break;
                default:
                    break;
            }
        }

        const char *inputFile = (optind < argc) ? argv[optind] : NULL;
        if (inputFile == NULL) {
            print_usage();
        } else {
            // Parse the log file.
            NSString *inputFileString = [[NSString alloc] initWithUTF8String:inputFile];
            CrashReport *report = [CrashReport crashReportWithFile:inputFileString];
            [inputFileString release];

            // Parse map files (optional).
            NSMutableDictionary *symbolMaps = [NSMutableDictionary dictionary];
            for (NSString *imagePath in mapFiles) {
                NSString *mapFile = [mapFiles objectForKey:imagePath];
                NSDictionary *result = parseMapFile(mapFile);
                if (result != nil) {
                    [symbolMaps setObject:result forKey:imagePath];
                } else {
                    fprintf(stderr, "WARNING: Unable to read map file \"%s\".\n", [mapFile UTF8String]);
                }
            }

#if 0
            // Symbolicate threads in the report.
            NSArray *blame = nil;
            NSString *result = symbolicate(description, symbolMaps, progressStepping, &blame);
            if (result != nil) {
                // Update the property list.
                NSMutableDictionary *newPlist = [plist mutableCopy];
                [newPlist setObject:result forKey:@"description"];

                // Update blame info.
                [newPlist setObject:blame forKey:@"blame"];

                // Mark that this file has been symbolicated.
                [newPlist setObject:[NSNumber numberWithBool:YES] forKey:@"symbolicated"];

                // Output the log file.
                NSString *filepath = (outputFile != NULL) ? [NSString stringWithUTF8String:outputFile] : nil;
                if (writeLogFile(newPlist, filepath, NO)) {
                    ret = 0;
                }
            }
#endif

            // Write out the log file.
            NSString *filepath = (outputFile != NULL) ? [[NSString alloc] initWithUTF8String:outputFile] : nil;
            [report writeToFile:filepath forcePropertyList:NO];
            [filepath release];
        }
    }

    [pool drain];
    return ret;
}

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
