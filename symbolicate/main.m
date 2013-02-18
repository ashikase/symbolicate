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

#import <UIKit/UIKit.h>
#import "symbolicate.h"
#include <string.h>

int main (int argc, char *argv[]) {
    int ret = 1;

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if (argc > 1) {
        NSString *filepath = [NSString stringWithUTF8String:argv[1]];
        NSString *content = [NSString stringWithContentsOfFile:filepath encoding:NSUTF8StringEncoding error:NULL];
        if (content != nil) {
            NSString *result = symbolicate(content, nil);
            if (result != nil) {
                printf("%s\n", [result UTF8String]);
                ret = 0;
            }
        }
#if 0
        NSString *symbolicatedFile = [[[file stringByDeletingPathExtension] stringByAppendingString:@".symbolicated.plist"] retain];
        NSString *lines_to_write = [file_lines componentsJoinedByString:@"\n"];
        [file_lines release];
        if (![lines_to_write writeToFile:symbolicatedFile atomically:NO encoding:NSUTF8StringEncoding error:NULL]) {
            char temp_name[strlen("/tmp/crash_reporter.XXXXXX") + 1];
            memcpy(temp_name, "/tmp/crash_reporter.XXXXXX", sizeof(temp_name));
            mktemp(temp_name);
            [lines_to_write writeToFile:[NSString stringWithUTF8String:temp_name] atomically:NO encoding:NSUTF8StringEncoding error:NULL];
            const char *actual_sym_file_path = [[curPath stringByAppendingPathComponent:symbolicatedFile] UTF8String];
            const char *actual_file_path = [[curPath stringByAppendingPathComponent:file] UTF8String];

            exec_move_as_root(temp_name, actual_sym_file_path, actual_file_path);
        }

        printf("Result written to %s.\n", [result UTF8String]);
#endif
    }

    [pool drain];
    return ret;
}

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
