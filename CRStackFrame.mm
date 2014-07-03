#import "BacktraceInfo.h"

@implementation BacktraceInfo

- (void)dealloc {
    [_symbolInfo release];
    [super dealloc];
}

@end

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
