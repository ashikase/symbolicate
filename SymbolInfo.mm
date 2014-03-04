#import "SymbolInfo.h"

@implementation SymbolInfo

- (void)dealloc {
    [_name release];
    [_sourcePath release];
    [super dealloc];
}

@end

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
