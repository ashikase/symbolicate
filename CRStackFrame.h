@class SymbolInfo;

@interface BacktraceInfo : NSObject {
    @package
        NSUInteger depth;
        uint64_t imageAddress;
        uint64_t address;
}
@property(nonatomic, retain) SymbolInfo *symbolInfo;
@end

/* vim: set ft=objcpp ff=unix sw=4 ts=4 tw=80 expandtab: */
