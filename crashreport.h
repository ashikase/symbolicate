@class NSString, NSDictionary;

#ifdef __cplusplus
extern "C" {
#endif

NSString *symbolicate(NSString *content, NSDictionary *symbolMaps, unsigned progressStepping, NSArray **blameInfo);
NSArray *blame(NSString *exceptionType, NSDictionary *binaryImages, NSArray *backtraceLines);

#ifdef __cplusplus
}
#endif

/* vim: set ft=objc ff=unix sw=4 ts=4 tw=80 expandtab: */
