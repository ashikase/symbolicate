#ifndef SYMBOLICATE_LOCALSYMBOLS_H_
#define SYMBOLICATE_LOCALSYMBOLS_H_

#ifdef __cplusplus
extern "C" {
#endif

NSString *nameForLocalSymbol(uint32_t dylibOffset, uint32_t symbolAddress);

#ifdef __cplusplus
}
#endif

#endif // SYMBOLICATE_LOCALSYMBOLS_H_
