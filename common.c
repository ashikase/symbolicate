/**
 * Name: symbolicate
 * Type: iOS/OS X shared command line tool
 * Desc: Tool for parsing and symbolicating iOS crash log files.
 *
 * Author: Lance Fetters (aka. ashikase)
 * License: GPL v3 (See LICENSE file for details)
 */

static unsigned char nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return 0xFF;
    }
}

unsigned long long unsignedLongLongFromHexString(const char* str, int len) {
    unsigned long long res = 0;
    int i;
    for (i = 0; i < len; ++ i) {
        unsigned char n = nibble(str[i]);
        if (n != 0xFF) {
            res = res * 16 + n;
        }
    }
    return res;
}
