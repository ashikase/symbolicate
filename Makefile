TOOL_NAME = symbolicate
PKG_ID = jp.ashikase.symbolicate

symbolicate_INSTALL_PATH = /usr/bin
symbolicate_OBJC_FILES = \
    common.c\
    localSymbols.mm \
    main.m \
    RegexKitLite.m \
    symbolicate.mm \
    symbolMaps.m
symbolicate_LDFLAGS = -lbz2 -licucore
symbolicate_PRIVATE_FRAMEWORKS = Symbolication
ADDITIONAL_CFLAGS = -DPKG_ID=\"$(PKG_ID)\"

TARGET = iphone:3.0
#ARCHS =
#SDKTARGET = arm-apple-darwin11
#TARGET_CXX = clang -ccc-host-triple $(SDKTARGET)
#TARGET_LD = $(SDKTARGET)-g++
#TARGET_CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE)

include theos/makefiles/common.mk
include $(THEOS)/makefiles/tool.mk

after-stage::
	# Optimize png files
	- find $(THEOS_STAGING_DIR) -iname '*.png' -exec pincrush -i {} \;
	# Convert plist files to binary
	- find $(THEOS_STAGING_DIR)/ -type f -iname '*.plist' -exec plutil -convert binary1 {} \;
	# Remove repository-related files
	- find $(THEOS_STAGING_DIR) -name '.gitkeep' -delete

distclean: clean
	- rm -f $(THEOS_PROJECT_DIR)/$(APP_ID)*.deb
	- rm -f $(THEOS_PROJECT_DIR)/.theos/packages/*
