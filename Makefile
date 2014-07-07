TOOL_NAME = symbolicate
PKG_ID = jp.ashikase.symbolicate

symbolicate_INSTALL_PATH = /usr/bin
symbolicate_OBJC_FILES = \
    common.c \
    main.m \
    symbolMaps.m
symbolicate_LDFLAGS = -lbz2 -licucore -lsymbolicate
symbolicate_PRIVATE_FRAMEWORKS = Symbolication
ADDITIONAL_CFLAGS = -DPKG_ID=\"$(PKG_ID)\" -ILibraries

ARCHS = armv6
TARGET = iphone
TARGET_IPHONEOS_DEPLOYMENT_VERSION = 3.0

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
