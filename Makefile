include $(TOPDIR)/rules.mk

PKG_NAME:=gduth3c
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
        SECTION:=utils
        CATEGORY:=Utilities
        PKG_BUILD_DEPENDS:=+libopenssl
        TITLE:=GDUT H3C client
endef

define Package/$(PKG_NAME)/description
      	A CLI Client for H3C
endef

#非本目录下的源码文件, 拷贝到此相应目录下.
# 如../../xucommon/xucommon.c, 则将 xucommon.c 拷贝到此目录下的源码的 ../../ 
define Build/Prepare
		mkdir -p $(PKG_BUILD_DIR)
		$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
		$(INSTALL_DIR) $(1)/usr/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/gduth3c $(1)/usr/bin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
