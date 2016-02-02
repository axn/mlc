include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ana
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/ana
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Analysis tools for mesh routing protocols
  URL:=http://dev.qmp.cat/ana
  DEPENDS:=\
	+coreutils +coreutils-timeout +coreutils-kill +less \
	+iputils-ping6 +iputils-ping +iputils-tracepath +iputils-tracepath6 +iputils-traceroute6 \
	+ip-full +ipip \
	+libpolarssl +zlib +kmod-ip6-tunnel +kmod-iptunnel6 +kmod-tun \
	+iw  +wireless-tools \
	+iptables +ip6tables 


# and deselect if needed: odhcpc ppp wpad-mini hostapd 
#       +netcat
#       +mtr +netperf 
#	+@BUSYBOX_CONFIG_KILLALL5


endef

define Package/ana/description
	Analysis tools for mesh routing protocols
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/ana/install
	$(INSTALL_DIR) $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/dropbear/
	$(INSTALL_DIR) $(1)/etc/config/
	$(CP) ./files/etc/dropbear/* $(1)/etc/dropbear/
	$(CP) ./files/etc/config/* $(1)/etc/config/
endef


$(eval $(call BuildPackage,ana))


