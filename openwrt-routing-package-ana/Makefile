include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ana
PKG_VERSION:=1.0.1
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
	+coreutils +coreutils-timeout +coreutils-kill \
	+iputils-ping6 +iputils-ping +iputils-tracepath +iputils-tracepath6 \
	+ip-full +ipip +iperf-mt \
	+libpolarssl +zlib +kmod-ip6-tunnel +kmod-iptunnel6 +kmod-tun \
	+iw +wireless-tools +libiwinfo \
	+iptables +ip6tables 


# and deselect if needed: odhcpc ppp wpad-mini hostapd 
#  +less  +iwinfo
#       +netcat
#   	+iputils-traceroute6
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
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(CP) ./files/etc/dropbear/* $(1)/etc/dropbear/
	$(CP) ./files/etc/config/* $(1)/etc/config/
	$(CP) ./files/etc/init.d/* $(1)/etc/init.d/
endef


$(eval $(call BuildPackage,ana))


