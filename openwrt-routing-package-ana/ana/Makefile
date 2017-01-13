include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ana
PKG_VERSION:=1.0.7
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
	+ip-full +ipip \
	+zlib +kmod-ip6-tunnel +kmod-iptunnel6 +kmod-tun \
	+iw +wireless-tools +libiwinfo \
	+iptables +ip6tables \
	+iperf3 \
	+libmbedtls

#	+iperf-mt 
#	+libpolarssl
#
# and deselect if needed: odhcpc ppp wpad-mini hostapd 
#  +less  +iwinfo
#       +netcat
#   	+iputils-traceroute6
#       +mtr +netperf 
#	+@BUSYBOX_CONFIG_KILLALL5

# DISABLE anything non-mandatory in make Menuconfig: network

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
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/dropbear
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) ./files/etc/dropbear/* $(1)/etc/dropbear/
	$(CP) ./files/etc/config/* $(1)/etc/config/
	$(INSTALL_BIN) ./files/etc/uci-defaults/99_ana $(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/etc/init.d/ana $(1)/etc/init.d/
endef

define Package/ana/postinst
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
        cp /etc/dropbear/authorized_keys.ana        /etc/dropbear/authorized_keys
	cp /etc/dropbear/dropbear_dss_host_key.ana  /etc/dropbear/dropbear_dss_host_key
	cp /etc/dropbear/dropbear_rsa_host_key.ana  /etc/dropbear/dropbear_rsa_host_key
fi
exit 0
endef


$(eval $(call BuildPackage,ana))


