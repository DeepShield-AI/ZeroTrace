Name:       zerotrace-agent
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    zerotrace agent

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2016 Yunshan Netwoks
URL:        http://yunshan.net
Source:     zerotrace-agent.spec

Requires(post): libpcap %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
Autoreq: 0

%define pwd %(echo $PWD)

%description
Zerotrace Agent

%prep
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/target/release/zerotrace-agent $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/target/release/zerotrace-agent-ctl $RPM_BUILD_ROOT/usr/sbin/
cp %pwd/output/src/ebpf/zerotrace-ebpfctl $RPM_BUILD_ROOT/usr/sbin/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp %pwd/output/target/release/ecapture  $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system/
cp %pwd/pkg/zerotrace-agent.service $RPM_BUILD_ROOT/lib/systemd/system/
mkdir -p $RPM_BUILD_ROOT/etc/
cp %pwd/config/zerotrace-agent.yaml $RPM_BUILD_ROOT/etc/

%files
/usr/sbin/zerotrace-agent
/usr/bin/ecapture
/lib/systemd/system/zerotrace-agent.service
%config(noreplace) /etc/zerotrace-agent.yaml

%preun
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ $1 == 0 ]; then # uninstall
        sed -i '/:\/usr\/sbin\/trident/d' /etc/inittab
        init q
    fi
else
    if [ $1 == 0 ]; then # uninstall
        systemctl stop zerotrace-agent
        systemctl disable zerotrace-agent
    fi
fi

%post
# sles: suse linux
if [ -n "`grep sles /etc/os-release`" ]; then
    if [ -n "`grep 'trid:' /etc/inittab`" ]; then
        echo 'inittab entry "trid" already exists!'
        exit 1
    fi
    sed -i '/:\/usr\/sbin\/zerotrace\-agent/d' /etc/inittab
    echo 'trid:2345:respawn:/usr/sbin/zerotrace-agent' >>/etc/inittab
    init q
else
    systemctl daemon-reload
    systemctl try-restart zerotrace-agent
    [ -f /etc/zerotrace-agent.yaml.sample ] || cp /etc/zerotrace-agent.yaml{,.sample}
fi

%postun
# sles: suse linux
if [ -z "`grep sles /etc/os-release`" ]; then
    systemctl daemon-reload
fi

%changelog

%package -n %{name}-tools
Summary:    zerotrace-agent tools

%description -n %{name}-tools
Zerotrace Agent debug tools

%files -n %{name}-tools
/usr/sbin/zerotrace-agent-ctl
/usr/sbin/zerotrace-ebpfctl
