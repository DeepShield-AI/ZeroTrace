Name:       zerotrace-agent_docker
Version:    1.0
Release:    %(git rev-list --count HEAD)%{?dist}
Summary:    zerotrace agent docker

Group:      Applications/File
Vendor:     Yunshan Networks
License:    Copyright (c) 2012-2022 Yunshan Netwoks
URL:        http://yunshan.net
Source:     zerotrace-agent_docker.spec

%define pwd %(echo $PWD)
%define full_version %{version}-%{release}

%description
zerotrace agent docker

%prep
mkdir -p $RPM_BUILD_ROOT/temp/
cp -r %pwd/output $RPM_BUILD_ROOT/temp/
cp %pwd/config/zerotrace-agent.yaml $RPM_BUILD_ROOT/temp/
cp %pwd/docker/dockerfile $RPM_BUILD_ROOT/temp/
cp %pwd/docker/zerotrace-agent-cm.yaml $RPM_BUILD_ROOT/temp/
mkdir -p $RPM_BUILD_ROOT/temp/docker/
(cd $RPM_BUILD_ROOT/temp/ &&
    docker build -t zerotrace-agent:%full_version . --load &&
    docker save -o zerotrace-agent-%full_version.tar zerotrace-agent:%full_version &&
    tar zcvf zerotrace-agent-%full_version.tar.gz zerotrace-agent-%full_version.tar &&
    cat zerotrace-agent.yaml >> zerotrace-agent-cm.yaml &&
    sed -i '9,$s/^/    /g' zerotrace-agent-cm.yaml
)
mkdir -p $RPM_BUILD_ROOT/tmp/zerotrace-agent
cp $RPM_BUILD_ROOT/temp/zerotrace-agent-%full_version.tar.gz $RPM_BUILD_ROOT/tmp/zerotrace-agent
cp $RPM_BUILD_ROOT/temp/zerotrace-agent-cm.yaml $RPM_BUILD_ROOT/tmp/zerotrace-agent
cp %pwd/docker/zerotrace-agent-ds.yaml $RPM_BUILD_ROOT/tmp/zerotrace-agent
(cd $RPM_BUILD_ROOT/tmp &&
    tar zcvf zerotrace-agent_%full_version.tar.gz zerotrace-agent/ &&
    rm -rf zerotrace-agent/ && cd $RPM_BUILD_ROOT && rm -rf temp/
)

%files
/tmp/zerotrace-agent_%full_version.tar.gz

%post
tar xf /tmp/zerotrace-agent_%full_version.tar.gz -C /tmp/
(cd /tmp/zerotrace-agent && tar xf zerotrace-agent-%full_version.tar.gz && rm -rf zerotrace-agent-%full_version.tar.gz)
rm -rf /tmp/zerotrace-agent_%full_version.tar.gz
