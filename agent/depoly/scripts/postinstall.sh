#!/usr/bin/env bash
root_dir="/etc/elkeid-agent"
service_unit="elkeid-agent.service"
sysvinit_script="elkeid-agentd"
sysvinit_dir="/etc/init.d/"
agent_ctl="elkeid-agentctl"
cgroup_dir="cgroup"
error(){
    echo -e "\e[91m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[ERRO]\t$1\e[0m"
}
warn(){
    echo -e "\e[93m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[WARN]\t$1\e[0m"
}
info(){
    echo -e "\e[96m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[INFO]\t$1\e[0m"
}
succ(){
    echo -e "\e[92m`date "+%Y-%m-%d %H:%M:%S.%3N"`\t[SUCC]\t$1\e[0m"
}
expect(){
    $1
    rtc=$?
    if [ $rtc -ne 0 ]; then
        if [ -n "$2" ]; then
            $2
        fi
	    error "when exec $1, an unexpected error occurred, code: $rtc"
	    exit $rtc
	fi
}
link_service() {
	info "linking agent's service"
	if command -v systemctl > /dev/null 2>&1; then
        info "found systemctl,linking service unit"
        expect "systemctl link ${root_dir}/${service_unit}"
        expect "systemctl enable ${root_dir}/${service_unit}" "systemctl disable ${service_unit}"
		service_type="systemd"
	elif command -v update-rc.d > /dev/null 2>&1; then
        expect "mkdir -p ${sysvinit_dir}"
		cp "${root_dir}/${sysvinit_script}" "${sysvinit_dir}"
		info "found update-rc.d, linking sysvinit script"
		expect "update-rc.d ${sysvinit_script} defaults" "rm -f ${sysvinit_dir}/${sysvinit_script}"
		service_type="sysvinit"
	elif command -v chkconfig > /dev/null 2>&1; then
        expect "mkdir -p ${sysvinit_dir}"
		cp "${root_dir}/${sysvinit_script}" "${sysvinit_dir}"
		info "found chkconfig, linking sysvinit script"
		expect "chkconfig --add ${sysvinit_script}" "rm -f ${sysvinit_dir}/${sysvinit_script}"
		service_type="sysvinit"
	else
		error "no compatible service daemon is available"
		exit 65
	fi
	expect "${root_dir}/${agent_ctl} set --service-type=${service_type}"
	succ "service linked successfully"
}
create_cgroups(){
    cat /proc/self/mountinfo|grep -q 'cgroup .* rw,memory'
    if [ $? -ne 0 ];then
        info "memory cgroup is umounted, trying mounting"
        expect "mkdir ${root_dir}/${cgroup_dir}/memory"
        expect "mount -t cgroup -o memory cgroup ${root_dir}/${cgroup_dir}/memory"
    fi
    cat /proc/self/mountinfo|grep -q 'cgroup .* rw,cpu'
    if [ $? -ne 0 ];then
        info "cpu cgroup is umounted, trying mounting"
        expect "mkdir ${root_dir}/${cgroup_dir}/cpu"
        expect "mount -t cgroup -o cpu cgroup ${root_dir}/${cgroup_dir}/cpu"
    fi
}
start_agent(){
    ${root_dir}/${agent_ctl} start
}
install(){
    link_service
    create_cgroups
    start_agent
    succ "installation finished successfully"
}
upgrade(){
    link_service
    start_agent
    succ "upgrade finished successfully"
}
install
# WORK_DIR="/etc/elkeid"
# PRODUCT_NAME="elkeid-agent"
# SERVICE_NAME="${PRODUCT_NAME}.service"

# chmod 700 ${WORK_DIR}/log
# chmod 701 ${WORK_DIR}/plugin
# chmod 700 ${WORK_DIR}/${PRODUCT_NAME}
# chmod 600 ${WORK_DIR}/${SERVICE_NAME}

# # when updating,envs will not be set.
# if [ -n "${SPECIFIED_IDC}" ];then
# echo "SPECIFIED_IDC=${SPECIFIED_IDC}" > ${WORK_DIR}/specified_env
# fi
# if [ -n "${SPECIFIED_AGENT_ID}" ];then
# echo "SPECIFIED_IDC=${SPECIFIED_AGENT_ID}" >> ${WORK_DIR}/specified_env
# fi

# systemctl link ${WORK_DIR}/${SERVICE_NAME}
# systemctl enable ${WORK_DIR}/${SERVICE_NAME}
# systemctl start ${SERVICE_NAME}