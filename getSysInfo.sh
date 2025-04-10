#!/bin/bash

# 检查是否为root用户执行
if [ "$(id -u)" -ne 0 ]; then
   echo "错误: 请使用root用户执行此脚本"
   echo "Error: This script must be run as root"
   exit 1
fi

# 记录检测时间
DETECTION_TIME=$(date +'%Y-%m-%d %H:%M:%S')

# 初始化用于存储标题和值的数组
declare -a categories=()
declare -a values=()

# 函数：获取数据，格式化，并添加到数组
# 参数1: 类别名称
# 参数2: 要调用的函数名
# 参数3...: 传递给函数的参数 [可选]
store_formatted_data() {
    local category="$1"
    local function_name="$2"
    shift 2 # 移除 category 和 function_name，剩下的是参数
    local args=("$@") # 将剩余参数存入数组
    local data
    local formatted_data
    local needs_quoting=0 # 标记是否需要加引号

    # 直接调用函数名，并将参数传递给它，抑制 stderr
    if command -v "$function_name" > /dev/null; then
        data=$("$function_name" "${args[@]}" 2>/dev/null)
    else
        data="Error: Function $function_name not found"
    fi

    # 1. 处理内部的双引号：替换为两个双引号 ""
    formatted_data=$(echo "$data" | sed 's/"/""/g')

    # 2. 检查是否包含逗号或原始双引号 (在 sed 转义前)
    case "$formatted_data" in
        *[,]* | *""*) needs_quoting=1 ;; # 检查逗号或已转义的双引号
    esac

    # 3. 检查是否包含换行符 (使用 POSIX printf 和 grep)
    if [ "$needs_quoting" -eq 0 ]; then
        # 使用普通的换行检测
        if printf "%s" "$formatted_data" | grep -q "
"; then
            needs_quoting=1
        fi
    fi

    # 4. 如果需要，添加外部引号
    if [ "$needs_quoting" -eq 1 ]; then
        formatted_data="\"$formatted_data\""
    fi

    # 将类别和格式化后的值添加到数组
    categories+=("$category")
    values+=("$formatted_data")
}

# --- 数据获取函数 [部分函数被拆分或移除] ---

# 1. 主机名
get_hostname() {
    hostname
}
store_formatted_data "Hostname" get_hostname

# 1.5 默认IPv4地址
get_default_ipv4() {
    local default_iface default_ipv4
    
    # 通过默认网关查找接口
    default_iface=$(ip route show default 2>/dev/null | awk '/default via/ {print $5}' | head -n1)
    if [ -n "$default_iface" ]; then
        # 从找到的接口获取IPv4地址
        default_ipv4=$(ip -4 addr show dev "$default_iface" 2>/dev/null | grep -oP 'inet \K[^/]+' | head -n1)
    fi
    
    # 如果没有默认路由，尝试获取第一个非回环的IPv4地址
    if [ -z "$default_ipv4" ]; then
        default_ipv4=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[^/]+' | grep -v '127.0.0.1' | head -n1)
    fi
    
    echo "${default_ipv4:-无}"
}
store_formatted_data "Default_IPv4" get_default_ipv4

# 1.6 默认IPv6地址
get_default_ipv6() {
    local default_iface default_ipv6
    
    # 通过默认网关查找接口
    default_iface=$(ip -6 route show default 2>/dev/null | awk '/default via/ {print $5}' | head -n1)
    if [ -n "$default_iface" ]; then
        # 从找到的接口获取IPv6地址（排除链路本地地址）
        default_ipv6=$(ip -6 addr show dev "$default_iface" scope global 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80::' | head -n1)
    fi
    
    # 如果没有默认路由，尝试获取第一个非链路本地的全局IPv6地址
    if [ -z "$default_ipv6" ]; then
        default_ipv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80::' | head -n1)
    fi
    
    echo "${default_ipv6:-无}"
}
store_formatted_data "Default_IPv6" get_default_ipv6

# 2. 网卡和 IP 地址 [保持聚合]
get_ip_info() {
    local default_iface
    local output=""
    
    # 获取默认网卡，不依赖外部网络
    default_iface=$(ip route show default 2>/dev/null | awk '/default via/ {print $5}' | head -n1)
    
    local interfaces
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1)
    for iface in $interfaces; do
        local status state ips ip_list mac
        status_line=$(ip link show dev "$iface" 2>/dev/null | head -n1)
        if [ -z "$status_line" ]; then continue; fi
        state_field=$(echo "$status_line" | awk '/ state / {print $9}')
        link_status=$(echo "$status_line" | awk -F'[<>]' '{print $2}')
        
        # 获取MAC地址
        mac=$(ip link show dev "$iface" 2>/dev/null | grep -o 'link/[^ ]* [^ ]*' | awk '{print $2}')
        if [ -z "$mac" ] || [ "$mac" = "00:00:00:00:00:00" ]; then
            mac="无MAC"
        fi
        
        if echo "$link_status" | grep -q 'UP'; then
            if echo "$link_status" | grep -q 'LOWER_UP'; then state="已链接UP";
             elif echo "$link_status" | grep -q 'NO-CARRIER'; then state="未插线UP";
             else state="已启用UP"; fi
        elif echo "$link_status" | grep -q 'DOWN'; then state="已禁用DOWN";
        else
             case "$state_field" in
                 UP) state="已链接StateUP";; DOWN) state="已禁用StateDOWN";;
                 UNKNOWN) state="未知状态StateUNKNOWN";; *) state="状态-${state_field}-${link_status}";;
             esac
        fi
        ips=$(ip -o addr show dev "$iface" 2>/dev/null | awk '$3 == "inet" {print $4} $3 == "inet6" && $4 !~ /^fe80:/ {print $4}' | sed 's|/[0-9]\+||')
        ip_list=$(echo "$ips" | paste -sd ' ')
        local prefix=""
        if [[ "$iface" == "$default_iface" ]]; then prefix="[DEFAULT]-"; fi
        output="${output}${prefix}${state}:${iface}:MAC=${mac}:[${ip_list}]"
        output="${output}
"
    done
    echo -n "$output" | sed '/^$/d'
}
store_formatted_data "IP_Info" get_ip_info

# 2.5 网卡 Bond 情况 [保持聚合]
get_bond_info() {
    local bond_dir="/proc/net/bonding"
    local output=""
    if [ -d "$bond_dir" ] && [ "$(ls -A $bond_dir)" ]; then
        for bond_file in "$bond_dir"/*; do
            local bond_name bond_mode slaves slave_list
            bond_name=$(basename "$bond_file")
            bond_mode=$(grep "Bonding Mode:" "$bond_file" | awk '{$1=$2=""; print $0}' | sed 's/^[ \t]*//')
            slaves=$(grep "Slave Interface:" "$bond_file" | awk '{print $3}')
            slave_list=$(echo "$slaves" | paste -sd ' ')
            output="${output}${bond_name}:${bond_mode}:[${slave_list}]"
            output="${output}
"
        done
    else
        output="未配置Bond"
    fi
    echo -n "$output" | sed '/^$/d'
}
store_formatted_data "Bond_Info" get_bond_info

# 3. 服务器系统和版本
get_os_version() {
    if [ -f /etc/os-release ]; then
        # Avoid source, use grep/cut which is safer in subshells
        local pretty_name
        pretty_name=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d'=' -f2- | tr -d '"')
        if [ -n "$pretty_name" ]; then
            echo "$pretty_name"
        else
            # Fallback if PRETTY_NAME is missing
            local name version
            name=$(grep '^NAME=' /etc/os-release | cut -d'=' -f2- | tr -d '"')
            version=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2- | tr -d '"')
            echo "${name:-Unknown OS} ${version:-}" # Combine NAME and VERSION_ID
        fi
    # 抑制 lsb_release 错误输出
    elif command -v lsb_release >/dev/null 2>&1 && lsb_output=$(lsb_release -ds 2>/dev/null); then
        echo "$lsb_output"
    elif [ -f /etc/redhat-release ]; then cat /etc/redhat-release
    elif [ -f /etc/debian_version ]; then echo "Debian $(cat /etc/debian_version)"
    elif [ -f /etc/system-release ]; then cat /etc/system-release
    else echo "未知操作系统"; fi
}
store_formatted_data "OS_Version" get_os_version

# 4. 内核版本
get_kernel_version() {
   uname -r
}
store_formatted_data "Kernel_Version" get_kernel_version

# 5. CPU 信息 [拆分]
get_cpu_model() {
    grep -m 1 "model name" /proc/cpuinfo | awk -F': ' '{print $2}'
}
get_cpu_logical_cores() {
    grep -c "^processor" /proc/cpuinfo
}
get_cpu_physical_count() {
    local count=$(grep "physical id" /proc/cpuinfo | sort -u | wc -l)
    echo ${count:-1} # Default to 1 if no physical id found
}
get_cpu_physical_cores_per_cpu() {
    grep -m 1 "cpu cores" /proc/cpuinfo | awk '{print $4}' 2>/dev/null || echo 1
}
get_cpu_total_physical_cores() {
    local physic_ids cores_per_physic physic_cores cores
    physic_ids=$(get_cpu_physical_count)
    cores_per_physic=$(get_cpu_physical_cores_per_cpu)
    physic_cores=$((physic_ids * cores_per_physic))
    if [[ "$physic_cores" -eq 0 ]]; then
        cores=$(get_cpu_logical_cores)
        if [[ "$cores" -gt 0 ]]; then physic_cores=$cores
        else physic_cores=0; fi
    fi
    echo $physic_cores
}
get_cpu_frequency_ghz() {
    grep -m 1 "cpu MHz" /proc/cpuinfo | awk -F': ' '{printf "%.2f", $2/1000}' || echo "N/A"
}

store_formatted_data "CPU_Model" get_cpu_model
store_formatted_data "CPU_Logical_Cores" get_cpu_logical_cores
store_formatted_data "CPU_Physical_Count" get_cpu_physical_count
store_formatted_data "CPU_Total_Physical_Cores" get_cpu_total_physical_cores
store_formatted_data "CPU_Frequency_GHz" get_cpu_frequency_ghz

# 6. 内存大小 [拆分, 移除 buffer/cache]
get_memory_value_gb() {
    local field=$1
    grep "^${field}:" /proc/meminfo | awk '{printf "%.2f", $2/1024/1024}' || echo "0.00"
}

store_formatted_data "Memory_Total_GB" get_memory_value_gb MemTotal
store_formatted_data "Memory_Available_GB" get_memory_value_gb MemAvailable
store_formatted_data "Memory_Free_GB" get_memory_value_gb MemFree
store_formatted_data "Memory_Swap_Total_GB" get_memory_value_gb SwapTotal
store_formatted_data "Memory_Swap_Free_GB" get_memory_value_gb SwapFree

# 7. 硬盘信息 [保持聚合]
get_disk_info() {
    local output=""
    if command -v lsblk > /dev/null 2>&1; then
        # 保持上次移除 2>/dev/null 的改动
        # 使用进程替换而非管道，避免子shell问题
        while IFS= read -r line; do
            local name="" rota="" model="" size_bytes="" type="" vendor="" disk_type="" serial="" size_human=""
            NAME=$(echo "$line" | awk -F'NAME=' '{print $2}' | awk -F'"' '{print $2}')
            ROTA=$(echo "$line" | awk -F'ROTA=' '{print $2}' | awk -F'"' '{print $2}')
            MODEL=$(echo "$line" | awk -F'MODEL=' '{print $2}' | awk -F'"' '{print $2}')
            SIZE=$(echo "$line" | awk -F'SIZE=' '{print $2}' | awk -F'"' '{print $2}')
            TYPE=$(echo "$line" | awk -F'TYPE=' '{print $2}' | awk -F'"' '{print $2}')
            VENDOR=$(echo "$line" | awk -F'VENDOR=' '{print $2}' | awk -F'"' '{print $2}')
            if [ -z "$NAME" ]; then continue; fi
            name="/dev/$NAME"; size_bytes="$SIZE"
            # 移除 numfmt 依赖，只使用手动计算
            if [[ "$size_bytes" -gt 0 ]]; then
                 # 使用awk进行浮点数计算替代bash计算
                 size_gb=$(awk -v size="$size_bytes" 'BEGIN {printf "%.0f", size/1024/1024/1024}')
                 if [[ $size_gb -gt 1024 ]]; then 
                     size_human=$(awk -v size="$size_bytes" 'BEGIN {printf "%.2f TiB", size/1024/1024/1024/1024}')
                 elif [[ $size_gb -gt 0 ]]; then 
                     size_human=$(awk -v size="$size_bytes" 'BEGIN {printf "%.2f GiB", size/1024/1024/1024}')
                 else 
                     size_human=$(awk -v size="$size_bytes" 'BEGIN {printf "%.2f MiB", size/1024/1024}')
                 fi
            else size_human="未知大小"; fi
            local sys_rota_path="/sys/block/$NAME/queue/rotational"
            if [ -f "$sys_rota_path" ]; then
                if [ "$(cat "$sys_rota_path")" = "0" ]; then disk_type="SSD/NVMe";
                elif [ "$(cat "$sys_rota_path")" = "1" ]; then disk_type="HDD";
                else disk_type="未知类型[sys:${ROTA}]"; fi
            else
                 if [ "$ROTA" = "0" ]; then disk_type="SSD/NVMe [推测]";
                 elif [ "$ROTA" = "1" ]; then disk_type="HDD [推测]";
                 else disk_type="未知类型"; fi
            fi
            serial="";
            # NVMe设备直接从sysfs获取序列号
            if [[ "$NAME" == nvme* ]] && [ -r "/sys/block/$NAME/device/serial" ]; then
                serial=$(cat "/sys/block/$NAME/device/serial" 2>/dev/null)
            # SATA/IDE设备使用hdparm
            elif command -v hdparm > /dev/null 2>&1 && [ -e "$name" ]; then
                serial=$(hdparm -I "$name" 2>/dev/null | grep -i "Serial Number" | sed 's/.*Serial Number[: \t]*//i')
            # 通用方式使用smartctl
            elif command -v smartctl > /dev/null 2>&1 && [ -e "$name" ]; then
                serial=$(smartctl -i "$name" 2>/dev/null | grep -i "Serial Number" | sed 's/.*Serial Number[: \t]*//i')
            # SAS/SCSI设备可使用sg_inq
            elif command -v sg_inq > /dev/null 2>&1 && [ -e "$name" ]; then
                serial=$(sg_inq -p 0x80 "$name" 2>/dev/null | grep -oP '(?<=Serial number: ).*')
            fi
            # 检查序列号是否为空
            if [ -z "$serial" ] || [ "$serial" = "0000000000000000" ] || [ "$serial" = "0" ]; then
                serial="无法获取"
            fi
             if [[ -z "$MODEL" || "$MODEL" == "Virtual" || -z "$VENDOR" ]] && command -v smartctl > /dev/null 2>&1; then
                 smart_info=$(smartctl -i "$name" 2>/dev/null)
                 if [ -z "$MODEL" ] || [ "$MODEL" == "Virtual" ]; then
                     model_smart=$(echo "$smart_info" | grep -E "^Device Model:|^Product:" | head -n1 | awk -F': ' '{print $2}')
                     if [ -n "$model_smart" ]; then MODEL="$model_smart"; fi
                 fi
                  if [ -z "$VENDOR" ]; then
                      vendor_smart=$(echo "$smart_info" | grep "^Vendor:" | head -n1 | awk -F': ' '{print $2}')
                       if [ -n "$vendor_smart" ]; then VENDOR="$vendor_smart"; fi
                  fi
             fi
            output+="设备:${name} | 类型:${disk_type} | 厂商:${VENDOR:-未知} | 型号:${MODEL:-未知} | 序列号:${serial} | 大小:${size_human}"
            output="${output}
"
        done < <(lsblk -d -b -n -P -o NAME,ROTA,MODEL,SIZE,TYPE,VENDOR | grep 'TYPE="disk"' | grep -vE 'loop|rom')
    else output="无法找到 lsblk 命令，无法获取详细磁盘信息。"; fi
    echo -n "$output" | sed '/^$/d'
}
store_formatted_data "Disk_Info" get_disk_info

# 8. 文件系统信息 [保持聚合]
get_fs_info() {
    local output=""
    output=$(df -hP -T 2>/dev/null | grep -vE '^Filesystem|tmpfs|devtmpfs|overlay|udev|squashfs|iso9660|efivarfs' | awk 'NF>=7 {
        filesystem=$1; type=$2; size=$3; used=$4; avail=$5; use_percent=$6;
        mp=""; for(i=7; i<=NF; i++) { mp = mp (mp=="" ? "" : " ") $i }
        avail_percent="N/A";
        if (use_percent ~ /^[0-9]+%?$/) {
            use_val = use_percent; sub(/%$/, "", use_val);
            if (use_val+0 == use_val) { avail_val = 100 - use_val; avail_percent = avail_val "%" }
        }
        printf "设备:%s | 挂载点:%s | 类型:%s | 总大小:%s | 已用:%s | 可用:%s | 可用百分比:%s\n", filesystem, mp, type, size, used, avail, avail_percent
    }')
    echo -n "$output"
}
store_formatted_data "Filesystem_Info" get_fs_info

# 9. 监听端口 [保持聚合]
get_listening_ports() {
    local output=""
    if command -v ss > /dev/null 2>&1; then
        output=$(ss -H -tuln 2>/dev/null | awk '{
                    proto=$1; listen_addr=$5; split(listen_addr, parts, ":");
                    port = parts[length(parts)]; ip_part = substr(listen_addr, 1, length(listen_addr)-length(port)-1);
                    if (ip_part == "*") { ip = "0.0.0.0"; } else if (ip_part == "[::]") { ip = "[::]"; }
                    else if (ip_part ~ /^::ffff:/) { sub(/^::ffff:/, "", ip_part); ip = ip_part; }
                    else { ip = ip_part; }
                    sub(/%.*/, "", ip);
                    print toupper(proto)":"ip":"port
                }')
    elif command -v netstat > /dev/null 2>&1; then
         output=$(netstat -tuln 2>/dev/null | grep -E 'LISTEN|UDP' | awk '
                 {
                     if ($1 ~ /tcp6?/) proto="TCP"; else proto="UDP";
                     listen_addr=$4; split(listen_addr, parts, ":");
                     port = parts[length(parts)]; ip_part = substr(listen_addr, 1, length(listen_addr)-length(port)-1);
                     if (ip_part == "0.0.0.0" || ip_part == "*") { ip = "0.0.0.0"; }
                     else if (ip_part == "::") { ip = "[::]"; }
                     else if (ip_part ~ /^::ffff:/) { sub(/^::ffff:/, "", ip_part); ip = ip_part; }
                     else { ip = ip_part; }
                     print proto":"ip":"port
                 }')
    else output="无法找到 ss 或 netstat 命令，无法获取监听端口信息。"; fi
    echo "$output" | sort -u | sed '/^$/d'
}
store_formatted_data "Listening_Ports" get_listening_ports

# === 其他常用信息 [部分移除或拆分] ===

# 10. 系统运行时间 [拆分]
get_uptime_duration() {
    uptime -p 2>/dev/null | sed 's/^up //' || uptime | sed -n 's/.*up \([^,]*\),.*/\1/p'
}
get_boot_time() {
    # 统一时间格式为 YYYY-MM-DD HH:MM:SS
    uptime -s 2>/dev/null | awk '{print $1" "$2}' || echo "N/A"
}
store_formatted_data "Uptime_Duration" get_uptime_duration
store_formatted_data "Boot_Time" get_boot_time

# 11. 当前登录用户 [移除]
# get_users() { ... }
# store_formatted_data "Logged_In_Users" get_users

# 12. 系统负载 [移除]
# get_load_average() { ... }
# store_formatted_data "Load_Average" get_load_average

# 13. CPU 架构
get_cpu_architecture() {
    uname -m
}
store_formatted_data "CPU_Architecture" get_cpu_architecture

# 14. SELinux/AppArmor Status [拆分]
get_selinux_status() {
    if command -v sestatus &> /dev/null; then
        sestatus 2>/dev/null | grep "SELinux status:" | awk '{print $3}' || echo "Error"
    else echo "Not Detected"; fi
}
get_apparmor_status() {
     if command -v aa-status &> /dev/null; then
        if aa-status --enabled &> /dev/null; then echo "Enabled";
        else echo "Disabled/Inactive"; fi
    else echo "Not Detected"; fi
}
store_formatted_data "SELinux_Status" get_selinux_status
store_formatted_data "AppArmor_Status" get_apparmor_status

# 15. 系统时间与时区
get_datetime_zone() {
    # 统一时间格式为 YYYY-MM-DD HH:MM:SS
    date +'%Y-%m-%d %H:%M:%S'
}
store_formatted_data "DateTime_TimeZone" get_datetime_zone

# 16. 检测时间
get_detection_time() {
    # 这里无需修改，因为DETECTION_TIME已经是正确格式
    echo "$DETECTION_TIME"
}
store_formatted_data "Detection_Time" get_detection_time

# 17. 服务器序列号
get_server_serial() {
    local serial
    # 首选方案: 使用dmidecode (需要root权限)
    if command -v dmidecode > /dev/null 2>&1; then
        serial=$(dmidecode -s system-serial-number 2>/dev/null | grep -v "^#" | grep -v "^Not" | grep -v "^To Be")
    fi
    
    # 备选方案1: 直接从sysfs读取
    if [ -z "$serial" ] && [ -f "/sys/class/dmi/id/product_serial" ]; then
        serial=$(cat /sys/class/dmi/id/product_serial 2>/dev/null)
    fi
    
    # 备选方案2: 使用lshw命令
    if [ -z "$serial" ] && command -v lshw > /dev/null 2>&1; then
        serial=$(lshw -c system 2>/dev/null | grep -i "serial:" | head -1 | awk -F': ' '{print $2}')
    fi
    
    # 备选方案3: 针对特定厂商的服务器
    if [ -z "$serial" ]; then
        # Dell服务器
        if command -v omreport > /dev/null 2>&1; then
            serial=$(omreport chassis info 2>/dev/null | grep -i "Chassis Service Tag" | awk -F': ' '{print $2}')
        # HP/HPE服务器
        elif command -v hpasmcli > /dev/null 2>&1; then
            serial=$(hpasmcli -s "show server" 2>/dev/null | grep -i "Serial Number" | awk -F': ' '{print $2}')
        # IBM/Lenovo服务器
        elif command -v ipmitool > /dev/null 2>&1; then
            serial=$(ipmitool fru print 2>/dev/null | grep -i "Product Serial" | head -1 | awk -F': ' '{print $2}')
        fi
    fi
    
    # 检查序列号是否为空、无效值或占位符
    if [ -z "$serial" ] || [ "$serial" = "0" ] || [ "$serial" = "Not Specified" ] || [ "$serial" = "N/A" ] || [ "$serial" = "None" ]; then
        serial="人工确认"
    fi
    
    echo "$serial"
}
store_formatted_data "Server_Serial" get_server_serial

# 18. 服务器型号和厂商
get_server_model() {
    local model manufacturer
    
    if command -v dmidecode > /dev/null 2>&1; then
        manufacturer=$(dmidecode -s system-manufacturer 2>/dev/null | grep -v "^#" | grep -v "^Not")
        model=$(dmidecode -s system-product-name 2>/dev/null | grep -v "^#" | grep -v "^Not")
        
        if [ -n "$manufacturer" ] && [ -n "$model" ]; then
            echo "$manufacturer $model"
            return
        fi
    fi
    
    echo "人工确认"
}
store_formatted_data "Server_Model" get_server_model

# 19. 服务器位置信息
get_server_location() {
    echo "人工确认"
}
store_formatted_data "Server_Location" get_server_location

# 20. 服务器功能
get_server_function() {
    echo "人工确认"
}
store_formatted_data "Server_Function" get_server_function

# 21. 服务器角色
get_server_role() {
    echo "人工确认"
}
store_formatted_data "Server_Role" get_server_role

# 22. 服务器环境
get_server_environment() {
    echo "人工确认"
}
store_formatted_data "Server_Environment" get_server_environment

# 23. SSH端口
get_ssh_port() {
    # 尝试检测默认SSH端口
    local default_port=22
    if [ -f "/etc/ssh/sshd_config" ]; then
        local configured_port=$(grep -E "^Port [0-9]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        if [ -n "$configured_port" ]; then
            echo "$configured_port (需人工确认)"
            return
        fi
    fi
    echo "人工确认"
}
store_formatted_data "SSH_Port" get_ssh_port

# 24. SSH账号密码
get_ssh_credentials() {
    echo "人工确认"
}
store_formatted_data "SSH_Credentials" get_ssh_credentials

# 25. 平台登录地址
get_platform_url() {
    echo "人工确认"
}
store_formatted_data "Platform_URL" get_platform_url

# 26. 平台账号密码
get_platform_credentials() {
    echo "人工确认"
}
store_formatted_data "Platform_Credentials" get_platform_credentials

# 27. 业务关键组件
get_critical_components() {
    echo "人工确认"
}
store_formatted_data "Critical_Components" get_critical_components

# --- 输出最终结果 --- 

# 创建英文到中文的标题映射
declare -A title_map
title_map["Hostname"]="主机名"
title_map["Default_IPv4"]="默认IPv4地址"
title_map["Default_IPv6"]="默认IPv6地址"
title_map["IP_Info"]="网络信息"
title_map["Bond_Info"]="网卡绑定"
title_map["OS_Version"]="操作系统"
title_map["Kernel_Version"]="内核版本"
title_map["CPU_Model"]="CPU型号"
title_map["CPU_Logical_Cores"]="CPU逻辑核心数"
title_map["CPU_Physical_Count"]="CPU物理颗数"
title_map["CPU_Total_Physical_Cores"]="CPU总物理核心数"
title_map["CPU_Frequency_GHz"]="CPU频率(GHz)"
title_map["Memory_Total_GB"]="内存总量(GB)"
title_map["Memory_Available_GB"]="可用内存(GB)"
title_map["Memory_Free_GB"]="空闲内存(GB)"
title_map["Memory_Swap_Total_GB"]="交换空间总量(GB)"
title_map["Memory_Swap_Free_GB"]="空闲交换空间(GB)"
title_map["Disk_Info"]="磁盘信息"
title_map["Filesystem_Info"]="文件系统"
title_map["Listening_Ports"]="监听端口"
title_map["Uptime_Duration"]="运行时长"
title_map["Boot_Time"]="启动时间"
title_map["CPU_Architecture"]="CPU架构"
title_map["SELinux_Status"]="SELinux状态"
title_map["AppArmor_Status"]="AppArmor状态" 
title_map["DateTime_TimeZone"]="系统时间"
title_map["Detection_Time"]="检测时间"
title_map["Server_Serial"]="服务器序列号"
title_map["Server_Model"]="服务器型号厂商"
title_map["Server_Location"]="服务器位置"
title_map["Server_Function"]="服务器功能"
title_map["Server_Role"]="服务器角色"
title_map["Server_Environment"]="服务器环境"
title_map["SSH_Port"]="SSH端口"
title_map["SSH_Credentials"]="SSH账号密码"
title_map["Platform_URL"]="平台登录地址"
title_map["Platform_Credentials"]="平台账号密码"
title_map["Critical_Components"]="业务关键组件"

# 打印中文标题行
chinese_titles=()
for category in "${categories[@]}"; do
    chinese_title="${title_map[$category]:-$category}"
    chinese_titles+=("$chinese_title")
done
(IFS=,; echo "${chinese_titles[*]}")

# 打印数据行
(IFS=,; echo "${values[*]}")

