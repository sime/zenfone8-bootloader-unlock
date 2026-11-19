#!/bin/bash
RED_COLOR='\E[1;31m'
RED_REVERSE_COLOR='\E[0;7;31m'
GREEN_COLOR='\E[1;32m'
RESET='\E[0m'
FASTBOOT=./fastboot


function failure_prompt()
{
	if [ "x$1" == "x0" ] && [ "x$2" != "x" ]; then
		echo -e "${GREEN_COLOR}$2 flash succeed!${RESET}"
	else
		echo -e "${RED_COLOR}$2 flash failed!${RESET}"
		echo Press any key to exit the script.
		read
		exit 1
	fi
}

function flash_image()
{
	if [ "x$1" != "x" ] && [ "x$2" != "x" ]; then
		echo -e "Start Flash $1"
		sudo $FASTBOOT flash -S 300M $1 $2
		failure_prompt $? $1
	fi
}

function erase_partition()
{
	if [ "x$1" != "x" ]; then
		echo -e "Start erase $1"
		sudo $FASTBOOT erase $1
		failure_prompt $? $1
	fi
}

function Crc32Checksum()
{
	partition_name_in_crc32file=$1
	filesize=`cat crc32_img_size.txt | grep -w $partition_name_in_crc32file | awk '{print$1}'`
	sudo $FASTBOOT oem hashsize_$filesize > /dev/null 2>&1
	pt_crc32_val=`sudo $FASTBOOT oem crc32check_$1 2>&1 | grep bootloader | awk '{print$2}'`
	img_crc32_val=`cat crc32_checksum.txt | grep -w $partition_name_in_crc32file | awk '{print$1}' | tr 'a-z' 'A-Z'`
	if [ "$pt_crc32_val" != "$img_crc32_val" ]; then
		echo -e "${RED_COLOR}filesize : $filesize${RESET}"
		echo -e "${RED_COLOR}pt_crc32_val:$pt_crc32_val  img_crc32_val:$img_crc32_val${RESET}"
		echo -e "${RED_COLOR}Crc32Check fail partition : ${RED_REVERSE_COLOR}$1${RESET}"
		exit 1
	else
		echo -e "${GREEN_COLOR}Partition $1 Crc32Check succeed!${RESET}"
	fi
}

function Crc32CheckGeneralPartition()
{
	Crc32Checksum multiimgoem_a
	Crc32Checksum multiimgoem_b
	Crc32Checksum xbl_a
	Crc32Checksum xbl_config_a
	Crc32Checksum xbl_b
	Crc32Checksum xbl_config_b
	Crc32Checksum abl_a
	Crc32Checksum abl_b
	Crc32Checksum aop_a
	Crc32Checksum aop_b
	Crc32Checksum tz_a
	Crc32Checksum tz_b
	Crc32Checksum hyp_a
	Crc32Checksum hyp_b
	Crc32Checksum modem_a
	Crc32Checksum modem_b
	Crc32Checksum bluetooth_a
	Crc32Checksum bluetooth_b
	Crc32Checksum dsp_a
	Crc32Checksum dsp_b
	Crc32Checksum keymaster_a
	Crc32Checksum keymaster_b
	Crc32Checksum rtice
	Crc32Checksum storsec
	Crc32Checksum shrm_a
	Crc32Checksum shrm_b
	Crc32Checksum asdf
	Crc32Checksum devcfg_a
	Crc32Checksum devcfg_b
	Crc32Checksum qupfw_a
	Crc32Checksum qupfw_b
	Crc32Checksum cpucp_a
	Crc32Checksum cpucp_b
	Crc32Checksum logfs
	Crc32Checksum uefisecapp_a
	Crc32Checksum uefisecapp_b
	Crc32Checksum featenabler_a
	Crc32Checksum featenabler_b
	Crc32Checksum imagefv_a
	Crc32Checksum imagefv_b
	Crc32Checksum qweslicstore_a
	Crc32Checksum qweslicstore_b
	Crc32Checksum ADF
	Crc32Checksum vbmeta_a
	Crc32Checksum vbmeta_b
	Crc32Checksum vbmeta_system_a
	Crc32Checksum vbmeta_system_b
	Crc32Checksum boot_a
	Crc32Checksum boot_b
	Crc32Checksum vendor_boot_a
	Crc32Checksum vendor_boot_b
	Crc32Checksum dtbo_a
	Crc32Checksum dtbo_b
	if [ "$CRC" == "skipcrc" ]; then
		echo -e "${GREEN_COLOR}^_^ Crc32Check General Partitions Pass ^o^${RESET}"
	else
		Crc32Checksum super
		echo -e "${GREEN_COLOR}^_^ Crc32Check General Partitions Pass ^o^${RESET}"
	fi
}

while [[ $# > 0 ]];do
	case $1 in
		"-s")
			shift
			SSN_ARG=$1
			if [[ $# == 0 ]]; then
				echo -e "${RED_COLOR}-s requires an argument.${RESET}"
				exit 1
			fi
			;;
		"noreboot")
			SKIPREBOOT="noreboot"
			shift
			;;
		"skipcrc")
			CRC="skipcrc"
			;;
		"skipcrcall")
			CRC="skipcrcall"
			;;
		*)
			echo -e "${RED_COLOR}Invalid parameter!${RESET}"
			exit 1
			;;
	esac
	shift
done

if [ "x$SSN_ARG" != "x" ]; then
	FASTBOOT="${FASTBOOT} -s ${SSN_ARG}"
fi

sudo $FASTBOOT getvar project > get_prjtemp$SSN_ARG.txt 2>&1
if [ $? != 0 ]; then
    echo -e "${RED_COLOR}Get project failed!${RESET}"
    exit 1
fi
project=`grep -o "ZS590KS" get_prjtemp$SSN_ARG.txt`
rm -rf get_prjtemp$SSN_ARG.txt
sudo $FASTBOOT oem get-hwid > get_hwtemp$SSN_ARG.txt 2>&1
if [ $? != 0 ]; then
    echo -e "${RED_COLOR}Get hwid failed!${RESET}"
    exit 1
fi
hwid=`grep HWID get_hwtemp$SSN_ARG.txt | awk -F'=' '{print $NF}' | awk -F' ' '{print $1}'`
rm -rf get_hwtemp$SSN_ARG.txt
if [ "$hwid" == "0" ]; then
    echo -e "${GREEN_COLOR}Hwid=$hwid,this is EVB!${RESET}"
elif [ "$hwid" == "1" ]; then
    echo -e "${GREEN_COLOR}Hwid=$hwid,this is EVB2!${RESET}"
elif [ "x$project" == "xZS590KS" ]; then
    echo -e "${GREEN_COLOR}Project $project matching success!${RESET}"
else
	echo -e "${RED_COLOR}The script can't be used in this devices,hwid=$hwid,project=$project!${RESET}"
	exit 1
fi

# =================== erase: misc ======================
erase_partition misc

# ====================== flash: abl ====================
flash_image abl_a abl.elf
flash_image abl_b abl.elf

sudo $FASTBOOT reboot-bootloader

sleep 5

# ============== add for fac flash fail ================
flash_image multiimgoem_a firmware/multi_image.mbn
flash_image multiimgoem_b firmware/multi_image.mbn

# ==================== partition_0 =====================
sudo $FASTBOOT flash partition:0 gpt_both0.bin
failure_prompt $? partition:0

# ==================== partition_1 =====================
sudo $FASTBOOT flash partition:1 gpt_both1.bin
failure_prompt $? partition:1

# ==================== partition_2 =====================
sudo $FASTBOOT flash partition:2 gpt_both2.bin
failure_prompt $? partition:2


# ==================== partition_3 =====================
sudo $FASTBOOT flash partition:3 gpt_both3.bin
failure_prompt $? partition:3


# ==================== partition_4 =====================
sudo $FASTBOOT flash partition:4 gpt_both4.bin
failure_prompt $? partition:4


# ==================== partition_5 =====================
sudo $FASTBOOT flash partition:5 gpt_both5.bin
failure_prompt $? partition:5


# ==================== partition_6 =====================
sudo $FASTBOOT flash partition:6 gpt_both6.bin
failure_prompt $? partition:6

# ================ flash: multiimgoem ==================
flash_image multiimgoem_a firmware/multi_image.mbn
flash_image multiimgoem_b firmware/multi_image.mbn

# =============== flash: xbl & xbl_config===============
flash_image xbl_a firmware/xbl.elf
flash_image	xbl_config_a firmware/xbl_config.elf
flash_image xbl_b firmware/xbl.elf
flash_image	xbl_config_b firmware/xbl_config.elf

# =================== flash: shrm ======================
flash_image shrm_a firmware/shrm.elf
flash_image shrm_b firmware/shrm.elf

# ====================== flash: abl ====================
flash_image abl_a abl.elf
flash_image abl_b abl.elf

# ==================== flash: aop ======================
flash_image aop_a firmware/aop.mbn
flash_image aop_b firmware/aop.mbn

# ==================== flash: TZ =======================
flash_image tz_a firmware/tz.mbn
flash_image tz_b firmware/tz.mbn

# ==================== flash: hyp ======================
flash_image hyp_a firmware/hypvm.mbn
flash_image hyp_b firmware/hypvm.mbn

# ================== flash: Modem ======================
flash_image modem_a firmware/NON-HLOS.bin
flash_image modem_b firmware/NON-HLOS.bin

# ================ flash: bluetooth ====================
flash_image bluetooth_a firmware/BTFM.bin
flash_image bluetooth_b firmware/BTFM.bin

# ===================== flash: dsp =====================
flash_image dsp_a firmware/dspso.bin
flash_image dsp_b firmware/dspso.bin

# ================= flash: keymaster ===================
flash_image keymaster_a firmware/km41.mbn
flash_image keymaster_b firmware/km41.mbn

# =================== flash: rtice =====================
flash_image rtice firmware/rtice.mbn

# ================== flash: storsec ====================
flash_image storsec firmware/storsec.mbn

# =================== erase: misc ======================
erase_partition misc

# =================== erase: ssd =======================
#erase_partition ssd

# ================= erase: keystore ====================
#erase_partition keystore

# ================ flash: apdp & spunvm ================
#flash_image apdp apdp.mbn
#flash_image	spunvm firmware/spunvm.bin
erase_partition spunvm

# ================ flash: qweslicstore =================
flash_image	qweslicstore_a firmware/qweslicstore.bin
flash_image	qweslicstore_b firmware/qweslicstore.bin

# ================== flash: batinfo ====================
#flash_image	batinfo batinfo.img

# ================== flash: devcfg =====================
flash_image devcfg_a firmware/devcfg.mbn
flash_image devcfg_b firmware/devcfg.mbn

# ============= flash: cmnlib & cmnlib64 ===============
#flash_image cmnlib_a firmware/cmnlib.mbn
#flash_image cmnlib_b firmware/cmnlib.mbn

#flash_image cmnlib64_a firmware/cmnlib64.mbn
#flash_image cmnlib64_b firmware/cmnlib64.mbn

# ==================== flash: qupfw ====================
flash_image qupfw_a firmware/qupv3fw.elf
flash_image qupfw_b firmware/qupv3fw.elf

# ==================== flash: qupfw ====================
flash_image cpucp_a firmware/cpucp.elf
flash_image cpucp_b firmware/cpucp.elf

# ==================== flash: logfs ====================
flash_image logfs firmware/logfs_ufs_8mb.bin

# ================= flash: uefisecapp ==================
flash_image uefisecapp_a firmware/uefi_sec.mbn
flash_image uefisecapp_b firmware/uefi_sec.mbn

# ================ flash: featenabler ==================
flash_image featenabler_a firmware/featenabler.mbn
flash_image featenabler_b firmware/featenabler.mbn

# =================== flash: imagefv ===================
flash_image imagefv_a firmware/imagefv.elf
flash_image imagefv_b firmware/imagefv.elf

# ==================== flash: vbmeta ===================
#flash_image persist persist.img

# ===================== flash: ADF =====================
if [ -e ADF.img ]; then
	flash_image ADF ADF.img
fi

# ==================== flash: vbmeta ===================
flash_image vbmeta_a vbmeta.img
flash_image vbmeta_b vbmeta.img

# =============== flash: vbmeta_system =================
flash_image vbmeta_system_a vbmeta_system.img
flash_image vbmeta_system_b vbmeta_system.img

# ==================== flash: boot =====================
flash_image boot_a boot.img
flash_image boot_b boot.img

# ================= flash: vendor_boot =================
flash_image vendor_boot_a vendor_boot.img
flash_image vendor_boot_b vendor_boot.img

# ==================== flash: dtbo =====================
flash_image dtbo_a dtbo.img
flash_image dtbo_b dtbo.img

# =================== flash: XROM ======================
if [ -e ASUS-xrom.img ]; then
	flash_image xrom_a ASUS-xrom.img
	flash_image xrom_b ASUS-xrom.img
fi

# ==================== flash: asdf =====================
erase_partition asdf
flash_image	asdf asdf_384M.img

# =================== flash: super =====================
erase_partition super
flash_image super super.img

if [ "$CRC" == "skipcrcall" ]; then
	echo -e "${GREEN_COLOR}^_^ Crc32Check General Partitions Skip ^o^${RESET}"
else
	Crc32CheckGeneralPartition
fi

# =================== erase: data ======================
sudo $FASTBOOT -w

# ==================== reset active ====================

# ====================== finished ======================
if [ "$SKIPREBOOT" == "noreboot" ]; then
	echo =======================
	echo  "Download Complete !"
	echo =======================
else
	echo =======================
	echo  "Download Complete !"
	echo =======================
	echo Press any key to continue, system will reboot.
	read
	sudo $FASTBOOT reboot
fi







































